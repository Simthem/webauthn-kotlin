package com.pqvault.core.sync

import com.pqvault.core.UnlockedVault
import com.pqvault.core.Vault
import com.pqvault.core.merge.VaultMerge

/**
 * Synchronises a vault with a WebDAV server using optimistic concurrency.
 *
 * WebDAV offers `LOCK`, but Nextcloud's support is inconsistent and a lock held by a
 * phone that lost signal would strand the vault. Conditional requests are both simpler
 * and safer: every write carries an `If-Match` for the exact version we merged against,
 * so a concurrent write from another device makes ours fail with 412 rather than
 * silently overwriting it. On 412 we re-read, re-merge and try again.
 */
class VaultSyncEngine(
    private val dav: WebDavClient,
    private val remotePath: String,
    /** How to unlock the *remote* file; the caller holds the passphrase or device key. */
    private val unlockRemote: (ByteArray, Long) -> Vault.OpenResult,
    private val maxAttempts: Int = 4,
) {

    sealed class Outcome {
        /**
         * A successful write. [bytes] is exactly what was uploaded, and callers must
         * persist *these* bytes locally rather than re-serialising: every serialize()
         * bumps the version counter, so a second call would leave the local file a
         * version ahead of the server and make the next sync look like a rollback.
         */
        sealed class Written : Outcome() {
            abstract val etag: String?
            abstract val version: Long
            abstract val bytes: ByteArray
        }

        /** Remote did not exist; we created it. */
        class Created(
            override val etag: String?,
            override val version: Long,
            override val bytes: ByteArray,
        ) : Written()

        /** Remote had not changed under us; we pushed our version. */
        class Pushed(
            override val etag: String?,
            override val version: Long,
            override val bytes: ByteArray,
        ) : Written()

        /** Both sides had changed; the merge was pushed. */
        class Merged(
            override val etag: String?,
            override val version: Long,
            override val bytes: ByteArray,
            val conflicts: List<VaultMerge.Conflict>,
        ) : Written()

        /**
         * The server returned a vault that fails our integrity checks: a bad signature,
         * an unknown signer, or a rolled-back version. This is never a transient error and
         * must never be retried away: it means the file was tampered with or replayed, and
         * the user has to be told.
         */
        class RemoteUntrusted(val cause: Untrusted) : Outcome()

        /**
         * Why a remote vault was refused, as data rather than prose.
         *
         * This module has no resources and no locale, so anything it phrased itself would
         * reach the user in English no matter what language the app is running in. The
         * facts travel; the app does the wording.
         */
        sealed class Untrusted {
            /** A genuine but stale file: the server replayed [fileVersion] over [lastSeenVersion]. */
            class Rollback(val fileVersion: Long, val lastSeenVersion: Long) : Untrusted()
            object SignatureInvalid : Untrusted()
            object UnknownSigner : Untrusted()
            class Malformed(val reason: String) : Untrusted()
        }

        /** The remote file exists but our key does not open it. */
        object RemoteUnreadable : Outcome()

        /**
         * [permanent] marks a failure that retrying cannot fix, such as the app not being
         * configured yet. It is a flag rather than something the caller infers from the
         * message, because inspecting a human-readable string breaks the moment that
         * string is translated.
         */
        class Failed(val reason: Failure, val permanent: Boolean = false) : Outcome()

        /** Why a sync did not complete. Typed for the same reason as [Untrusted]. */
        sealed class Failure {
            /** Text the caller has already localised itself. */
            class Reported(val text: String) : Failure()

            /** [detail] is a server or transport message, useful but never translated. */
            class RemoteReadFailed(val detail: String) : Failure()
            class RemoteCreateFailed(val detail: String) : Failure()
            class RemoteWriteFailed(val detail: String) : Failure()

            /** Other devices kept writing between our read and our write. */
            class Contended(val attempts: Int) : Failure()
        }
    }

    /**
     * @param lastSyncEtag the ETag we last successfully synced, or null if never.
     * @param lastSeenVersion the highest vault version this device has accepted; the
     *        rollback check is only meaningful if the caller persists this.
     */
    suspend fun sync(
        local: UnlockedVault,
        lastSyncEtag: String? = null,
        lastSeenVersion: Long = 0,
    ): Outcome {
        var attempt = 0
        while (attempt < maxAttempts) {
            attempt++

            when (val remote = dav.get(remotePath, lastSyncEtag)) {
                is WebDavClient.GetResult.Error ->
                    return Outcome.Failed(Outcome.Failure.RemoteReadFailed(remote.message))

                is WebDavClient.GetResult.NotFound -> {
                    val bytes = local.serialize()
                    when (val put = dav.put(remotePath, bytes, ifNoneMatchAny = true)) {
                        is WebDavClient.PutResult.Success ->
                            return Outcome.Created(put.etag, local.vaultVersion, bytes)
                        // Another device created it first: start over and merge with it.
                        is WebDavClient.PutResult.PreconditionFailed -> continue
                        is WebDavClient.PutResult.Error ->
                            return Outcome.Failed(Outcome.Failure.RemoteCreateFailed(put.message))
                    }
                }

                is WebDavClient.GetResult.Found -> {
                    val opened = unlockRemote(remote.bytes, lastSeenVersion)
                    val remoteVault = when (opened) {
                        is Vault.OpenResult.Success -> opened.vault
                        is Vault.OpenResult.Rollback -> return Outcome.RemoteUntrusted(
                            Outcome.Untrusted.Rollback(opened.fileVersion, opened.lastSeenVersion),
                        )
                        is Vault.OpenResult.SignatureInvalid ->
                            return Outcome.RemoteUntrusted(Outcome.Untrusted.SignatureInvalid)
                        is Vault.OpenResult.UnknownSigner ->
                            return Outcome.RemoteUntrusted(Outcome.Untrusted.UnknownSigner)
                        is Vault.OpenResult.Malformed ->
                            return Outcome.RemoteUntrusted(Outcome.Untrusted.Malformed(opened.reason))
                        is Vault.OpenResult.WrongPassphrase,
                        is Vault.OpenResult.NoMatchingRecipient,
                        -> return Outcome.RemoteUnreadable
                    }

                    val merge = VaultMerge.merge(
                        localEntries = local.entries,
                        localTombstones = local.tombstones,
                        localDevices = local.devices,
                        remoteEntries = remoteVault.entries,
                        remoteTombstones = remoteVault.tombstones,
                        remoteDevices = remoteVault.devices,
                    )
                    val hadRemoteChanges = local.applyMerge(merge)

                    // The pushed version must exceed the one already on the server, or the
                    // next device to read it would correctly diagnose a rollback.
                    local.vaultVersion = maxOf(local.vaultVersion, remoteVault.vaultVersion)
                    remoteVault.close()

                    val bytes = local.serialize()
                    when (val put = dav.put(remotePath, bytes, ifMatch = remote.etag)) {
                        is WebDavClient.PutResult.Success ->
                            return if (hadRemoteChanges || merge.conflicts.isNotEmpty()) {
                                Outcome.Merged(put.etag, local.vaultVersion, bytes, merge.conflicts)
                            } else {
                                Outcome.Pushed(put.etag, local.vaultVersion, bytes)
                            }
                        // Someone wrote between our GET and our PUT: re-read and re-merge.
                        is WebDavClient.PutResult.PreconditionFailed -> continue
                        is WebDavClient.PutResult.Error ->
                            return Outcome.Failed(Outcome.Failure.RemoteWriteFailed(put.message))
                    }
                }
            }
        }
        return Outcome.Failed(Outcome.Failure.Contended(maxAttempts))
    }
}
