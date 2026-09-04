package com.pqvault.app.data

import android.content.Context
import com.pqvault.app.R
import com.pqvault.app.notify.SyncNotifications
import com.pqvault.app.sync.OkHttpWebDavClient
import com.pqvault.core.UnlockedVault
import com.pqvault.core.Vault
import com.pqvault.core.format.Base64Url
import com.pqvault.core.model.PasskeyEntry
import com.pqvault.core.sync.VaultSyncEngine
import com.pqvault.core.sync.WebDavClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File

/**
 * Owns the on-device vault file and the unlocked state derived from it.
 *
 * Process-wide singleton because the credential provider service, the sync worker and the
 * UI all need the same unlocked vault; two copies would race and lose passkeys. The mutex
 * serialises every operation that reads or writes the file.
 */
class VaultRepository private constructor(private val context: Context) {

    private val mutex = Mutex()
    private val settings = SecureSettings(context)
    private val deviceIdentity = DeviceIdentity(context)
    private val notifications = SyncNotifications(context)

    private var unlocked: UnlockedVault? = null

    /**
     * Its own scope rather than a caller's: the auto-lock timer has to outlive whatever
     * unlocked the vault. The credential provider can unlock it from a transient activity
     * that finishes a second later, and the vault would then sit open in memory with
     * nothing left running to close it.
     */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var autoLockJob: Job? = null

    @Volatile
    private var lastActivityAt: Long = 0

    private val _unlockedState = MutableStateFlow(false)

    /** Emits false when the vault closes, including when it closes by itself. */
    val unlockedState: StateFlow<Boolean> = _unlockedState.asStateFlow()

    val vaultFile: File get() = File(context.filesDir, "vault.pqvault")

    val isInitialised: Boolean get() = vaultFile.exists()

    val isUnlocked: Boolean get() = unlocked != null

    sealed class UnlockOutcome {
        object Success : UnlockOutcome()
        object WrongPassphrase : UnlockOutcome()
        object NotInitialised : UnlockOutcome()
        class Untrusted(val reason: String) : UnlockOutcome()
    }

    sealed class RestoreOutcome {
        object Success : RestoreOutcome()

        /** No vault at that path yet, so this device is the one that creates it. */
        object NotFound : RestoreOutcome()
        object WrongPassphrase : RestoreOutcome()
        object NotConfigured : RestoreOutcome()
        object AlreadyInitialised : RestoreOutcome()
        class Untrusted(val reason: String) : RestoreOutcome()
        class Failed(val message: String) : RestoreOutcome()
    }

    suspend fun create(passphrase: CharArray): Unit = mutex.withLock {
        val vault = Vault.create(passphrase)
        // Enrol straight away: without a device recipient there is no way to merge in the
        // background, and asking for the passphrase on every sync is not sync.
        val identity = runCatching { deviceIdentity.loadOrCreate() }
            .getOrElse { deviceIdentity.recreate() }
        vault.enrollDevice(identity.deviceId, android.os.Build.MODEL ?: "this device", identity.keyPair.publicKey)
        val bytes = vault.serialize()
        vaultFile.writeBytes(bytes)
        // A new vault shares nothing with whatever was here before, so the whole synced
        // history goes with it. Carrying over a watermark from the old vault would have
        // the first sync read the server's copy of the *new* one as a rollback.
        settings.save(
            settings.load().copy(
                pinnedSigningKey = Base64Url.encode(vault.signingPublicKeyEncoded),
                localVersion = vault.vaultVersion,
                lastSeenVersion = 0,
                lastSyncEtag = "",
            ),
        )
        unlocked = vault
        onUnlocked()
    }

    /**
     * Brings down the vault that already exists on the server.
     *
     * This is the other half of pairing and it was missing: scanning a pairing code
     * copied the server coordinates across but nothing ever fetched the vault, so the
     * second device sat on the onboarding screen and the only thing it could do was
     * create a second, unrelated vault pointing at the same file.
     *
     * The passphrase is required because a pairing code deliberately does not carry it,
     * and this device holds no key of its own until it has been enrolled.
     */
    suspend fun restoreFromRemote(passphrase: CharArray): RestoreOutcome = mutex.withLock {
        if (vaultFile.exists()) return RestoreOutcome.AlreadyInitialised
        val current = settings.load()
        if (current.webdavBaseUrl.isEmpty()) return RestoreOutcome.NotConfigured

        val dav = OkHttpWebDavClient(
            baseUrl = current.webdavBaseUrl,
            username = current.webdavUsername,
            appPassword = current.webdavAppPassword,
        )
        val remote = when (val result = dav.get(current.remotePath)) {
            is WebDavClient.GetResult.NotFound -> return RestoreOutcome.NotFound
            is WebDavClient.GetResult.Error -> return RestoreOutcome.Failed(result.message)
            is WebDavClient.GetResult.Found -> result
        }

        val pinned = current.pinnedSigningKey.takeIf { it.isNotEmpty() }?.let(Base64Url::decode)
        val opened = Vault.open(remote.bytes, passphrase, pinned, lastSeenVersion = 0)
        val success = when (opened) {
            is Vault.OpenResult.Success -> opened
            is Vault.OpenResult.WrongPassphrase,
            is Vault.OpenResult.NoMatchingRecipient,
            -> return RestoreOutcome.WrongPassphrase
            is Vault.OpenResult.UnknownSigner ->
                return RestoreOutcome.Untrusted(context.getString(R.string.untrusted_signer))
            is Vault.OpenResult.SignatureInvalid ->
                return RestoreOutcome.Untrusted(context.getString(R.string.untrusted_signature))
            is Vault.OpenResult.Malformed ->
                return RestoreOutcome.Untrusted(context.getString(R.string.untrusted_malformed, opened.reason))
            is Vault.OpenResult.Rollback ->
                return RestoreOutcome.Untrusted(context.getString(R.string.untrusted_signer))
        }

        // The pairing code carried a digest rather than the key itself. Checking it here
        // is the whole point of having carried it: it is what makes this a vault the
        // other device vouched for, rather than whatever the server chose to hand back.
        if (!signerMatchesPinnedDigest(current, success.signingPublicKey)) {
            success.vault.close()
            return RestoreOutcome.Untrusted(context.getString(R.string.untrusted_signer))
        }

        vaultFile.writeBytes(remote.bytes)
        settings.save(
            settings.load().copy(
                pinnedSigningKey = Base64Url.encode(success.signingPublicKey),
                lastSyncEtag = remote.etag.orEmpty(),
                lastSeenVersion = success.vault.vaultVersion,
                localVersion = success.vault.vaultVersion,
            ),
        )
        unlocked = success.vault
        onUnlocked()
        RestoreOutcome.Success
    }

    suspend fun unlock(passphrase: CharArray): UnlockOutcome = mutex.withLock {
        if (!vaultFile.exists()) return UnlockOutcome.NotInitialised
        val current = settings.load()
        val result = Vault.open(
            fileBytes = vaultFile.readBytes(),
            passphrase = passphrase,
            pinnedSigningKey = current.pinnedSigningKey.takeIf { it.isNotEmpty() }?.let(Base64Url::decode),
            lastSeenVersion = current.localWatermark,
        )
        applyOpenResult(result, current)
    }

    /** Unlocks using a master key recovered from the biometric wrap. */
    suspend fun unlockWithMasterKey(masterKey: ByteArray): UnlockOutcome = mutex.withLock {
        if (!vaultFile.exists()) return UnlockOutcome.NotInitialised
        val current = settings.load()
        val result = Vault.openWithMasterKey(
            fileBytes = vaultFile.readBytes(),
            masterKey = masterKey,
            pinnedSigningKey = current.pinnedSigningKey.takeIf { it.isNotEmpty() }?.let(Base64Url::decode),
            lastSeenVersion = current.localWatermark,
        )
        applyOpenResult(result, current)
    }

    private fun applyOpenResult(
        result: Vault.OpenResult,
        current: SecureSettings.Settings,
    ): UnlockOutcome = when (result) {
        is Vault.OpenResult.Success -> {
            if (!signerMatchesPinnedDigest(current, result.signingPublicKey)) {
                result.vault.close()
                UnlockOutcome.Untrusted(context.getString(R.string.untrusted_signer))
            } else {
                unlocked = result.vault
                if (current.pinnedSigningKey.isEmpty()) {
                    // Trust on first use: pin the signer now so every later open can
                    // detect a substituted vault.
                    settings.save(current.copy(pinnedSigningKey = Base64Url.encode(result.signingPublicKey)))
                }
                onUnlocked()
                UnlockOutcome.Success
            }
        }
        is Vault.OpenResult.WrongPassphrase,
        is Vault.OpenResult.NoMatchingRecipient,
        -> UnlockOutcome.WrongPassphrase
        is Vault.OpenResult.Rollback -> UnlockOutcome.Untrusted(
            context.getString(R.string.untrusted_rollback, result.fileVersion, result.lastSeenVersion),
        )
        is Vault.OpenResult.SignatureInvalid ->
            UnlockOutcome.Untrusted(context.getString(R.string.untrusted_signature))
        is Vault.OpenResult.UnknownSigner ->
            UnlockOutcome.Untrusted(context.getString(R.string.untrusted_signer))
        is Vault.OpenResult.Malformed ->
            UnlockOutcome.Untrusted(context.getString(R.string.untrusted_malformed, result.reason))
    }

    /**
     * Fire-and-forget lock, for callers with no coroutine of their own.
     *
     * It goes through the same mutex as everything else rather than nulling the field on
     * the spot: closing the vault zeroes the master key, and doing that underneath a save
     * already in flight would write a file encrypted with zeroes.
     */
    fun lock() {
        scope.launch { lockNow() }
    }

    suspend fun lockNow(): Unit = mutex.withLock { closeUnlocked() }

    private fun closeUnlocked() {
        autoLockJob?.cancel()
        autoLockJob = null
        unlocked?.close()
        unlocked = null
        _unlockedState.value = false
    }

    /**
     * Records that the user is still there, deferring the auto-lock.
     *
     * Cheap enough to call from every touch event: it writes one long.
     */
    fun touch() {
        lastActivityAt = System.currentTimeMillis()
    }

    /** Locks straight away if the idle deadline has already passed, used on resume. */
    suspend fun lockIfIdle() {
        val idleMillis = settings.load().autoLockSeconds * 1000L
        if (idleMillis <= 0) return
        mutex.withLock {
            if (unlocked != null && System.currentTimeMillis() - lastActivityAt >= idleMillis) {
                closeUnlocked()
            }
        }
    }

    private fun onUnlocked() {
        touch()
        _unlockedState.value = true
        startAutoLock()
    }

    /**
     * Closes the vault once it has gone unused for the configured time.
     *
     * The loop re-reads the deadline every pass instead of sleeping for the whole
     * interval, so touching the screen genuinely postpones the lock and a change to the
     * setting takes effect without having to lock and unlock first.
     */
    private fun startAutoLock() {
        autoLockJob?.cancel()
        autoLockJob = scope.launch {
            while (isActive) {
                val idleMillis = settings.load().autoLockSeconds * 1000L
                if (idleMillis <= 0) {
                    // "Never" keeps polling rather than ending the job. Ending it would
                    // mean that turning the timer back on in settings did nothing until
                    // the next unlock, which is the one moment the user is not watching.
                    delay(AUTO_LOCK_POLL_MS)
                    continue
                }
                val remaining = idleMillis - (System.currentTimeMillis() - lastActivityAt)
                if (remaining <= 0) {
                    lockNow()
                    return@launch
                }
                delay(remaining.coerceAtMost(AUTO_LOCK_POLL_MS))
            }
        }
    }

    /**
     * Listing is passive: the system queries the provider whenever any app raises a
     * credential picker, so counting it as activity would hold the vault open on
     * somebody else's schedule. Actually using a passkey does count, below.
     */
    fun entriesFor(rpId: String): List<PasskeyEntry> = unlocked?.findByRpId(rpId).orEmpty()

    fun entry(credentialId: String): PasskeyEntry? {
        // Reached only when the user has picked this credential to sign with, which is
        // real use of the vault even with no screen of ours in front of them.
        touch()
        return unlocked?.find(credentialId)
    }

    fun allEntries(): List<PasskeyEntry> = unlocked?.entries.orEmpty()

    suspend fun upsert(entry: PasskeyEntry): Unit = mutex.withLock {
        val vault = unlocked ?: return
        touch()
        vault.addOrReplace(entry)
        vaultFile.writeBytes(vault.serialize())
        rememberVersion(vault)
    }

    suspend fun delete(credentialId: String): Unit = mutex.withLock {
        val vault = unlocked ?: return
        touch()
        vault.delete(credentialId)
        vaultFile.writeBytes(vault.serialize())
        rememberVersion(vault)
    }

    /**
     * Records a local write. It must raise `localVersion` only: the server has not seen
     * these bytes, so treating this counter as the remote watermark would make the
     * server's genuine copy read as a rollback on the next sync and jam it for good.
     */
    private fun rememberVersion(vault: UnlockedVault) {
        settings.save(settings.load().copy(localVersion = vault.vaultVersion))
    }


    /** True once this device holds a recipient entry and can sync unattended. */
    fun isDeviceEnrolled(): Boolean {
        if (!deviceIdentity.exists()) return false
        val id = runCatching { deviceIdentity.loadOrCreate().deviceId }.getOrNull() ?: return false
        return unlocked?.devices?.any { it.deviceId == id } ?: false
    }

    /** Adds this device as a recipient of an already-unlocked vault. */
    suspend fun enrollThisDevice(): Boolean = mutex.withLock {
        val vault = unlocked ?: return false
        val identity = runCatching { deviceIdentity.loadOrCreate() }
            .getOrElse { deviceIdentity.recreate() }
        vault.enrollDevice(
            identity.deviceId,
            android.os.Build.MODEL ?: "this device",
            identity.keyPair.publicKey,
        )
        vaultFile.writeBytes(vault.serialize())
        rememberVersion(vault)
        true
    }

    /**
     * Unattended sync, used by the background worker.
     *
     * Opens the local vault and the remote one with this device's KEM key rather than the
     * passphrase, so it can run with the screen off.
     */
    suspend fun syncUnattended(): VaultSyncEngine.Outcome = mutex.withLock {
        val current = settings.load()
        if (current.webdavBaseUrl.isEmpty()) {
            return failure(R.string.no_webdav_configured, permanent = true)
        }
        if (!vaultFile.exists()) {
            return failure(R.string.sync_no_local_vault, permanent = true)
        }
        if (!deviceIdentity.exists()) {
            return failure(R.string.device_not_enrolled, permanent = true)
        }

        // Never regenerate here: an unattended worker replacing the identity would
        // un-enrol the phone behind the user's back and leave sync failing forever.
        val identity = runCatching { deviceIdentity.loadOrCreate() }.getOrElse {
            return failure(R.string.sync_device_identity_lost, permanent = true)
        }
        val pinned = current.pinnedSigningKey.takeIf { it.isNotEmpty() }?.let(Base64Url::decode)

        // The worker may run with the vault locked, so it opens its own copy rather than
        // relying on whatever the UI happens to have open.
        val localOpen = Vault.openWithDeviceKey(
            fileBytes = vaultFile.readBytes(),
            deviceId = identity.deviceId,
            devicePrivateKey = identity.keyPair.privateKey,
            devicePublicKey = identity.keyPair.publicKey,
            pinnedSigningKey = pinned,
            lastSeenVersion = current.localWatermark,
        )
        val localVault = when (localOpen) {
            is Vault.OpenResult.Success -> localOpen.vault
            // Almost always this device's identity being newer than the vault copy that
            // enrolled it, which re-enrolling fixes, so say that rather than "failed".
            else -> return failure(R.string.sync_device_key_rejected, permanent = true)
        }

        val engine = VaultSyncEngine(
            dav = OkHttpWebDavClient(
                baseUrl = current.webdavBaseUrl,
                username = current.webdavUsername,
                appPassword = current.webdavAppPassword,
            ),
            remotePath = current.remotePath,
            unlockRemote = { bytes, lastSeen ->
                Vault.openWithDeviceKey(
                    fileBytes = bytes,
                    deviceId = identity.deviceId,
                    devicePrivateKey = identity.keyPair.privateKey,
                    devicePublicKey = identity.keyPair.publicKey,
                    pinnedSigningKey = pinned,
                    lastSeenVersion = lastSeen,
                )
            },
        )

        val outcome = engine.sync(
            local = localVault,
            lastSyncEtag = current.lastSyncEtag.takeIf { it.isNotEmpty() },
            lastSeenVersion = current.lastSeenVersion,
        )
        reportOutcome(outcome, localVault.entries.size)

        if (outcome is VaultSyncEngine.Outcome.Written) {
            // The file on disk is now the merged version, which makes any vault already
            // open in this process stale. Left alone, the next passkey saved from the UI
            // would serialise that stale copy back over the merge and quietly drop
            // whatever the other device had contributed. Adopting the vault the sync just
            // produced keeps the app unlocked and correct; only when nothing was open do
            // we close it.
            val stale = unlocked
            if (stale != null) {
                stale.close()
                unlocked = localVault
                _unlockedState.value = true
            } else {
                localVault.close()
            }
        } else {
            localVault.close()
        }
        outcome
    }

    /**
     * Pushes and pulls the vault. Requires the passphrase because the remote copy has to
     * be opened before it can be merged, and the local unlocked key does not necessarily
     * open a vault whose key was rotated elsewhere.
     */
    suspend fun sync(passphrase: CharArray): VaultSyncEngine.Outcome = mutex.withLock {
        val vault = unlocked ?: return failure(R.string.vault_locked_error)
        val current = settings.load()
        if (current.webdavBaseUrl.isEmpty()) {
            return failure(R.string.no_webdav_configured, permanent = true)
        }

        val pinned = current.pinnedSigningKey.takeIf { it.isNotEmpty() }?.let(Base64Url::decode)
        val engine = VaultSyncEngine(
            dav = OkHttpWebDavClient(
                baseUrl = current.webdavBaseUrl,
                username = current.webdavUsername,
                appPassword = current.webdavAppPassword,
            ),
            remotePath = current.remotePath,
            unlockRemote = { bytes, lastSeen -> Vault.open(bytes, passphrase, pinned, lastSeen) },
        )

        val outcome = engine.sync(
            local = vault,
            lastSyncEtag = current.lastSyncEtag.takeIf { it.isNotEmpty() },
            lastSeenVersion = current.lastSeenVersion,
        )

        reportOutcome(outcome, vault.entries.size)
        outcome
    }

    /**
     * True unless a pairing code pinned a digest that this signing key does not match.
     *
     * Returns true when nothing was pinned, which is trust on first use and the caller's
     * business rather than this function's.
     */
    private fun signerMatchesPinnedDigest(
        current: SecureSettings.Settings,
        signingPublicKey: ByteArray,
    ): Boolean {
        if (current.pinnedSigningKeyDigest.isEmpty()) return true
        val actual = Base64Url.encode(
            java.security.MessageDigest.getInstance("SHA-256").digest(signingPublicKey),
        )
        return actual == current.pinnedSigningKeyDigest
    }

    private fun failure(messageId: Int, permanent: Boolean = false) = VaultSyncEngine.Outcome.Failed(
        VaultSyncEngine.Outcome.Failure.Reported(context.getString(messageId)),
        permanent = permanent,
    )

    private fun reportOutcome(outcome: VaultSyncEngine.Outcome, entryCount: Int) {
        when (outcome) {
            is VaultSyncEngine.Outcome.Created,
            is VaultSyncEngine.Outcome.Pushed,
            -> {
                persistAfterSync(outcome as VaultSyncEngine.Outcome.Written)
                notifications.syncSucceeded(entryCount, merged = false)
            }
            is VaultSyncEngine.Outcome.Merged -> {
                persistAfterSync(outcome)
                notifications.syncSucceeded(entryCount, merged = true)
                notifications.conflictsResolved(outcome.conflicts)
            }
            is VaultSyncEngine.Outcome.RemoteUntrusted ->
                notifications.remoteUntrusted(describe(context, outcome.cause))
            is VaultSyncEngine.Outcome.RemoteUnreadable ->
                notifications.syncFailed(context.getString(R.string.sync_remote_unreadable))
            is VaultSyncEngine.Outcome.Failed ->
                notifications.syncFailed(describe(context, outcome.reason))
        }
    }

    private fun persistAfterSync(written: VaultSyncEngine.Outcome.Written) {
        // Store the exact bytes that were uploaded. Re-serialising here would bump the
        // version again and leave the local file ahead of the server, which the next
        // sync would correctly report as a rollback.
        vaultFile.writeBytes(written.bytes)
        settings.save(
            settings.load().copy(
                lastSyncEtag = written.etag.orEmpty(),
                lastSeenVersion = written.version,
                localVersion = written.version,
            ),
        )
    }

    /**
     * Takes whatever the server currently holds as the new rollback reference.
     *
     * The anti-replay check has no way to tell a malicious replay from a server that was
     * legitimately restored from backup, so when it fires the user is the only one who
     * can say which happened. Without this the app has told them something is wrong and
     * offered no way forward, which is not a security control so much as a dead end.
     * Clearing the watermark is deliberately explicit, deliberately theirs, and never
     * automatic; the pinned signing key still refuses a vault that is not theirs, and the
     * next sync merges rather than overwrites.
     */
    suspend fun acceptRemoteVersion(): Unit = mutex.withLock {
        settings.save(settings.load().copy(lastSeenVersion = 0, lastSyncEtag = ""))
    }

    fun masterKeyForBiometricWrap(): ByteArray? = unlocked?.exportMasterKeyForLocalWrapping()

    /**
     * The rollback watermark for the *local* file. Normally just `localVersion`, but a
     * settings file written before that field existed leaves it at zero, so the last
     * synced version stands in until the next local write.
     */
    private val SecureSettings.Settings.localWatermark: Long
        get() = maxOf(localVersion, lastSeenVersion)

    companion object {
        /**
         * How often the idle timer wakes up. Short enough that the lock lands close to
         * the deadline the user chose, long enough to be invisible on a battery graph.
         */
        private const val AUTO_LOCK_POLL_MS = 15_000L

        // The instance holds the *application* context, taken in get() below, so it
        // lives exactly as long as the process does and leaks nothing. Lint cannot see
        // that from the field declaration alone.
        @Volatile
        @Suppress("StaticFieldLeak")
        private var instance: VaultRepository? = null

        fun get(context: Context): VaultRepository =
            instance ?: synchronized(this) {
                instance ?: VaultRepository(context.applicationContext).also { instance = it }
            }

        /**
         * Turns a sync engine verdict into text for this device's language.
         *
         * The engine module has no resources, so it reports facts and the wording happens
         * here. Doing it any other way is how an English sentence ends up in the middle of
         * a French screen.
         */
        fun describe(context: Context, cause: VaultSyncEngine.Outcome.Untrusted): String = when (cause) {
            is VaultSyncEngine.Outcome.Untrusted.Rollback ->
                context.getString(R.string.sync_untrusted_rollback, cause.fileVersion, cause.lastSeenVersion)
            is VaultSyncEngine.Outcome.Untrusted.SignatureInvalid ->
                context.getString(R.string.sync_untrusted_signature)
            is VaultSyncEngine.Outcome.Untrusted.UnknownSigner ->
                context.getString(R.string.sync_untrusted_signer)
            is VaultSyncEngine.Outcome.Untrusted.Malformed ->
                context.getString(R.string.sync_untrusted_malformed, cause.reason)
        }

        fun describe(context: Context, reason: VaultSyncEngine.Outcome.Failure): String = when (reason) {
            is VaultSyncEngine.Outcome.Failure.Reported -> reason.text
            is VaultSyncEngine.Outcome.Failure.RemoteReadFailed ->
                context.getString(R.string.sync_read_failed, reason.detail)
            is VaultSyncEngine.Outcome.Failure.RemoteCreateFailed ->
                context.getString(R.string.sync_create_failed, reason.detail)
            is VaultSyncEngine.Outcome.Failure.RemoteWriteFailed ->
                context.getString(R.string.sync_write_failed, reason.detail)
            is VaultSyncEngine.Outcome.Failure.Contended ->
                context.getString(R.string.sync_contended, reason.attempts)
        }
    }
}
