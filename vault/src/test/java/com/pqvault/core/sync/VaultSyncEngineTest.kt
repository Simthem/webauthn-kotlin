package com.pqvault.core.sync

import com.google.common.truth.Truth.assertThat
import com.pqvault.core.UnlockedVault
import com.pqvault.core.Vault
import com.pqvault.core.crypto.Argon2id
import com.pqvault.core.model.PasskeyEntry
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

class VaultSyncEngineTest {

    private val testKdf = Argon2id.Params(memoryKib = 8 * 1024, iterations = 1, parallelism = 1)
    private val passphrase = "correct horse battery staple".toCharArray()
    private val remotePath = "/passkeys/vault.pqvault"

    private fun entry(id: String, rpId: String, updatedAt: Long = 1_000, signCount: Long = 0) = PasskeyEntry(
        credentialId = id,
        rpId = rpId,
        userHandle = "dXNlcg",
        userName = "simon",
        privateKeyPkcs8 = "cHJpdmF0ZQ",
        publicKeySpki = "cHVibGlj",
        signCount = signCount,
        createdAt = 1_000,
        updatedAt = updatedAt,
    )

    private fun engine(server: FakeWebDavServer, pinned: ByteArray? = null) = VaultSyncEngine(
        dav = server.client,
        remotePath = remotePath,
        unlockRemote = { bytes, lastSeen -> Vault.open(bytes, passphrase, pinned, lastSeen) },
    )

    /** Two devices sharing one vault, as they would after enrolling from the same file. */
    private fun twoDevicesSharingAVault(): Triple<ByteArray, UnlockedVault, UnlockedVault> {
        val origin = Vault.create(passphrase, testKdf)
        val shared = origin.serialize()
        val a = (Vault.open(shared, passphrase) as Vault.OpenResult.Success).vault
        val b = (Vault.open(shared, passphrase) as Vault.OpenResult.Success).vault
        return Triple(shared, a, b)
    }

    @Test
    fun `the first sync creates the remote vault`() = runTest {
        val server = FakeWebDavServer()
        val vault = Vault.create(passphrase, testKdf)
        vault.addOrReplace(entry("cred-1", "github.com"))

        val outcome = engine(server).sync(vault)

        assertThat(outcome).isInstanceOf(VaultSyncEngine.Outcome.Created::class.java)
        assertThat(server.read(remotePath)).isNotNull()
    }

    @Test
    fun `a second device merges rather than overwriting`() = runTest {
        val server = FakeWebDavServer()
        val (_, deviceA, deviceB) = twoDevicesSharingAVault()

        deviceA.addOrReplace(entry("cred-A", "github.com"))
        engine(server).sync(deviceA)

        deviceB.addOrReplace(entry("cred-B", "gitlab.com"))
        val outcome = engine(server).sync(deviceB)

        assertThat(outcome).isInstanceOf(VaultSyncEngine.Outcome.Merged::class.java)

        val remote = Vault.open(server.read(remotePath)!!, passphrase) as Vault.OpenResult.Success
        assertThat(remote.vault.entries.map { it.credentialId })
            .containsExactly("cred-A", "cred-B")
    }

    @Test
    fun `a deletion on one device survives the merge`() = runTest {
        val server = FakeWebDavServer()
        val origin = Vault.create(passphrase, testKdf)
        origin.addOrReplace(entry("cred-1", "github.com"))
        val shared = origin.serialize()
        val deviceA = (Vault.open(shared, passphrase) as Vault.OpenResult.Success).vault
        val deviceB = (Vault.open(shared, passphrase) as Vault.OpenResult.Success).vault

        deviceA.delete("cred-1", now = 9_000)
        engine(server).sync(deviceA)

        // Device B still holds the entry and must not resurrect it.
        val outcome = engine(server).sync(deviceB)

        assertThat(outcome).isNotInstanceOf(VaultSyncEngine.Outcome.Failed::class.java)
        val remote = Vault.open(server.read(remotePath)!!, passphrase) as Vault.OpenResult.Success
        assertThat(remote.vault.entries).isEmpty()
    }

    /**
     * The race the whole design exists for: another device writes in the window between
     * our read and our write. The PUT must fail its precondition, and the retry must fold
     * that other write into the result rather than clobbering it.
     */
    @Test
    fun `a concurrent write is detected and nothing is lost`() = runTest {
        val server = FakeWebDavServer()
        val (shared, deviceA, deviceB) = twoDevicesSharingAVault()

        deviceA.addOrReplace(entry("cred-A", "github.com"))
        engine(server).sync(deviceA)

        // A third device slips a write in, exactly once, just before our PUT lands.
        val interloper = (Vault.open(shared, passphrase) as Vault.OpenResult.Success).vault
        interloper.addOrReplace(entry("cred-C", "codeberg.org"))
        var injected = false
        server.onBeforePut = {
            if (!injected) {
                injected = true
                interloper.vaultVersion = 50
                server.writeDirectly(remotePath, interloper.serialize())
            }
        }

        deviceB.addOrReplace(entry("cred-B", "gitlab.com"))
        val outcome = engine(server).sync(deviceB)

        assertThat(server.conflictCount).isAtLeast(1)
        assertThat(outcome).isInstanceOf(VaultSyncEngine.Outcome.Merged::class.java)

        val remote = Vault.open(server.read(remotePath)!!, passphrase) as Vault.OpenResult.Success
        assertThat(remote.vault.entries.map { it.credentialId })
            .containsExactly("cred-A", "cred-B", "cred-C")
    }

    @Test
    fun `a server replaying an older vault is refused`() = runTest {
        val server = FakeWebDavServer()
        val (_, deviceA, _) = twoDevicesSharingAVault()
        deviceA.addOrReplace(entry("cred-A", "github.com"))
        engine(server).sync(deviceA)

        val currentVersion = deviceA.vaultVersion

        // The server hands back a genuine, correctly signed, but older file.
        val stale = Vault.create(passphrase, testKdf)
        stale.vaultVersion = 0
        server.writeDirectly(remotePath, stale.serialize())

        val outcome = engine(server).sync(deviceA, lastSeenVersion = currentVersion)

        assertThat(outcome).isInstanceOf(VaultSyncEngine.Outcome.RemoteUntrusted::class.java)
        val cause = (outcome as VaultSyncEngine.Outcome.RemoteUntrusted).cause
        assertThat(cause).isInstanceOf(VaultSyncEngine.Outcome.Untrusted.Rollback::class.java)
        val rollback = cause as VaultSyncEngine.Outcome.Untrusted.Rollback
        assertThat(rollback.fileVersion).isLessThan(rollback.lastSeenVersion)
        assertThat(rollback.lastSeenVersion).isEqualTo(currentVersion)
    }

    @Test
    fun `a tampered remote vault is refused rather than merged`() = runTest {
        val server = FakeWebDavServer()
        val (_, deviceA, _) = twoDevicesSharingAVault()
        deviceA.addOrReplace(entry("cred-A", "github.com"))
        engine(server).sync(deviceA)

        val corrupted = server.read(remotePath)!!.copyOf()
        corrupted[corrupted.size - 300] = (corrupted[corrupted.size - 300].toInt() xor 0x01).toByte()
        server.writeDirectly(remotePath, corrupted)

        val outcome = engine(server).sync(deviceA)

        assertThat(outcome).isInstanceOf(VaultSyncEngine.Outcome.RemoteUntrusted::class.java)
    }

    @Test
    fun `a vault signed by an unknown key is refused when the signer is pinned`() = runTest {
        val server = FakeWebDavServer()
        val deviceA = Vault.create(passphrase, testKdf)
        val pinned = (Vault.open(deviceA.serialize(), passphrase) as Vault.OpenResult.Success).signingPublicKey

        // An attacker replaces the file with their own valid vault, same passphrase.
        server.writeDirectly(remotePath, Vault.create(passphrase, testKdf).serialize())

        val outcome = engine(server, pinned = pinned).sync(deviceA)

        assertThat(outcome).isInstanceOf(VaultSyncEngine.Outcome.RemoteUntrusted::class.java)
    }

    @Test
    fun `syncing twice with no changes does not keep rewriting`() = runTest {
        val server = FakeWebDavServer()
        val vault = Vault.create(passphrase, testKdf)
        vault.addOrReplace(entry("cred-1", "github.com"))

        engine(server).sync(vault)
        val outcome = engine(server).sync(vault)

        assertThat(outcome).isInstanceOf(VaultSyncEngine.Outcome.Pushed::class.java)
        assertThat(server.conflictCount).isEqualTo(0)
    }

    /**
     * Regression test. The repository persists what sync uploaded and remembers the
     * version; if the engine and the stored file ever disagree by even one version, the
     * next sync reads its own file as a rollback and sync jams permanently. Three full
     * cycles is enough to catch any per-round drift.
     */
    @Test
    fun `repeated sync cycles do not drift into a false rollback`() = runTest {
        val server = FakeWebDavServer()
        var localBytes = Vault.create(passphrase, testKdf).serialize()
        var etag: String? = null
        var lastSeen = 0L

        repeat(3) { round ->
            val opened = Vault.open(localBytes, passphrase, lastSeenVersion = lastSeen)
            assertThat(opened).isInstanceOf(Vault.OpenResult.Success::class.java)
            val vault = (opened as Vault.OpenResult.Success).vault
            vault.addOrReplace(entry("cred-$round", "site$round.example"))

            val outcome = engine(server).sync(vault, etag, lastSeen)
            assertThat(outcome).isInstanceOf(VaultSyncEngine.Outcome.Written::class.java)

            val written = outcome as VaultSyncEngine.Outcome.Written
            // Exactly what the repository does.
            localBytes = written.bytes
            etag = written.etag
            lastSeen = written.version
        }

        val finalOpen = Vault.open(localBytes, passphrase, lastSeenVersion = lastSeen)
        assertThat(finalOpen).isInstanceOf(Vault.OpenResult.Success::class.java)
        assertThat((finalOpen as Vault.OpenResult.Success).vault.entries.map { it.credentialId })
            .containsExactly("cred-0", "cred-1", "cred-2")

        // The local file and the server must agree on the version, byte for byte.
        assertThat(server.read(remotePath)).isEqualTo(localBytes)
    }

    /**
     * Regression test for the bug that jammed sync in the field. Every local write
     * re-serialises and so bumps the file's version, but the server hears nothing about
     * it. If the repository folds those bumps into the version it feeds the rollback
     * check, the server's own untouched file comes back "older than what this device
     * already accepted" and sync is stuck for good: only a successful push may raise the
     * remote watermark.
     */
    @Test
    fun `local writes between syncs do not make the untouched server look rolled back`() = runTest {
        val server = FakeWebDavServer()
        var localBytes = Vault.create(passphrase, testKdf).serialize()

        val first = engine(server).sync(
            (Vault.open(localBytes, passphrase) as Vault.OpenResult.Success).vault,
        )
        val created = first as VaultSyncEngine.Outcome.Written
        localBytes = created.bytes
        val remoteWatermark = created.version
        var localWatermark = created.version
        val serverVersionBeforeEdits = created.version

        // Three offline saves, as a passkey used three times would produce.
        repeat(3) { use ->
            val opened = Vault.open(localBytes, passphrase, lastSeenVersion = localWatermark)
            val vault = (opened as Vault.OpenResult.Success).vault
            vault.addOrReplace(entry("cred-used", "github.com", updatedAt = 2_000L + use, signCount = 1L + use))
            localBytes = vault.serialize()
            localWatermark = vault.vaultVersion
        }
        assertThat(localWatermark).isGreaterThan(serverVersionBeforeEdits)
        assertThat(server.read(remotePath)).isNotEqualTo(localBytes)

        val opened = Vault.open(localBytes, passphrase, lastSeenVersion = localWatermark)
        val vault = (opened as Vault.OpenResult.Success).vault
        val outcome = engine(server).sync(vault, created.etag, remoteWatermark)

        assertThat(outcome).isInstanceOf(VaultSyncEngine.Outcome.Written::class.java)
        val written = outcome as VaultSyncEngine.Outcome.Written
        assertThat(written.version).isGreaterThan(localWatermark)
        assertThat(server.read(remotePath)).isEqualTo(written.bytes)

        val reopened = Vault.open(written.bytes, passphrase, lastSeenVersion = written.version)
        assertThat(reopened).isInstanceOf(Vault.OpenResult.Success::class.java)
        assertThat((reopened as Vault.OpenResult.Success).vault.entries.single().signCount).isEqualTo(3L)
    }
}
