package com.pqvault.core

import com.google.common.truth.Truth.assertThat
import com.pqvault.core.crypto.Argon2id
import com.pqvault.core.crypto.HybridKem
import com.pqvault.core.model.PasskeyEntry
import org.junit.jupiter.api.Test

class VaultTest {

    /** Deliberately far below the shipping defaults so the suite stays fast. */
    private val testKdf = Argon2id.Params(memoryKib = 8 * 1024, iterations = 1, parallelism = 1)

    private val passphrase = "correct horse battery staple".toCharArray()

    private fun entry(id: String, rpId: String = "github.com", updatedAt: Long = 1_000) = PasskeyEntry(
        credentialId = id,
        rpId = rpId,
        userHandle = "dXNlcg",
        userName = "simon",
        privateKeyPkcs8 = "cHJpdmF0ZQ",
        publicKeySpki = "cHVibGlj",
        createdAt = 1_000,
        updatedAt = updatedAt,
    )

    private fun openSuccess(bytes: ByteArray, pinned: ByteArray? = null, lastSeen: Long = 0) =
        Vault.open(bytes, passphrase, pinned, lastSeen) as Vault.OpenResult.Success

    @Test
    fun `a new vault round-trips through serialize and open`() {
        val vault = Vault.create(passphrase, testKdf)
        vault.addOrReplace(entry("cred-1"))
        val bytes = vault.serialize()

        val reopened = openSuccess(bytes)

        assertThat(reopened.vault.entries).hasSize(1)
        assertThat(reopened.vault.entries[0].credentialId).isEqualTo("cred-1")
        assertThat(reopened.vault.entries[0].rpId).isEqualTo("github.com")
    }

    @Test
    fun `the vault version increments on every save`() {
        val vault = Vault.create(passphrase, testKdf)

        val first = openSuccess(vault.serialize())
        assertThat(first.vault.vaultVersion).isEqualTo(1)

        val second = openSuccess(vault.serialize())
        assertThat(second.vault.vaultVersion).isEqualTo(2)
    }

    @Test
    fun `a wrong passphrase is reported as such`() {
        val bytes = Vault.create(passphrase, testKdf).serialize()

        val result = Vault.open(bytes, "wrong passphrase".toCharArray())

        assertThat(result).isInstanceOf(Vault.OpenResult.WrongPassphrase::class.java)
    }

    @Test
    fun `tampering with the ciphertext is caught by the signature`() {
        val vault = Vault.create(passphrase, testKdf)
        vault.addOrReplace(entry("cred-1"))
        val bytes = vault.serialize()

        // Flip a byte near the end, inside the content or signature region.
        bytes[bytes.size - 200] = (bytes[bytes.size - 200].toInt() xor 0x01).toByte()

        assertThat(Vault.open(bytes, passphrase)).isInstanceOf(Vault.OpenResult.SignatureInvalid::class.java)
    }

    @Test
    fun `a vault signed by another key is rejected once the signer is pinned`() {
        val ours = Vault.create(passphrase, testKdf)
        val pinned = openSuccess(ours.serialize()).signingPublicKey

        // An attacker builds a perfectly valid vault of their own, with the same passphrase.
        val theirs = Vault.create(passphrase, testKdf).serialize()

        assertThat(Vault.open(theirs, passphrase, pinnedSigningKey = pinned))
            .isInstanceOf(Vault.OpenResult.UnknownSigner::class.java)
    }

    @Test
    fun `an older but genuine version is rejected as a rollback`() {
        val vault = Vault.create(passphrase, testKdf)
        vault.addOrReplace(entry("cred-1"))
        val old = vault.serialize()
        vault.addOrReplace(entry("cred-2"))
        val current = vault.serialize()

        val currentVersion = openSuccess(current).vault.vaultVersion

        // The server hands back the older file: it decrypts and verifies perfectly, and
        // only the version counter gives the replay away.
        val result = Vault.open(old, passphrase, lastSeenVersion = currentVersion)

        assertThat(result).isInstanceOf(Vault.OpenResult.Rollback::class.java)
        val rollback = result as Vault.OpenResult.Rollback
        assertThat(rollback.fileVersion).isLessThan(rollback.lastSeenVersion)
    }

    @Test
    fun `deleting an entry leaves a tombstone`() {
        val vault = Vault.create(passphrase, testKdf)
        vault.addOrReplace(entry("cred-1"))
        vault.delete("cred-1", now = 5_000)

        val reopened = openSuccess(vault.serialize())

        assertThat(reopened.vault.entries).isEmpty()
        assertThat(reopened.vault.tombstones.map { it.credentialId }).containsExactly("cred-1")
    }

    @Test
    fun `an enrolled device can open the vault without the passphrase`() {
        val vault = Vault.create(passphrase, testKdf)
        vault.addOrReplace(entry("cred-1"))
        val phone = HybridKem.generateKeyPair()
        vault.enrollDevice("phone-1", "/e/OS phone", phone.publicKey)
        val bytes = vault.serialize()

        val result = Vault.openWithDeviceKey(bytes, "phone-1", phone.privateKey, phone.publicKey)

        assertThat(result).isInstanceOf(Vault.OpenResult.Success::class.java)
        assertThat((result as Vault.OpenResult.Success).vault.entries).hasSize(1)
    }

    @Test
    fun `a revoked device can no longer open the vault`() {
        val vault = Vault.create(passphrase, testKdf)
        val phone = HybridKem.generateKeyPair()
        vault.enrollDevice("phone-1", "/e/OS phone", phone.publicKey)
        vault.serialize()

        vault.revokeDevice("phone-1")
        val afterRevocation = vault.serialize()

        val result = Vault.openWithDeviceKey(afterRevocation, "phone-1", phone.privateKey, phone.publicKey)
        assertThat(result).isInstanceOf(Vault.OpenResult.WrongPassphrase::class.java)
    }

    @Test
    fun `a device key belonging to someone else does not open the vault`() {
        val vault = Vault.create(passphrase, testKdf)
        val phone = HybridKem.generateKeyPair()
        val attacker = HybridKem.generateKeyPair()
        vault.enrollDevice("phone-1", "/e/OS phone", phone.publicKey)
        val bytes = vault.serialize()

        val result = Vault.openWithDeviceKey(bytes, "phone-1", attacker.privateKey, attacker.publicKey)

        assertThat(result).isNotInstanceOf(Vault.OpenResult.Success::class.java)
    }

    @Test
    fun `the biometric master key path unlocks the vault`() {
        val vault = Vault.create(passphrase, testKdf)
        vault.addOrReplace(entry("cred-1"))
        // What the Android layer will wrap in the Keystore behind a fingerprint prompt.
        val masterKey = vault.exportMasterKeyForLocalWrapping()
        val bytes = vault.serialize()

        val result = Vault.openWithMasterKey(bytes, masterKey)

        assertThat(result).isInstanceOf(Vault.OpenResult.Success::class.java)
        assertThat((result as Vault.OpenResult.Success).vault.entries).hasSize(1)
    }

    @Test
    fun `garbage input is reported as malformed rather than crashing`() {
        assertThat(Vault.open(ByteArray(0), passphrase)).isInstanceOf(Vault.OpenResult.Malformed::class.java)
        assertThat(Vault.open("not a vault at all".toByteArray(), passphrase))
            .isInstanceOf(Vault.OpenResult.Malformed::class.java)
        assertThat(Vault.open(ByteArray(5000) { 0x41 }, passphrase))
            .isInstanceOf(Vault.OpenResult.Malformed::class.java)
    }

    @Test
    fun `the header is readable without the passphrase but not modifiable`() {
        val vault = Vault.create(passphrase, testKdf)
        val bytes = vault.serialize()

        val raw = com.pqvault.core.format.VaultFile.decode(bytes)
        assertThat(raw.headerJson).contains("argon2id")

        // Downgrading the KDF cost in the header must not yield a readable vault.
        val weakened = String(bytes, Charsets.ISO_8859_1)
            .replace("\"iterations\":1", "\"iterations\":2")
            .toByteArray(Charsets.ISO_8859_1)
        assertThat(Vault.open(weakened, passphrase))
            .isNotInstanceOf(Vault.OpenResult.Success::class.java)
    }
}
