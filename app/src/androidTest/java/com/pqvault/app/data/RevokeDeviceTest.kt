package com.pqvault.app.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.common.truth.Truth.assertThat
import com.pqvault.core.Vault
import com.pqvault.core.crypto.HybridKem
import com.pqvault.core.webauthn.AuthenticatorData
import com.pqvault.core.webauthn.SoftwareAuthenticator
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assume.assumeFalse
import org.junit.Test
import org.junit.runner.RunWith

/** Revocation through the repository, on the device's own vault file. Refuses to run over a real vault. */
@RunWith(AndroidJUnit4::class)
class RevokeDeviceTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val repository = VaultRepository.get(context)
    private val passphrase = "correct horse battery staple"
    private var created = false

    @After
    fun deleteVault(): Unit = runBlocking {
        if (!created) return@runBlocking
        repository.lockNow()
        repository.vaultFile.delete()
    }

    @Test
    fun revokingAnotherDeviceRotatesTheKeysAndExposesItsCredentials(): Unit = runBlocking {
        assumeFalse("a vault already exists on this device", repository.isInitialised)
        val lost = HybridKem.generateKeyPair()
        val origin = Vault.create(passphrase.toCharArray())
        origin.enrollDevice("lost", "lost phone", lost.publicKey)
        origin.addOrReplace(
            SoftwareAuthenticator().makeCredential(
                rpId = "example.org",
                rpName = "Example",
                userHandle = "user".toByteArray(),
                userName = "simon",
                userDisplayName = "Simon",
                clientDataHash = AuthenticatorData.sha256("client data".toByteArray()),
            ).entry,
        )
        val imported = repository.importVault(origin.serialize(), passphrase.toCharArray())
        created = true
        assertThat(imported).isInstanceOf(VaultRepository.ImportOutcome.Success::class.java)

        assertThat(repository.revokeDevice("lost", "wrong".toCharArray()))
            .isEqualTo(VaultRepository.RevokeOutcome.WrongPassphrase)
        val outcome = repository.revokeDevice("lost", passphrase.toCharArray())

        assertThat((outcome as VaultRepository.RevokeOutcome.Success).exposed).isEqualTo(1)
        assertThat(repository.enrolledDevices().map { it.deviceId }).doesNotContain("lost")
        assertThat(repository.revokeDevice(repository.thisDeviceId()!!, passphrase.toCharArray()))
            .isEqualTo(VaultRepository.RevokeOutcome.ThisDevice)
        val onDisk = repository.vaultFile.readBytes()
        assertThat(Vault.openWithDeviceKey(onDisk, "lost", lost.privateKey, lost.publicKey, null, 0))
            .isNotInstanceOf(Vault.OpenResult.Success::class.java)
        val reopened = Vault.open(onDisk, passphrase.toCharArray(), null, 0) as Vault.OpenResult.Success
        assertThat(reopened.vault.exposedEntries()).hasSize(1)
        assertThat(reopened.vault.revokedDevices.map { it.deviceId }).containsExactly("lost")
    }
}
