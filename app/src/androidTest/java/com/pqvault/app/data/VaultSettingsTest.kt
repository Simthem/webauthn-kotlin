package com.pqvault.app.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.common.truth.Truth.assertThat
import com.pqvault.core.sync.VaultSyncEngine
import com.pqvault.core.webauthn.AuthenticatorData
import com.pqvault.core.webauthn.SoftwareAuthenticator
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assume.assumeFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore

/**
 * The vault on a real device when what sits beside it goes missing: the settings store,
 * or the Keystore key that seals it. The passphrase must still open the vault with every
 * passkey, and the signer must be pinned again from the vault itself.
 *
 * Creates its own vault and deletes it afterwards, so it refuses to run where one exists:
 * on a phone that holds real passkeys it would otherwise replace them.
 */
@RunWith(AndroidJUnit4::class)
class VaultSettingsTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val repository = VaultRepository.get(context)
    private val authenticator = SoftwareAuthenticator()
    private val passphrase = "correct horse battery staple"
    private val settingsFile = File(context.filesDir, "settings.bin")
    private var created = false
    private lateinit var pinned: String

    @Before
    fun createVault(): Unit = runBlocking {
        assumeFalse("a vault already exists on this device", repository.isInitialised)
        repository.create(passphrase.toCharArray())
        created = true
        repository.upsert(register("github.com"))
        repository.upsert(register("example.com"))
        pinned = SecureSettings(context).load().pinnedSigningKey
        assertThat(pinned).isNotEmpty()
        repository.lockNow()
    }

    @After
    fun deleteVault(): Unit = runBlocking {
        if (!created) return@runBlocking
        repository.lockNow()
        repository.vaultFile.delete()
        settingsFile.delete()
    }

    private fun register(rpId: String) = authenticator.makeCredential(
        rpId = rpId,
        rpName = rpId,
        userHandle = rpId.toByteArray(),
        userName = "simon",
        userDisplayName = "Simon",
        clientDataHash = AuthenticatorData.sha256(rpId.toByteArray()),
    ).entry

    private suspend fun opensWithEveryPasskey() {
        assertThat(repository.unlock(passphrase.toCharArray()))
            .isEqualTo(VaultRepository.UnlockOutcome.Success)
        assertThat(repository.entriesFor("github.com")).hasSize(1)
        assertThat(repository.entriesFor("example.com")).hasSize(1)
        assertThat(SecureSettings(context).load().pinnedSigningKey).isEqualTo(pinned)
    }

    private fun overwrite(file: File, bytes: ByteArray) {
        FileOutputStream(file).use { it.write(bytes) }
    }

    @Test
    fun aWrongPassphraseOpensNothing(): Unit = runBlocking {
        assertThat(repository.unlock("wrong horse".toCharArray()))
            .isEqualTo(VaultRepository.UnlockOutcome.WrongPassphrase)
        assertThat(repository.isUnlocked).isFalse()
        opensWithEveryPasskey()
    }

    @Test
    fun lostSettingsKeepTheVaultAndPinItsSignerAgain(): Unit = runBlocking {
        assertThat(settingsFile.delete()).isTrue()

        opensWithEveryPasskey()
        // Nothing to sync with until the server details are entered again.
        assertThat(repository.syncUnattended()).isInstanceOf(VaultSyncEngine.Outcome.Failed::class.java)
    }

    @Test
    fun unreadableSettingsAreTreatedAsAbsent(): Unit = runBlocking {
        overwrite(settingsFile, ByteArray(64) { 7 })

        opensWithEveryPasskey()
    }

    @Test
    fun aLostKeystoreKeyOnlyCostsTheSettings(): Unit = runBlocking {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry("pqvault_settings")

        opensWithEveryPasskey()
    }

    @Test
    fun anOlderCopyOfTheVaultIsRefusedWhileTheSettingsRemember(): Unit = runBlocking {
        val older = repository.vaultFile.readBytes()
        assertThat(repository.unlock(passphrase.toCharArray()))
            .isEqualTo(VaultRepository.UnlockOutcome.Success)
        repository.upsert(register("example.org"))
        repository.lockNow()

        overwrite(repository.vaultFile, older)

        assertThat(repository.unlock(passphrase.toCharArray()))
            .isInstanceOf(VaultRepository.UnlockOutcome.Untrusted::class.java)
        assertThat(repository.isUnlocked).isFalse()
    }
}
