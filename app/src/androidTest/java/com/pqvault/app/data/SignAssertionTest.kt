package com.pqvault.app.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.common.truth.Truth.assertThat
import com.pqvault.core.webauthn.AuthenticatorData
import com.pqvault.core.webauthn.SoftwareAuthenticator
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assume.assumeFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer

/**
 * The repository on a real device: its vault file, the Keystore-backed settings and the
 * device identity, all as the credential provider uses them.
 *
 * Creates its own vault and deletes it afterwards, so it refuses to run where one exists:
 * on a phone that holds real passkeys it would otherwise replace them.
 */
@RunWith(AndroidJUnit4::class)
class SignAssertionTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val repository = VaultRepository.get(context)
    private val authenticator = SoftwareAuthenticator()
    private val clientDataHash = AuthenticatorData.sha256("client data".toByteArray())
    private val passphrase = "correct horse battery staple"
    private var created = false
    private lateinit var credentialId: String

    @Before
    fun createVault(): Unit = runBlocking {
        assumeFalse("a vault already exists on this device", repository.isInitialised)
        repository.create(passphrase.toCharArray())
        created = true
        val registration = authenticator.makeCredential(
            rpId = "github.com",
            rpName = "GitHub",
            userHandle = "user-handle".toByteArray(),
            userName = "simon",
            userDisplayName = "Simon",
            clientDataHash = clientDataHash,
        )
        repository.upsert(registration.entry)
        credentialId = registration.entry.credentialId
    }

    @After
    fun deleteVault(): Unit = runBlocking {
        if (!created) return@runBlocking
        repository.lockNow()
        repository.vaultFile.delete()
    }

    /** rpIdHash(32) | flags(1) | signCount(4, big-endian). */
    private fun counterOf(assertion: SoftwareAuthenticator.Assertion) =
        ByteBuffer.wrap(assertion.authenticatorData, 33, 4).int.toLong() and 0xffffffffL

    private suspend fun sign() = repository.signAssertion(credentialId) {
        authenticator.getAssertion(it, clientDataHash)
    }

    private suspend fun storedCounter(): Long {
        repository.lockNow()
        assertThat(repository.unlock(passphrase.toCharArray())).isEqualTo(VaultRepository.UnlockOutcome.Success)
        val entries = repository.entriesFor("github.com")
        assertThat(entries).hasSize(1)
        return entries[0].signCount
    }

    // Plain loops and java.util lists below: R8 drops the standard-library helpers the
    // app never uses, and these tests run against that shrunk debug APK.
    private fun oneTo(last: Int): List<Long> {
        val values = ArrayList<Long>()
        for (value in 1..last) values.add(value.toLong())
        return values
    }

    @Test
    fun concurrentSignInsGetDistinctCountersThatReachTheFile(): Unit = runBlocking {
        val signIns = ArrayList<Deferred<Long>>()
        for (attempt in 1..20) signIns.add(async(Dispatchers.Default) { counterOf(sign()!!) })

        assertThat(awaitAll(*signIns.toTypedArray())).containsExactlyElementsIn(oneTo(20))
        assertThat(storedCounter()).isEqualTo(20)
    }

    @Test
    fun aLockedVaultSignsNothing(): Unit = runBlocking {
        repository.lockNow()
        var signed = false

        val assertion = repository.signAssertion(credentialId) {
            signed = true
            authenticator.getAssertion(it, clientDataHash)
        }

        assertThat(assertion).isNull()
        assertThat(signed).isFalse()
    }

    @Test
    fun anUnknownPasskeySignsNothing(): Unit = runBlocking {
        var signed = false

        val assertion = repository.signAssertion("unknown") {
            signed = true
            authenticator.getAssertion(it, clientDataHash)
        }

        assertThat(assertion).isNull()
        assertThat(signed).isFalse()
        assertThat(storedCounter()).isEqualTo(0)
    }

    @Test
    fun noSignatureLeavesWithoutItsCounterOnDiskWhenTheVaultLocksMeanwhile(): Unit = runBlocking {
        val tasks = ArrayList<Deferred<Long?>>()
        for (index in 1..12) {
            tasks.add(
                async(Dispatchers.Default) {
                    if (index == 6) {
                        repository.lockNow()
                        null
                    } else {
                        sign()?.let(::counterOf)
                    }
                },
            )
        }
        val signed = ArrayList<Long>()
        for (counter in awaitAll(*tasks.toTypedArray())) counter?.let(signed::add)

        assertThat(signed).containsExactlyElementsIn(oneTo(signed.size))
        assertThat(storedCounter()).isEqualTo(signed.size.toLong())
    }
}
