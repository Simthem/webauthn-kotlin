package com.pqvault.core.webauthn

import com.google.common.truth.Truth.assertThat
import com.pqvault.core.Vault
import com.pqvault.core.crypto.Argon2id
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer

class AssertionCounterTest {

    private val testKdf = Argon2id.Params(memoryKib = 8 * 1024, iterations = 1, parallelism = 1)
    private val authenticator = SoftwareAuthenticator()
    private val clientDataHash = AuthenticatorData.sha256("client data".toByteArray())

    private fun vaultWithPasskey() = Vault.create("passphrase".toCharArray(), testKdf).also {
        it.addOrReplace(
            authenticator.makeCredential(
                rpId = "github.com",
                rpName = "GitHub",
                userHandle = "user-handle".toByteArray(),
                userName = "simon",
                userDisplayName = "Simon",
                clientDataHash = clientDataHash,
            ).entry,
        )
    }

    /** rpIdHash(32) | flags(1) | signCount(4, big-endian). */
    private fun counterOf(assertion: SoftwareAuthenticator.Assertion) =
        ByteBuffer.wrap(assertion.authenticatorData, 33, 4).int.toLong() and 0xffffffffL

    @Test
    fun `signing twice from an earlier copy repeats the counter`() {
        val vault = vaultWithPasskey()
        val earlierCopy = vault.entries.single()

        val first = authenticator.getAssertion(earlierCopy, clientDataHash)
        vault.addOrReplace(first.updatedEntry)
        val second = authenticator.getAssertion(earlierCopy, clientDataHash)

        // What a relying party reads as a cloned authenticator.
        assertThat(counterOf(second)).isEqualTo(counterOf(first))
    }

    @Test
    fun `signing from the stored passkey always raises the counter`() {
        val vault = vaultWithPasskey()
        val id = vault.entries.single().credentialId

        val first = vault.recordAssertion(id) { authenticator.getAssertion(it, clientDataHash) }!!
        val second = vault.recordAssertion(id) { authenticator.getAssertion(it, clientDataHash) }!!

        assertThat(counterOf(first)).isEqualTo(1)
        assertThat(counterOf(second)).isEqualTo(2)
        assertThat(vault.find(id)!!.signCount).isEqualTo(2)
    }

    @Test
    fun `concurrent sign-ins under the vault lock never share a counter`() = runBlocking {
        val vault = vaultWithPasskey()
        val id = vault.entries.single().credentialId
        val lock = Mutex()

        val counters = (1..20).map {
            async(Dispatchers.Default) {
                lock.withLock {
                    counterOf(vault.recordAssertion(id) { authenticator.getAssertion(it, clientDataHash) }!!)
                }
            }
        }.awaitAll()

        assertThat(counters).containsExactlyElementsIn((1L..20L).toList())
        assertThat(vault.find(id)!!.signCount).isEqualTo(20)
    }

    @Test
    fun `a passkey deleted meanwhile signs nothing`() {
        val vault = vaultWithPasskey()
        val id = vault.entries.single().credentialId
        vault.delete(id)
        var signed = false

        val assertion = vault.recordAssertion(id) {
            signed = true
            authenticator.getAssertion(it, clientDataHash)
        }

        assertThat(assertion).isNull()
        assertThat(signed).isFalse()
        assertThat(vault.entries).isEmpty()
        assertThat(vault.tombstones.map { it.credentialId }).containsExactly(id)
    }
}
