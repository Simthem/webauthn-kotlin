package com.pqvault.core.hybrid

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.Test
import java.security.KeyPair

class CableNoiseTest {
    @Test
    fun `KNpsk0 responder interoperates with an independent initiator`() {
        val psk = ByteArray(32) { (it * 7).toByte() }
        val identity = HybridCrypto.generateP256KeyPair()
        val initiator = TestInitiator(psk, identity)

        val responder = CableNoise.respond(psk, identity.public, initiator.initialMessage())
        val keys = initiator.processResponse(responder.response)

        assertThat(responder.response).hasLength(81)
        assertThat(responder.handshakeHash).isEqualTo(keys.handshakeHash)

        val fromPhone = "phone response".toByteArray()
        assertThat(decryptTransport(keys.readKey, responder.transport.encrypt(fromPhone)))
            .isEqualTo(fromPhone)

        val fromComputer = "computer request".toByteArray()
        assertThat(responder.transport.decrypt(encryptTransport(keys.writeKey, fromComputer)))
            .isEqualTo(fromComputer)
    }

    private data class InitiatorKeys(
        val writeKey: ByteArray,
        val readKey: ByteArray,
        val handshakeHash: ByteArray,
    )

    private class TestInitiator(psk: ByteArray, identity: KeyPair) {
        private var chainingKey = PROTOCOL.toByteArray().copyOf(32)
        private var hash = chainingKey.copyOf()
        private var key = ByteArray(32)
        private var nonce = 0
        private val identityPrivate = identity.private
        private val identityPublic = HybridCrypto.encodeUncompressed(identity.public)
        private val ephemeral = HybridCrypto.generateP256KeyPair()

        init {
            mixHash(byteArrayOf(1))
            mixHash(identityPublic)
            mixKeyAndHash(psk)
        }

        fun initialMessage(): ByteArray {
            val public = HybridCrypto.encodeUncompressed(ephemeral.public)
            mixHash(public)
            mixKey(public)
            return public + encryptAndHash(ByteArray(0))
        }

        fun processResponse(response: ByteArray): InitiatorKeys {
            val publicBytes = response.copyOfRange(0, 65)
            val public = HybridCrypto.decodeUncompressed(publicBytes)
            mixHash(publicBytes)
            mixKey(publicBytes)
            mixKey(HybridCrypto.ecdh(ephemeral.private, public))
            mixKey(HybridCrypto.ecdh(identityPrivate, public))
            assertThat(decryptAndHash(response.copyOfRange(65, response.size))).isEmpty()
            val traffic = HybridCrypto.hkdf(ByteArray(0), chainingKey, length = 64)
            return InitiatorKeys(
                writeKey = traffic.copyOfRange(0, 32),
                readKey = traffic.copyOfRange(32, 64),
                handshakeHash = hash.copyOf(),
            )
        }

        private fun mixHash(input: ByteArray) {
            hash = HybridCrypto.sha256(hash, input)
        }

        private fun mixKey(input: ByteArray) {
            val output = HybridCrypto.hkdf(input, chainingKey, length = 64)
            chainingKey = output.copyOfRange(0, 32)
            key = output.copyOfRange(32, 64)
            nonce = 0
        }

        private fun mixKeyAndHash(input: ByteArray) {
            val output = HybridCrypto.hkdf(input, chainingKey, length = 96)
            chainingKey = output.copyOfRange(0, 32)
            mixHash(output.copyOfRange(32, 64))
            key = output.copyOfRange(64, 96)
            nonce = 0
        }

        private fun encryptAndHash(plaintext: ByteArray): ByteArray {
            val ciphertext = HybridCrypto.aesGcmEncrypt(key, handshakeNonce(nonce++), plaintext, hash)
            mixHash(ciphertext)
            return ciphertext
        }

        private fun decryptAndHash(ciphertext: ByteArray): ByteArray {
            val plaintext = HybridCrypto.aesGcmDecrypt(key, handshakeNonce(nonce++), ciphertext, hash)
            mixHash(ciphertext)
            return plaintext
        }

        private fun handshakeNonce(sequence: Int) = ByteArray(12).also {
            it[0] = (sequence ushr 24).toByte()
            it[1] = (sequence ushr 16).toByte()
            it[2] = (sequence ushr 8).toByte()
            it[3] = sequence.toByte()
        }
    }

    private fun encryptTransport(key: ByteArray, plaintext: ByteArray): ByteArray {
        val zeros = (32 - ((plaintext.size + 1) % 32)) % 32
        val padded = plaintext + ByteArray(zeros) + byteArrayOf(zeros.toByte())
        return HybridCrypto.aesGcmEncrypt(key, ByteArray(12), padded)
    }

    private fun decryptTransport(key: ByteArray, ciphertext: ByteArray): ByteArray {
        val padded = HybridCrypto.aesGcmDecrypt(key, ByteArray(12), ciphertext)
        val zeros = padded.last().toInt() and 0xff
        return padded.copyOfRange(0, padded.size - zeros - 1)
    }

    private companion object {
        const val PROTOCOL = "Noise_KNpsk0_P256_AESGCM_SHA256"
    }
}
