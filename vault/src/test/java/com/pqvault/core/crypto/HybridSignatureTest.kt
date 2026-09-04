package com.pqvault.core.crypto

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Test

class HybridSignatureTest {

    private val message = "vault v7, 42 entries".toByteArray()

    @Test
    fun `sign then verify accepts a genuine signature`() {
        val kp = HybridSignature.generateKeyPair()

        val signature = HybridSignature.sign(kp.privateKey, message)

        assertThat(HybridSignature.verify(kp.publicKey, message, signature)).isTrue()
    }

    @Test
    fun `verify rejects a modified message`() {
        val kp = HybridSignature.generateKeyPair()
        val signature = HybridSignature.sign(kp.privateKey, message)

        val other = "vault v6, 42 entries".toByteArray()

        assertThat(HybridSignature.verify(kp.publicKey, other, signature)).isFalse()
    }

    @Test
    fun `verify rejects a signature from another key`() {
        val kp = HybridSignature.generateKeyPair()
        val mallory = HybridSignature.generateKeyPair()
        val signature = HybridSignature.sign(mallory.privateKey, message)

        assertThat(HybridSignature.verify(kp.publicKey, message, signature)).isFalse()
    }

    /**
     * The two tests below are the ones that actually prove the construction is hybrid.
     * If verification only checked one algorithm, corrupting the other half would still
     * pass and the post-quantum half would be decorative.
     */
    @Test
    fun `verify rejects when only the Ed25519 half is corrupted`() {
        val kp = HybridSignature.generateKeyPair()
        val signature = HybridSignature.sign(kp.privateKey, message)

        signature[1] = (signature[1].toInt() xor 0x01).toByte()

        assertThat(HybridSignature.verify(kp.publicKey, message, signature)).isFalse()
    }

    @Test
    fun `verify rejects when only the ML-DSA half is corrupted`() {
        val kp = HybridSignature.generateKeyPair()
        val signature = HybridSignature.sign(kp.privateKey, message)

        val pqOffset = HybridSignature.ED25519_SIGNATURE_SIZE + 10
        signature[pqOffset] = (signature[pqOffset].toInt() xor 0x01).toByte()

        assertThat(HybridSignature.verify(kp.publicKey, message, signature)).isFalse()
    }

    @Test
    fun `verify rejects a truncated signature`() {
        val kp = HybridSignature.generateKeyPair()
        val signature = HybridSignature.sign(kp.privateKey, message)

        assertThat(HybridSignature.verify(kp.publicKey, message, signature.copyOf(64))).isFalse()
        assertThat(HybridSignature.verify(kp.publicKey, message, ByteArray(0))).isFalse()
    }

    @Test
    fun `verify rejects an oversized signature before parsing it`() {
        val kp = HybridSignature.generateKeyPair()
        val signature = HybridSignature.sign(kp.privateKey, message)

        assertThat(HybridSignature.verify(kp.publicKey, message, signature + 0)).isFalse()
    }

    @Test
    fun `public key survives an encode decode round trip`() {
        val kp = HybridSignature.generateKeyPair()
        val signature = HybridSignature.sign(kp.privateKey, message)

        val decoded = HybridSignature.PublicKey.decode(kp.publicKey.encoded())

        assertThat(HybridSignature.verify(decoded, message, signature)).isTrue()
    }

    @Test
    fun `public key decoder rejects malformed lengths`() {
        val encoded = HybridSignature.generateKeyPair().publicKey.encoded()

        assertThrows<IllegalArgumentException> { HybridSignature.PublicKey.decode(byteArrayOf()) }
        assertThrows<IllegalArgumentException> { HybridSignature.PublicKey.decode(encoded.copyOf(encoded.size - 1)) }
        assertThrows<IllegalArgumentException> { HybridSignature.PublicKey.decode(encoded + 0) }
    }

    @Test
    fun `private key rejects malformed component lengths`() {
        assertThrows<IllegalArgumentException> {
            HybridSignature.PrivateKey(ByteArray(HybridSignature.ED25519_PRIVATE_SIZE - 1), ByteArray(32))
        }
        assertThrows<IllegalArgumentException> {
            HybridSignature.PrivateKey(ByteArray(32), ByteArray(HybridSignature.ML_DSA_SEED_SIZE - 1))
        }
    }
}
