package com.pqvault.core.crypto

import com.google.common.truth.Truth.assertThat
import java.security.SecureRandom
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
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

    /**
     * Vaults written before the move to BouncyCastle's current APIs stored the expanded
     * ML-DSA private key, not the seed. Rejecting that encoding made every one of those
     * vaults unreadable, so both forms have to sign, and sign identically.
     */
    @Test
    fun `the expanded ML-DSA private key of an older vault still signs`() {
        val random = SecureRandom()
        val edPriv = Ed25519PrivateKeyParameters(random)
        val generator = MLDSAKeyPairGenerator()
        generator.init(MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_65))
        val pair = generator.generateKeyPair()
        val pqPublic = pair.public as MLDSAPublicKeyParameters
        val pqPrivate = pair.private as MLDSAPrivateKeyParameters

        assertThat(pqPrivate.encoded.size).isEqualTo(HybridSignature.ML_DSA_65_EXPANDED_PRIVATE_SIZE)
        assertThat(pqPrivate.seed.size).isEqualTo(HybridSignature.ML_DSA_SEED_SIZE)

        val publicKey = HybridSignature.PublicKey(edPriv.generatePublicKey().encoded, pqPublic.encoded)
        val older = HybridSignature.PrivateKey(edPriv.encoded, pqPrivate.encoded)
        val current = HybridSignature.PrivateKey(edPriv.encoded, pqPrivate.seed)

        val signature = HybridSignature.sign(older, message)

        assertThat(HybridSignature.verify(publicKey, message, signature)).isTrue()
        assertThat(signature).isEqualTo(HybridSignature.sign(current, message))
    }
}
