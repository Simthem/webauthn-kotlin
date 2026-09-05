package com.pqvault.core.crypto

import com.google.common.truth.Truth.assertThat
import java.security.SecureRandom
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Test

class HybridKemTest {

    @Test
    fun `encapsulate then decapsulate agrees on the shared secret`() {
        val kp = HybridKem.generateKeyPair()

        val encap = HybridKem.encapsulate(kp.publicKey)
        val recovered = HybridKem.decapsulate(kp.privateKey, kp.publicKey, encap.ciphertext)

        assertThat(recovered).isEqualTo(encap.sharedSecret)
        assertThat(encap.sharedSecret).hasLength(32)
    }

    @Test
    fun `ciphertext has the expected hybrid size`() {
        val kp = HybridKem.generateKeyPair()
        val encap = HybridKem.encapsulate(kp.publicKey)

        assertThat(encap.ciphertext).hasLength(
            HybridKem.X25519_PUBLIC_SIZE + HybridKem.ML_KEM_768_CIPHERTEXT_SIZE,
        )
    }

    @Test
    fun `each encapsulation to the same key is distinct`() {
        val kp = HybridKem.generateKeyPair()

        val a = HybridKem.encapsulate(kp.publicKey)
        val b = HybridKem.encapsulate(kp.publicKey)

        assertThat(a.ciphertext).isNotEqualTo(b.ciphertext)
        assertThat(a.sharedSecret).isNotEqualTo(b.sharedSecret)
    }

    @Test
    fun `a different recipient cannot recover the secret`() {
        val alice = HybridKem.generateKeyPair()
        val mallory = HybridKem.generateKeyPair()

        val encap = HybridKem.encapsulate(alice.publicKey)
        val wrong = HybridKem.decapsulate(mallory.privateKey, mallory.publicKey, encap.ciphertext)

        assertThat(wrong).isNotEqualTo(encap.sharedSecret)
    }

    /**
     * ML-KEM uses implicit rejection: a corrupted ciphertext yields a deterministic but
     * wrong secret instead of an error. So the failure mode we must assert is
     * "different secret", not "throws".
     */
    @Test
    fun `a tampered post-quantum ciphertext yields a different secret`() {
        val kp = HybridKem.generateKeyPair()
        val encap = HybridKem.encapsulate(kp.publicKey)

        val tampered = encap.ciphertext.copyOf()
        tampered[HybridKem.X25519_PUBLIC_SIZE + 5] =
            (tampered[HybridKem.X25519_PUBLIC_SIZE + 5].toInt() xor 0x01).toByte()

        val recovered = HybridKem.decapsulate(kp.privateKey, kp.publicKey, tampered)
        assertThat(recovered).isNotEqualTo(encap.sharedSecret)
    }

    @Test
    fun `a tampered classical ciphertext yields a different secret`() {
        val kp = HybridKem.generateKeyPair()
        val encap = HybridKem.encapsulate(kp.publicKey)

        val tampered = encap.ciphertext.copyOf()
        tampered[2] = (tampered[2].toInt() xor 0x01).toByte()

        val recovered = HybridKem.decapsulate(kp.privateKey, kp.publicKey, tampered)
        assertThat(recovered).isNotEqualTo(encap.sharedSecret)
    }

    @Test
    fun `public and private keys survive an encode decode round trip`() {
        val kp = HybridKem.generateKeyPair()

        val pub = HybridKem.PublicKey.decode(kp.publicKey.encoded())
        val priv = HybridKem.PrivateKey.decode(kp.privateKey.encoded())

        val encap = HybridKem.encapsulate(pub)
        assertThat(HybridKem.decapsulate(priv, pub, encap.ciphertext)).isEqualTo(encap.sharedSecret)
    }

    @Test
    fun `private key decoder rejects truncated and oversized encodings`() {
        val encoded = HybridKem.generateKeyPair().privateKey.encoded()

        assertThrows<IllegalArgumentException> { HybridKem.PrivateKey.decode(byteArrayOf()) }
        assertThrows<IllegalArgumentException> { HybridKem.PrivateKey.decode(encoded.copyOf(encoded.size - 1)) }
        assertThrows<IllegalArgumentException> { HybridKem.PrivateKey.decode(encoded + 0) }
    }

    @Test
    fun `private key decoder rejects a forged component length`() {
        val encoded = HybridKem.generateKeyPair().privateKey.encoded()
        encoded[0] = (HybridKem.X25519_PUBLIC_SIZE - 1).toByte()

        assertThrows<IllegalArgumentException> { HybridKem.PrivateKey.decode(encoded) }
    }

    /**
     * The counterpart of the signing case: device identities written before the move to
     * BouncyCastle's current APIs carry the expanded ML-KEM private key. Refusing it
     * locked those devices out of every vault they had been enrolled in.
     */
    @Test
    fun `the expanded ML-KEM private key of an older device still decapsulates`() {
        val random = SecureRandom()
        val xPrivate = X25519PrivateKeyParameters(random)
        val generator = MLKEMKeyPairGenerator()
        generator.init(MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768))
        val pair = generator.generateKeyPair()
        val pqPublic = pair.public as MLKEMPublicKeyParameters
        val pqPrivate = pair.private as MLKEMPrivateKeyParameters

        assertThat(pqPrivate.encoded.size).isEqualTo(HybridKem.ML_KEM_768_EXPANDED_PRIVATE_SIZE)
        assertThat(pqPrivate.seed.size).isEqualTo(HybridKem.ML_KEM_SEED_SIZE)

        val publicKey = HybridKem.PublicKey(xPrivate.generatePublicKey().encoded, pqPublic.encoded)
        val older = HybridKem.PrivateKey(xPrivate.encoded, pqPrivate.encoded)

        assertThat(HybridKem.PrivateKey.decode(older.encoded()).mlKemSeed.size)
            .isEqualTo(HybridKem.ML_KEM_768_EXPANDED_PRIVATE_SIZE)

        val encapsulation = HybridKem.encapsulate(publicKey, random)
        val recovered = HybridKem.decapsulate(older, publicKey, encapsulation.ciphertext)

        assertThat(recovered).isEqualTo(encapsulation.sharedSecret)
    }
}
