package com.pqvault.core.crypto

import com.google.common.truth.Truth.assertThat
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
}
