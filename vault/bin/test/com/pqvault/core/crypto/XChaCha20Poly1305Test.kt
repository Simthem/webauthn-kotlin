package com.pqvault.core.crypto

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class XChaCha20Poly1305Test {

    private fun hex(s: String): ByteArray =
        s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    /** draft-irtf-cfrg-xchacha-03, section 2.2.1. */
    @Test
    fun `hChaCha20 matches the CFRG draft test vector`() {
        val key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        val nonce = hex("000000090000004a0000000031415927")

        val out = XChaCha20Poly1305.hChaCha20(key, nonce)

        assertThat(out.toHex())
            .isEqualTo("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    }

    /** draft-irtf-cfrg-xchacha-03, section A.3.1. */
    @Test
    fun `aead matches the CFRG draft test vector`() {
        val key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        val nonce = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
        val aad = hex("50515253c0c1c2c3c4c5c6c7")
        val plaintext = ("Ladies and Gentlemen of the class of '99: If I could offer you " +
            "only one tip for the future, sunscreen would be it.").toByteArray()

        val sealed = XChaCha20Poly1305.seal(key, nonce, plaintext, aad)

        assertThat(sealed.toHex()).isEqualTo(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
                "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
                "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
                "21f9664c97637da9768812f615c68b13b52e" +
                "c0875924c1c7987947deafd8780acf49"
        )
    }

    @Test
    fun `seal then open round-trips`() {
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val nonce = ByteArray(24).also { SecureRandom().nextBytes(it) }
        val plaintext = "some thoroughly secret vault contents".toByteArray()
        val aad = "header".toByteArray()

        val sealed = XChaCha20Poly1305.seal(key, nonce, plaintext, aad)
        val opened = XChaCha20Poly1305.open(key, nonce, sealed, aad)

        assertThat(opened).isEqualTo(plaintext)
    }

    @Test
    fun `open returns null when the ciphertext is tampered with`() {
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val nonce = ByteArray(24).also { SecureRandom().nextBytes(it) }
        val sealed = XChaCha20Poly1305.seal(key, nonce, "secret".toByteArray(), ByteArray(0))

        sealed[3] = (sealed[3].toInt() xor 0x01).toByte()

        assertThat(XChaCha20Poly1305.open(key, nonce, sealed, ByteArray(0))).isNull()
    }

    @Test
    fun `open returns null when the aad does not match`() {
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val nonce = ByteArray(24).also { SecureRandom().nextBytes(it) }
        val sealed = XChaCha20Poly1305.seal(key, nonce, "secret".toByteArray(), "header-v1".toByteArray())

        assertThat(XChaCha20Poly1305.open(key, nonce, sealed, "header-v2".toByteArray())).isNull()
    }

    @Test
    fun `open returns null for a different key`() {
        val nonce = ByteArray(24).also { SecureRandom().nextBytes(it) }
        val sealed = XChaCha20Poly1305.seal(ByteArray(32) { 1 }, nonce, "secret".toByteArray(), ByteArray(0))

        assertThat(XChaCha20Poly1305.open(ByteArray(32) { 2 }, nonce, sealed, ByteArray(0))).isNull()
    }
}
