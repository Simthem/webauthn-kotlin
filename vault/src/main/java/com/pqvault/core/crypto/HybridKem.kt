package com.pqvault.core.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.SecureRandom

/**
 * Hybrid X25519 + ML-KEM-768 key encapsulation.
 *
 * This is the one place in the vault where post-quantum cryptography genuinely buys us
 * something. The vault contents are protected by a symmetric key, which Grover only
 * weakens quadratically, so 256 bits stays comfortably out of reach. But enrolling a
 * second device means wrapping the vault key *to that device's public key*, and a
 * classical KEM there would be a harvest-now-decrypt-later target: the wrapped key sits
 * on a Nextcloud server for years, and an attacker who copies it today only needs a
 * quantum computer eventually.
 *
 * It is hybrid rather than pure ML-KEM because ML-KEM is young. If a classical break of
 * X25519 or a lattice break of ML-KEM lands, the other half still holds. Both shared
 * secrets, both ciphertexts and the recipient key are fed into HKDF, which binds the
 * result to the exact transcript and rules out re-encapsulation tricks.
 */
object HybridKem {

    private val ML_KEM = MLKEMParameters.ml_kem_768
    private const val HKDF_INFO = "pqvault/kem/x25519+ml-kem-768/v1"

    const val X25519_PUBLIC_SIZE = 32
    private const val X25519_SHARED_SIZE = 32
    const val ML_KEM_768_PUBLIC_SIZE = 1184
    const val ML_KEM_768_CIPHERTEXT_SIZE = 1088

    class PublicKey(val x25519: ByteArray, val mlKem: ByteArray) {
        init {
            require(x25519.size == X25519_PUBLIC_SIZE) { "bad X25519 public key size ${x25519.size}" }
            require(mlKem.size == ML_KEM_768_PUBLIC_SIZE) { "bad ML-KEM-768 public key size ${mlKem.size}" }
        }

        fun encoded(): ByteArray = x25519 + mlKem

        companion object {
            fun decode(bytes: ByteArray): PublicKey {
                require(bytes.size == X25519_PUBLIC_SIZE + ML_KEM_768_PUBLIC_SIZE) {
                    "bad hybrid public key size ${bytes.size}"
                }
                return PublicKey(
                    bytes.copyOfRange(0, X25519_PUBLIC_SIZE),
                    bytes.copyOfRange(X25519_PUBLIC_SIZE, bytes.size),
                )
            }
        }
    }

    class PrivateKey(val x25519: ByteArray, val mlKemSeed: ByteArray) {
        fun encoded(): ByteArray = byteArrayOf(x25519.size.toByte()) + x25519 + mlKemSeed

        companion object {
            fun decode(bytes: ByteArray): PrivateKey {
                val xLen = bytes[0].toInt() and 0xff
                return PrivateKey(
                    bytes.copyOfRange(1, 1 + xLen),
                    bytes.copyOfRange(1 + xLen, bytes.size),
                )
            }
        }
    }

    class KeyPair(val publicKey: PublicKey, val privateKey: PrivateKey)

    /** The encapsulation a recipient needs in order to recover [sharedSecret]. */
    class Encapsulation(val ciphertext: ByteArray, val sharedSecret: ByteArray)

    fun generateKeyPair(random: SecureRandom = SecureRandom()): KeyPair {
        val xPriv = X25519PrivateKeyParameters(random)

        val kpg = MLKEMKeyPairGenerator()
        kpg.init(MLKEMKeyGenerationParameters(random, ML_KEM))
        val pair = kpg.generateKeyPair()
        val pqPub = pair.public as MLKEMPublicKeyParameters
        val pqPriv = pair.private as MLKEMPrivateKeyParameters

        return KeyPair(
            PublicKey(xPriv.generatePublicKey().encoded, pqPub.encoded),
            // Store the 64-byte seed rather than the expanded key: it is far smaller and
            // BouncyCastle can deterministically re-expand it.
            PrivateKey(xPriv.encoded, pqPriv.getParametersWithFormat(MLKEMPrivateKeyParameters.SEED_ONLY).encoded),
        )
    }

    fun encapsulate(recipient: PublicKey, random: SecureRandom = SecureRandom()): Encapsulation {
        val ephemeral = X25519PrivateKeyParameters(random)
        val ephemeralPub = ephemeral.generatePublicKey().encoded

        val classicalSecret = ByteArray(X25519_SHARED_SIZE)
        X25519Agreement().apply {
            init(ephemeral)
            calculateAgreement(X25519PublicKeyParameters(recipient.x25519), classicalSecret, 0)
        }

        val pqEncap = MLKEMGenerator(random)
            .generateEncapsulated(MLKEMPublicKeyParameters(ML_KEM, recipient.mlKem))
        val pqSecret = pqEncap.secret
        val pqCiphertext = pqEncap.encapsulation

        val ciphertext = ephemeralPub + pqCiphertext
        val shared = combine(classicalSecret, pqSecret, ciphertext, recipient)

        classicalSecret.fill(0)
        pqSecret.fill(0)
        return Encapsulation(ciphertext, shared)
    }

    fun decapsulate(privateKey: PrivateKey, publicKey: PublicKey, ciphertext: ByteArray): ByteArray {
        require(ciphertext.size == X25519_PUBLIC_SIZE + ML_KEM_768_CIPHERTEXT_SIZE) {
            "bad hybrid ciphertext size ${ciphertext.size}"
        }
        val ephemeralPub = ciphertext.copyOfRange(0, X25519_PUBLIC_SIZE)
        val pqCiphertext = ciphertext.copyOfRange(X25519_PUBLIC_SIZE, ciphertext.size)

        val classicalSecret = ByteArray(X25519_SHARED_SIZE)
        X25519Agreement().apply {
            init(X25519PrivateKeyParameters(privateKey.x25519))
            calculateAgreement(X25519PublicKeyParameters(ephemeralPub), classicalSecret, 0)
        }

        val pqSecret = MLKEMExtractor(MLKEMPrivateKeyParameters(ML_KEM, privateKey.mlKemSeed))
            .extractSecret(pqCiphertext)

        val shared = combine(classicalSecret, pqSecret, ciphertext, publicKey)
        classicalSecret.fill(0)
        pqSecret.fill(0)
        return shared
    }

    /**
     * Binds both shared secrets to the full transcript. Feeding the ciphertext and the
     * recipient key in, not just the two secrets, is what stops an attacker from
     * replaying one half of the encapsulation against a different recipient.
     */
    private fun combine(
        classicalSecret: ByteArray,
        pqSecret: ByteArray,
        ciphertext: ByteArray,
        recipient: PublicKey,
    ): ByteArray {
        val ikm = classicalSecret + pqSecret
        val info = HKDF_INFO.toByteArray() + ciphertext + recipient.encoded()
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(ikm, null, info))
        val out = ByteArray(32)
        hkdf.generateBytes(out, 0, out.size)
        ikm.fill(0)
        return out
    }
}
