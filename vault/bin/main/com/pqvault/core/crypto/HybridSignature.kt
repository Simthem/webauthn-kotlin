package com.pqvault.core.crypto

import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.MLDSASigner
import java.security.SecureRandom

/**
 * Hybrid Ed25519 + ML-DSA-65 signature over the vault file.
 *
 * This is not about secrecy (the file is already encrypted) but about authenticity.
 * A malicious or compromised WebDAV server can otherwise serve an *older* vault it
 * captured earlier. That version is perfectly decryptable, so encryption alone does not
 * catch it; the rollback is only detectable if each version is signed and carries a
 * version number the client checks. Signing post-quantum matters for the same
 * harvest-now reason as the KEM: these files are meant to outlive the decade.
 *
 * Verification requires *both* signatures to pass, so forging one needs a break of
 * Ed25519 and of ML-DSA at once.
 */
object HybridSignature {

    private val ML_DSA = MLDSAParameters.ml_dsa_65

    const val ED25519_PUBLIC_SIZE = 32
    const val ED25519_PRIVATE_SIZE = 32
    const val ED25519_SIGNATURE_SIZE = 64
    const val ML_DSA_SEED_SIZE = 32

    /**
     * The expanded ML-DSA-65 private key, which is what vaults written before the move to
     * BouncyCastle's current APIs carry in place of the seed. The seed is hashed to derive
     * the expanded key, so it cannot be recovered from one: a vault written that way keeps
     * this encoding for the life of its signing key. BouncyCastle accepts either form and
     * produces the same signatures from both, so nothing else has to know which it holds.
     */
    const val ML_DSA_65_EXPANDED_PRIVATE_SIZE = 4032
    const val ML_DSA_65_PUBLIC_SIZE = 1952
    const val ML_DSA_65_SIGNATURE_SIZE = 3309

    class PublicKey(val ed25519: ByteArray, val mlDsa: ByteArray) {
        init {
            require(ed25519.size == ED25519_PUBLIC_SIZE) { "bad Ed25519 public key size ${ed25519.size}" }
            require(mlDsa.size == ML_DSA_65_PUBLIC_SIZE) { "bad ML-DSA-65 public key size ${mlDsa.size}" }
        }

        fun encoded(): ByteArray = ed25519 + mlDsa

        companion object {
            fun decode(bytes: ByteArray): PublicKey {
                require(bytes.size == ED25519_PUBLIC_SIZE + ML_DSA_65_PUBLIC_SIZE) {
                    "bad hybrid signing public key size ${bytes.size}"
                }
                return PublicKey(
                    bytes.copyOfRange(0, ED25519_PUBLIC_SIZE),
                    bytes.copyOfRange(ED25519_PUBLIC_SIZE, bytes.size),
                )
            }
        }
    }

    class PrivateKey(val ed25519: ByteArray, val mlDsaSeed: ByteArray) {
        init {
            require(ed25519.size == ED25519_PRIVATE_SIZE) { "bad Ed25519 private key size ${ed25519.size}" }
            require(
                mlDsaSeed.size == ML_DSA_SEED_SIZE ||
                    mlDsaSeed.size == ML_DSA_65_EXPANDED_PRIVATE_SIZE,
            ) { "bad ML-DSA private key size ${mlDsaSeed.size}" }
        }
    }

    class KeyPair(val publicKey: PublicKey, val privateKey: PrivateKey)

    fun generateKeyPair(random: SecureRandom = SecureRandom()): KeyPair {
        val edPriv = Ed25519PrivateKeyParameters(random)

        val kpg = MLDSAKeyPairGenerator()
        kpg.init(MLDSAKeyGenerationParameters(random, ML_DSA))
        val pair = kpg.generateKeyPair()
        val pqPub = pair.public as MLDSAPublicKeyParameters
        val pqPriv = pair.private as MLDSAPrivateKeyParameters

        return KeyPair(
            PublicKey(edPriv.generatePublicKey().encoded, pqPub.encoded),
            PrivateKey(edPriv.encoded, pqPriv.seed),
        )
    }

    fun sign(privateKey: PrivateKey, message: ByteArray): ByteArray {
        val edSignature = Ed25519Signer().run {
            init(true, Ed25519PrivateKeyParameters(privateKey.ed25519))
            update(message, 0, message.size)
            generateSignature()
        }
        val pqSignature = MLDSASigner().run {
            init(true, MLDSAPrivateKeyParameters(ML_DSA, privateKey.mlDsaSeed))
            update(message, 0, message.size)
            generateSignature()
        }
        return edSignature + pqSignature
    }

    /** True only when both halves verify. */
    fun verify(publicKey: PublicKey, message: ByteArray, signature: ByteArray): Boolean {
        if (signature.size != ED25519_SIGNATURE_SIZE + ML_DSA_65_SIGNATURE_SIZE) return false
        val edSignature = signature.copyOfRange(0, ED25519_SIGNATURE_SIZE)
        val pqSignature = signature.copyOfRange(ED25519_SIGNATURE_SIZE, signature.size)

        val edOk = try {
            Ed25519Signer().run {
                init(false, Ed25519PublicKeyParameters(publicKey.ed25519, 0))
                update(message, 0, message.size)
                verifySignature(edSignature)
            }
        } catch (e: IllegalArgumentException) {
            false
        }

        val pqOk = try {
            MLDSASigner().run {
                init(false, MLDSAPublicKeyParameters(ML_DSA, publicKey.mlDsa))
                update(message, 0, message.size)
                verifySignature(pqSignature)
            }
        } catch (e: IllegalArgumentException) {
            false
        }

        return edOk && pqOk
    }
}
