package com.pqvault.core.crypto

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner
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
    const val ED25519_SIGNATURE_SIZE = 64

    class PublicKey(val ed25519: ByteArray, val mlDsa: ByteArray) {
        fun encoded(): ByteArray = ed25519 + mlDsa

        companion object {
            fun decode(bytes: ByteArray): PublicKey = PublicKey(
                bytes.copyOfRange(0, ED25519_PUBLIC_SIZE),
                bytes.copyOfRange(ED25519_PUBLIC_SIZE, bytes.size),
            )
        }
    }

    class PrivateKey(val ed25519: ByteArray, val mlDsaSeed: ByteArray)

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
            PrivateKey(edPriv.encoded, pqPriv.getParametersWithFormat(MLDSAPrivateKeyParameters.SEED_ONLY).encoded),
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
        if (signature.size <= ED25519_SIGNATURE_SIZE) return false
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
