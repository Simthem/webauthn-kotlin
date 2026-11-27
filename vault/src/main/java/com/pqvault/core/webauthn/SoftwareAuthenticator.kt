package com.pqvault.core.webauthn

import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.pqvault.core.format.Base64Url
import com.pqvault.core.model.CoseAlgorithm
import com.pqvault.core.model.PasskeyEntry
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.UUID

/**
 * A WebAuthn authenticator whose keys live in software, inside the vault.
 *
 * Software keys are the deliberate trade this project makes. Hardware-bound keys are
 * strictly safer against someone who has the unlocked phone in their hands, but they can
 * never be backed up or moved, which makes a synced vault impossible. Everything else
 * here (Argon2id, the AEAD, the hybrid signature over the file) exists to make that
 * trade defensible.
 */
class SoftwareAuthenticator(
    private val random: SecureRandom = SecureRandom(),
    /** Identifies the authenticator model. Ours is self-assigned and stable. */
    private val aaguid: UUID = DEFAULT_AAGUID,
) {

    class Registration(
        val entry: PasskeyEntry,
        /** CBOR attestation object, format "none". */
        val attestationObject: ByteArray,
        val authenticatorData: ByteArray,
        /** "none", or "packed" when [attestationSignature] self-attests the new key. */
        val attestationFormat: String = "none",
        val attestationSignature: ByteArray? = null,
    )

    class Assertion(
        val authenticatorData: ByteArray,
        val signature: ByteArray,
        val credentialId: ByteArray,
        val userHandle: ByteArray?,
        val updatedEntry: PasskeyEntry,
    )

    /**
     * Creates a new credential. [algorithm] should come from [selectAlgorithm] over the
     * relying party's `pubKeyCredParams`.
     */
    fun makeCredential(
        rpId: String,
        rpName: String?,
        userHandle: ByteArray,
        userName: String,
        userDisplayName: String?,
        clientDataHash: ByteArray,
        algorithm: CoseAlgorithm = CoseAlgorithm.ES256,
        userVerified: Boolean = true,
        now: Long = System.currentTimeMillis(),
        /** The credProtect level the client asked for, echoed in the authenticator data. */
        credentialProtection: Int? = null,
        discoverable: Boolean = true,
        selfAttestation: Boolean = false,
    ): Registration {
        require(algorithm in SUPPORTED_ALGORITHMS) {
            "${algorithm.label} is registered with IANA but not yet accepted by relying " +
                "parties. Only ES256 and Ed25519 can currently produce a usable credential"
        }
        require(credentialProtection == null || credentialProtection in 1..3) {
            "credProtect level must be 1, 2 or 3"
        }

        val keys = generateKeys(algorithm)
        val credentialId = ByteArray(32).also { random.nextBytes(it) }

        val authenticatorData = AuthenticatorData.build(
            rpId = rpId,
            flags = AuthenticatorData.FLAG_USER_PRESENT or
                (if (userVerified) AuthenticatorData.FLAG_USER_VERIFIED else 0) or
                // Always set: this credential lives in a vault that is designed to be
                // backed up and synced, and saying otherwise would be a lie to the site.
                AuthenticatorData.FLAG_BACKUP_ELIGIBLE or
                AuthenticatorData.FLAG_BACKUP_STATE,
            signCount = 0,
            attestedCredentialData = AuthenticatorData.attestedCredentialData(
                aaguid = aaguidBytes(),
                credentialId = credentialId,
                cosePublicKey = keys.cosePublicKey,
            ),
            extensions = credentialProtection?.let(::credProtectOutput),
        )

        val entry = PasskeyEntry(
            credentialId = Base64Url.encode(credentialId),
            rpId = rpId,
            rpName = rpName,
            userHandle = Base64Url.encode(userHandle),
            userName = userName,
            userDisplayName = userDisplayName,
            algorithmId = algorithm.id,
            privateKeyPkcs8 = Base64Url.encode(keys.privateKeyPkcs8),
            publicKeySpki = Base64Url.encode(keys.publicKeySpki),
            signCount = 0,
            discoverable = discoverable,
            credentialProtection = credentialProtection ?: 1,
            createdAt = now,
            updatedAt = now,
        )

        return Registration(
            entry = entry,
            attestationObject = noneAttestationObject(authenticatorData),
            authenticatorData = authenticatorData,
            attestationFormat = if (selfAttestation) "packed" else "none",
            attestationSignature = if (selfAttestation) {
                sign(algorithm, keys.privateKeyPkcs8, authenticatorData, clientDataHash)
            } else {
                null
            },
        )
    }

    /** Signs an authentication challenge with an existing credential. */
    fun getAssertion(
        entry: PasskeyEntry,
        clientDataHash: ByteArray,
        userVerified: Boolean = true,
        now: Long = System.currentTimeMillis(),
    ): Assertion {
        val algorithm = entry.algorithm
            ?: throw IllegalArgumentException("unknown COSE algorithm ${entry.algorithmId}")
        require(algorithm in SUPPORTED_ALGORITHMS) {
            "${algorithm.label} assertions are not supported yet"
        }

        // Incremented before signing: the counter the relying party sees must be strictly
        // greater than the last one it saw, or it treats the authenticator as cloned.
        val nextCount = entry.signCount + 1

        val authenticatorData = AuthenticatorData.build(
            rpId = entry.rpId,
            flags = AuthenticatorData.FLAG_USER_PRESENT or
                (if (userVerified) AuthenticatorData.FLAG_USER_VERIFIED else 0) or
                AuthenticatorData.FLAG_BACKUP_ELIGIBLE or
                AuthenticatorData.FLAG_BACKUP_STATE,
            signCount = nextCount,
            attestedCredentialData = null,
        )

        val signature = sign(
            algorithm,
            Base64Url.decode(entry.privateKeyPkcs8),
            authenticatorData,
            clientDataHash,
        )

        return Assertion(
            authenticatorData = authenticatorData,
            signature = signature,
            credentialId = Base64Url.decode(entry.credentialId),
            userHandle = Base64Url.decode(entry.userHandle),
            updatedEntry = entry.copy(signCount = nextCount, updatedAt = now),
        )
    }

    private class GeneratedKeys(
        val privateKeyPkcs8: ByteArray,
        val publicKeySpki: ByteArray,
        val cosePublicKey: ByteArray,
    )

    private fun generateKeys(algorithm: CoseAlgorithm): GeneratedKeys = when (algorithm) {
        CoseAlgorithm.ES256 -> {
            val keyPair = KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"), random)
            }.generateKeyPair()
            GeneratedKeys(
                privateKeyPkcs8 = keyPair.private.encoded,
                publicKeySpki = keyPair.public.encoded,
                cosePublicKey = CoseKey.forEs256(keyPair.public as ECPublicKey),
            )
        }
        CoseAlgorithm.EDDSA -> {
            val privateKey = Ed25519PrivateKeyParameters(random)
            val publicKey = privateKey.generatePublicKey()
            GeneratedKeys(
                privateKeyPkcs8 = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey).encoded,
                publicKeySpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey).encoded,
                cosePublicKey = CoseKey.forEdDsa(publicKey.encoded),
            )
        }
        else -> throw IllegalArgumentException("${algorithm.label} keys are not supported")
    }

    /** Signs authenticatorData || clientDataHash, the message every WebAuthn signature covers. */
    private fun sign(
        algorithm: CoseAlgorithm,
        privateKeyPkcs8: ByteArray,
        authenticatorData: ByteArray,
        clientDataHash: ByteArray,
    ): ByteArray = when (algorithm) {
        CoseAlgorithm.ES256 -> {
            val privateKey = KeyFactory.getInstance("EC").generatePrivate(
                PKCS8EncodedKeySpec(privateKeyPkcs8),
            )
            Signature.getInstance("SHA256withECDSA").run {
                initSign(privateKey)
                update(authenticatorData)
                update(clientDataHash)
                sign()
            }
        }
        CoseAlgorithm.EDDSA -> {
            val privateKey = PrivateKeyFactory.createKey(privateKeyPkcs8) as? Ed25519PrivateKeyParameters
                ?: throw IllegalArgumentException("stored key is not an Ed25519 key")
            Ed25519Signer().run {
                init(true, privateKey)
                update(authenticatorData, 0, authenticatorData.size)
                update(clientDataHash, 0, clientDataHash.size)
                generateSignature()
            }
        }
        else -> throw IllegalArgumentException("${algorithm.label} signatures are not supported")
    }

    private fun credProtectOutput(level: Int): ByteArray {
        val out = ByteArrayOutputStream()
        CborEncoder(out).encode(
            CborMap().put(UnicodeString("credProtect"), UnsignedInteger(level.toLong())),
        )
        return out.toByteArray()
    }

    /**
     * Attestation format "none". A self-hosted vault has no attestation story worth
     * telling, since there is no manufacturer certificate chain behind it, and claiming one
     * would be dishonest. Relying parties that demand real attestation will refuse us,
     * which is the correct outcome.
     */
    private fun noneAttestationObject(authenticatorData: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        CborEncoder(out).encode(
            CborBuilder()
                .addMap()
                .put("fmt", "none")
                .putMap("attStmt").end()
                .put("authData", authenticatorData)
                .end()
                .build(),
        )
        return out.toByteArray()
    }

    private fun aaguidBytes(): ByteArray {
        val out = ByteArrayOutputStream()
        val high = aaguid.mostSignificantBits
        val low = aaguid.leastSignificantBits
        for (i in 7 downTo 0) out.write(((high ushr (i * 8)) and 0xff).toInt())
        for (i in 7 downTo 0) out.write(((low ushr (i * 8)) and 0xff).toInt())
        return out.toByteArray()
    }

    companion object {
        /** Self-assigned; identifies "PQ Vault software authenticator". */
        val DEFAULT_AAGUID: UUID = UUID.fromString("70715641-554c-4700-b000-000000000001")

        /** In order of preference when a client offers several. */
        val SUPPORTED_ALGORITHMS: List<CoseAlgorithm> = listOf(CoseAlgorithm.ES256, CoseAlgorithm.EDDSA)

        /** The first supported algorithm the client offers, ES256 first, or null when none is. */
        fun selectAlgorithm(offered: List<Int>): CoseAlgorithm? =
            SUPPORTED_ALGORITHMS.firstOrNull { it.id in offered }
    }
}
