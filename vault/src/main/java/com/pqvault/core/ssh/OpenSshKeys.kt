package com.pqvault.core.ssh

import com.pqvault.core.format.Base64Url
import com.pqvault.core.hybrid.HybridCrypto
import com.pqvault.core.model.CoseAlgorithm
import com.pqvault.core.model.PasskeyEntry
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.util.PublicKeyFactory
import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * OpenSSH security keys held in the vault, whose relying party ID is an application starting
 * with `ssh:`. Nothing here reads the private key.
 */
object OpenSshKeys {
    const val APPLICATION_PREFIX = "ssh:"

    const val FLAG_USER_PRESENCE_REQUIRED = 0x01
    const val FLAG_USER_VERIFICATION_REQUIRED = 0x04
    const val FLAG_RESIDENT_KEY = 0x20

    /** OpenSSH's label for this format, also used for security key files that hold no private key. */
    const val KEY_FILE_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----" // gitleaks:allow
    const val KEY_FILE_END = "-----END OPENSSH PRIVATE KEY-----"

    private const val ECDSA_TYPE = "sk-ecdsa-sha2-nistp256@openssh.com"
    private const val ED25519_TYPE = "sk-ssh-ed25519@openssh.com"
    private const val CURVE = "nistp256"
    private const val AUTH_MAGIC = "openssh-key-v1"
    private const val BLOCK_SIZE = 8
    private const val LINE_LENGTH = 70

    fun isApplication(rpId: String): Boolean = rpId.startsWith(APPLICATION_PREFIX)

    fun isSshKey(entry: PasskeyEntry): Boolean = isApplication(entry.rpId)

    /** The key type name OpenSSH prints, as in "Confirm user presence for key ECDSA-SK ...". */
    fun label(entry: PasskeyEntry): String = label(entry.algorithm)

    fun label(algorithm: CoseAlgorithm?): String = when (algorithm) {
        CoseAlgorithm.ES256 -> "ECDSA-SK"
        CoseAlgorithm.EDDSA -> "ED25519-SK"
        else -> throw IllegalArgumentException("no OpenSSH key type for algorithm ${algorithm?.id}")
    }

    fun keyType(entry: PasskeyEntry): String = when (entry.algorithm) {
        CoseAlgorithm.ES256 -> ECDSA_TYPE
        CoseAlgorithm.EDDSA -> ED25519_TYPE
        else -> throw IllegalArgumentException("no OpenSSH key type for algorithm ${entry.algorithmId}")
    }

    /** The default file name `ssh-keygen` gives this key type. */
    fun keyFileName(entry: PasskeyEntry): String = when (entry.algorithm) {
        CoseAlgorithm.ES256 -> "id_ecdsa_sk"
        CoseAlgorithm.EDDSA -> "id_ed25519_sk"
        else -> throw IllegalArgumentException("no OpenSSH key type for algorithm ${entry.algorithmId}")
    }

    /** The public key in the SSH wire format, the blob of `authorized_keys`. */
    fun publicKeyBlob(entry: PasskeyEntry): ByteArray {
        require(isSshKey(entry)) { "${entry.rpId} is not an OpenSSH application" }
        return SshBuffer().apply {
            putString(keyType(entry))
            putPublicKey(entry)
            putString(entry.rpId)
        }.toByteArray()
    }

    /** Same value as `ssh-keygen -l` prints for this key. */
    fun fingerprint(entry: PasskeyEntry): String =
        "SHA256:" + Base64.getEncoder().withoutPadding()
            .encodeToString(HybridCrypto.sha256(publicKeyBlob(entry)))

    /** The line to paste on a server: the server then also refuses unverified signatures. */
    fun verifyRequiredLine(entry: PasskeyEntry, comment: String): String =
        "verify-required " + authorizedKeysLine(entry, comment)

    fun authorizedKeysLine(entry: PasskeyEntry, comment: String): String {
        val line = keyType(entry) + " " + Base64.getEncoder().encodeToString(publicKeyBlob(entry))
        val cleanComment = comment.filter { it >= ' ' && it != '\u007f' }.trim()
        return if (cleanComment.isEmpty()) line else "$line $cleanComment"
    }

    /** Flags written into an exported key file. Every signature is verified on the phone. */
    fun flags(entry: PasskeyEntry): Int =
        FLAG_USER_PRESENCE_REQUIRED or FLAG_USER_VERIFICATION_REQUIRED or
            (if (entry.discoverable) FLAG_RESIDENT_KEY else 0)

    /**
     * The key handle file `ssh-keygen` writes for a security key, in the unencrypted
     * `openssh-key-v1` format. It holds the public key and the credential ID only.
     */
    fun keyFile(entry: PasskeyEntry, comment: String, random: SecureRandom = SecureRandom()): String {
        val publicBlob = publicKeyBlob(entry)
        val check = random.nextInt()
        val private = SshBuffer().apply {
            putUInt32(check)
            putUInt32(check)
            putString(keyType(entry))
            putPublicKey(entry)
            putString(entry.rpId)
            putByte(flags(entry))
            putBytes(Base64Url.decode(entry.credentialId))
            putBytes(ByteArray(0))
            putString(comment)
            var padding = 0
            while (size() % BLOCK_SIZE != 0) putByte(++padding)
        }.toByteArray()

        val encoded = SshBuffer().apply {
            write((AUTH_MAGIC + "\u0000").toByteArray(Charsets.US_ASCII))
            putString("none")
            putString("none")
            putBytes(ByteArray(0))
            putUInt32(1)
            putBytes(publicBlob)
            putBytes(private)
        }.toByteArray()

        val body = Base64.getEncoder().encodeToString(encoded).chunked(LINE_LENGTH).joinToString("\n")
        return "$KEY_FILE_BEGIN\n$body\n$KEY_FILE_END\n"
    }

    /** The SEC1 uncompressed point for ECDSA, the raw 32 bytes for Ed25519. */
    fun rawPublicKey(entry: PasskeyEntry): ByteArray {
        val spki = Base64Url.decode(entry.publicKeySpki)
        return when (entry.algorithm) {
            CoseAlgorithm.ES256 ->
                HybridCrypto.encodeUncompressed(KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki)))
            CoseAlgorithm.EDDSA -> (
                PublicKeyFactory.createKey(spki) as? Ed25519PublicKeyParameters
                    ?: throw IllegalArgumentException("stored key is not an Ed25519 key")
                ).encoded
            else -> throw IllegalArgumentException("no OpenSSH key type for algorithm ${entry.algorithmId}")
        }
    }

    private fun SshBuffer.putPublicKey(entry: PasskeyEntry) {
        if (entry.algorithm == CoseAlgorithm.ES256) putString(CURVE)
        putBytes(rawPublicKey(entry))
    }

    private class SshBuffer : ByteArrayOutputStream() {
        fun putByte(value: Int) = write(value and 0xff)

        fun putUInt32(value: Int) {
            write(value ushr 24)
            write(value ushr 16)
            write(value ushr 8)
            write(value)
        }

        fun putBytes(value: ByteArray) {
            putUInt32(value.size)
            write(value)
        }

        fun putString(value: String) = putBytes(value.toByteArray(Charsets.UTF_8))
    }
}
