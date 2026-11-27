package com.pqvault.core.format

import com.pqvault.core.model.DeviceRecord
import com.pqvault.core.model.PasskeyEntry
import com.pqvault.core.model.RevokedDevice
import com.pqvault.core.model.Tombstone
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class KdfParams(
    val algorithm: String = "argon2id",
    val memoryKib: Int,
    val iterations: Int,
    val parallelism: Int,
    /** base64url */
    val salt: String,
)

/**
 * A way of unwrapping the vault master key (VMK).
 *
 * The VMK encrypts the vault content exactly once; each recipient holds its own wrapped
 * copy. That indirection is what lets a second device be enrolled without ever learning
 * the passphrase, and lets a device be revoked by rotating the VMK and wrapping the new
 * one for the remaining recipients only.
 */
@Serializable
sealed class Recipient {
    /** base64url of XChaCha20-Poly1305(kek, wrapNonce, vmk). */
    abstract val wrappedKey: String

    /** base64url, 24 bytes. */
    abstract val wrapNonce: String

    @Serializable
    @SerialName("passphrase")
    data class Passphrase(
        val kdf: KdfParams,
        override val wrappedKey: String,
        override val wrapNonce: String,
    ) : Recipient()

    /**
     * A second device, holding the hybrid X25519+ML-KEM-768 private key that opens
     * [kemCiphertext]. This is the post-quantum-relevant path: it is the one wrapped copy
     * that an attacker could harvest from the WebDAV server today and attack later.
     */
    @Serializable
    @SerialName("device")
    data class Device(
        val deviceId: String,
        val label: String,
        /** base64url of the recipient's hybrid public key; bound into the KEM transcript. */
        val kemPublicKey: String,
        val kemCiphertext: String,
        override val wrappedKey: String,
        override val wrapNonce: String,
    ) : Recipient()
}

/**
 * The cleartext part of the file.
 *
 * It is not secret, but it *is* authenticated: it is fed to the content cipher as
 * additional data, so tampering with a recipient list or a KDF cost makes the content
 * fail to decrypt rather than silently downgrading us.
 */
/**
 * One signing key rotation: [nextKey] replaces [previousKey], which signed the change. A
 * client pinned to an older key follows these links to the current one.
 */
@Serializable
data class SigningKeyLink(
    /** base64url hybrid public key. */
    val previousKey: String,
    /** base64url hybrid public key. */
    val nextKey: String,
    /** base64url hybrid signature by [previousKey]. */
    val signature: String,
)

@Serializable
data class VaultHeader(
    val formatVersion: Int = VaultFile.FORMAT_VERSION,
    /**
     * What a reader must understand to handle this vault safely. Any feature moves the
     * file to [VaultFile.FEATURES_FORMAT_VERSION], which releases that predate it refuse.
     */
    val features: List<String> = emptyList(),
    /**
     * Monotonic counter, incremented on every save. A WebDAV server that replays an
     * older-but-genuine vault would otherwise be undetectable, since old versions
     * decrypt and verify perfectly well. Clients refuse to accept a version lower than
     * the one they last saw.
     */
    val vaultVersion: Long,
    /** base64url, 24 bytes. */
    val contentNonce: String,
    /** base64url hybrid Ed25519+ML-DSA-65 public key; pinned by clients on first open. */
    val signingPublicKey: String,
    val recipients: List<Recipient>,
    /** Oldest first, the last link ending at [signingPublicKey]. */
    val signingKeyChain: List<SigningKeyLink> = emptyList(),
)

/** The encrypted part of the file. */
@Serializable
data class VaultContent(
    val entries: List<PasskeyEntry> = emptyList(),
    val tombstones: List<Tombstone> = emptyList(),
    val devices: List<DeviceRecord> = emptyList(),
    val revokedDevices: List<RevokedDevice> = emptyList(),
    /**
     * base64url Ed25519 private key + base64url ML-DSA-65 seed, joined by ':'.
     * Kept inside the ciphertext so that any device able to open the vault can sign the
     * next version, and no device that cannot open it can forge one.
     */
    val signingPrivateKey: String,
)
