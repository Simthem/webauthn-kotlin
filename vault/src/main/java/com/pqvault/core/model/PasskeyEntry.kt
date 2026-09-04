package com.pqvault.core.model

import kotlinx.serialization.Serializable

/**
 * One passkey, including its private key.
 *
 * This is the deliberate architectural break from the upstream LINE library, which kept
 * every private key inside the AndroidKeyStore. Hardware-bound keys cannot be exported,
 * which makes them impossible to back up or move to a second device, the whole reason
 * this project exists. Holding the key in software is what makes a syncable vault
 * possible at all, and it is the same trade-off KeePass made: the file is only ever as
 * safe as the passphrase and the AEAD wrapped around it.
 */
@Serializable
data class PasskeyEntry(
    /** base64url, also the WebAuthn credential ID handed to the relying party. */
    val credentialId: String,
    val rpId: String,
    val rpName: String? = null,
    /** base64url of the user handle chosen by the relying party. */
    val userHandle: String,
    val userName: String,
    val userDisplayName: String? = null,
    val algorithmId: Int = CoseAlgorithm.ES256.id,
    /** base64url PKCS#8 private key. */
    val privateKeyPkcs8: String,
    /** base64url SPKI public key, kept so we never have to re-derive it to show details. */
    val publicKeySpki: String,
    val signCount: Long = 0,
    val discoverable: Boolean = true,
    val createdAt: Long,
    /** Drives last-writer-wins during a sync merge. Milliseconds since epoch. */
    val updatedAt: Long,
) {
    val algorithm: CoseAlgorithm?
        get() = CoseAlgorithm.fromId(algorithmId)
}

/**
 * Marks a deleted entry so the deletion survives a merge.
 *
 * Without these, a device that still has the entry would simply re-add it on the next
 * sync: deletions would silently undo themselves, which is the classic failure mode of
 * naive file sync.
 */
@Serializable
data class Tombstone(
    val credentialId: String,
    val deletedAt: Long,
)

/** A device enrolled against this vault, able to unwrap the vault key via its hybrid KEM key. */
@Serializable
data class DeviceRecord(
    val deviceId: String,
    val label: String,
    val kemPublicKey: String,
    val enrolledAt: Long,
)
