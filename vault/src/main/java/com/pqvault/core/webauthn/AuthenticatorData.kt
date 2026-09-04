package com.pqvault.core.webauthn

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Builds the `authenticatorData` structure that every WebAuthn response is signed over.
 *
 * Layout: rpIdHash(32) | flags(1) | signCount(4, big-endian) | [attested credential data]
 */
object AuthenticatorData {

    const val FLAG_USER_PRESENT = 0x01
    const val FLAG_USER_VERIFIED = 0x04

    /**
     * Backup eligible / backup state. These two are what tell a relying party it is
     * looking at a *synced* passkey rather than one welded to a single device, and they
     * are the flags the upstream library could never honestly set: its keys lived in the
     * Keystore and could not be backed up at all. Setting them is what stops a site from
     * nagging the user to enrol a second authenticator, and what makes recovery on a new
     * phone a supported flow rather than a surprise.
     */
    const val FLAG_BACKUP_ELIGIBLE = 0x08
    const val FLAG_BACKUP_STATE = 0x10

    const val FLAG_ATTESTED_CREDENTIAL_DATA = 0x40

    fun build(
        rpId: String,
        flags: Int,
        signCount: Long,
        attestedCredentialData: ByteArray? = null,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(sha256(rpId.toByteArray(Charsets.UTF_8)))

        val effectiveFlags = if (attestedCredentialData != null) {
            flags or FLAG_ATTESTED_CREDENTIAL_DATA
        } else {
            flags and FLAG_ATTESTED_CREDENTIAL_DATA.inv()
        }
        out.write(effectiveFlags and 0xff)

        // The counter is 32 bits on the wire; it wraps rather than overflowing the field.
        val counter = signCount and 0xffffffffL
        out.write(((counter ushr 24) and 0xff).toInt())
        out.write(((counter ushr 16) and 0xff).toInt())
        out.write(((counter ushr 8) and 0xff).toInt())
        out.write((counter and 0xff).toInt())

        attestedCredentialData?.let { out.write(it) }
        return out.toByteArray()
    }

    /** aaguid(16) | credentialIdLength(2) | credentialId | credentialPublicKey(COSE) */
    fun attestedCredentialData(
        aaguid: ByteArray,
        credentialId: ByteArray,
        cosePublicKey: ByteArray,
    ): ByteArray {
        require(aaguid.size == 16) { "aaguid must be 16 bytes, was ${aaguid.size}" }
        require(credentialId.size <= 1023) { "credential id must be at most 1023 bytes" }

        val out = ByteArrayOutputStream()
        out.write(aaguid)
        out.write((credentialId.size ushr 8) and 0xff)
        out.write(credentialId.size and 0xff)
        out.write(credentialId)
        out.write(cosePublicKey)
        return out.toByteArray()
    }

    fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)
}
