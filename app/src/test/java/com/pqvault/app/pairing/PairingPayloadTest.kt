package com.pqvault.app.pairing

import com.google.common.truth.Truth.assertThat
import com.google.zxing.WriterException
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.google.zxing.qrcode.encoder.Encoder
import com.pqvault.app.data.SecureSettings
import com.pqvault.core.format.Base64Url
import org.junit.jupiter.api.Test
import java.security.MessageDigest

class PairingPayloadTest {

    /**
     * A hybrid Ed25519 + ML-DSA-65 signing public key, at its real size. The size is the
     * whole point of these tests, so it is spelled out rather than mocked small.
     */
    private val signingKey = ByteArray(32 + 1952) { (it % 251).toByte() }

    private fun settings(
        url: String = "https://cloud.example.org/remote.php/dav/files/simon/Passkeys",
    ) = SecureSettings.Settings(
        webdavBaseUrl = url,
        webdavUsername = "simon",
        webdavAppPassword = "aaaaa-bbbbb-ccccc-ddddd-eeeee",
        remotePath = "vault.pqvault",
        pinnedSigningKey = Base64Url.encode(signingKey),
    )

    /** Encodes exactly as [QrCode] does, minus the Android bitmap it cannot make here. */
    private fun fitsInAQrCode(content: String): Boolean = try {
        Encoder.encode(content, ErrorCorrectionLevel.M)
        true
    } catch (e: WriterException) {
        false
    }

    /**
     * The regression that matters. Carrying the signing key itself put the payload at
     * roughly 3800 characters against a hard QR ceiling of 2953 bytes, so *every* pairing
     * code the app ever produced threw WriterException and the button did nothing at all.
     */
    @Test
    fun `a pairing code fits in a QR code`() {
        val content = PairingPayload.encode(settings())

        assertThat(content.length).isLessThan(2953)
        assertThat(fitsInAQrCode(content)).isTrue()
    }

    @Test
    fun `it still fits with an unusually long server address`() {
        val long = "https://nextcloud.internal.example.org/remote.php/dav/files/" +
            "a-rather-long-account-name/Documents/Security/Passkeys/Shared"
        assertThat(fitsInAQrCode(PairingPayload.encode(settings(long)))).isTrue()
    }

    @Test
    fun `the server details survive a round trip`() {
        val original = settings()

        val result = PairingPayload.decode(PairingPayload.encode(original))

        assertThat(result).isInstanceOf(PairingPayload.ParseResult.Valid::class.java)
        val payload = (result as PairingPayload.ParseResult.Valid).payload
        assertThat(payload.webdavBaseUrl).isEqualTo(original.webdavBaseUrl)
        assertThat(payload.webdavUsername).isEqualTo(original.webdavUsername)
        assertThat(payload.webdavAppPassword).isEqualTo(original.webdavAppPassword)
        assertThat(payload.remotePath).isEqualTo(original.remotePath)
    }

    @Test
    fun `the code carries a digest of the signing key, never the key`() {
        val content = PairingPayload.encode(settings())
        val payload = (PairingPayload.decode(content) as PairingPayload.ParseResult.Valid).payload

        val expected = Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(signingKey))
        assertThat(payload.pinnedSigningKeyDigest).isEqualTo(expected)
        assertThat(content).doesNotContain(Base64Url.encode(signingKey))
    }

    /** A device that has only ever been paired passes on the digest it inherited. */
    @Test
    fun `a device holding only a digest can still pair a third one`() {
        val digest = Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(signingKey))
        val paired = settings().copy(pinnedSigningKey = "", pinnedSigningKeyDigest = digest)

        val content = PairingPayload.encode(paired)
        val payload = (PairingPayload.decode(content) as PairingPayload.ParseResult.Valid).payload

        assertThat(payload.pinnedSigningKeyDigest).isEqualTo(digest)
    }

    @Test
    fun `applying a payload pins the digest and clears any stale key`() {
        val scanned = (PairingPayload.decode(PairingPayload.encode(settings()))
            as PairingPayload.ParseResult.Valid).payload

        val applied = PairingPayload.applyTo(
            SecureSettings.Settings(pinnedSigningKey = "left over from another vault"),
            scanned,
        )

        assertThat(applied.pinnedSigningKey).isEmpty()
        assertThat(applied.pinnedSigningKeyDigest).isEqualTo(scanned.pinnedSigningKeyDigest)
        // A newly paired device has synced nothing, so it inherits no watermark either.
        assertThat(applied.lastSeenVersion).isEqualTo(0)
        assertThat(applied.localVersion).isEqualTo(0)
        assertThat(applied.lastSyncEtag).isEmpty()
    }

    @Test
    fun `a code past its validity window is refused`() {
        val now = 1_000_000L
        val content = PairingPayload.encode(settings(), now = now)

        val result = PairingPayload.decode(content, now = now + PairingPayload.VALIDITY_MS + 1)

        assertThat(result).isInstanceOf(PairingPayload.ParseResult.Expired::class.java)
    }

    @Test
    fun `anything that is not a pairing code is refused rather than parsed`() {
        for (text in listOf("", "https://example.org", "pqvault://pair?d=not-base64!!", "{}")) {
            assertThat(PairingPayload.decode(text))
                .isInstanceOf(PairingPayload.ParseResult.NotAPairingCode::class.java)
        }
    }
}
