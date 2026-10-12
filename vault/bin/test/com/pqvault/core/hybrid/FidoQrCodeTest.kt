package com.pqvault.core.hybrid

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream

class FidoQrCodeTest {
    private val compressedPoint = byteArrayOf(
        0x03, 0x36, 0x4c, 0x15, 0xee.toByte(), 0xc3.toByte(), 0x43, 0x31,
        0xd2.toByte(), 0x86.toByte(), 0x57, 0x57, 0x42, 0x1d, 0x49, 0x7e,
        0x56, 0x9e.toByte(), 0x1e, 0xba.toByte(), 0x6c, 0xff.toByte(), 0x9a.toByte(),
        0x69, 0xd3.toByte(), 0x2e, 0x90.toByte(), 0xf1.toByte(), 0x9e.toByte(),
        0x7f, 0x6f, 0xd1.toByte(), 0x5e,
    )

    @Test
    fun `digit decoder matches the Chromium compatibility vector`() {
        assertThat(FidoQrCode.digitsToBytes("16736865"))
            .isEqualTo(byteArrayOf('a'.code.toByte(), 'b'.code.toByte(), 0xff.toByte()))
    }

    @Test
    fun `valid make credential code exposes its key secret and hint`() {
        val secret = ByteArray(16) { it.toByte() }
        val map = CborMap()
            .put(UnsignedInteger(0), ByteString(compressedPoint))
            .put(UnsignedInteger(1), ByteString(secret))
            .put(UnsignedInteger(2), UnsignedInteger(2))
            .put(UnsignedInteger(5), UnicodeString("mc"))

        val parsed = FidoQrCode.parse("FIDO:/" + bytesToDigits(encode(map)))

        assertThat(parsed).isNotNull()
        assertThat(parsed!!.secret).isEqualTo(secret)
        assertThat(parsed.knownTunnelDomains).isEqualTo(2)
        assertThat(parsed.requestTypeHint).isEqualTo(FidoQrCode.RequestType.MakeCredential)
        assertThat(parsed.peerIdentityUncompressed).hasLength(65)
        assertThat(parsed.peerIdentityUncompressed[0]).isEqualTo(4)
    }

    @Test
    fun `invalid prefix digit lengths and overflowing chunks are refused`() {
        assertThat(FidoQrCode.parse("https://example.test")).isNull()
        assertThat(FidoQrCode.parse("FIDO:/1")).isNull()
        assertThat(FidoQrCode.parse("FIDO:/999")).isNull()
    }

    private fun encode(map: CborMap): ByteArray = ByteArrayOutputStream().also {
        CborEncoder(it).encode(map)
    }.toByteArray()

    private fun bytesToDigits(bytes: ByteArray): String = buildString {
        var offset = 0
        val widths = intArrayOf(0, 3, 5, 8, 10, 13, 15, 17)
        while (offset < bytes.size) {
            val count = minOf(7, bytes.size - offset)
            var value = 0L
            repeat(count) { index ->
                value = value or ((bytes[offset + index].toLong() and 0xff) shl (index * 8))
            }
            append(value.toString().padStart(widths[count], '0'))
            offset += count
        }
    }
}
