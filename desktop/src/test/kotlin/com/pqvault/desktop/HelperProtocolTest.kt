package com.pqvault.desktop

import com.google.common.truth.Truth.assertThat
import com.google.zxing.qrcode.decoder.Decoder
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream

class HelperProtocolTest {

    @Test
    fun `a request survives the trip from the library`() {
        val out = ByteArrayOutputStream()
        HelperProtocol.writeRequest(
            out,
            HelperProtocol.Request(HelperProtocol.OP_SIGN, HelperProtocol.ALG_ED25519, 0x05, "ssh:work", byteArrayOf(1, 2), byteArrayOf(3)),
        )

        val request = HelperProtocol.readRequest(ByteArrayInputStream(out.toByteArray()))

        assertThat(request.operation).isEqualTo(HelperProtocol.OP_SIGN)
        assertThat(request.algorithm).isEqualTo(HelperProtocol.ALG_ED25519)
        assertThat(request.flags).isEqualTo(0x05)
        assertThat(request.application).isEqualTo("ssh:work")
        assertThat(request.message).isEqualTo(byteArrayOf(1, 2))
        assertThat(request.handle).isEqualTo(byteArrayOf(3))
    }

    @Test
    fun `malformed or oversized requests are refused`() {
        val valid = ByteArrayOutputStream().also {
            HelperProtocol.writeRequest(it, HelperProtocol.Request(1, 0, 1, "ssh:", ByteArray(32), ByteArray(0)))
        }.toByteArray()
        val badMagic = valid.copyOf().also { it[0] = 'X'.code.toByte() }
        val badOperation = valid.copyOf().also { it[5] = 9 }
        val hugeApplication = valid.copyOf().also { it[11] = 0x10 }

        for (request in listOf(badMagic, badOperation, hugeApplication, valid.copyOf(valid.size - 1))) {
            assertThrows<Exception> { HelperProtocol.readRequest(ByteArrayInputStream(request)) }
        }
    }

    @Test
    fun `responses carry the layout the library reads`() {
        val signed = ByteArrayOutputStream().also {
            HelperProtocol.writeResponse(it, HelperProtocol.Response.Signed(0x1d, 7, byteArrayOf(1), byteArrayOf(2, 3)))
        }.toByteArray()
        val failed = ByteArrayOutputStream().also {
            HelperProtocol.writeResponse(it, HelperProtocol.Response.Failed(HelperProtocol.ERR_DEVICE_NOT_FOUND))
        }.toByteArray()

        val data = DataInputStream(ByteArrayInputStream(signed))
        assertThat(String(ByteArray(4).also(data::readFully))).isEqualTo("PQSK")
        assertThat(data.readUnsignedByte()).isEqualTo(1)
        assertThat(data.readInt()).isEqualTo(0)
        assertThat(data.readUnsignedByte()).isEqualTo(HelperProtocol.OP_SIGN)
        assertThat(data.readUnsignedByte()).isEqualTo(0x1d)
        assertThat(data.readInt()).isEqualTo(7)
        assertThat(data.readInt()).isEqualTo(1)
        data.readByte()
        assertThat(data.readInt()).isEqualTo(2)
        assertThat(failed.copyOfRange(5, 9)).isEqualTo(byteArrayOf(-1, -1, -1, -4))
        assertThat(failed).hasLength(9)
    }

    @Test
    fun `the terminal code decodes back to the FIDO text`() {
        val text = "FIDO:/" + "1234567890".repeat(20)

        val decoded = Decoder().decode(TerminalPrompt.matrix(text, margin = 0)).text
        val rendered = TerminalPrompt.render(TerminalPrompt.matrix(text, margin = 2))
        val lines = rendered.trimEnd('\n').split('\n')

        assertThat(decoded).isEqualTo(text)
        assertThat(lines).hasSize((TerminalPrompt.matrix(text, margin = 2).height + 1) / 2)
        assertThat(lines.all { it.startsWith("\u001b[30;47m") && it.endsWith("\u001b[0m") }).isTrue()
    }

    @Test
    fun `BlueZ service data is read whether dbus-java gives a list or an array`() {
        val advert = ByteArray(20) { it.toByte() }

        assertThat(BluezAdverts.serviceDataBytes(advert.toList())).isEqualTo(advert)
        assertThat(BluezAdverts.serviceDataBytes(advert)).isEqualTo(advert)
        assertThat(BluezAdverts.serviceDataBytes(listOf<Any>(1, "x"))).isNull()
        assertThat(BluezAdverts.serviceDataBytes("not bytes")).isNull()
    }

    @Test
    fun `the listed keys carry the layout the library reads`() {
        val out = ByteArrayOutputStream().also {
            HelperProtocol.writeResponse(
                it,
                HelperProtocol.Response.Listed(
                    listOf(HelperProtocol.Response.Listed.Key(1, "ssh:", 0x25, ByteArray(32), ByteArray(16), ByteArray(0))),
                ),
            )
        }
        val data = DataInputStream(ByteArrayInputStream(out.toByteArray()))
        data.skipBytes(5)

        assertThat(data.readInt()).isEqualTo(0)
        assertThat(data.readUnsignedByte()).isEqualTo(HelperProtocol.OP_LIST)
        assertThat(data.readInt()).isEqualTo(1)
        assertThat(data.readInt()).isEqualTo(1)
        assertThat(data.readInt()).isEqualTo(4)
        data.skipBytes(4)
        assertThat(data.readUnsignedByte()).isEqualTo(0x25)
        assertThat(data.readInt()).isEqualTo(32)
    }

    @Test
    fun `the window shows a code any scanner reads`() {
        val text = "FIDO:/" + "9876543210".repeat(15)
        val image = WindowPrompt.image(TerminalPrompt.matrix(text, margin = 4), 6)
        val pixels = IntArray(image.width * image.height)
        image.getRGB(0, 0, image.width, image.height, pixels, 0, image.width)
        val bitmap = com.google.zxing.BinaryBitmap(
            com.google.zxing.common.HybridBinarizer(com.google.zxing.RGBLuminanceSource(image.width, image.height, pixels)),
        )

        assertThat(com.google.zxing.qrcode.QRCodeReader().decode(bitmap).text).isEqualTo(text)
    }
}
