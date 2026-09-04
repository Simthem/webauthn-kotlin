package com.pqvault.core.hybrid

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.Number
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import java.security.PublicKey

/** Decoder for the digit-encoded `FIDO:/` QR format used by hybrid WebAuthn. */
object FidoQrCode {
    private const val PREFIX = "FIDO:/"
    private const val CHUNK_DIGITS = 17
    private const val CHUNK_BYTES = 7
    private val remainderBytes = mapOf(0 to 0, 3 to 1, 5 to 2, 8 to 3, 10 to 4, 13 to 5, 15 to 6)

    data class Payload(
        val peerIdentity: PublicKey,
        val peerIdentityUncompressed: ByteArray,
        val secret: ByteArray,
        val knownTunnelDomains: Int,
        val requestTypeHint: RequestType,
        val supportsWebSocket: Boolean,
    )

    enum class RequestType { GetAssertion, MakeCredential, Other }

    fun parse(text: String): Payload? = runCatching {
        require(text.length <= 4096)
        require(text.regionMatches(0, PREFIX, 0, PREFIX.length, ignoreCase = true))
        val encoded = text.substring(PREFIX.length)
        val root = CborDecoder.decode(digitsToBytes(encoded)).single() as Map

        val compressedKey = (root.integer(0) as? ByteString)?.bytes
            ?: throw IllegalArgumentException("missing QR public key")
        val secret = (root.integer(1) as? ByteString)?.bytes
            ?: throw IllegalArgumentException("missing QR secret")
        require(secret.size == 16)
        val publicKey = HybridCrypto.decompressP256(compressedKey)

        val knownDomains = (root.integer(2) as? Number)?.value?.toInt() ?: 0
        val hint = (root.integer(5) as? UnicodeString)?.string
        val transports = (root.integer(6) as? Array)?.dataItems
            ?.mapNotNull { (it as? Number)?.value?.toInt() }
        Payload(
            peerIdentity = publicKey,
            peerIdentityUncompressed = HybridCrypto.encodeUncompressed(publicKey),
            secret = secret.copyOf(),
            knownTunnelDomains = knownDomains,
            requestTypeHint = when (hint) {
                "mc" -> RequestType.MakeCredential
                "ga", null -> RequestType.GetAssertion
                else -> RequestType.Other
            },
            supportsWebSocket = transports == null || 0 in transports,
        )
    }.getOrNull()

    /** Reverses the seven-byte to seventeen-digit little-endian QR encoding. */
    internal fun digitsToBytes(digits: String): ByteArray {
        require(digits.isNotEmpty() && digits.all(Char::isDigit))
        val remainderDigits = digits.length % CHUNK_DIGITS
        val trailingBytes = remainderBytes[remainderDigits]
            ?: throw IllegalArgumentException("invalid FIDO digit count")
        val output = ArrayList<Byte>((digits.length / CHUNK_DIGITS) * CHUNK_BYTES + trailingBytes)
        var offset = 0
        while (digits.length - offset >= CHUNK_DIGITS) {
            appendLittleEndian(digits.substring(offset, offset + CHUNK_DIGITS), CHUNK_BYTES, output)
            offset += CHUNK_DIGITS
        }
        if (trailingBytes > 0) appendLittleEndian(digits.substring(offset), trailingBytes, output)
        return output.toByteArray()
    }

    private fun appendLittleEndian(decimal: String, byteCount: Int, output: MutableList<Byte>) {
        var value = decimal.toLong()
        require(value >= 0 && (value ushr (byteCount * 8)) == 0L) { "FIDO digit chunk overflows" }
        repeat(byteCount) {
            output += value.toByte()
            value = value ushr 8
        }
    }

    private fun Map.integer(key: Long) = get(UnsignedInteger(key))
}
