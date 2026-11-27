package com.pqvault.core.hybrid

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.Number
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import java.io.ByteArrayOutputStream
import java.security.PublicKey

/** The digit-encoded `FIDO:/` QR format used by hybrid WebAuthn, read and written. */
object FidoQrCode {
    private const val PREFIX = "FIDO:/"
    private const val CHUNK_DIGITS = 17
    private const val CHUNK_BYTES = 7
    private val remainderBytes = mapOf(0 to 0, 3 to 1, 5 to 2, 8 to 3, 10 to 4, 13 to 5, 15 to 6)
    private const val KNOWN_TUNNEL_DOMAINS = 2L

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
        val bytes = digitsToBytes(encoded)
        CborBounds.check(bytes)
        val root = CborDecoder.decode(bytes).single() as Map

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

    /** The code a computer shows for one request, carrying its identity key and a fresh secret. */
    fun encode(
        identity: PublicKey,
        secret: ByteArray,
        requestType: RequestType,
        nowSeconds: Long = System.currentTimeMillis() / 1000,
    ): String {
        require(secret.size == 16)
        val map = Map()
            .put(UnsignedInteger(0), ByteString(HybridCrypto.compressP256(identity)))
            .put(UnsignedInteger(1), ByteString(secret))
            .put(UnsignedInteger(2), UnsignedInteger(KNOWN_TUNNEL_DOMAINS))
            .put(UnsignedInteger(3), UnsignedInteger(nowSeconds))
            .put(UnsignedInteger(4), SimpleValue.FALSE)
            .put(UnsignedInteger(5), UnicodeString(if (requestType == RequestType.MakeCredential) "mc" else "ga"))
        val bytes = ByteArrayOutputStream().also { CborEncoder(it).encode(map) }.toByteArray()
        return PREFIX + bytesToDigits(bytes)
    }

    internal fun bytesToDigits(bytes: ByteArray): String {
        val digitsForBytes = remainderBytes.entries.associate { (digits, count) -> count to digits }
        val output = StringBuilder()
        var offset = 0
        while (offset < bytes.size) {
            val count = minOf(CHUNK_BYTES, bytes.size - offset)
            var value = 0L
            for (index in count - 1 downTo 0) value = (value shl 8) or (bytes[offset + index].toLong() and 0xff)
            val width = if (count == CHUNK_BYTES) CHUNK_DIGITS else digitsForBytes.getValue(count)
            output.append(value.toString().padStart(width, '0'))
            offset += count
        }
        return output.toString()
    }

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
