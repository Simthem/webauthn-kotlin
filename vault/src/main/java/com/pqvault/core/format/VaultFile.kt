package com.pqvault.core.format

import java.io.ByteArrayOutputStream

/**
 * On-disk framing:
 *
 *   magic[8] = "PQVAULT1"
 *   u32 headerLength  | header   (UTF-8 JSON, cleartext, authenticated)
 *   u32 contentLength | content  (XChaCha20-Poly1305, AAD = everything before it)
 *   u32 sigLength     | signature (hybrid, over everything before it)
 *
 * Lengths are big-endian. Keeping the header in cleartext JSON is deliberate: a future
 * version of the app, or a recovery tool, must be able to see which KDF parameters and
 * recipients a file uses without first being able to decrypt it.
 */
object VaultFile {

    const val FORMAT_VERSION = 1
    val MAGIC: ByteArray = "PQVAULT1".toByteArray(Charsets.US_ASCII)

    /** A file split into its parts, before any cryptography has been checked. */
    class Raw(
        val headerJson: String,
        val content: ByteArray,
        val signature: ByteArray,
        /** magic + header + content, exactly as signed. */
        val signedBytes: ByteArray,
        /** magic + header, exactly as used for the content AAD. */
        val contentAad: ByteArray,
    )

    class MalformedVaultException(message: String) : Exception(message)

    fun encode(headerJson: String, content: ByteArray, signature: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        val headerBytes = headerJson.toByteArray(Charsets.UTF_8)
        out.write(MAGIC)
        out.writeInt(headerBytes.size)
        out.write(headerBytes)
        out.writeInt(content.size)
        out.write(content)
        out.writeInt(signature.size)
        out.write(signature)
        return out.toByteArray()
    }

    /** The bytes the signature must cover, for a given header and content. */
    fun signedBytes(headerJson: String, content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        val headerBytes = headerJson.toByteArray(Charsets.UTF_8)
        out.write(MAGIC)
        out.writeInt(headerBytes.size)
        out.write(headerBytes)
        out.writeInt(content.size)
        out.write(content)
        return out.toByteArray()
    }

    /** The bytes used as AEAD additional data, binding the content to its header. */
    fun contentAad(headerJson: String): ByteArray {
        val out = ByteArrayOutputStream()
        val headerBytes = headerJson.toByteArray(Charsets.UTF_8)
        out.write(MAGIC)
        out.writeInt(headerBytes.size)
        out.write(headerBytes)
        return out.toByteArray()
    }

    fun decode(bytes: ByteArray): Raw {
        var offset = 0

        fun need(n: Int, what: String) {
            if (offset + n > bytes.size) {
                throw MalformedVaultException("truncated vault: needed $n more bytes for $what")
            }
        }

        need(MAGIC.size, "magic")
        if (!bytes.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) {
            throw MalformedVaultException("not a pqvault file (bad magic)")
        }
        offset += MAGIC.size

        need(4, "header length")
        val headerLength = readInt(bytes, offset).also { offset += 4 }
        if (headerLength < 0 || headerLength > MAX_HEADER_BYTES) {
            throw MalformedVaultException("implausible header length $headerLength")
        }
        need(headerLength, "header")
        val headerBytes = bytes.copyOfRange(offset, offset + headerLength).also { offset += headerLength }

        need(4, "content length")
        val contentLength = readInt(bytes, offset).also { offset += 4 }
        if (contentLength < 0 || contentLength > MAX_CONTENT_BYTES) {
            throw MalformedVaultException("implausible content length $contentLength")
        }
        need(contentLength, "content")
        val content = bytes.copyOfRange(offset, offset + contentLength).also { offset += contentLength }

        need(4, "signature length")
        val signatureLength = readInt(bytes, offset).also { offset += 4 }
        if (signatureLength < 0 || signatureLength > MAX_SIGNATURE_BYTES) {
            throw MalformedVaultException("implausible signature length $signatureLength")
        }
        need(signatureLength, "signature")
        val signature = bytes.copyOfRange(offset, offset + signatureLength).also { offset += signatureLength }

        val headerJson = String(headerBytes, Charsets.UTF_8)
        return Raw(
            headerJson = headerJson,
            content = content,
            signature = signature,
            signedBytes = bytes.copyOfRange(0, offset - 4 - signatureLength),
            contentAad = bytes.copyOfRange(0, MAGIC.size + 4 + headerLength),
        )
    }

    // Bounds exist so a hostile file cannot make us allocate gigabytes before any
    // authentication has happened.
    private const val MAX_HEADER_BYTES = 1 shl 20
    private const val MAX_CONTENT_BYTES = 1 shl 26
    private const val MAX_SIGNATURE_BYTES = 1 shl 16

    private fun ByteArrayOutputStream.writeInt(value: Int) {
        write((value ushr 24) and 0xff)
        write((value ushr 16) and 0xff)
        write((value ushr 8) and 0xff)
        write(value and 0xff)
    }

    private fun readInt(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 24) or
            ((bytes[offset + 1].toInt() and 0xff) shl 16) or
            ((bytes[offset + 2].toInt() and 0xff) shl 8) or
            (bytes[offset + 3].toInt() and 0xff)
}
