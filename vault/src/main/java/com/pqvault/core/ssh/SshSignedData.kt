package com.pqvault.core.ssh

import com.pqvault.core.hybrid.HybridCrypto
import java.util.Base64

/**
 * What an OpenSSH client asks a security key to sign, read from the bytes being signed.
 * Once their SHA-256 matches the client data hash, nothing here can differ from what the
 * signature covers.
 */
sealed class SshSignedData {

    /**
     * A user authentication request. [serverHostKey] is the `SHA256:` fingerprint of the
     * host key in a host-bound request, which only that server accepts.
     */
    data class Login(val user: String, val service: String, val serverHostKey: String?) : SshSignedData()

    /** An `ssh-keygen -Y sign` signature, `git` for Git commits and tags. */
    data class Signature(val namespace: String) : SshSignedData()

    companion object {
        const val MAX_SIZE = 16 * 1024
        private const val MAX_TEXT = 256
        private const val USERAUTH_REQUEST = 50
        private val SIGNATURE_MAGIC = "SSHSIG".toByteArray()

        /** Null when [data] is neither a login nor a signature, or carries unprintable text. */
        fun parse(data: ByteArray): SshSignedData? = try {
            if (data.size > MAX_SIZE) {
                null
            } else if (data.size >= SIGNATURE_MAGIC.size &&
                data.copyOfRange(0, SIGNATURE_MAGIC.size).contentEquals(SIGNATURE_MAGIC)
            ) {
                signature(Reader(data, SIGNATURE_MAGIC.size))
            } else {
                login(Reader(data, 0))
            }
        } catch (_: IllegalArgumentException) {
            null
        }

        private fun signature(reader: Reader): Signature {
            val namespace = reader.text()
            reader.bytes()
            reader.text()
            reader.bytes()
            reader.end()
            return Signature(namespace)
        }

        private fun login(reader: Reader): Login {
            reader.bytes()
            require(reader.byte() == USERAUTH_REQUEST)
            val user = reader.text()
            val service = reader.text()
            val method = reader.text()
            require(reader.byte() == 1)
            reader.text()
            reader.bytes()
            val hostKey = when (method) {
                "publickey" -> null
                "publickey-hostbound-v00@openssh.com" -> fingerprint(reader.bytes())
                else -> throw IllegalArgumentException("unknown method")
            }
            reader.end()
            return Login(user, service, hostKey)
        }

        private fun fingerprint(blob: ByteArray) =
            "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(HybridCrypto.sha256(blob))

        /** Text fit for display: bounded, with no control or formatting characters. */
        fun displayable(text: String): Boolean =
            text.length <= MAX_TEXT && text.none { Character.isISOControl(it) || Character.getType(it) == Character.FORMAT.toInt() }
    }

    private class Reader(private val data: ByteArray, private var position: Int) {
        fun byte(): Int {
            require(position < data.size)
            return data[position++].toInt() and 0xff
        }

        fun bytes(): ByteArray {
            require(data.size - position >= 4)
            val length = (byte() shl 24) or (byte() shl 16) or (byte() shl 8) or byte()
            require(length >= 0 && length <= data.size - position)
            return data.copyOfRange(position, position + length).also { position += length }
        }

        fun text(): String {
            val text = String(bytes(), Charsets.UTF_8)
            require(displayable(text))
            return text
        }

        fun end() = require(position == data.size)
    }
}
