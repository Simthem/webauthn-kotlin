package com.pqvault.core.hybrid

import java.security.PublicKey

/** Noise KNpsk0 responder and post-handshake record protection for FIDO hybrid. */
class CableNoise private constructor(
    private val readKey: ByteArray,
    private val writeKey: ByteArray,
) {
    private var readSequence = 0
    private var writeSequence = 0

    data class Handshake(val response: ByteArray, val transport: CableNoise, val handshakeHash: ByteArray)

    fun encrypt(plaintext: ByteArray): ByteArray {
        require(writeSequence < (1 shl 24)) { "hybrid write sequence exhausted" }
        val zeroCount = (32 - ((plaintext.size + 1) % 32)) % 32
        val padded = plaintext + ByteArray(zeroCount) + byteArrayOf(zeroCount.toByte())
        return HybridCrypto.aesGcmEncrypt(writeKey, transportNonce(writeSequence++), padded)
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        require(readSequence < (1 shl 24)) { "hybrid read sequence exhausted" }
        val padded = HybridCrypto.aesGcmDecrypt(readKey, transportNonce(readSequence++), ciphertext)
        require(padded.isNotEmpty()) { "empty hybrid record" }
        val zeroCount = padded.last().toInt() and 0xff
        require(zeroCount + 1 <= padded.size) { "invalid hybrid padding" }
        require(padded.copyOfRange(padded.size - zeroCount - 1, padded.size - 1).all { it == 0.toByte() }) {
            "invalid hybrid padding bytes"
        }
        return padded.copyOfRange(0, padded.size - zeroCount - 1)
    }

    companion object {
        private const val PROTOCOL_NAME = "Noise_KNpsk0_P256_AESGCM_SHA256"

        /** Responds to the desktop's single KNpsk0 handshake message. */
        fun respond(psk: ByteArray, peerIdentity: PublicKey, message: ByteArray): Handshake {
            require(psk.size == 32)
            require(message.size == 81) { "invalid hybrid handshake length" }
            val peerEphemeralBytes = message.copyOfRange(0, 65)
            val peerEphemeral = HybridCrypto.decodeUncompressed(peerEphemeralBytes)
            val state = NoiseState(PROTOCOL_NAME)
            state.mixHash(byteArrayOf(1))
            state.mixHash(HybridCrypto.encodeUncompressed(peerIdentity))
            state.mixKeyAndHash(psk)
            state.mixHash(peerEphemeralBytes)
            state.mixKey(peerEphemeralBytes)
            require(state.decryptAndHash(message.copyOfRange(65, message.size)).isEmpty())

            val ephemeral = HybridCrypto.generateP256KeyPair()
            val publicBytes = HybridCrypto.encodeUncompressed(ephemeral.public)
            state.mixHash(publicBytes)
            state.mixKey(publicBytes)
            state.mixKey(HybridCrypto.ecdh(ephemeral.private, peerEphemeral))
            state.mixKey(HybridCrypto.ecdh(ephemeral.private, peerIdentity))
            val ciphertext = state.encryptAndHash(ByteArray(0))
            val (readKey, writeKey) = state.split()
            return Handshake(
                response = publicBytes + ciphertext,
                transport = CableNoise(readKey, writeKey),
                handshakeHash = state.handshakeHash(),
            )
        }

        private fun transportNonce(sequence: Int) = ByteArray(12).also {
            it[8] = (sequence ushr 24).toByte()
            it[9] = (sequence ushr 16).toByte()
            it[10] = (sequence ushr 8).toByte()
            it[11] = sequence.toByte()
        }
    }
}

private class NoiseState(protocolName: String) {
    private var chainingKey = ByteArray(32).also {
        protocolName.toByteArray(Charsets.US_ASCII).copyInto(it, endIndex = minOf(32, protocolName.length))
    }
    private var hash = chainingKey.copyOf()
    private var symmetricKey = ByteArray(32)
    private var symmetricNonce = 0

    fun mixHash(input: ByteArray) {
        hash = HybridCrypto.sha256(hash, input)
    }

    fun mixKey(input: ByteArray) {
        val output = HybridCrypto.hkdf(input, chainingKey, length = 64)
        chainingKey = output.copyOfRange(0, 32)
        initialiseKey(output.copyOfRange(32, 64))
    }

    fun mixKeyAndHash(input: ByteArray) {
        val output = HybridCrypto.hkdf(input, chainingKey, length = 96)
        chainingKey = output.copyOfRange(0, 32)
        mixHash(output.copyOfRange(32, 64))
        initialiseKey(output.copyOfRange(64, 96))
    }

    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val ciphertext = HybridCrypto.aesGcmEncrypt(
            symmetricKey,
            handshakeNonce(symmetricNonce++),
            plaintext,
            hash,
        )
        mixHash(ciphertext)
        return ciphertext
    }

    fun decryptAndHash(ciphertext: ByteArray): ByteArray {
        val plaintext = HybridCrypto.aesGcmDecrypt(
            symmetricKey,
            handshakeNonce(symmetricNonce++),
            ciphertext,
            hash,
        )
        mixHash(ciphertext)
        return plaintext
    }

    fun split(): Pair<ByteArray, ByteArray> {
        val output = HybridCrypto.hkdf(ByteArray(0), chainingKey, length = 64)
        return output.copyOfRange(0, 32) to output.copyOfRange(32, 64)
    }

    fun handshakeHash() = hash.copyOf()

    private fun initialiseKey(key: ByteArray) {
        symmetricKey = key
        symmetricNonce = 0
    }

    private fun handshakeNonce(sequence: Int) = ByteArray(12).also {
        // caBLE's Noise construction predates the final transport nonce layout.
        it[0] = (sequence ushr 24).toByte()
        it[1] = (sequence ushr 16).toByte()
        it[2] = (sequence ushr 8).toByte()
        it[3] = sequence.toByte()
    }
}
