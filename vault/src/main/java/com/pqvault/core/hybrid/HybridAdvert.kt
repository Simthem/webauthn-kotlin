package com.pqvault.core.hybrid

import java.security.MessageDigest
import java.security.SecureRandom

/** The 20-byte BLE advert proving the phone is nearby, readable only with the QR secret. */
object HybridAdvert {
    const val SERVICE_DATA_SIZE = 20

    class Sealed(val serviceData: ByteArray, val plaintext: ByteArray)

    class Opened(val plaintext: ByteArray, val routingId: ByteArray, val tunnelDomainId: Int)

    fun seal(
        secret: ByteArray,
        routingId: ByteArray,
        tunnelDomainId: Int = 0,
        random: SecureRandom = SecureRandom(),
    ): Sealed {
        require(secret.size == 16)
        require(routingId.size == 3)
        require(tunnelDomainId in 0..0xffff)
        val plaintext = ByteArray(16)
        ByteArray(10).also(random::nextBytes).copyInto(plaintext, 1)
        routingId.copyInto(plaintext, 11)
        plaintext[14] = tunnelDomainId.toByte()
        plaintext[15] = (tunnelDomainId ushr 8).toByte()

        val keys = keys(secret)
        val ciphertext = HybridCrypto.aesEncryptBlock(keys.copyOfRange(0, 32), plaintext)
        val tag = HybridCrypto.hmacSha256(keys.copyOfRange(32, 64), ciphertext).copyOf(4)
        return Sealed(ciphertext + tag, plaintext)
    }

    /** Null for service data that was not sealed with this QR secret. */
    fun open(secret: ByteArray, serviceData: ByteArray): Opened? {
        if (secret.size != 16 || serviceData.size != SERVICE_DATA_SIZE) return null
        val keys = keys(secret)
        val ciphertext = serviceData.copyOfRange(0, 16)
        val tag = HybridCrypto.hmacSha256(keys.copyOfRange(32, 64), ciphertext).copyOf(4)
        if (!MessageDigest.isEqual(tag, serviceData.copyOfRange(16, 20))) return null
        val plaintext = HybridCrypto.aesDecryptBlock(keys.copyOfRange(0, 32), ciphertext)
        if (plaintext[0] != 0.toByte()) return null
        return Opened(
            plaintext = plaintext,
            routingId = plaintext.copyOfRange(11, 14),
            tunnelDomainId = (plaintext[14].toInt() and 0xff) or ((plaintext[15].toInt() and 0xff) shl 8),
        )
    }

    private fun keys(secret: ByteArray) = HybridCrypto.derive(secret, purpose = 1, length = 64)
}
