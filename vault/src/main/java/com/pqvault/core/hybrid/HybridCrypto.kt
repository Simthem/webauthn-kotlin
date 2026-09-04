package com.pqvault.core.hybrid

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.params.KeyParameter

/** Cryptographic building blocks used by the FIDO hybrid transport. */
object HybridCrypto {
    private val p256: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
    }

    fun sha256(vararg inputs: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        inputs.forEach(digest::update)
        return digest.digest()
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(data)
        }

    /** RFC 5869 HKDF-SHA256, with the exact empty-salt semantics used by caBLE. */
    fun hkdf(
        inputKeyMaterial: ByteArray,
        salt: ByteArray = ByteArray(0),
        info: ByteArray = ByteArray(0),
        length: Int,
    ): ByteArray {
        require(length in 1..(255 * 32))
        val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
        val pseudorandomKey = hmacSha256(effectiveSalt, inputKeyMaterial)
        val output = ByteArray(length)
        var previous = ByteArray(0)
        var written = 0
        var counter = 1
        while (written < length) {
            previous = hmacSha256(
                pseudorandomKey,
                previous + info + byteArrayOf(counter.toByte()),
            )
            val count = minOf(previous.size, length - written)
            previous.copyInto(output, written, 0, count)
            written += count
            counter++
        }
        return output
    }

    /** Derivation shared by EID, tunnel ID, and handshake PSK generation. */
    fun derive(secret: ByteArray, salt: ByteArray = ByteArray(0), purpose: Int, length: Int): ByteArray {
        require(purpose in 0..255)
        return hkdf(
            inputKeyMaterial = secret,
            salt = salt,
            info = byteArrayOf(purpose.toByte(), 0, 0, 0),
            length = length,
        )
    }

    /**
     * One AES block, which is what the CTAP hybrid transport specifies for the BLE
     * advert's EID.
     *
     * This uses the raw block cipher rather than `Cipher.getInstance("AES/ECB/NoPadding")`
     * because the raw block cipher is what is meant. ECB is a *mode*: it is the rule for
     * chaining many blocks, and it is dangerous precisely because that rule leaks which
     * blocks repeat. With a single block there is no chaining and no mode, so asking the
     * JCA for one described the operation inaccurately and every scanner that reads the
     * transformation string was right to say so.
     *
     * The size is enforced rather than assumed, so this cannot quietly grow into real ECB
     * later: a second block would throw instead of being encrypted independently.
     */
    fun aesEncryptBlock(key: ByteArray, plaintext: ByteArray): ByteArray {
        require(plaintext.size == AES_BLOCK_SIZE) {
            "the hybrid advert is a single AES block, was ${plaintext.size} bytes"
        }
        val engine = AESEngine.newInstance()
        engine.init(true, KeyParameter(key))
        return ByteArray(AES_BLOCK_SIZE).also { engine.processBlock(plaintext, 0, it, 0) }
    }

    private const val AES_BLOCK_SIZE = 16

    fun aesGcmEncrypt(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        associatedData: ByteArray = ByteArray(0),
    ): ByteArray = Cipher.getInstance("AES/GCM/NoPadding").run {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        if (associatedData.isNotEmpty()) updateAAD(associatedData)
        doFinal(plaintext)
    }

    fun aesGcmDecrypt(
        key: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        associatedData: ByteArray = ByteArray(0),
    ): ByteArray = Cipher.getInstance("AES/GCM/NoPadding").run {
        init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        if (associatedData.isNotEmpty()) updateAAD(associatedData)
        doFinal(ciphertext)
    }

    fun generateP256KeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }

    fun ecdh(privateKey: java.security.PrivateKey, publicKey: PublicKey): ByteArray =
        KeyAgreement.getInstance("ECDH").run {
            init(privateKey)
            doPhase(publicKey, true)
            generateSecret()
        }.fixedWidth(32)

    fun encodeUncompressed(publicKey: PublicKey): ByteArray {
        val point = (publicKey as ECPublicKey).w
        return byteArrayOf(4) + point.affineX.toByteArray().fixedWidth(32) +
            point.affineY.toByteArray().fixedWidth(32)
    }

    fun decodeUncompressed(bytes: ByteArray): PublicKey {
        require(bytes.size == 65 && bytes[0] == 4.toByte()) { "invalid uncompressed P-256 point" }
        val point = ECPoint(
            BigInteger(1, bytes.copyOfRange(1, 33)),
            BigInteger(1, bytes.copyOfRange(33, 65)),
        )
        require(isOnP256(point)) { "P-256 point is not on the curve" }
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, p256))
    }

    fun decompressP256(bytes: ByteArray): PublicKey {
        require(bytes.size == 33 && (bytes[0] == 2.toByte() || bytes[0] == 3.toByte())) {
            "invalid compressed P-256 point"
        }
        val x = BigInteger(1, bytes.copyOfRange(1, 33))
        val prime = (p256.curve.field as java.security.spec.ECFieldFp).p
        require(x < prime) { "P-256 x coordinate is out of range" }
        val a = p256.curve.a
        val b = p256.curve.b
        val ySquared = x.modPow(BigInteger.valueOf(3), prime)
            .add(a.multiply(x))
            .add(b)
            .mod(prime)
        var y = ySquared.modPow(prime.add(BigInteger.ONE).shiftRight(2), prime)
        require(y.multiply(y).mod(prime) == ySquared) { "compressed point has no P-256 solution" }
        val odd = bytes[0] == 3.toByte()
        if (y.testBit(0) != odd) y = prime.subtract(y)
        val point = ECPoint(x, y)
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, p256))
    }

    private fun isOnP256(point: ECPoint): Boolean {
        val prime = (p256.curve.field as java.security.spec.ECFieldFp).p
        if (point.affineX.signum() < 0 || point.affineX >= prime ||
            point.affineY.signum() < 0 || point.affineY >= prime
        ) return false
        val left = point.affineY.modPow(BigInteger.TWO, prime)
        val right = point.affineX.modPow(BigInteger.valueOf(3), prime)
            .add(p256.curve.a.multiply(point.affineX))
            .add(p256.curve.b)
            .mod(prime)
        return left == right
    }

    private fun ByteArray.fixedWidth(width: Int): ByteArray = when {
        size == width -> this
        size == width + 1 && first() == 0.toByte() -> copyOfRange(1, size)
        size < width -> ByteArray(width - size) + this
        else -> copyOfRange(size - width, size)
    }
}
