package com.pqvault.core.crypto

import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

/**
 * XChaCha20-Poly1305 as specified by draft-irtf-cfrg-xchacha-03.
 *
 * The extended 192-bit nonce is what makes this safe here: the vault master key is
 * long-lived and re-used on every save, so a 96-bit random nonce would put us on the
 * wrong side of the birthday bound. With 192 bits, random nonces never collide in
 * practice and we never have to maintain a counter across devices, which we could
 * not do reliably anyway, since two devices may save while both are offline.
 */
object XChaCha20Poly1305 {

    const val KEY_SIZE = 32
    const val NONCE_SIZE = 24
    const val TAG_SIZE = 16

    fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == KEY_SIZE) { "key must be $KEY_SIZE bytes, was ${key.size}" }
        require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes, was ${nonce.size}" }

        val subKey = hChaCha20(key, nonce.copyOfRange(0, 16))
        val innerNonce = innerNonce(nonce)
        try {
            val cipher = ChaCha20Poly1305()
            cipher.init(true, AEADParameters(KeyParameter(subKey), TAG_SIZE * 8, innerNonce, aad))
            val out = ByteArray(cipher.getOutputSize(plaintext.size))
            val n = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
            cipher.doFinal(out, n)
            return out
        } finally {
            subKey.fill(0)
        }
    }

    /** Returns null when authentication fails, rather than throwing, so callers cannot
     *  accidentally treat a forged vault as a corrupt one and "recover" from it. */
    fun open(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray? {
        require(key.size == KEY_SIZE) { "key must be $KEY_SIZE bytes, was ${key.size}" }
        require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes, was ${nonce.size}" }
        if (ciphertext.size < TAG_SIZE) return null

        val subKey = hChaCha20(key, nonce.copyOfRange(0, 16))
        val innerNonce = innerNonce(nonce)
        return try {
            val cipher = ChaCha20Poly1305()
            cipher.init(false, AEADParameters(KeyParameter(subKey), TAG_SIZE * 8, innerNonce, aad))
            val out = ByteArray(cipher.getOutputSize(ciphertext.size))
            val n = cipher.processBytes(ciphertext, 0, ciphertext.size, out, 0)
            cipher.doFinal(out, n)
            out
        } catch (e: org.bouncycastle.crypto.InvalidCipherTextException) {
            null
        } finally {
            subKey.fill(0)
        }
    }

    /** ChaCha20-Poly1305 takes a 96-bit nonce: four zero bytes then the last 8 of ours. */
    private fun innerNonce(nonce: ByteArray): ByteArray =
        ByteArray(4) + nonce.copyOfRange(16, 24)

    /**
     * HChaCha20 key-derivation function. Runs the ChaCha20 core over key+nonce and
     * returns words 0..3 and 12..15, crucially *without* the feed-forward addition
     * that ChaCha20 proper performs, which is what makes the output a PRF suitable
     * for use as a subkey.
     */
    internal fun hChaCha20(key: ByteArray, nonce16: ByteArray): ByteArray {
        require(key.size == 32) { "key must be 32 bytes" }
        require(nonce16.size == 16) { "nonce must be 16 bytes" }

        val s = IntArray(16)
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574
        for (i in 0 until 8) s[4 + i] = leInt(key, i * 4)
        for (i in 0 until 4) s[12 + i] = leInt(nonce16, i * 4)

        repeat(10) {
            quarterRound(s, 0, 4, 8, 12)
            quarterRound(s, 1, 5, 9, 13)
            quarterRound(s, 2, 6, 10, 14)
            quarterRound(s, 3, 7, 11, 15)
            quarterRound(s, 0, 5, 10, 15)
            quarterRound(s, 1, 6, 11, 12)
            quarterRound(s, 2, 7, 8, 13)
            quarterRound(s, 3, 4, 9, 14)
        }

        val out = ByteArray(32)
        for (i in 0 until 4) putLeInt(out, i * 4, s[i])
        for (i in 0 until 4) putLeInt(out, 16 + i * 4, s[12 + i])
        return out
    }

    private fun quarterRound(s: IntArray, a: Int, b: Int, c: Int, d: Int) {
        s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] xor s[a], 16)
        s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] xor s[c], 12)
        s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] xor s[a], 8)
        s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] xor s[c], 7)
    }

    private fun leInt(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xff) or
            ((b[off + 1].toInt() and 0xff) shl 8) or
            ((b[off + 2].toInt() and 0xff) shl 16) or
            ((b[off + 3].toInt() and 0xff) shl 24)

    private fun putLeInt(b: ByteArray, off: Int, v: Int) {
        b[off] = v.toByte()
        b[off + 1] = (v ushr 8).toByte()
        b[off + 2] = (v ushr 16).toByte()
        b[off + 3] = (v ushr 24).toByte()
    }
}
