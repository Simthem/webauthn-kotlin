package com.pqvault.core.hybrid

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class HybridCryptoTest {
    /**
     * The block encryption behind the BLE advert's EID moved from
     * `Cipher.getInstance("AES/ECB/NoPadding")` to a raw block cipher, because a single
     * block has no mode. This pins the result against NIST SP 800-38A F.1.5
     * (ECB-AES256.Encrypt, block 1), so the change is provably a change of wording and
     * not of output: any drift makes the advert unreadable by the browser on the other
     * side, which no unit test would otherwise catch.
     */
    @Test
    fun `a single block matches the NIST AES-256 vector`() {
        val key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        val plaintext = hex("6bc1bee22e409f96e93d7e117393172a")

        assertThat(HybridCrypto.aesEncryptBlock(key, plaintext))
            .isEqualTo(hex("f3eed1bdb5d2a03c064b5a7e3db181f8"))
    }

    /**
     * The size check is the guard that keeps this a block cipher call rather than ECB
     * mode: a second block must fail loudly instead of being encrypted independently.
     */
    @Test
    fun `more than one block is refused rather than chained`() {
        val key = ByteArray(32)

        assertThrows<IllegalArgumentException> {
            HybridCrypto.aesEncryptBlock(key, ByteArray(32))
        }
        assertThrows<IllegalArgumentException> {
            HybridCrypto.aesEncryptBlock(key, ByteArray(15))
        }
    }

    private fun hex(value: String): ByteArray =
        ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
