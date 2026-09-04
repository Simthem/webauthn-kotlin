package com.pqvault.core.crypto

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class Argon2idTest {

    @Test
    fun `the mobile default is a sane working set`() {
        assertThat(Argon2id.MOBILE_DEFAULT.memoryKib).isAtLeast(8 * 1024)
        assertThat(Argon2id.MOBILE_DEFAULT.memoryKib).isAtMost(Argon2id.MAX_MEMORY_KIB)
    }

    @Test
    fun `parameters below the floor are refused`() {
        assertThrows<IllegalArgumentException> { Argon2id.Params(1024, 3, 4) }
        assertThrows<IllegalArgumentException> { Argon2id.Params(64 * 1024, 0, 4) }
        assertThrows<IllegalArgumentException> { Argon2id.Params(64 * 1024, 3, 0) }
    }

    /**
     * The reason the ceiling exists. Cost parameters are read out of a vault header, so a
     * file from a hostile server can name any working set it likes. Honouring a request
     * for terabytes would take the app down every time it tried to open that file, which
     * is a denial of service against someone's passkeys rather than a mere annoyance.
     */
    @Test
    fun `parameters above the ceiling are refused rather than allocated`() {
        assertThrows<IllegalArgumentException> { Argon2id.Params(Int.MAX_VALUE, 3, 4) }
        assertThrows<IllegalArgumentException> {
            Argon2id.Params(64 * 1024, Argon2id.MAX_ITERATIONS + 1, 4)
        }
        assertThrows<IllegalArgumentException> {
            Argon2id.Params(64 * 1024, 3, Argon2id.MAX_PARALLELISM + 1)
        }
    }

    @Test
    fun `the same passphrase and salt derive the same key`() {
        val salt = ByteArray(16) { it.toByte() }
        val cheap = Argon2id.Params(memoryKib = 8 * 1024, iterations = 1, parallelism = 1)

        val first = Argon2id.derive("hunter2".toCharArray(), salt, cheap)
        val second = Argon2id.derive("hunter2".toCharArray(), salt, cheap)
        val other = Argon2id.derive("hunter3".toCharArray(), salt, cheap)

        assertThat(first).isEqualTo(second)
        assertThat(first).isNotEqualTo(other)
    }
}
