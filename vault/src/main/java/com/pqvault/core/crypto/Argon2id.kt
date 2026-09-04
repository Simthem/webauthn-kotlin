package com.pqvault.core.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Argon2id password hashing, used to turn the user passphrase into a key-encryption key.
 *
 * The cost parameters travel inside the vault header rather than being baked in, so a
 * vault written by a desktop today still opens on a phone tomorrow, and so we can raise
 * the defaults over time without orphaning existing files.
 */
object Argon2id {

    /** Tuned for a mid-range phone: roughly 0.5-1s, which is the most we can ask of
     *  someone unlocking their vault to log in to a website. */
    val MOBILE_DEFAULT = Params(memoryKib = 64 * 1024, iterations = 3, parallelism = 4)

    /**
     * Upper bounds, not tuning targets. Cost parameters arrive inside a vault header, so
     * a hostile or corrupt file could otherwise ask us to allocate terabytes and take the
     * app down with it. A phone that legitimately needs more than 1 GiB or 32 passes does
     * not exist, so refusing beyond that costs nothing and removes the denial of service.
     */
    const val MAX_MEMORY_KIB = 1024 * 1024
    const val MAX_ITERATIONS = 32
    const val MAX_PARALLELISM = 64

    data class Params(
        val memoryKib: Int,
        val iterations: Int,
        val parallelism: Int,
    ) {
        init {
            require(memoryKib >= 8 * 1024) { "memoryKib must be at least 8192 (8 MiB), was $memoryKib" }
            require(memoryKib <= MAX_MEMORY_KIB) { "memoryKib must be at most $MAX_MEMORY_KIB, was $memoryKib" }
            require(iterations >= 1) { "iterations must be at least 1, was $iterations" }
            require(iterations <= MAX_ITERATIONS) { "iterations must be at most $MAX_ITERATIONS, was $iterations" }
            require(parallelism >= 1) { "parallelism must be at least 1, was $parallelism" }
            require(parallelism <= MAX_PARALLELISM) { "parallelism must be at most $MAX_PARALLELISM, was $parallelism" }
        }
    }

    fun derive(
        passphrase: CharArray,
        salt: ByteArray,
        params: Params = MOBILE_DEFAULT,
        outputLength: Int = 32,
    ): ByteArray {
        require(salt.size >= 16) { "salt must be at least 16 bytes, was ${salt.size}" }

        val generator = Argon2BytesGenerator()
        generator.init(
            Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(params.memoryKib)
                .withIterations(params.iterations)
                .withParallelism(params.parallelism)
                .build(),
        )
        val out = ByteArray(outputLength)
        generator.generateBytes(passphrase, out)
        return out
    }
}
