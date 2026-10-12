package com.pqvault.core.sync

/**
 * The slice of WebDAV the vault actually needs.
 *
 * Kept as an interface so the sync algorithm can be tested against an in-memory server
 * (including the races that are almost impossible to provoke against a real Nextcloud
 * on demand), and so the HTTP stack stays out of this module.
 */
interface WebDavClient {

    sealed class GetResult {
        class Found(val bytes: ByteArray, val etag: String?) : GetResult()
        object NotFound : GetResult()
        class Error(val message: String, val cause: Throwable? = null) : GetResult()
    }

    sealed class PutResult {
        class Success(val etag: String?) : PutResult()

        /**
         * The precondition failed: someone else wrote the file between our read and our
         * write. This is the case that makes optimistic concurrency work, and the reason
         * we never blind-PUT a vault.
         */
        object PreconditionFailed : PutResult()

        class Error(val message: String, val cause: Throwable? = null) : PutResult()
    }

    /** Conditional read. Implementations should send `If-None-Match` when [knownEtag] is set. */
    suspend fun get(path: String, knownEtag: String? = null): GetResult

    /**
     * Conditional write. Exactly one of [ifMatch] (update this exact version) or
     * [ifNoneMatchAny] (create only if absent) should be used.
     */
    suspend fun put(
        path: String,
        bytes: ByteArray,
        ifMatch: String? = null,
        ifNoneMatchAny: Boolean = false,
    ): PutResult

    /** Creates a collection, returning true if it exists afterwards. */
    suspend fun mkcol(path: String): Boolean
}
