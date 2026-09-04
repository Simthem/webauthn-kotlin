package com.pqvault.core.sync

/**
 * An in-memory WebDAV server that honours ETags and conditional requests.
 *
 * Real Nextcloud cannot be made to race on demand, so [onBeforePut] exists to inject a
 * competing write in the exact window between our GET and our PUT, the only moment
 * where the optimistic-concurrency logic can actually go wrong.
 */
class FakeWebDavServer {

    private class Stored(val bytes: ByteArray, val etag: String)

    private val files = mutableMapOf<String, Stored>()
    private var etagCounter = 0

    var getCount = 0
        private set
    var putCount = 0
        private set
    var conflictCount = 0
        private set

    /** Runs just before a PUT's precondition is evaluated, to simulate another writer. */
    var onBeforePut: (() -> Unit)? = null

    fun writeDirectly(path: String, bytes: ByteArray) {
        files[path] = Stored(bytes, nextEtag())
    }

    fun read(path: String): ByteArray? = files[path]?.bytes

    fun etagOf(path: String): String? = files[path]?.etag

    private fun nextEtag(): String = "etag-${++etagCounter}"

    val client: WebDavClient = object : WebDavClient {

        override suspend fun get(path: String, knownEtag: String?): WebDavClient.GetResult {
            getCount++
            val stored = files[path] ?: return WebDavClient.GetResult.NotFound
            return WebDavClient.GetResult.Found(stored.bytes.copyOf(), stored.etag)
        }

        override suspend fun put(
            path: String,
            bytes: ByteArray,
            ifMatch: String?,
            ifNoneMatchAny: Boolean,
        ): WebDavClient.PutResult {
            putCount++
            onBeforePut?.invoke()

            val existing = files[path]
            if (ifNoneMatchAny && existing != null) {
                conflictCount++
                return WebDavClient.PutResult.PreconditionFailed
            }
            if (ifMatch != null && existing?.etag != ifMatch) {
                conflictCount++
                return WebDavClient.PutResult.PreconditionFailed
            }
            val etag = nextEtag()
            files[path] = Stored(bytes.copyOf(), etag)
            return WebDavClient.PutResult.Success(etag)
        }

        override suspend fun mkcol(path: String): Boolean = true
    }
}
