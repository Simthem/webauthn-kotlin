package com.pqvault.app.sync

import com.pqvault.core.sync.WebDavClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Credentials
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * WebDAV over OkHttp, aimed at Nextcloud but not specific to it.
 *
 * The base URL is the collection the vault lives in, e.g.
 * `https://cloud.example.org/remote.php/dav/files/simon/Passkeys`.
 *
 * Use a Nextcloud *app password* rather than the account password: it is scoped, it can
 * be revoked from the web UI without changing the account password, and it survives
 * two-factor authentication being enabled.
 */
class OkHttpWebDavClient(
    private val baseUrl: String,
    private val username: String,
    private val appPassword: String,
    client: OkHttpClient? = null,
) : WebDavClient {

    private val http: OkHttpClient = client ?: OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        // Every request carries the app password in an HTTP Basic header. A server that
        // answers with a redirect to http:// would have OkHttp replay that header in
        // clear text by default, so the downgrade is refused outright. Ordinary
        // https-to-https redirects are still followed.
        .followSslRedirects(false)
        .build()

    private val authorization = Credentials.basic(username, appPassword)

    /**
     * Joins the base URL and the vault path.
     *
     * The path is a single file name from settings, so a `..` in it would walk out of the
     * collection the user pointed us at and let a mistyped setting overwrite something
     * else in their cloud. Segments are kept, traversal is not.
     */
    private fun urlFor(path: String): String {
        val safe = path.split('/')
            .filter { it.isNotEmpty() && it != "." && it != ".." }
            .joinToString("/")
        return baseUrl.trimEnd('/') + "/" + safe
    }

    override suspend fun get(path: String, knownEtag: String?): WebDavClient.GetResult =
        withContext(Dispatchers.IO) {
            val request = Request.Builder()
                .url(urlFor(path))
                .header("Authorization", authorization)
                .apply { knownEtag?.let { header("If-None-Match", quoteEtag(it)) } }
                .get()
                .build()
            try {
                http.newCall(request).execute().use { response ->
                    when {
                        response.code == 404 -> WebDavClient.GetResult.NotFound
                        // 304 means our cached copy is current. The engine still wants
                        // bytes to merge against, so we re-fetch unconditionally rather
                        // than inventing an "unchanged" state it cannot act on.
                        response.code == 304 -> refetch(path)
                        response.isSuccessful -> WebDavClient.GetResult.Found(
                            bytes = response.body?.bytes() ?: ByteArray(0),
                            etag = normaliseEtag(response.header("ETag")),
                        )
                        else -> WebDavClient.GetResult.Error("HTTP ${response.code} ${response.message}")
                    }
                }
            } catch (e: IOException) {
                WebDavClient.GetResult.Error(e.message ?: "network error", e)
            }
        }

    private fun refetch(path: String): WebDavClient.GetResult {
        val request = Request.Builder()
            .url(urlFor(path))
            .header("Authorization", authorization)
            .get()
            .build()
        return try {
            http.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    WebDavClient.GetResult.Found(
                        bytes = response.body?.bytes() ?: ByteArray(0),
                        etag = normaliseEtag(response.header("ETag")),
                    )
                } else {
                    WebDavClient.GetResult.Error("HTTP ${response.code} ${response.message}")
                }
            }
        } catch (e: IOException) {
            WebDavClient.GetResult.Error(e.message ?: "network error", e)
        }
    }

    override suspend fun put(
        path: String,
        bytes: ByteArray,
        ifMatch: String?,
        ifNoneMatchAny: Boolean,
    ): WebDavClient.PutResult = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(urlFor(path))
            .header("Authorization", authorization)
            .apply {
                // Stored unquoted for comparison, but the header must carry quotes.
                ifMatch?.let { header("If-Match", quoteEtag(it)) }
                if (ifNoneMatchAny) header("If-None-Match", "*")
            }
            .put(bytes.toRequestBody("application/octet-stream".toMediaType()))
            .build()
        try {
            http.newCall(request).execute().use { response ->
                when {
                    // 412 is the conditional request failing; 409 is Nextcloud's answer
                    // when the parent collection does not exist yet.
                    response.code == 412 -> WebDavClient.PutResult.PreconditionFailed
                    response.isSuccessful -> WebDavClient.PutResult.Success(
                        normaliseEtag(response.header("ETag")),
                    )
                    else -> WebDavClient.PutResult.Error("HTTP ${response.code} ${response.message}")
                }
            }
        } catch (e: IOException) {
            WebDavClient.PutResult.Error(e.message ?: "network error", e)
        }
    }

    override suspend fun mkcol(path: String): Boolean = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(urlFor(path))
            .header("Authorization", authorization)
            .method("MKCOL", null)
            .build()
        try {
            http.newCall(request).execute().use { response ->
                // 405 Method Not Allowed is what servers return when it already exists,
                // which for our purposes is success.
                response.isSuccessful || response.code == 405
            }
        } catch (e: IOException) {
            false
        }
    }

    /**
     * Strips the weak-comparison prefix and surrounding quotes. Nextcloud returns quoted
     * ETags and echoes them back unquoted in some proxy setups, so comparing raw header
     * values leads to spurious 412s.
     */
    private fun normaliseEtag(raw: String?): String? =
        raw?.removePrefix("W/")?.trim('"')?.takeIf { it.isNotEmpty() }

    /** Re-adds the quoting that [normaliseEtag] stripped, as the header syntax requires. */
    private fun quoteEtag(etag: String): String =
        if (etag.startsWith("\"")) etag else "\"" + etag + "\""
}
