package com.pqvault.app.provider

import android.content.Context
import androidx.core.content.edit
import com.pqvault.core.format.Base64Url
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLException

/**
 * Checks, via Digital Asset Links, that a native app is actually entitled to use a given
 * relying party id.
 *
 * Without this, any app could ask us for a passkey belonging to `github.com` simply by
 * naming it. The site publishes `https://<rpId>/.well-known/assetlinks.json` listing the
 * package names and signing certificates it recognises, and we refuse anything absent
 * from that list.
 *
 * Browsers are exempt: an allowlisted browser has already been verified by
 * [CallerVerifier] and legitimately speaks for many origins.
 *
 * Only an outage leaves the question open: a TLS failure, a redirect, an error status
 * or an unreadable file is a refusal. [Result.Unavailable] says whether the same
 * association was verified within [VERIFIED_GRACE_MS], the only case a caller may let
 * through.
 */
class AssetLinksValidator(
    client: OkHttpClient? = null,
    private val clock: () -> Long = System::currentTimeMillis,
    private val verified: VerifiedAssociations = VerifiedAssociations.InMemory(),
) {

    /** When each association was last verified online, kept across restarts. */
    interface VerifiedAssociations {
        fun verifiedAt(key: String): Long?
        fun record(key: String, at: Long)
        fun forget(key: String)

        class InMemory : VerifiedAssociations {
            private val times = java.util.concurrent.ConcurrentHashMap<String, Long>()
            override fun verifiedAt(key: String) = times[key]
            override fun record(key: String, at: Long) {
                times[key] = at
            }
            override fun forget(key: String) {
                times.remove(key)
            }
        }

        /** Stores digests of the associations, not the site and package names. */
        class Persistent(context: Context) : VerifiedAssociations {
            private val preferences = context.getSharedPreferences("asset_links", Context.MODE_PRIVATE)
            private fun digest(key: String) =
                Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(key.toByteArray()))
            override fun verifiedAt(key: String) =
                preferences.getLong(digest(key), 0L).takeIf { it > 0L }
            override fun record(key: String, at: Long) {
                preferences.edit { putLong(digest(key), at) }
            }
            override fun forget(key: String) {
                preferences.edit { remove(digest(key)) }
            }
        }
    }

    private val http = client ?: OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        // A statement file is an authorisation document, and the only host entitled to
        // publish it is the rpId itself. Following a redirect would let that host hand
        // the decision to somebody else, so a redirect is treated as no answer at all.
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    private class Entry(val allowed: Boolean, val fetchedAt: Long)

    // Validation runs on Dispatchers.IO and two credential requests can overlap, so the
    // cache has to tolerate concurrent access.
    private val cache = java.util.concurrent.ConcurrentHashMap<String, Entry>()

    sealed class Result {
        object Allowed : Result()
        class Denied(val reason: String) : Result()

        /**
         * The site could not be reached. [previouslyVerified] is true when this exact
         * association was verified online less than [VERIFIED_GRACE_MS] ago.
         */
        class Unavailable(val reason: String, val previouslyVerified: Boolean) : Result()
    }

    suspend fun validate(
        rpId: String,
        packageName: String,
        certificateFingerprintHex: String,
    ): Result = withContext(Dispatchers.IO) {
        // The rpId comes from the caller. Anything but a bare hostname could steer the
        // fetch somewhere else entirely: "good.example@evil.test" parses as userinfo plus
        // a host, and we would end up asking evil.test to vouch for good.example.
        if (!isHostname(rpId)) {
            return@withContext Result.Denied("$rpId is not a valid relying party id")
        }

        cached(rpId, packageName, certificateFingerprintHex)?.let { return@withContext it }

        val request = Request.Builder()
            .url("https://$rpId/.well-known/assetlinks.json")
            .get()
            .build()

        val key = key(rpId, packageName, certificateFingerprintHex)
        fun denied(reason: String): Result {
            cache[key] = Entry(false, clock())
            verified.forget(key)
            return Result.Denied(reason)
        }
        fun unavailable(reason: String) = Result.Unavailable(
            reason,
            previouslyVerified = verified.verifiedAt(key)?.let { clock() - it in 0 until VERIFIED_GRACE_MS } == true,
        )

        val body = try {
            http.newCall(request).execute().use { response ->
                when {
                    response.isSuccessful -> Unit
                    response.code >= 500 || response.code == 408 || response.code == 429 ->
                        return@withContext unavailable("HTTP ${response.code} from $rpId")
                    // No statement file, a redirect or a refusal is the site's answer.
                    else -> return@withContext denied("HTTP ${response.code} from $rpId")
                }
                // A statement file is a few kilobytes. Capping the read stops a hostile
                // or broken host from feeding us an endless body until the app dies.
                response.body?.source()?.let { source ->
                    source.request(MAX_BODY_BYTES + 1)
                    if (source.buffer.size > MAX_BODY_BYTES) {
                        return@withContext denied("assetlinks.json on $rpId is too large")
                    }
                    source.buffer.readUtf8()
                }
            }
        } catch (e: SSLException) {
            return@withContext denied("TLS failure with $rpId: ${e.message}")
        } catch (e: IOException) {
            return@withContext unavailable(e.message ?: "network unavailable")
        } ?: return@withContext denied("empty response from $rpId")

        val allowed = try {
            isDeclared(JSONArray(body), packageName, certificateFingerprintHex)
        } catch (e: org.json.JSONException) {
            return@withContext denied("unreadable assetlinks.json on $rpId")
        }
        if (!allowed) return@withContext denied("$packageName is not declared by $rpId")

        cache[key] = Entry(true, clock())
        verified.record(key, clock())
        Result.Allowed
    }

    /**
     * The answer still fresh in the cache, without touching the network, or null when
     * there is none. The credential provider must reply to the system within moments, so this is
     * all it can consult before deciding whether to list a site's accounts.
     */
    fun cached(rpId: String, packageName: String, certificateFingerprintHex: String): Result? {
        val cached = cache[key(rpId, packageName, certificateFingerprintHex)] ?: return null
        val ttl = if (cached.allowed) CACHE_TTL_MS else DENIED_CACHE_TTL_MS
        if (clock() - cached.fetchedAt >= ttl) return null
        return if (cached.allowed) Result.Allowed else Result.Denied("$packageName is not declared by $rpId")
    }

    private fun key(rpId: String, packageName: String, certificateFingerprintHex: String) =
        association(rpId, packageName, certificateFingerprintHex)

    private fun isDeclared(
        statements: JSONArray,
        packageName: String,
        fingerprintHex: String,
    ): Boolean {
        for (i in 0 until statements.length()) {
            val statement = statements.optJSONObject(i) ?: continue

            val relations = statement.optJSONArray("relation") ?: continue
            var hasLoginRelation = false
            for (r in 0 until relations.length()) {
                if (relations.optString(r) == LOGIN_RELATION) hasLoginRelation = true
            }
            if (!hasLoginRelation) continue

            val target = statement.optJSONObject("target") ?: continue
            if (target.optString("namespace") != "android_app") continue
            if (target.optString("package_name") != packageName) continue

            val fingerprints = target.optJSONArray("sha256_cert_fingerprints") ?: continue
            for (f in 0 until fingerprints.length()) {
                if (fingerprints.optString(f).equals(fingerprintHex, ignoreCase = true)) return true
            }
        }
        return false
    }

    /** A bare DNS hostname: labels of letters, digits and hyphens, separated by dots. */
    private fun isHostname(value: String): Boolean =
        value.isNotEmpty() && value.length <= 253 && HOSTNAME.matches(value)

    companion object {
        @Volatile
        private var instance: AssetLinksValidator? = null

        /** The key [VerifiedAssociations] files an association under. */
        internal fun association(rpId: String, packageName: String, certificateFingerprintHex: String) =
            "$rpId|$packageName|$certificateFingerprintHex"

        /** One per process, so that what one request learnt serves the next ones. */
        fun shared(context: Context): AssetLinksValidator = instance ?: synchronized(this) {
            instance ?: AssetLinksValidator(
                verified = VerifiedAssociations.Persistent(context.applicationContext),
            ).also { instance = it }
        }

        /** How long a verified association is still honoured while its site is unreachable. */
        const val VERIFIED_GRACE_MS = 7 * 24 * 60 * 60 * 1000L

        private const val LOGIN_RELATION = "delegate_permission/common.get_login_creds"

        /**
         * Positive answers are cached for a day; a refusal only for a few minutes. They
         * are not symmetrical: a stale "yes" merely delays noticing a revocation, while a
         * stale "no" locks a user out of an app that has just been added to the site's
         * statement file, with nothing they can do but wait.
         */
        private const val CACHE_TTL_MS = 24 * 60 * 60 * 1000L
        private const val DENIED_CACHE_TTL_MS = 5 * 60 * 1000L
        private const val MAX_BODY_BYTES = 512L * 1024L

        private val HOSTNAME = Regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
    }
}
