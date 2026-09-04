package com.pqvault.app.provider

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import java.io.IOException
import java.util.concurrent.TimeUnit

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
 */
class AssetLinksValidator(
    client: OkHttpClient? = null,
    private val clock: () -> Long = System::currentTimeMillis,
) {

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
         * The statement file could not be fetched. Deliberately distinct from [Denied]:
         * an offline phone must not permanently lock the user out of their own passkeys,
         * so the caller decides how much to trust a credential it already holds.
         */
        class Unavailable(val reason: String) : Result()
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

        val key = "$rpId|$packageName|$certificateFingerprintHex"
        cache[key]?.let { cached ->
            val ttl = if (cached.allowed) CACHE_TTL_MS else DENIED_CACHE_TTL_MS
            if (clock() - cached.fetchedAt < ttl) {
                return@withContext if (cached.allowed) {
                    Result.Allowed
                } else {
                    Result.Denied("$packageName is not declared by $rpId")
                }
            }
        }

        val request = Request.Builder()
            .url("https://$rpId/.well-known/assetlinks.json")
            .get()
            .build()

        val body = try {
            http.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    return@withContext Result.Unavailable("HTTP ${response.code} from $rpId")
                }
                // A statement file is a few kilobytes. Capping the read stops a hostile
                // or broken host from feeding us an endless body until the app dies.
                response.body?.source()?.let { source ->
                    source.request(MAX_BODY_BYTES + 1)
                    if (source.buffer.size > MAX_BODY_BYTES) {
                        return@withContext Result.Unavailable("assetlinks.json on $rpId is too large")
                    }
                    source.buffer.readUtf8()
                }
            }
        } catch (e: IOException) {
            return@withContext Result.Unavailable(e.message ?: "network unavailable")
        } ?: return@withContext Result.Unavailable("empty response from $rpId")

        val allowed = try {
            isDeclared(JSONArray(body), packageName, certificateFingerprintHex)
        } catch (e: org.json.JSONException) {
            return@withContext Result.Unavailable("unreadable assetlinks.json on $rpId")
        }

        cache[key] = Entry(allowed, clock())
        if (allowed) Result.Allowed else Result.Denied("$packageName is not declared by $rpId")
    }

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

    private companion object {
        const val LOGIN_RELATION = "delegate_permission/common.get_login_creds"

        /**
         * Positive answers are cached for a day; a refusal only for a few minutes. They
         * are not symmetrical: a stale "yes" merely delays noticing a revocation, while a
         * stale "no" locks a user out of an app that has just been added to the site's
         * statement file, with nothing they can do but wait.
         */
        const val CACHE_TTL_MS = 24 * 60 * 60 * 1000L
        const val DENIED_CACHE_TTL_MS = 5 * 60 * 1000L
        const val MAX_BODY_BYTES = 512L * 1024L

        val HOSTNAME = Regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
    }
}
