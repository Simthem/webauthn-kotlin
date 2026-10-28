package com.pqvault.app.provider

import com.pqvault.core.format.Base64Url
import org.json.JSONException
import org.json.JSONObject
import java.net.URI
import java.net.URISyntaxException

/**
 * The checks made on a Credential Manager request before anything is signed, kept free of
 * Android so they run as plain JVM tests, like [com.pqvault.app.hybrid.HybridApprovalPolicy].
 *
 * The request JSON is written by the calling app. A browser relays what a web page asked
 * for, and any installed app may send whatever it likes, so none of it is trusted to be
 * well formed.
 */
internal object ProviderRequestPolicy {

    /** WebAuthn caps user.id at 64 bytes, and an empty one identifies nobody. */
    private const val MAX_USER_HANDLE_BYTES = 64

    /** Null when the request is not JSON: the caller fails it instead of crashing on it. */
    fun parse(requestJson: String): JSONObject? = try {
        JSONObject(requestJson)
    } catch (_: JSONException) {
        null
    }

    /** Registration nests the relying party id under "rp", authentication carries it at the top level. */
    fun rpIdOf(request: JSONObject): String? =
        request.optJSONObject("rp")?.optString("id")?.takeIf { it.isNotEmpty() }
            ?: request.optString("rpId").takeIf { it.isNotEmpty() }

    /**
     * The passkey chosen in the system sheet has to belong to the site this request is for.
     * The sheet only offers matching entries, so a mismatch means the request reaching the
     * activity is not the one the entries were built from, and nothing gets signed.
     */
    fun targets(request: JSONObject, entryRpId: String): Boolean = rpIdOf(request) == entryRpId

    /**
     * The clientDataJSON hash to sign as the caller gave it, or null when we build that JSON
     * ourselves. Only an allowlisted browser builds it: from any other app, a ready-made hash
     * could name a web origin the app has no claim to, and we would sign for that site.
     */
    fun callerClientDataHash(provided: ByteArray?, privilegedBrowser: Boolean): ByteArray? =
        provided.takeIf { privilegedBrowser }

    /**
     * Whether a web origin relayed by a trusted browser may act for [rpId]: a page may use
     * its own host or one of its parent domains, over HTTPS, or plain HTTP on localhost.
     */
    fun originServes(origin: String, rpId: String): Boolean {
        val uri = try {
            URI(origin)
        } catch (_: URISyntaxException) {
            return false
        }
        val host = uri.host?.lowercase() ?: return false
        val id = rpId.lowercase()
        val secure = uri.scheme == "https" || (uri.scheme == "http" && host == "localhost")
        return secure && uri.rawUserInfo == null && (host == id || host.endsWith(".$id"))
    }

    /**
     * True only when the site insists on user verification. "preferred", the WebAuthn
     * default, still gets a fresh verification whenever the phone can perform one, but
     * does not fail when it cannot.
     */
    fun requiresVerification(request: JSONObject, creating: Boolean): Boolean {
        val preference = if (creating) {
            request.optJSONObject("authenticatorSelection")?.optString("userVerification")
        } else {
            request.optString("userVerification")
        }
        return preference == "required"
    }

    /** The decoded user.id, or null when it is not base64url or outside 1..64 bytes. */
    fun userHandle(user: JSONObject): ByteArray? = try {
        Base64Url.decode(user.optString("id")).takeIf { it.size in 1..MAX_USER_HANDLE_BYTES }
    } catch (_: IllegalArgumentException) {
        null
    }
}
