package com.pqvault.app.pairing

import com.pqvault.app.data.SecureSettings
import com.pqvault.core.format.Base64Url
import org.json.JSONObject
import java.security.MessageDigest

/**
 * What a pairing QR code carries.
 *
 * Deliberately *not* the passphrase. Someone who photographs the screen over your
 * shoulder must not walk away with the vault; they only get the server coordinates, which
 * are useless without the passphrase that decrypts what is stored there. What the code
 * saves is the tedious part: a long WebDAV URL, a username, and a 40-character app
 * password typed on a phone keyboard.
 *
 * The trust decision made on the first device travels too, as a digest of the signing
 * key rather than the key itself, so the new device inherits it instead of blindly
 * trusting whatever the server hands back.
 *
 * The digest is not an optimisation, it is what makes the code encodable at all. The
 * hybrid Ed25519 + ML-DSA-65 public key is 1984 bytes, which is 2646 characters of
 * base64url and pushed the payload to roughly 3800 characters. A QR code holds 2953 bytes
 * at the very most, so every pairing code this app ever produced failed to encode. A
 * SHA-256 digest is 43 characters and pins just as tightly: the key itself arrives inside
 * the vault header, and the digest is what proves it is the right one.
 */
object PairingPayload {

    const val SCHEME = "pqvault"
    const val HOST = "pair"

    /** 2 carries `sigd`, a key digest, where 1 carried `sig`, the whole unencodable key. */
    private const val VERSION = 2

    /** Short-lived on purpose: a screenshot left in a gallery should not stay usable. */
    const val VALIDITY_MS = 5 * 60 * 1000L

    class Payload(
        val webdavBaseUrl: String,
        val webdavUsername: String,
        val webdavAppPassword: String,
        val remotePath: String,
        /** base64url SHA-256 of the signing public key the other device has pinned. */
        val pinnedSigningKeyDigest: String,
        val expiresAt: Long,
    )

    sealed class ParseResult {
        class Valid(val payload: Payload) : ParseResult()
        object NotAPairingCode : ParseResult()
        object Expired : ParseResult()
    }

    fun encode(settings: SecureSettings.Settings, now: Long = System.currentTimeMillis()): String {
        val json = JSONObject().apply {
            put("v", VERSION)
            put("url", settings.webdavBaseUrl)
            put("user", settings.webdavUsername)
            put("pw", settings.webdavAppPassword)
            put("path", settings.remotePath)
            put("sigd", digestOf(settings))
            put("exp", now + VALIDITY_MS)
        }
        return "$SCHEME://$HOST?d=" + Base64Url.encode(json.toString().toByteArray())
    }

    /**
     * The digest of whichever form of the pinned key this device happens to hold: the key
     * itself once it has opened the vault, or a digest inherited from its own pairing.
     */
    private fun digestOf(settings: SecureSettings.Settings): String = when {
        settings.pinnedSigningKey.isNotEmpty() -> Base64Url.encode(
            MessageDigest.getInstance("SHA-256").digest(Base64Url.decode(settings.pinnedSigningKey)),
        )
        else -> settings.pinnedSigningKeyDigest
    }

    fun decode(text: String, now: Long = System.currentTimeMillis()): ParseResult {
        val prefix = "$SCHEME://$HOST?d="
        if (!text.startsWith(prefix)) return ParseResult.NotAPairingCode

        val json = try {
            JSONObject(String(Base64Url.decode(text.removePrefix(prefix))))
        } catch (e: Exception) {
            return ParseResult.NotAPairingCode
        }

        // Version 1 codes never encoded, so none exist in the wild to stay compatible
        // with; refusing them outright is honest rather than lossy.
        if (json.optInt("v") != VERSION) return ParseResult.NotAPairingCode

        val expiresAt = json.optLong("exp")
        if (expiresAt <= now) return ParseResult.Expired

        return ParseResult.Valid(
            Payload(
                webdavBaseUrl = json.optString("url"),
                webdavUsername = json.optString("user"),
                webdavAppPassword = json.optString("pw"),
                remotePath = json.optString("path").ifEmpty { "vault.pqvault" },
                pinnedSigningKeyDigest = json.optString("sigd"),
                expiresAt = expiresAt,
            ),
        )
    }

    fun applyTo(settings: SecureSettings.Settings, payload: Payload): SecureSettings.Settings =
        settings.copy(
            webdavBaseUrl = payload.webdavBaseUrl,
            webdavUsername = payload.webdavUsername,
            webdavAppPassword = payload.webdavAppPassword,
            remotePath = payload.remotePath,
            // The key itself is not known yet; it arrives with the vault and is pinned
            // once its digest has been checked against what the pairing code carried.
            pinnedSigningKey = "",
            pinnedSigningKeyDigest = payload.pinnedSigningKeyDigest,
            // The new device has seen no version yet, so it must not inherit a counter
            // that would make the server's genuine current file look like a rollback.
            lastSeenVersion = 0,
            localVersion = 0,
            lastSyncEtag = "",
        )
}
