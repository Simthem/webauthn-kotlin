package com.pqvault.app.provider

import android.content.pm.SigningInfo
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.credentials.provider.CallingAppInfo
import com.pqvault.core.format.Base64Url
import java.security.MessageDigest

/**
 * Works out the WebAuthn `origin` to put in clientDataJSON, and refuses callers that
 * cannot justify the one they claim.
 *
 * This matters more than it looks. The origin is what binds an assertion to the site it
 * was meant for. Get it wrong and a malicious app can ask us to sign an assertion that a
 * relying party will happily accept as coming from its own web origin, the attack
 * passkeys are supposed to make impossible.
 *
 * Two kinds of caller:
 *
 * - A **browser** passes an origin of its own ("https://github.com"), because it is
 *   relaying a request from a web page. We may only believe it if the browser is on a
 *   privileged allowlist, verified by package name *and* signing certificate. Otherwise
 *   any app could claim to be a browser.
 * - A **native app** passes nothing, and the origin is derived from its own signing
 *   certificate: `android:apk-key-hash:<base64url sha-256>`.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CallerVerifier(private val privilegedAllowlist: String?) {

    sealed class Result {
        class Trusted(
            val origin: String,
            /** base64url SHA-256, the form used inside an apk-key-hash origin. */
            val certificateFingerprint: String,
            /** Colon-separated uppercase hex, the form assetlinks.json uses. */
            val certificateFingerprintHex: String,
            /**
             * Every certificate the OS has proven this caller is entitled to use, current
             * one first, in assetlinks.json's hex form. An app that has rotated its
             * signing key may be listed by a site under either the old or the new
             * certificate, and both are equally authorised, so the statement check tries
             * them all rather than only [certificateFingerprintHex].
             */
            val certificateFingerprintsHex: List<String>,
            val packageName: String,
            /** True when an allowlisted browser is relaying a real web origin. */
            val isPrivilegedBrowser: Boolean,
        ) : Result()

        /** The caller claimed a web origin but is not an allowlisted browser. */
        class Rejected(val reason: String) : Result()
    }

    fun verify(callingAppInfo: CallingAppInfo): Result {
        val digests = signingDigests(callingAppInfo.signingInfo)
        if (digests.isEmpty()) {
            return Result.Rejected("cannot read the caller's signing certificate")
        }
        val fingerprint = Base64Url.encode(digests.first())
        val fingerprintsHex = digests.map { digest -> digest.joinToString(":") { "%02X".format(it) } }

        if (!callingAppInfo.isOriginPopulated()) {
            // An ordinary app. Its origin is its own identity; nothing to validate.
            return Result.Trusted(
                origin = "android:apk-key-hash:$fingerprint",
                certificateFingerprint = fingerprint,
                certificateFingerprintHex = fingerprintsHex.first(),
                certificateFingerprintsHex = fingerprintsHex,
                packageName = callingAppInfo.packageName,
                isPrivilegedBrowser = false,
            )
        }

        // The caller claims to speak for a web origin. Fail closed if we have no
        // allowlist to check it against: an unverified claim is worth nothing.
        val allowlist = privilegedAllowlist
            ?: return Result.Rejected(
                "${callingAppInfo.packageName} claims a web origin but no browser is trusted",
            )

        val origin = try {
            callingAppInfo.getOrigin(allowlist)
        } catch (e: IllegalStateException) {
            // Thrown when the caller is not in the allowlist or its signature mismatches.
            null
        } catch (e: IllegalArgumentException) {
            null
        }

        return origin?.let {
            Result.Trusted(
                origin = it,
                certificateFingerprint = fingerprint,
                certificateFingerprintHex = fingerprintsHex.first(),
                certificateFingerprintsHex = fingerprintsHex,
                packageName = callingAppInfo.packageName,
                isPrivilegedBrowser = true,
            )
        }
            ?: Result.Rejected(
                "${callingAppInfo.packageName} is not a trusted browser",
            )
    }

    /**
     * SHA-256 of every signing certificate the OS vouches for, current signer first.
     *
     * [SigningInfo.getSigningCertificateHistory] returns a rotation lineage ordered oldest
     * to newest, so the *last* entry is the certificate the app is signed with today and
     * the one a relying party will have been told about. Taking the first instead would
     * hand back the certificate the developer rotated away from, and every origin and
     * statement check for a rotated app would be made against the wrong key. Apps with
     * several concurrent signers have no lineage and no ordering, so those come back as
     * they are.
     */
    private fun signingDigests(signingInfo: SigningInfo): List<ByteArray> {
        val ordered = if (signingInfo.hasMultipleSigners()) {
            signingInfo.apkContentsSigners?.toList().orEmpty()
        } else {
            signingInfo.signingCertificateHistory?.toList().orEmpty().asReversed()
        }
        val sha256 = MessageDigest.getInstance("SHA-256")
        return ordered.map { sha256.digest(it.toByteArray()) }
    }
}
