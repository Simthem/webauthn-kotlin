package com.pqvault.app.provider

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.net.toUri
import java.security.MessageDigest

/**
 * Lists the browsers installed on the device, with the signing fingerprint the caller
 * verifier will actually see.
 *
 * A browser has to be trusted explicitly because it declares a web origin on behalf of a
 * page, and nothing stops a hostile app from claiming to be one. Making the user write
 * that trust list by hand, in Google's privileged-app JSON format, with fingerprints
 * extracted through keytool, is a good way to guarantee nobody ever configures it. So we
 * enumerate the candidates ourselves and let the user tick the ones they recognise.
 */
object InstalledBrowsers {

    class Browser(
        val packageName: String,
        val label: String,
        /** Colon-separated uppercase hex, the form the allowlist uses. */
        val fingerprint: String,
        /** True when this is the user's currently selected default browser. */
        val isDefault: Boolean,
    )

    /**
     * Anything that can open an https URL. That deliberately over-collects: some entries
     * will be a webview shell or a link handler rather than a real browser, which is
     * exactly why the user picks rather than us guessing.
     */
    fun detect(context: Context): List<Browser> {
        val packageManager = context.packageManager
        val probe = Intent(Intent.ACTION_VIEW, "https://example.com".toUri())

        val resolved = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.queryIntentActivities(
                probe,
                PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_ALL.toLong()),
            )
        } else {
            @Suppress("DEPRECATION")
            packageManager.queryIntentActivities(probe, PackageManager.MATCH_ALL)
        }

        val defaultPackage = packageManager.resolveActivity(
            probe,
            PackageManager.MATCH_DEFAULT_ONLY,
        )?.activityInfo?.packageName

        return resolved
            .map { it.activityInfo.packageName }
            .distinct()
            .filter { it != context.packageName }
            .mapNotNull { packageName ->
                fingerprintOf(context, packageName)?.let { fingerprint ->
                    Browser(
                        packageName = packageName,
                        label = labelOf(context, packageName) ?: packageName,
                        fingerprint = fingerprint,
                        isDefault = packageName == defaultPackage,
                    )
                }
            }
            .sortedWith(compareByDescending<Browser> { it.isDefault }.thenBy { it.label.lowercase() })
    }

    private fun labelOf(context: Context, packageName: String): String? = try {
        val info = context.packageManager.getApplicationInfo(packageName, 0)
        context.packageManager.getApplicationLabel(info).toString()
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    private fun fingerprintOf(context: Context, packageName: String): String? = try {
        val packageManager = context.packageManager
        val info = packageManager.getPackageInfo(
            packageName,
            PackageManager.GET_SIGNING_CERTIFICATES,
        )
        val signingInfo = info.signingInfo
        val signatures = when {
            signingInfo == null -> null
            signingInfo.hasMultipleSigners() -> signingInfo.apkContentsSigners
            else -> signingInfo.signingCertificateHistory
        }
        signatures?.firstOrNull()?.let { signature ->
            MessageDigest.getInstance("SHA-256")
                .digest(signature.toByteArray())
                .joinToString(":") { "%02X".format(it) }
        }
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    /**
     * Builds the allowlist that [CallerVerifier] hands to `CallingAppInfo.getOrigin`.
     * Same shape as Google's privileged-app list, so the platform parser accepts it, but
     * assembled from what the user ticked rather than typed.
     */
    fun buildAllowlist(browsers: List<Browser>): String {
        if (browsers.isEmpty()) return ""
        val apps = browsers.joinToString(",\n") { browser ->
            """
            {
              "type": "android",
              "info": {
                "package_name": "${browser.packageName}",
                "signatures": [
                  { "build": "release", "cert_fingerprint": "${browser.fingerprint}" }
                ]
              }
            }
            """.trimIndent()
        }
        return "{\n  \"apps\": [\n$apps\n  ]\n}"
    }

    /** Package names present in a stored allowlist, so the UI can restore the ticks. */
    fun packagesIn(allowlist: String): Set<String> {
        if (allowlist.isBlank()) return emptySet()
        return Regex("\"package_name\"\\s*:\\s*\"([^\"]+)\"")
            .findAll(allowlist)
            .map { it.groupValues[1] }
            .toSet()
    }
}
