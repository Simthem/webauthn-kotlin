package com.pqvault.app.provider

import com.google.common.truth.Truth.assertThat
import com.pqvault.app.provider.CredentialEntries.Listing
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.jupiter.api.Test

/**
 * Which callers see the accounts a site has in the vault, before anything is signed. The
 * provider service answers from what it already knows, without the network.
 */
class CredentialListingTest {

    private val current = "AA:BB"
    private val rotated = "CC:DD"
    private var now = 0L

    private fun browser(origin: String) = CallerVerifier.Result.Trusted(
        origin = origin,
        certificateFingerprint = "browser",
        certificateFingerprintHex = "EE:FF",
        certificateFingerprintsHex = listOf("EE:FF"),
        packageName = "org.mozilla.fennec_fdroid",
        isPrivilegedBrowser = true,
    )

    private val app = CallerVerifier.Result.Trusted(
        origin = "android:apk-key-hash:app",
        certificateFingerprint = "app",
        certificateFingerprintHex = current,
        certificateFingerprintsHex = listOf(current, rotated),
        packageName = "com.example.app",
        isPrivilegedBrowser = false,
    )

    /** Serves [statement] as every site's assetlinks.json, without any network. */
    private fun validator(statement: String, status: Int = 200) = AssetLinksValidator(
        client = OkHttpClient.Builder()
            .addInterceptor { chain ->
                Response.Builder()
                    .request(chain.request())
                    .protocol(Protocol.HTTP_1_1)
                    .code(status)
                    .message("test")
                    .body(statement.toResponseBody("application/json".toMediaType()))
                    .build()
            }
            .build(),
        clock = { now },
    )

    private fun declaring(fingerprint: String) = """
        [{"relation": ["delegate_permission/common.get_login_creds"],
          "target": {"namespace": "android_app", "package_name": "com.example.app",
                     "sha256_cert_fingerprints": ["$fingerprint"]}}]
    """.trimIndent()

    @Test
    fun `a browser lists a site only for one of its own pages`() {
        assertThat(ProviderRequestPolicy.originServes("https://github.com", "github.com")).isTrue()
        assertThat(ProviderRequestPolicy.originServes("https://gist.GitHub.com/", "github.com")).isTrue()
        assertThat(ProviderRequestPolicy.originServes("https://notgithub.com", "github.com")).isFalse()
        assertThat(ProviderRequestPolicy.originServes("https://github.com.evil.test", "github.com")).isFalse()
        assertThat(ProviderRequestPolicy.originServes("http://github.com", "github.com")).isFalse()
        assertThat(ProviderRequestPolicy.originServes("https://user@github.com", "github.com")).isFalse()
        assertThat(ProviderRequestPolicy.originServes("http://localhost:3000", "localhost")).isTrue()
        assertThat(ProviderRequestPolicy.originServes("android:apk-key-hash:x", "github.com")).isFalse()
        assertThat(ProviderRequestPolicy.originServes("not a uri", "github.com")).isFalse()

        val links = validator(declaring(current))
        assertThat(CredentialEntries.listing(browser("https://github.com"), "github.com", links))
            .isEqualTo(Listing.ALLOWED)
        assertThat(CredentialEntries.listing(browser("https://evil.test"), "github.com", links))
            .isEqualTo(Listing.DENIED)
    }

    @Test
    fun `a caller that cannot be verified sees nothing`() {
        val links = validator(declaring(current))
        assertThat(CredentialEntries.listing(null, "github.com", links)).isEqualTo(Listing.DENIED)
        assertThat(
            CredentialEntries.listing(CallerVerifier.Result.Rejected("untrusted"), "github.com", links),
        ).isEqualTo(Listing.DENIED)
    }

    @Test
    fun `a native app is undecided until its asset links are known`() = runBlocking {
        val links = validator(declaring(rotated))
        assertThat(CredentialEntries.listing(app, "example.org", links)).isEqualTo(Listing.UNKNOWN)
        // Nothing was fetched by asking: the provider service never reaches the network.
        assertThat(links.cached("example.org", app.packageName, rotated)).isNull()

        // The site lists the app under the certificate it rotated away from.
        assertThat(links.validate("example.org", app.packageName, current))
            .isInstanceOf(AssetLinksValidator.Result.Denied::class.java)
        assertThat(CredentialEntries.listing(app, "example.org", links)).isEqualTo(Listing.UNKNOWN)
        assertThat(links.validate("example.org", app.packageName, rotated))
            .isEqualTo(AssetLinksValidator.Result.Allowed)
        assertThat(CredentialEntries.listing(app, "example.org", links)).isEqualTo(Listing.ALLOWED)
        assertThat(CredentialEntries.listing(app, "other.example", links)).isEqualTo(Listing.UNKNOWN)

        now += 24 * 60 * 60 * 1000L
        assertThat(CredentialEntries.listing(app, "example.org", links)).isEqualTo(Listing.UNKNOWN)
    }

    @Test
    fun `a native app the site does not declare is refused without a prompt`() = runBlocking {
        val links = validator(declaring("00:11"))
        for (fingerprint in app.certificateFingerprintsHex) {
            links.validate("example.org", app.packageName, fingerprint)
        }
        assertThat(CredentialEntries.listing(app, "example.org", links)).isEqualTo(Listing.DENIED)

        // A refusal is only remembered for a few minutes.
        now += 5 * 60 * 1000L
        assertThat(CredentialEntries.listing(app, "example.org", links)).isEqualTo(Listing.UNKNOWN)
    }

    @Test
    fun `an unreachable statement file decides nothing in advance`() = runBlocking {
        val links = validator("", status = 503)
        assertThat(links.validate("example.org", app.packageName, current))
            .isInstanceOf(AssetLinksValidator.Result.Unavailable::class.java)
        assertThat(CredentialEntries.listing(app, "example.org", links)).isEqualTo(Listing.UNKNOWN)
    }

    @Test
    fun `a site without a statement file vouches for no app`() = runBlocking {
        for (status in listOf(404, 410)) {
            val links = validator("", status = status)
            for (fingerprint in app.certificateFingerprintsHex) {
                assertThat(links.validate("example.org", app.packageName, fingerprint))
                    .isInstanceOf(AssetLinksValidator.Result.Denied::class.java)
            }
            assertThat(CredentialEntries.listing(app, "example.org", links)).isEqualTo(Listing.DENIED)
        }
    }
}
