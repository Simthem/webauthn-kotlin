package com.pqvault.app.provider

import com.google.common.truth.Truth.assertThat
import org.json.JSONObject
import org.junit.jupiter.api.Test

class InstalledBrowsersTest {

    @Test
    fun `allowlist uses the exact Android fingerprint field`() {
        val json = InstalledBrowsers.buildAllowlist(
            listOf(
                InstalledBrowsers.Browser(
                    packageName = "org.example.browser",
                    label = "Browser",
                    fingerprints = listOf("AA:BB:CC"),
                    isDefault = true,
                ),
            ),
        )

        val signature = JSONObject(json)
            .getJSONArray("apps")
            .getJSONObject(0)
            .getJSONObject("info")
            .getJSONArray("signatures")
            .getJSONObject(0)

        assertThat(signature.getString("cert_fingerprint_sha256")).isEqualTo("AA:BB:CC")
        assertThat(signature.has("cert_fingerprint")).isFalse()
    }

    @Test
    fun `every current signer is included`() {
        val json = InstalledBrowsers.buildAllowlist(
            listOf(
                InstalledBrowsers.Browser(
                    packageName = "org.example.browser",
                    label = "Browser",
                    fingerprints = listOf("AA:BB", "CC:DD"),
                    isDefault = false,
                ),
            ),
        )

        val signatures = JSONObject(json)
            .getJSONArray("apps")
            .getJSONObject(0)
            .getJSONObject("info")
            .getJSONArray("signatures")

        assertThat(signatures.length()).isEqualTo(2)
        assertThat(signatures.getJSONObject(1).getString("cert_fingerprint_sha256"))
            .isEqualTo("CC:DD")
    }

    @Test
    fun `legacy allowlist is upgraded without changing the trusted fingerprint`() {
        val legacy =
            """{"apps":[{"info":{"cert_fingerprint":"AA:BB"}}]}"""

        val upgraded = InstalledBrowsers.upgradeAllowlist(legacy)

        assertThat(upgraded).contains("\"cert_fingerprint_sha256\":\"AA:BB\"")
        assertThat(upgraded).doesNotContain("\"cert_fingerprint\":")
    }
}
