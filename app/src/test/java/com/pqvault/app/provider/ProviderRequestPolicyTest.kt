package com.pqvault.app.provider

import com.google.common.truth.Truth.assertThat
import com.pqvault.core.format.Base64Url
import org.json.JSONObject
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class ProviderRequestPolicyTest {
    private val random = SecureRandom()

    private fun randomBytes(size: Int) = ByteArray(size).also { random.nextBytes(it) }

    private fun signIn(rpId: String? = "example.org", userVerification: String? = null) = JSONObject().apply {
        put("challenge", Base64Url.encode(randomBytes(32)))
        rpId?.let { put("rpId", it) }
        userVerification?.let { put("userVerification", it) }
    }

    private fun creation(userVerification: String? = null, userId: String = Base64Url.encode(randomBytes(16))) =
        JSONObject().apply {
            put("challenge", Base64Url.encode(randomBytes(32)))
            put("rp", JSONObject().put("id", "example.org").put("name", "Example"))
            put("user", JSONObject().put("id", userId).put("name", "alice"))
            userVerification?.let {
                put("authenticatorSelection", JSONObject().put("userVerification", it))
            }
        }

    @Test
    fun `malformed request json is rejected instead of thrown`() {
        assertThat(ProviderRequestPolicy.parse("{not json")).isNull()
        assertThat(ProviderRequestPolicy.parse("")).isNull()
        assertThat(ProviderRequestPolicy.parse("""{"rpId":"example.org"}""")).isNotNull()
    }

    @Test
    fun `relying party id is read from both request shapes`() {
        assertThat(ProviderRequestPolicy.rpIdOf(signIn())).isEqualTo("example.org")
        assertThat(ProviderRequestPolicy.rpIdOf(creation())).isEqualTo("example.org")
        assertThat(ProviderRequestPolicy.rpIdOf(signIn(rpId = null))).isNull()
    }

    @Test
    fun `a passkey is only used for the site the request names`() {
        assertThat(ProviderRequestPolicy.targets(signIn(), "example.org")).isTrue()
        assertThat(ProviderRequestPolicy.targets(signIn(rpId = "evil.test"), "example.org")).isFalse()
        assertThat(ProviderRequestPolicy.targets(signIn(rpId = null), "example.org")).isFalse()
        // Not a suffix match: a subdomain is a different relying party id.
        assertThat(ProviderRequestPolicy.targets(signIn(rpId = "login.example.org"), "example.org")).isFalse()
    }

    @Test
    fun `only an explicit required makes verification mandatory on sign in`() {
        assertThat(ProviderRequestPolicy.requiresVerification(signIn("example.org", "required"), creating = false))
            .isTrue()
        assertThat(ProviderRequestPolicy.requiresVerification(signIn("example.org", "preferred"), creating = false))
            .isFalse()
        assertThat(ProviderRequestPolicy.requiresVerification(signIn("example.org", "discouraged"), creating = false))
            .isFalse()
        assertThat(ProviderRequestPolicy.requiresVerification(signIn(), creating = false)).isFalse()
    }

    @Test
    fun `registration reads the preference from authenticatorSelection`() {
        assertThat(ProviderRequestPolicy.requiresVerification(creation("required"), creating = true)).isTrue()
        assertThat(ProviderRequestPolicy.requiresVerification(creation("preferred"), creating = true)).isFalse()
        assertThat(ProviderRequestPolicy.requiresVerification(creation(), creating = true)).isFalse()
        // A top-level member is not where registration puts it, and is not honoured there.
        val misplaced = creation().put("userVerification", "required")
        assertThat(ProviderRequestPolicy.requiresVerification(misplaced, creating = true)).isFalse()
    }

    @Test
    fun `user handle must decode to between 1 and 64 bytes`() {
        val user = { id: String -> JSONObject().put("id", id) }
        val handle = randomBytes(64)

        assertThat(ProviderRequestPolicy.userHandle(user(Base64Url.encode(handle)))).isEqualTo(handle)
        assertThat(ProviderRequestPolicy.userHandle(user(Base64Url.encode(randomBytes(65))))).isNull()
        assertThat(ProviderRequestPolicy.userHandle(user(""))).isNull()
        assertThat(ProviderRequestPolicy.userHandle(user("not*base64url"))).isNull()
        assertThat(ProviderRequestPolicy.userHandle(JSONObject())).isNull()
    }
}
