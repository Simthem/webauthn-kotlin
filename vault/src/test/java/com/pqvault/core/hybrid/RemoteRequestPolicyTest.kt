package com.pqvault.core.hybrid

import com.google.common.truth.Truth.assertThat
import com.pqvault.core.format.Base64Url
import com.pqvault.core.model.CoseAlgorithm
import com.pqvault.core.model.PasskeyEntry
import com.pqvault.core.webauthn.SoftwareAuthenticator
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class RemoteRequestPolicyTest {
    private val authenticator = SoftwareAuthenticator()

    private fun creation(
        rpId: String = "ssh:",
        algorithms: List<Int> = listOf(-7),
        residentKey: Boolean = false,
        userVerification: Boolean = false,
        credentialProtection: Int? = null,
        excluded: List<ByteArray> = emptyList(),
    ) = Ctap2Protocol.Request.MakeCredential(
        clientDataHash = ByteArray(32),
        rpId = rpId,
        rpName = null,
        userHandle = ByteArray(32),
        userName = "openssh",
        userDisplayName = "openssh",
        offeredAlgorithms = algorithms,
        excludedCredentialIds = excluded,
        residentKey = residentKey,
        userVerification = userVerification,
        credentialProtection = credentialProtection,
    )

    private fun signIn(
        rpId: String = "ssh:",
        allowed: List<PasskeyEntry> = emptyList(),
        userVerification: Boolean = false,
        userPresence: Boolean = true,
    ) = Ctap2Protocol.Request.GetAssertion(
        rpId = rpId,
        clientDataHash = ByteArray(32),
        allowedCredentialIds = allowed.map { Base64Url.decode(it.credentialId) },
        userVerification = userVerification,
        userPresence = userPresence,
    )

    private fun stored(request: Ctap2Protocol.Request.MakeCredential): PasskeyEntry =
        RemoteRequestPolicy.register(authenticator, request, CoseAlgorithm.ES256, verified = true).entry

    @Test
    fun `an SSH key always needs verification, even when the client does not ask for it`() {
        val request = creation(userVerification = false)

        assertThat(RemoteRequestPolicy.requiresVerification(request)).isTrue()
        assertThat(RemoteRequestPolicy.admit(request, emptyList(), verificationAvailable = false))
            .isEqualTo(RemoteRequestPolicy.Creation.Refused(RemoteRequestPolicy.Refusal.VERIFICATION_UNAVAILABLE))
        assertThat(RemoteRequestPolicy.mayCreate(request, verified = false)).isFalse()
        assertThrows<IllegalStateException> {
            RemoteRequestPolicy.register(authenticator, request, CoseAlgorithm.ES256, verified = false)
        }
    }

    @Test
    fun `an SSH signature is never released without verification`() {
        val key = stored(creation())
        val request = signIn(allowed = listOf(key))

        assertThat(RemoteRequestPolicy.select(request, listOf(key), verificationAvailable = false))
            .isEqualTo(RemoteRequestPolicy.Assertion.Refused(RemoteRequestPolicy.Refusal.VERIFICATION_UNAVAILABLE))
        assertThat(RemoteRequestPolicy.select(request, listOf(key), verificationAvailable = true))
            .isEqualTo(RemoteRequestPolicy.Assertion.Allowed(listOf(key)))
        assertThat(RemoteRequestPolicy.maySign(request, key, verified = false)).isFalse()
        assertThat(RemoteRequestPolicy.maySign(request, key, verified = true)).isTrue()
    }

    @Test
    fun `a silent probe never reaches the user and never gets a signature`() {
        val key = stored(creation())
        val probe = signIn(allowed = listOf(key), userPresence = false)

        assertThat(RemoteRequestPolicy.select(probe, listOf(key), verificationAvailable = true))
            .isEqualTo(RemoteRequestPolicy.Assertion.Refused(RemoteRequestPolicy.Refusal.NO_CREDENTIALS))
        assertThat(RemoteRequestPolicy.maySign(probe, key, verified = true)).isFalse()
    }

    @Test
    fun `an SSH key is created self attested, non resident unless asked, with Ed25519 when only that is offered`() {
        val plain = RemoteRequestPolicy.register(
            authenticator,
            creation(algorithms = listOf(-8)),
            CoseAlgorithm.EDDSA,
            verified = true,
        )
        val resident = stored(creation(residentKey = true, credentialProtection = 2))

        assertThat(RemoteRequestPolicy.admit(creation(algorithms = listOf(-8)), emptyList(), true))
            .isEqualTo(RemoteRequestPolicy.Creation.Allowed(CoseAlgorithm.EDDSA))
        assertThat(plain.attestationFormat).isEqualTo("packed")
        assertThat(plain.entry.discoverable).isFalse()
        assertThat(resident.discoverable).isTrue()
        assertThat(resident.credentialProtection).isEqualTo(2)
    }

    @Test
    fun `a website passkey keeps its existing behaviour`() {
        val request = creation(rpId = "github.com", residentKey = false)
        val registration = RemoteRequestPolicy.register(authenticator, request, CoseAlgorithm.ES256, verified = false)
        val login = signIn(rpId = "github.com")

        assertThat(RemoteRequestPolicy.requiresVerification(request)).isFalse()
        assertThat(registration.attestationFormat).isEqualTo("none")
        assertThat(registration.entry.discoverable).isTrue()
        assertThat(RemoteRequestPolicy.select(login, listOf(registration.entry), verificationAvailable = false))
            .isEqualTo(RemoteRequestPolicy.Assertion.Allowed(listOf(registration.entry)))
        assertThat(RemoteRequestPolicy.maySign(login, registration.entry, verified = false)).isTrue()
    }

    @Test
    fun `credProtect levels hide credentials that need verification the phone cannot give`() {
        val optionalWithId = RemoteRequestPolicy.register(
            authenticator,
            creation(rpId = "example.com", credentialProtection = 2),
            CoseAlgorithm.ES256,
            verified = false,
        ).entry
        val required = RemoteRequestPolicy.register(
            authenticator,
            creation(rpId = "example.com", credentialProtection = 3),
            CoseAlgorithm.ES256,
            verified = true,
        ).entry
        val discovery = signIn(rpId = "example.com")
        val byId = signIn(rpId = "example.com", allowed = listOf(optionalWithId, required))

        assertThat(RemoteRequestPolicy.select(discovery, listOf(optionalWithId, required), false))
            .isEqualTo(RemoteRequestPolicy.Assertion.Refused(RemoteRequestPolicy.Refusal.NO_CREDENTIALS))
        assertThat(RemoteRequestPolicy.select(byId, listOf(optionalWithId, required), false))
            .isEqualTo(RemoteRequestPolicy.Assertion.Allowed(listOf(optionalWithId)))
        assertThat(RemoteRequestPolicy.maySign(byId, required, verified = false)).isFalse()
        assertThat(RemoteRequestPolicy.admit(creation(rpId = "example.com", credentialProtection = 3), emptyList(), false))
            .isEqualTo(RemoteRequestPolicy.Creation.Refused(RemoteRequestPolicy.Refusal.VERIFICATION_UNAVAILABLE))
    }

    @Test
    fun `a non resident SSH key is only offered when the client names it`() {
        val key = stored(creation(residentKey = false))

        assertThat(RemoteRequestPolicy.select(signIn(), listOf(key), true))
            .isEqualTo(RemoteRequestPolicy.Assertion.Refused(RemoteRequestPolicy.Refusal.NO_CREDENTIALS))
        assertThat(RemoteRequestPolicy.select(signIn(allowed = listOf(key)), listOf(key), true))
            .isEqualTo(RemoteRequestPolicy.Assertion.Allowed(listOf(key)))
    }

    @Test
    fun `SSH keys and website passkeys never answer for each other`() {
        val sshKey = stored(creation())
        val passkey = RemoteRequestPolicy.register(
            authenticator,
            creation(rpId = "example.com"),
            CoseAlgorithm.ES256,
            verified = true,
        ).entry
        val sshLogin = signIn(allowed = listOf(sshKey, passkey))
        val webLogin = signIn(rpId = "example.com", allowed = listOf(sshKey, passkey))

        assertThat(RemoteRequestPolicy.select(sshLogin, listOf(sshKey, passkey), true))
            .isEqualTo(RemoteRequestPolicy.Assertion.Allowed(listOf(sshKey)))
        assertThat(RemoteRequestPolicy.select(webLogin, listOf(sshKey, passkey), true))
            .isEqualTo(RemoteRequestPolicy.Assertion.Allowed(listOf(passkey)))
        assertThat(RemoteRequestPolicy.maySign(webLogin, sshKey, verified = true)).isFalse()
    }

    @Test
    fun `an excluded or unsupported registration is refused before the user is asked`() {
        val key = stored(creation())

        assertThat(
            RemoteRequestPolicy.admit(creation(excluded = listOf(Base64Url.decode(key.credentialId))), listOf(key), true),
        ).isEqualTo(RemoteRequestPolicy.Creation.Refused(RemoteRequestPolicy.Refusal.EXCLUDED))
        assertThat(RemoteRequestPolicy.admit(creation(algorithms = listOf(-257)), emptyList(), true))
            .isEqualTo(RemoteRequestPolicy.Creation.Refused(RemoteRequestPolicy.Refusal.NO_ALGORITHM))
    }

    @Test
    fun `only resident SSH keys can be listed, and only after verification`() {
        val resident = stored(creation(residentKey = true))
        val plain = stored(creation(residentKey = false))
        val website = RemoteRequestPolicy.register(
            authenticator, creation(rpId = "example.com", residentKey = true), CoseAlgorithm.ES256, verified = true,
        ).entry

        assertThat(RemoteRequestPolicy.residentSshKeys(listOf(resident, plain, website))).containsExactly(resident)
        assertThat(RemoteRequestPolicy.isSsh(Ctap2Protocol.Request.ListSshKeys)).isTrue()
        assertThat(RemoteRequestPolicy.mayList(verified = false)).isFalse()
        assertThat(RemoteRequestPolicy.mayList(verified = true)).isTrue()
    }
}
