package com.pqvault.app.hybrid

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import com.pqvault.core.format.Base64Url
import com.pqvault.core.hybrid.Ctap2Protocol
import com.pqvault.core.hybrid.RemoteRequestPolicy
import com.pqvault.core.model.CoseAlgorithm
import com.pqvault.core.ssh.OpenSshKeys
import com.pqvault.core.webauthn.AuthenticatorData
import com.pqvault.core.webauthn.SoftwareAuthenticator
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/** SSH keys created and used inside the shrunk APK, on the device's own crypto providers. */
@RunWith(AndroidJUnit4::class)
class SshKeyTest {

    private val authenticator = SoftwareAuthenticator()
    private val signedData = AuthenticatorData.sha256("ssh session".toByteArray())

    private fun creation(algorithm: Int) = Ctap2Protocol.Request.MakeCredential(
        clientDataHash = AuthenticatorData.sha256("challenge".toByteArray()),
        rpId = "ssh:",
        rpName = null,
        userHandle = ByteArray(32),
        userName = "openssh",
        userDisplayName = "openssh",
        offeredAlgorithms = listOf(algorithm),
        excludedCredentialIds = emptyList(),
        residentKey = true,
        userVerification = true,
        credentialProtection = 3,
    )

    private fun login(credentialId: String) = Ctap2Protocol.Request.GetAssertion(
        rpId = "ssh:",
        clientDataHash = signedData,
        allowedCredentialIds = listOf(Base64Url.decode(credentialId)),
        userVerification = true,
        userPresence = true,
    )

    @Test
    fun ed25519SshKeySignsAndExports() {
        val registration = RemoteRequestPolicy.register(authenticator, creation(-8), CoseAlgorithm.EDDSA, verified = true)
        val entry = registration.entry
        val assertion = authenticator.getAssertion(entry, signedData)
        val publicKey = PublicKeyFactory.createKey(Base64Url.decode(entry.publicKeySpki)) as Ed25519PublicKeyParameters
        val valid = Ed25519Signer().run {
            init(false, publicKey)
            update(assertion.authenticatorData, 0, assertion.authenticatorData.size)
            update(signedData, 0, signedData.size)
            verifySignature(assertion.signature)
        }

        assertThat(registration.attestationFormat).isEqualTo("packed")
        assertThat(valid).isTrue()
        assertThat(RemoteRequestPolicy.maySign(login(entry.credentialId), entry, verified = false)).isFalse()
        assertThat(OpenSshKeys.authorizedKeysLine(entry, "pq-vault")).startsWith("sk-ssh-ed25519@openssh.com ")
        assertThat(OpenSshKeys.keyFile(entry, "pq-vault")).startsWith("-----BEGIN OPENSSH PRIVATE KEY-----")
        assertThat(RemoteRequestPolicy.residentSshKeys(listOf(entry))).containsExactly(entry)
        assertThat(Ctap2Protocol.sshKeyListResponse(listOf(entry))[0]).isEqualTo(Ctap2Protocol.STATUS_OK.toByte())
        assertThat(OpenSshKeys.verifyRequiredLine(entry, "pq-vault")).startsWith("verify-required sk-ssh-ed25519@openssh.com ")
    }

    @Test
    fun ecdsaSshKeySignsAndExports() {
        val registration = RemoteRequestPolicy.register(authenticator, creation(-7), CoseAlgorithm.ES256, verified = true)
        val entry = registration.entry
        val assertion = authenticator.getAssertion(entry, signedData)
        val publicKey = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(Base64Url.decode(entry.publicKeySpki)))
        val valid = Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(assertion.authenticatorData)
            update(signedData)
            verify(assertion.signature)
        }

        assertThat(valid).isTrue()
        assertThat(OpenSshKeys.fingerprint(entry)).startsWith("SHA256:")
        assertThat(OpenSshKeys.keyFile(entry, "pq-vault")).contains("-----END OPENSSH PRIVATE KEY-----")
    }
}
