package com.pqvault.core.hybrid

import com.google.common.truth.Truth.assertThat
import com.pqvault.core.model.CoseAlgorithm
import com.pqvault.core.model.PasskeyEntry
import com.pqvault.core.webauthn.AuthenticatorData
import com.pqvault.core.webauthn.SoftwareAuthenticator
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.math.BigInteger
import java.security.Signature

/** The computer's requests answered by the phone's own code, as they meet in the tunnel. */
class Ctap2ClientTest {
    private val authenticator = SoftwareAuthenticator()
    private val challenge = AuthenticatorData.sha256("challenge".toByteArray())

    private fun enrol(
        algorithm: CoseAlgorithm,
        application: String = "ssh:",
        resident: Boolean = false,
        credentialProtection: Int? = null,
        verified: Boolean = true,
    ): Pair<ByteArray, PasskeyEntry> {
        val request = Ctap2Protocol.parse(
            Ctap2Client.makeCredential(application, challenge, ByteArray(32), algorithm, resident, credentialProtection),
        ) as Ctap2Protocol.Request.MakeCredential
        val admission = RemoteRequestPolicy.admit(request, emptyList(), verificationAvailable = true)
        val chosen = (admission as RemoteRequestPolicy.Creation.Allowed).algorithm
        val registration = authenticator.makeCredential(
            rpId = request.rpId,
            rpName = request.rpName,
            userHandle = request.userHandle,
            userName = request.userName,
            userDisplayName = request.userDisplayName,
            clientDataHash = request.clientDataHash,
            algorithm = chosen,
            userVerified = verified,
            credentialProtection = request.credentialProtection,
            discoverable = request.residentKey,
            selfAttestation = true,
        )
        return Ctap2Protocol.makeCredentialResponse(registration) to registration.entry
    }

    @Test
    fun `requests decode on the phone with the options OpenSSH asks for`() {
        val creation = Ctap2Protocol.parse(
            Ctap2Client.makeCredential("ssh:work", challenge, ByteArray(32) { 7 }, CoseAlgorithm.EDDSA, true, 3),
        ) as Ctap2Protocol.Request.MakeCredential
        val login = Ctap2Protocol.parse(
            Ctap2Client.getAssertion("ssh:work", challenge, byteArrayOf(1, 2, 3)),
        ) as Ctap2Protocol.Request.GetAssertion

        assertThat(creation.rpId).isEqualTo("ssh:work")
        assertThat(creation.offeredAlgorithms).containsExactly(-8)
        assertThat(creation.residentKey).isTrue()
        assertThat(creation.userVerification).isTrue()
        assertThat(creation.credentialProtection).isEqualTo(3)
        assertThat(creation.userHandle).isEqualTo(ByteArray(32) { 7 })
        assertThat(login.allowedCredentialIds.single()).isEqualTo(byteArrayOf(1, 2, 3))
        assertThat(login.userVerification).isTrue()
        assertThat(login.userPresence).isTrue()
        assertThrows<IllegalArgumentException> {
            Ctap2Client.getAssertion("github.com", challenge, byteArrayOf(1))
        }
    }

    @Test
    fun `an ECDSA key is enrolled and its signature is what sshd checks`() {
        val (response, entry) = enrol(CoseAlgorithm.ES256)
        val credential = Ctap2Client.parseCredential(response, "ssh:", challenge, CoseAlgorithm.ES256, null)
        val data = "session data".toByteArray()
        val signed = authenticator.getAssertion(entry, AuthenticatorData.sha256(data))
        val assertion = Ctap2Client.parseAssertion(
            Ctap2Protocol.getAssertionResponse(signed, signed.updatedEntry, includeUser = false, includeIdentifyingInformation = true),
            "ssh:",
            credential.credentialId,
        )
        val (r, s) = Ctap2Client.ecdsaComponents(assertion.signature)

        val sshdMessage = AuthenticatorData.sha256("ssh:".toByteArray()) + byteArrayOf(assertion.flags.toByte()) +
            byteArrayOf(0, 0, 0, assertion.counter.toByte()) + AuthenticatorData.sha256(data)
        val valid = Signature.getInstance("SHA256withECDSA").run {
            initVerify(HybridCrypto.decodeUncompressed(credential.publicKey))
            update(sshdMessage)
            verify(assertion.signature)
        }

        assertThat(credential.publicKey).hasLength(65)
        assertThat(valid).isTrue()
        assertThat(assertion.counter).isEqualTo(1)
        assertThat(BigInteger(1, r).signum()).isEqualTo(1)
        assertThat(r.first()).isNotEqualTo(0.toByte())
        assertThat(s.first()).isNotEqualTo(0.toByte())
    }

    @Test
    fun `an Ed25519 resident key keeps its credProtect level and signs`() {
        val (response, entry) = enrol(CoseAlgorithm.EDDSA, "ssh:work", resident = true, credentialProtection = 2)
        val credential = Ctap2Client.parseCredential(response, "ssh:work", challenge, CoseAlgorithm.EDDSA, 2)
        val data = AuthenticatorData.sha256("session".toByteArray())
        val signed = authenticator.getAssertion(entry, data)
        val assertion = Ctap2Client.parseAssertion(
            Ctap2Protocol.getAssertionResponse(signed, signed.updatedEntry, includeUser = false, includeIdentifyingInformation = true),
            "ssh:work",
            credential.credentialId,
        )
        val valid = Ed25519Signer().run {
            init(false, Ed25519PublicKeyParameters(credential.publicKey, 0))
            update(signed.authenticatorData, 0, signed.authenticatorData.size)
            update(data, 0, data.size)
            verifySignature(assertion.signature)
        }

        assertThat(credential.publicKey).hasLength(32)
        assertThat(assertion.signature).hasLength(64)
        assertThat(valid).isTrue()
    }

    @Test
    fun `an answer without user verification is refused by the computer`() {
        val (response, entry) = enrol(CoseAlgorithm.ES256, verified = false)
        val unverified = authenticator.getAssertion(entry, challenge, userVerified = false)

        assertThrows<IllegalArgumentException> {
            Ctap2Client.parseCredential(response, "ssh:", challenge, CoseAlgorithm.ES256, null)
        }
        assertThrows<IllegalArgumentException> {
            Ctap2Client.parseAssertion(
                Ctap2Protocol.getAssertionResponse(unverified, entry, includeUser = false, includeIdentifyingInformation = false),
                "ssh:",
                java.util.Base64.getUrlDecoder().decode(entry.credentialId),
            )
        }
    }

    @Test
    fun `answers for another application, key or extension set are refused`() {
        val (response, _) = enrol(CoseAlgorithm.ES256, credentialProtection = 2)
        val (plain, entry) = enrol(CoseAlgorithm.ES256)
        val signed = authenticator.getAssertion(entry, challenge)
        val signedResponse = Ctap2Protocol.getAssertionResponse(signed, entry, includeUser = false, includeIdentifyingInformation = true)

        assertThrows<IllegalArgumentException> {
            Ctap2Client.parseCredential(plain, "ssh:other", challenge, CoseAlgorithm.ES256, null)
        }
        assertThrows<IllegalArgumentException> {
            Ctap2Client.parseCredential(response, "ssh:", challenge, CoseAlgorithm.ES256, null)
        }
        assertThrows<IllegalArgumentException> {
            Ctap2Client.parseCredential(plain, "ssh:", challenge, CoseAlgorithm.ES256, 2)
        }
        assertThrows<IllegalArgumentException> {
            Ctap2Client.parseCredential(plain, "ssh:", ByteArray(32), CoseAlgorithm.ES256, null)
        }
        assertThrows<IllegalArgumentException> {
            Ctap2Client.parseCredential(plain, "ssh:", challenge, CoseAlgorithm.EDDSA, null)
        }
        assertThrows<IllegalArgumentException> {
            Ctap2Client.parseAssertion(signedResponse, "ssh:", ByteArray(32))
        }
        assertThrows<IllegalArgumentException> {
            Ctap2Client.parseAssertion(signedResponse, "ssh:other", java.util.Base64.getUrlDecoder().decode(entry.credentialId))
        }
    }

    @Test
    fun `a refusal from the phone surfaces its CTAP status`() {
        val failure = assertThrows<Ctap2Client.Failure> {
            Ctap2Client.parseAssertion(
                Ctap2Protocol.error(Ctap2Protocol.STATUS_NO_CREDENTIALS),
                "ssh:",
                byteArrayOf(1),
            )
        }

        assertThat(failure.status).isEqualTo(Ctap2Protocol.STATUS_NO_CREDENTIALS)
    }

    @Test
    fun `the phone's post-handshake message tells whether it can verify`() {
        assertThat(Ctap2Client.parseInfo(Ctap2Protocol.postHandshakeMessage(true)).userVerification).isTrue()
        assertThat(Ctap2Client.parseInfo(Ctap2Protocol.postHandshakeMessage(false)).userVerification).isFalse()
    }

    @Test
    fun `the resident SSH key list travels intact and website passkeys stay home`() {
        val (_, resident) = enrol(CoseAlgorithm.EDDSA, "ssh:work", resident = true, credentialProtection = 3)
        val (_, plain) = enrol(CoseAlgorithm.ES256)
        val website = authenticator.makeCredential(
            rpId = "example.com", rpName = null, userHandle = byteArrayOf(1), userName = "alice",
            userDisplayName = null, clientDataHash = challenge,
        ).entry

        assertThat(Ctap2Protocol.parse(Ctap2Client.listSshKeys())).isEqualTo(Ctap2Protocol.Request.ListSshKeys)
        val keys = Ctap2Client.parseSshKeyList(
            Ctap2Protocol.sshKeyListResponse(RemoteRequestPolicy.residentSshKeys(listOf(resident, plain, website))),
        )

        val key = keys.single()
        assertThat(key.application).isEqualTo("ssh:work")
        assertThat(key.algorithm).isEqualTo(CoseAlgorithm.EDDSA)
        assertThat(key.credentialId).isEqualTo(java.util.Base64.getUrlDecoder().decode(resident.credentialId))
        assertThat(key.publicKey).isEqualTo(com.pqvault.core.ssh.OpenSshKeys.rawPublicKey(resident))
        assertThat(key.userId).isEqualTo(ByteArray(32))
        assertThat(key.credentialProtection).isEqualTo(3)
    }

    @Test
    fun `a list naming a website or a broken key is refused`() {
        val website = authenticator.makeCredential(
            rpId = "example.com", rpName = null, userHandle = byteArrayOf(1), userName = "alice",
            userDisplayName = null, clientDataHash = challenge,
        ).entry

        assertThrows<IllegalArgumentException> {
            Ctap2Client.parseSshKeyList(Ctap2Protocol.sshKeyListResponse(listOf(website)))
        }
        assertThat(Ctap2Client.parseSshKeyList(Ctap2Protocol.sshKeyListResponse(emptyList()))).isEmpty()
        assertThrows<IllegalArgumentException> {
            Ctap2Protocol.parse(byteArrayOf(Ctap2Protocol.COMMAND_LIST_SSH_KEYS.toByte(), 0))
        }
    }
}
