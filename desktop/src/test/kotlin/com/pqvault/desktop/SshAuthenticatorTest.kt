package com.pqvault.desktop

import com.google.common.truth.Truth.assertThat
import com.pqvault.core.hybrid.HybridCrypto
import com.pqvault.core.ssh.OpenSshKeys
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.Signature

/** OpenSSH's requests, as the library forwards them, carried end to end to the phone's code. */
class SshAuthenticatorTest {
    private val phone = PhoneSimulator()
    private val authenticator = SshAuthenticator(HybridClient(phone, phone, phone), phone)

    private fun enrol(algorithm: Int, flags: Int = OpenSshKeys.FLAG_USER_PRESENCE_REQUIRED, application: String = "ssh:") =
        authenticator.handle(
            HelperProtocol.Request(
                HelperProtocol.OP_ENROLL, algorithm, flags, application, ByteArray(32) { 5 }, ByteArray(0),
            ),
        )

    private fun sign(algorithm: Int, keyHandle: ByteArray, data: ByteArray, application: String = "ssh:") =
        authenticator.handle(
            HelperProtocol.Request(
                HelperProtocol.OP_SIGN, algorithm, OpenSshKeys.FLAG_USER_PRESENCE_REQUIRED, application, data, keyHandle,
            ),
        )

    /** What sshd rebuilds: SHA-256(application) | flags | counter | SHA-256(data). */
    private fun sshdMessage(application: String, signed: HelperProtocol.Response.Signed, data: ByteArray) =
        HybridCrypto.sha256(application.toByteArray()) + byteArrayOf(signed.flags.toByte()) +
            byteArrayOf(
                (signed.counter ushr 24).toByte(), (signed.counter ushr 16).toByte(),
                (signed.counter ushr 8).toByte(), signed.counter.toByte(),
            ) + HybridCrypto.sha256(data)

    @Test
    fun `an ecdsa-sk key is created on the phone and its login signature verifies like sshd`() {
        val enrolled = enrol(HelperProtocol.ALG_ECDSA) as HelperProtocol.Response.Enrolled
        val data = "ssh userauth".toByteArray()
        val signed = sign(HelperProtocol.ALG_ECDSA, enrolled.keyHandle, data) as HelperProtocol.Response.Signed
        val der = DERSequence(arrayOf(ASN1Integer(BigInteger(1, signed.r)), ASN1Integer(BigInteger(1, signed.s)))).encoded
        val valid = Signature.getInstance("SHA256withECDSA").run {
            initVerify(HybridCrypto.decodeUncompressed(enrolled.publicKey))
            update(sshdMessage("ssh:", signed, data))
            verify(der)
        }

        assertThat(enrolled.flags).isEqualTo(OpenSshKeys.FLAG_USER_PRESENCE_REQUIRED)
        assertThat(enrolled.publicKey).hasLength(65)
        assertThat(valid).isTrue()
        assertThat(signed.flags and 0x05).isEqualTo(0x05)
        assertThat(signed.counter).isEqualTo(1)
        assertThat(phone.vault.single().discoverable).isFalse()
        assertThat(phone.stages).containsAtLeast(
            HybridClient.Stage.WaitingForPhone, HybridClient.Stage.Connecting, HybridClient.Stage.WaitingForApproval,
        )
        assertThat(phone.completed).isEqualTo(2)
    }

    @Test
    fun `an ed25519-sk resident verify-required key round trips`() {
        val flags = OpenSshKeys.FLAG_USER_PRESENCE_REQUIRED or OpenSshKeys.FLAG_RESIDENT_KEY or
            OpenSshKeys.FLAG_USER_VERIFICATION_REQUIRED
        val enrolled = enrol(HelperProtocol.ALG_ED25519, flags, "ssh:work") as HelperProtocol.Response.Enrolled
        val data = "session".toByteArray()
        val signed = sign(HelperProtocol.ALG_ED25519, enrolled.keyHandle, data, "ssh:work") as HelperProtocol.Response.Signed
        val message = sshdMessage("ssh:work", signed, data)
        val valid = Ed25519Signer().run {
            init(false, Ed25519PublicKeyParameters(enrolled.publicKey, 0))
            update(message, 0, message.size)
            verifySignature(signed.r)
        }

        assertThat(valid).isTrue()
        assertThat(signed.s).isEmpty()
        assertThat(phone.vault.single().credentialProtection).isEqualTo(3)
        assertThat(phone.vault.single().discoverable).isTrue()
    }

    @Test
    fun `a phone without a secure screen lock is refused before anything is asked`() {
        phone.verificationAvailable = false

        assertThat(enrol(HelperProtocol.ALG_ECDSA))
            .isEqualTo(HelperProtocol.Response.Failed(HelperProtocol.ERR_UNSUPPORTED))
        assertThat(phone.vault).isEmpty()
        assertThat(phone.stages).doesNotContain(HybridClient.Stage.WaitingForApproval)
    }

    @Test
    fun `a refusal on the phone and an unknown key are reported as OpenSSH errors`() {
        val enrolled = enrol(HelperProtocol.ALG_ECDSA) as HelperProtocol.Response.Enrolled
        phone.approves = false

        assertThat(sign(HelperProtocol.ALG_ECDSA, enrolled.keyHandle, ByteArray(8)))
            .isEqualTo(HelperProtocol.Response.Failed(HelperProtocol.ERR_GENERAL))
        phone.approves = true
        assertThat(sign(HelperProtocol.ALG_ECDSA, ByteArray(32), ByteArray(8)))
            .isEqualTo(HelperProtocol.Response.Failed(HelperProtocol.ERR_DEVICE_NOT_FOUND))
        assertThat(phone.failures).hasSize(2)
    }

    @Test
    fun `a signature made without verification never reaches OpenSSH`() {
        val enrolled = enrol(HelperProtocol.ALG_ECDSA) as HelperProtocol.Response.Enrolled
        phone.forgeUnverified = true

        assertThat(sign(HelperProtocol.ALG_ECDSA, enrolled.keyHandle, ByteArray(8)))
            .isEqualTo(HelperProtocol.Response.Failed(HelperProtocol.ERR_GENERAL))
    }

    @Test
    fun `only OpenSSH applications are accepted`() {
        assertThat(enrol(HelperProtocol.ALG_ECDSA, application = "github.com"))
            .isEqualTo(HelperProtocol.Response.Failed(HelperProtocol.ERR_GENERAL))
        assertThat(phone.shownCodes).isEmpty()
    }

    @Test
    fun `every request shows a fresh code`() {
        val enrolled = enrol(HelperProtocol.ALG_ECDSA) as HelperProtocol.Response.Enrolled
        sign(HelperProtocol.ALG_ECDSA, enrolled.keyHandle, ByteArray(8))

        assertThat(phone.shownCodes).hasSize(2)
        assertThat(phone.shownCodes[0]).isNotEqualTo(phone.shownCodes[1])
    }

    private fun list() = authenticator.handle(
        HelperProtocol.Request(HelperProtocol.OP_LIST, HelperProtocol.ALG_ECDSA, 0, "ssh:", ByteArray(0), ByteArray(0)),
    )

    @Test
    fun `ssh-keygen -K receives the resident keys only, ready to sign`() {
        val resident = enrol(
            HelperProtocol.ALG_ED25519,
            OpenSshKeys.FLAG_USER_PRESENCE_REQUIRED or OpenSshKeys.FLAG_RESIDENT_KEY,
            "ssh:work",
        ) as HelperProtocol.Response.Enrolled
        enrol(HelperProtocol.ALG_ECDSA)

        val listed = list() as HelperProtocol.Response.Listed
        val key = listed.keys.single()
        val signed = sign(HelperProtocol.ALG_ED25519, key.keyHandle, ByteArray(8), key.application)

        assertThat(key.application).isEqualTo("ssh:work")
        assertThat(key.algorithm).isEqualTo(HelperProtocol.ALG_ED25519)
        assertThat(key.publicKey).isEqualTo(resident.publicKey)
        assertThat(key.keyHandle).isEqualTo(resident.keyHandle)
        assertThat(key.flags).isEqualTo(0x25)
        assertThat(signed).isInstanceOf(HelperProtocol.Response.Signed::class.java)
    }

    @Test
    fun `an empty vault lists nothing and a phone without screen lock lists nothing either`() {
        assertThat((list() as HelperProtocol.Response.Listed).keys).isEmpty()
        enrol(HelperProtocol.ALG_ECDSA, OpenSshKeys.FLAG_RESIDENT_KEY)
        phone.verificationAvailable = false

        assertThat(list()).isEqualTo(HelperProtocol.Response.Failed(HelperProtocol.ERR_UNSUPPORTED))
    }
}
