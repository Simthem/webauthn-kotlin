package com.pqvault.core.webauthn

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.google.common.truth.Truth.assertThat
import com.pqvault.core.format.Base64Url
import com.pqvault.core.model.CoseAlgorithm
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

class SoftwareAuthenticatorTest {

    private val authenticator = SoftwareAuthenticator()
    private val clientDataHash = AuthenticatorData.sha256("client data".toByteArray())

    private fun register(rpId: String = "github.com") = authenticator.makeCredential(
        rpId = rpId,
        rpName = "GitHub",
        userHandle = "user-handle".toByteArray(),
        userName = "simon",
        userDisplayName = "Simon",
        clientDataHash = clientDataHash,
    )

    @Test
    fun `authenticator data starts with the SHA-256 of the rp id`() {
        val registration = register("github.com")

        val rpIdHash = registration.authenticatorData.copyOfRange(0, 32)

        assertThat(rpIdHash).isEqualTo(AuthenticatorData.sha256("github.com".toByteArray()))
    }

    /**
     * The flags that declare this a synced passkey. Without them a relying party treats
     * the credential as device-bound and will keep prompting the user to add a backup.
     */
    @Test
    fun `the backup eligible and backup state flags are set`() {
        val flags = register().authenticatorData[32].toInt()

        assertThat(flags and AuthenticatorData.FLAG_BACKUP_ELIGIBLE).isNotEqualTo(0)
        assertThat(flags and AuthenticatorData.FLAG_BACKUP_STATE).isNotEqualTo(0)
    }

    @Test
    fun `user presence and verification flags are set`() {
        val flags = register().authenticatorData[32].toInt()

        assertThat(flags and AuthenticatorData.FLAG_USER_PRESENT).isNotEqualTo(0)
        assertThat(flags and AuthenticatorData.FLAG_USER_VERIFIED).isNotEqualTo(0)
    }

    @Test
    fun `registration includes attested credential data with a matching credential id`() {
        val registration = register()
        val data = registration.authenticatorData

        assertThat(data[32].toInt() and AuthenticatorData.FLAG_ATTESTED_CREDENTIAL_DATA).isNotEqualTo(0)

        // rpIdHash(32) + flags(1) + counter(4) = 37, then aaguid(16), then the length.
        val credentialIdLength = ((data[53].toInt() and 0xff) shl 8) or (data[54].toInt() and 0xff)
        val credentialId = data.copyOfRange(55, 55 + credentialIdLength)

        assertThat(credentialIdLength).isEqualTo(32)
        assertThat(Base64Url.encode(credentialId)).isEqualTo(registration.entry.credentialId)
    }

    @Test
    fun `the attestation object is CBOR with format none`() {
        val decoded = CborDecoder.decode(register().attestationObject)
        val map = decoded[0] as CborMap

        assertThat((map.get(UnicodeString("fmt")) as UnicodeString).string).isEqualTo("none")
        assertThat(map.get(UnicodeString("attStmt"))).isInstanceOf(CborMap::class.java)
        assertThat(map.get(UnicodeString("authData"))).isInstanceOf(ByteString::class.java)
    }

    @Test
    fun `the COSE public key advertises EC2 P-256 and ES256`() {
        val registration = register()
        val data = registration.authenticatorData
        val credentialIdLength = ((data[53].toInt() and 0xff) shl 8) or (data[54].toInt() and 0xff)
        val coseBytes = data.copyOfRange(55 + credentialIdLength, data.size)

        val cose = CborDecoder.decode(coseBytes)[0] as CborMap

        assertThat((cose.get(UnsignedInteger(1)) as UnsignedInteger).value).isEqualTo(BigInteger.valueOf(2))
        assertThat((cose.get(UnsignedInteger(3)) as NegativeInteger).value)
            .isEqualTo(BigInteger.valueOf(CoseAlgorithm.ES256.id.toLong()))
        assertThat((cose.get(NegativeInteger(-1)) as UnsignedInteger).value).isEqualTo(BigInteger.ONE)
        assertThat((cose.get(NegativeInteger(-2)) as ByteString).bytes).hasLength(32)
        assertThat((cose.get(NegativeInteger(-3)) as ByteString).bytes).hasLength(32)
    }

    /**
     * The test that matters most: a relying party verifies the assertion by checking the
     * signature over authenticatorData || SHA-256(clientDataJSON) against the public key
     * it stored at registration. This reproduces that exactly.
     */
    @Test
    fun `an assertion verifies against the registered public key`() {
        val registration = register()

        val assertion = authenticator.getAssertion(registration.entry, clientDataHash)

        val publicKey = KeyFactory.getInstance("EC").generatePublic(
            X509EncodedKeySpec(Base64Url.decode(registration.entry.publicKeySpki)),
        )
        val verified = Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(assertion.authenticatorData)
            update(clientDataHash)
            verify(assertion.signature)
        }

        assertThat(verified).isTrue()
    }

    @Test
    fun `an assertion does not verify against a different challenge`() {
        val registration = register()
        val assertion = authenticator.getAssertion(registration.entry, clientDataHash)

        val publicKey = KeyFactory.getInstance("EC").generatePublic(
            X509EncodedKeySpec(Base64Url.decode(registration.entry.publicKeySpki)),
        )
        val verified = Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(assertion.authenticatorData)
            update(AuthenticatorData.sha256("a different challenge".toByteArray()))
            verify(assertion.signature)
        }

        assertThat(verified).isFalse()
    }

    @Test
    fun `the signature counter increments on every assertion`() {
        val registration = register()

        val first = authenticator.getAssertion(registration.entry, clientDataHash)
        val second = authenticator.getAssertion(first.updatedEntry, clientDataHash)

        assertThat(registration.entry.signCount).isEqualTo(0)
        assertThat(first.updatedEntry.signCount).isEqualTo(1)
        assertThat(second.updatedEntry.signCount).isEqualTo(2)
    }

    @Test
    fun `the counter in authenticator data matches the entry`() {
        val registration = register()
        val assertion = authenticator.getAssertion(registration.entry, clientDataHash)

        val data = assertion.authenticatorData
        val counter = ((data[33].toInt() and 0xff) shl 24) or
            ((data[34].toInt() and 0xff) shl 16) or
            ((data[35].toInt() and 0xff) shl 8) or
            (data[36].toInt() and 0xff)

        assertThat(counter.toLong()).isEqualTo(assertion.updatedEntry.signCount)
    }

    @Test
    fun `an assertion carries no attested credential data`() {
        val assertion = authenticator.getAssertion(register().entry, clientDataHash)

        assertThat(assertion.authenticatorData).hasLength(37)
        assertThat(assertion.authenticatorData[32].toInt() and AuthenticatorData.FLAG_ATTESTED_CREDENTIAL_DATA)
            .isEqualTo(0)
    }

    @Test
    fun `two credentials for the same site get distinct ids and keys`() {
        val a = register()
        val b = register()

        assertThat(a.entry.credentialId).isNotEqualTo(b.entry.credentialId)
        assertThat(a.entry.privateKeyPkcs8).isNotEqualTo(b.entry.privateKeyPkcs8)
    }

    @Test
    fun `requesting a post-quantum algorithm is refused with a clear reason`() {
        val failure = runCatching {
            authenticator.makeCredential(
                rpId = "github.com",
                rpName = null,
                userHandle = "u".toByteArray(),
                userName = "simon",
                userDisplayName = null,
                clientDataHash = clientDataHash,
                algorithm = CoseAlgorithm.ML_DSA_65,
            )
        }.exceptionOrNull()

        assertThat(failure).isInstanceOf(IllegalArgumentException::class.java)
        assertThat(failure).hasMessageThat().contains("not yet accepted by relying")
    }
}
