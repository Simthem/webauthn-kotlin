package com.pqvault.core.hybrid

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.google.common.truth.Truth.assertThat
import com.pqvault.core.webauthn.AuthenticatorData
import com.pqvault.core.webauthn.SoftwareAuthenticator
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream

class Ctap2ProtocolTest {
    @Test
    fun `make credential request is decoded from CTAP CBOR`() {
        val rp = CborMap().put(text("id"), text("example.com")).put(text("name"), text("Example"))
        val user = CborMap()
            .put(text("id"), ByteString(byteArrayOf(1, 2, 3)))
            .put(text("name"), text("alice"))
            .put(text("displayName"), text("Alice"))
        val algorithms = CborArray().add(
            CborMap().put(text("type"), text("public-key")).put(text("alg"), NegativeInteger(-7)),
        )
        val options = CborMap().put(text("rk"), SimpleValue.TRUE).put(text("uv"), SimpleValue.TRUE)
        val body = CborMap()
            .put(uint(1), ByteString(ByteArray(32) { it.toByte() }))
            .put(uint(2), rp)
            .put(uint(3), user)
            .put(uint(4), algorithms)
            .put(uint(7), options)

        val request = Ctap2Protocol.parse(
            byteArrayOf(Ctap2Protocol.COMMAND_MAKE_CREDENTIAL.toByte()) + encode(body),
        ) as Ctap2Protocol.Request.MakeCredential

        assertThat(request.rpId).isEqualTo("example.com")
        assertThat(request.userName).isEqualTo("alice")
        assertThat(request.offeredAlgorithms).containsExactly(-7)
        assertThat(request.residentKey).isTrue()
        assertThat(request.userVerification).isTrue()
    }

    @Test
    fun `get assertion allow list is decoded`() {
        val id = ByteArray(32) { (it + 4).toByte() }
        val allowList = CborArray().add(
            CborMap().put(text("id"), ByteString(id)).put(text("type"), text("public-key")),
        )
        val body = CborMap()
            .put(uint(1), text("example.com"))
            .put(uint(2), ByteString(ByteArray(32)))
            .put(uint(3), allowList)

        val request = Ctap2Protocol.parse(
            byteArrayOf(Ctap2Protocol.COMMAND_GET_ASSERTION.toByte()) + encode(body),
        ) as Ctap2Protocol.Request.GetAssertion

        assertThat(request.rpId).isEqualTo("example.com")
        assertThat(request.allowedCredentialIds).hasSize(1)
        assertThat(request.allowedCredentialIds.single()).isEqualTo(id)
    }

    @Test
    fun `get info advertises hybrid transport and user verification accurately`() {
        val response = Ctap2Protocol.getInfoResponse(userVerificationAvailable = true)
        assertThat(response[0]).isEqualTo(Ctap2Protocol.STATUS_OK.toByte())
        val info = CborDecoder.decode(response.copyOfRange(1, response.size)).single() as CborMap
        val options = info.get(uint(4)) as CborMap
        val transports = info.get(uint(9)) as CborArray

        assertThat(options.get(text("rk"))).isEqualTo(SimpleValue.TRUE)
        assertThat(options.get(text("uv"))).isEqualTo(SimpleValue.TRUE)
        assertThat(transports.dataItems.map { (it as UnicodeString).string }).contains("hybrid")
    }

    @Test
    fun `registration response contains authenticator data and none attestation`() {
        val authenticator = SoftwareAuthenticator()
        val registration = authenticator.makeCredential(
            rpId = "example.com",
            rpName = "Example",
            userHandle = byteArrayOf(7),
            userName = "alice",
            userDisplayName = "Alice",
            clientDataHash = AuthenticatorData.sha256("client".toByteArray()),
        )

        val response = Ctap2Protocol.makeCredentialResponse(registration)
        val body = CborDecoder.decode(response.copyOfRange(1, response.size)).single() as CborMap

        assertThat(response[0]).isEqualTo(0)
        assertThat((body.get(uint(1)) as UnicodeString).string).isEqualTo("none")
        assertThat((body.get(uint(2)) as ByteString).bytes).isEqualTo(registration.authenticatorData)
    }

    @Test
    fun `get info keeps every key at the type CTAP2 requires`() {
        val response = Ctap2Protocol.getInfoResponse(userVerificationAvailable = false)
        val info = CborDecoder.decode(response.copyOfRange(1, response.size)).single() as CborMap

        // pinUvAuthProtocols is an array; sending an integer makes clients drop the whole
        // response and close the hybrid tunnel.
        val pinProtocols = info.get(uint(6))
        assertThat(pinProtocols == null || pinProtocols is CborArray).isTrue()
        assertThat(info.get(uint(7))).isInstanceOf(UnsignedInteger::class.java)
        assertThat(info.get(uint(8))).isInstanceOf(UnsignedInteger::class.java)
        assertThat((info.get(uint(3)) as ByteString).bytes).hasLength(16)
        assertThat(info.get(uint(9))).isInstanceOf(CborArray::class.java)
        assertThat(info.get(uint(10))).isInstanceOf(CborArray::class.java)
    }

    @Test
    fun `post handshake message carries the getInfo response and the ctap feature`() {
        val message = Ctap2Protocol.postHandshakeMessage(userVerificationAvailable = true)
        val map = CborDecoder.decode(message).single() as CborMap
        val getInfo = (map.get(uint(1)) as ByteString).bytes
        val features = (map.get(uint(3)) as CborArray).dataItems.map { (it as UnicodeString).string }

        assertThat(features).containsExactly("ctap")
        // The post-handshake copy is the bare getInfo map, without a CTAP status byte.
        assertThat(CborDecoder.decode(getInfo).single()).isInstanceOf(CborMap::class.java)
    }

    private fun encode(map: CborMap): ByteArray = ByteArrayOutputStream().also {
        CborEncoder(it).encode(map)
    }.toByteArray()

    private fun uint(value: Long) = UnsignedInteger(value)
    private fun text(value: String) = UnicodeString(value)
}
