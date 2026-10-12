package com.pqvault.core.hybrid

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.Number
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.pqvault.core.model.PasskeyEntry
import com.pqvault.core.webauthn.SoftwareAuthenticator
import java.io.ByteArrayOutputStream

/**
 * The CTAP2 subset carried by the hybrid transport.
 *
 * Parsing lives in the platform-neutral module so malformed data from the tunnel is kept
 * away from Android UI code and can be covered by ordinary JVM tests.
 */
object Ctap2Protocol {
    const val COMMAND_MAKE_CREDENTIAL = 0x01
    const val COMMAND_GET_ASSERTION = 0x02
    const val COMMAND_GET_INFO = 0x04
    const val COMMAND_SELECTION = 0x0b
    const val COMMAND_CANCEL = 0x11

    const val STATUS_OK = 0x00
    const val STATUS_INVALID_COMMAND = 0x01
    const val STATUS_INVALID_CBOR = 0x12
    const val STATUS_CREDENTIAL_EXCLUDED = 0x19
    const val STATUS_UNSUPPORTED_ALGORITHM = 0x26
    const val STATUS_OPERATION_DENIED = 0x27
    const val STATUS_KEEPALIVE_CANCEL = 0x2d
    const val STATUS_NO_CREDENTIALS = 0x2e
    const val STATUS_UNSUPPORTED_OPTION = 0x2b

    /** Credential IDs are 32 random bytes; the ceiling leaves room for a future format. */
    private const val MAX_CREDENTIAL_ID_LENGTH = 64L
    private const val MAX_CREDENTIAL_COUNT_IN_LIST = 64L

    sealed interface Request {
        data object GetInfo : Request
        data object Selection : Request
        data object Cancel : Request

        data class MakeCredential(
            val clientDataHash: ByteArray,
            val rpId: String,
            val rpName: String?,
            val userHandle: ByteArray,
            val userName: String,
            val userDisplayName: String?,
            val offeredAlgorithms: List<Int>,
            val excludedCredentialIds: List<ByteArray>,
            val residentKey: Boolean,
            val userVerification: Boolean,
        ) : Request

        data class GetAssertion(
            val rpId: String,
            val clientDataHash: ByteArray,
            val allowedCredentialIds: List<ByteArray>,
            val userVerification: Boolean,
        ) : Request

        data class Unknown(val command: Int) : Request
    }

    fun parse(packet: ByteArray): Request {
        require(packet.isNotEmpty()) { "empty CTAP packet" }
        val command = packet[0].toInt() and 0xff
        if (command == COMMAND_GET_INFO) return Request.GetInfo
        if (command == COMMAND_SELECTION) return Request.Selection
        if (command == COMMAND_CANCEL) return Request.Cancel
        if (command != COMMAND_MAKE_CREDENTIAL && command != COMMAND_GET_ASSERTION) {
            return Request.Unknown(command)
        }

        val map = CborDecoder.decode(packet.copyOfRange(1, packet.size)).singleOrNull() as? CborMap
            ?: throw IllegalArgumentException("CTAP payload is not a CBOR map")
        return if (command == COMMAND_MAKE_CREDENTIAL) parseMakeCredential(map) else parseGetAssertion(map)
    }

    /** CBOR map included in the responder's encrypted post-handshake message. */
    fun postHandshakeMessage(userVerificationAvailable: Boolean): ByteArray {
        val map = CborMap()
            .put(uint(1), ByteString(getInfoMap(userVerificationAvailable)))
            .put(uint(3), CborArray().add(text("ctap")))
        return encode(map)
    }

    fun getInfoResponse(userVerificationAvailable: Boolean): ByteArray =
        success(getInfoMap(userVerificationAvailable))

    fun makeCredentialResponse(registration: SoftwareAuthenticator.Registration): ByteArray {
        val body = CborMap()
            .put(uint(1), text("none"))
            .put(uint(2), ByteString(registration.authenticatorData))
            .put(uint(3), CborMap())
        return success(encode(body))
    }

    fun getAssertionResponse(
        assertion: SoftwareAuthenticator.Assertion,
        entry: PasskeyEntry,
        includeUser: Boolean,
        includeIdentifyingInformation: Boolean,
    ): ByteArray {
        val descriptor = CborMap()
            .put(text("id"), ByteString(assertion.credentialId))
            .put(text("type"), text("public-key"))
        val body = CborMap()
            .put(uint(1), descriptor)
            .put(uint(2), ByteString(assertion.authenticatorData))
            .put(uint(3), ByteString(assertion.signature))
        if (includeUser) {
            val user = CborMap()
                .put(text("id"), ByteString(assertion.userHandle ?: ByteArray(0)))
            if (includeIdentifyingInformation) {
                user.put(text("name"), text(entry.userName))
                entry.userDisplayName?.let { user.put(text("displayName"), text(it)) }
            }
            body.put(uint(4), user)
        }
        return success(encode(body))
    }

    fun success(): ByteArray = byteArrayOf(STATUS_OK.toByte())

    fun error(status: Int): ByteArray = byteArrayOf(status.toByte())

    private fun success(cbor: ByteArray): ByteArray = byteArrayOf(STATUS_OK.toByte()) + cbor

    private fun parseMakeCredential(map: CborMap): Request.MakeCredential {
        val clientDataHash = map.bytes(1) ?: throw IllegalArgumentException("missing clientDataHash")
        require(clientDataHash.size == 32) { "clientDataHash must be 32 bytes" }
        val rp = map.map(2) ?: throw IllegalArgumentException("missing RP")
        val user = map.map(3) ?: throw IllegalArgumentException("missing user")
        val parameters = map.array(4) ?: throw IllegalArgumentException("missing pubKeyCredParams")
        val options = map.map(7)
        return Request.MakeCredential(
            clientDataHash = clientDataHash,
            rpId = rp.text("id")?.takeIf(String::isNotBlank)
                ?: throw IllegalArgumentException("missing RP ID"),
            rpName = rp.text("name"),
            userHandle = user.bytes("id") ?: throw IllegalArgumentException("missing user ID"),
            userName = user.text("name") ?: "",
            userDisplayName = user.text("displayName"),
            offeredAlgorithms = parameters.dataItems.mapNotNull { item ->
                (item as? CborMap)?.number("alg")
            },
            excludedCredentialIds = credentialIds(map.array(5)),
            residentKey = options?.boolean("rk") == true,
            userVerification = options?.boolean("uv") == true,
        )
    }

    private fun parseGetAssertion(map: CborMap): Request.GetAssertion {
        val clientDataHash = map.bytes(2) ?: throw IllegalArgumentException("missing clientDataHash")
        require(clientDataHash.size == 32) { "clientDataHash must be 32 bytes" }
        val options = map.map(5)
        return Request.GetAssertion(
            rpId = map.text(1)?.takeIf(String::isNotBlank)
                ?: throw IllegalArgumentException("missing RP ID"),
            clientDataHash = clientDataHash,
            allowedCredentialIds = credentialIds(map.array(3)),
            userVerification = options?.boolean("uv") == true,
        )
    }

    private fun credentialIds(array: CborArray?): List<ByteArray> =
        array?.dataItems.orEmpty().mapNotNull { item ->
            (item as? CborMap)?.bytes("id")
        }

    private fun getInfoMap(userVerificationAvailable: Boolean): ByteArray {
        val versions = CborArray().add(text("FIDO_2_0")).add(text("FIDO_2_1"))
        val options = CborMap()
            .put(text("rk"), SimpleValue.TRUE)
            .put(text("up"), SimpleValue.TRUE)
            .put(text("uv"), if (userVerificationAvailable) SimpleValue.TRUE else SimpleValue.FALSE)
        val transports = CborArray().add(text("hybrid"))
        val algorithms = CborArray().add(
            CborMap()
                .put(text("alg"), co.nstant.`in`.cbor.model.NegativeInteger(-7))
                .put(text("type"), text("public-key")),
        )
        // Key 6 is pinUvAuthProtocols and must be an array; no PIN protocol is supported here, so
        // the key is left out. Clients reject the whole getInfo response when a key has the wrong
        // type, which tears the hybrid tunnel down right after the handshake.
        val info = CborMap()
            .put(uint(1), versions)
            .put(uint(3), ByteString(aaguidBytes()))
            .put(uint(4), options)
            .put(uint(5), uint(4096))
            .put(uint(7), uint(MAX_CREDENTIAL_COUNT_IN_LIST))
            .put(uint(8), uint(MAX_CREDENTIAL_ID_LENGTH))
            .put(uint(9), transports)
            .put(uint(10), algorithms)
        return encode(info)
    }

    private fun aaguidBytes(): ByteArray {
        val uuid = SoftwareAuthenticator.DEFAULT_AAGUID
        return ByteArray(16).also { bytes ->
            for (index in 0..7) {
                bytes[index] = (uuid.mostSignificantBits ushr ((7 - index) * 8)).toByte()
                bytes[index + 8] = (uuid.leastSignificantBits ushr ((7 - index) * 8)).toByte()
            }
        }
    }

    private fun encode(item: DataItem): ByteArray = ByteArrayOutputStream().also {
        CborEncoder(it).encode(item)
    }.toByteArray()

    private fun uint(value: Long) = UnsignedInteger(value)
    private fun text(value: String) = UnicodeString(value)

    private fun CborMap.item(key: Long): DataItem? = get(uint(key))
    private fun CborMap.item(key: String): DataItem? = get(UnicodeString(key))
    private fun CborMap.bytes(key: Long): ByteArray? = (item(key) as? ByteString)?.bytes
    private fun CborMap.bytes(key: String): ByteArray? = (item(key) as? ByteString)?.bytes
    private fun CborMap.text(key: Long): String? = (item(key) as? UnicodeString)?.string
    private fun CborMap.text(key: String): String? = (item(key) as? UnicodeString)?.string
    private fun CborMap.map(key: Long): CborMap? = item(key) as? CborMap
    private fun CborMap.array(key: Long): CborArray? = item(key) as? CborArray
    private fun CborMap.number(key: String): Int? = (item(key) as? Number)?.value?.toInt()
    private fun CborMap.boolean(key: String): Boolean? = when (item(key)) {
        SimpleValue.TRUE -> true
        SimpleValue.FALSE -> false
        else -> null
    }
}
