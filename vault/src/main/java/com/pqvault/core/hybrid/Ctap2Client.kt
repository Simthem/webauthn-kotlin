package com.pqvault.core.hybrid

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.Number
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.pqvault.core.model.CoseAlgorithm
import com.pqvault.core.ssh.OpenSshKeys
import com.pqvault.core.webauthn.AuthenticatorData
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.Signature

/** The computer's side of CTAP2 for OpenSSH keys. Answers without user verification are refused. */
object Ctap2Client {
    private const val MESSAGE_TYPE_CTAP = 1
    private const val MAX_RESIDENT_KEYS = 256

    class Failure(val status: Int) : Exception("the authenticator answered status 0x%02x".format(status))

    class Credential(
        val algorithm: CoseAlgorithm,
        val credentialId: ByteArray,
        /** SEC1 uncompressed point for ECDSA, the raw 32 bytes for Ed25519. */
        val publicKey: ByteArray,
        val authenticatorData: ByteArray,
        val attestationSignature: ByteArray,
    )

    class Assertion(val flags: Int, val counter: Long, val signature: ByteArray)

    class Info(val userVerification: Boolean)

    class ResidentKey(
        val application: String,
        val credentialId: ByteArray,
        val algorithm: CoseAlgorithm,
        val publicKey: ByteArray,
        val userId: ByteArray,
        val credentialProtection: Int,
    )

    fun makeCredential(
        application: String,
        clientDataHash: ByteArray,
        userId: ByteArray,
        algorithm: CoseAlgorithm,
        residentKey: Boolean,
        credentialProtection: Int?,
    ): ByteArray {
        require(OpenSshKeys.isApplication(application)) { "not an OpenSSH application" }
        require(clientDataHash.size == 32)
        require(credentialProtection == null || credentialProtection in 1..3)
        val options = CborMap()
        if (residentKey) options.put(text("rk"), SimpleValue.TRUE)
        options.put(text("uv"), SimpleValue.TRUE)
        val body = CborMap()
            .put(uint(1), ByteString(clientDataHash))
            .put(uint(2), CborMap().put(text("id"), text(application)))
            .put(
                uint(3),
                CborMap()
                    .put(text("id"), ByteString(userId))
                    .put(text("name"), text("openssh"))
                    .put(text("displayName"), text("openssh")),
            )
            .put(
                uint(4),
                CborArray().add(
                    CborMap()
                        .put(text("alg"), NegativeInteger(algorithm.id.toLong()))
                        .put(text("type"), text("public-key")),
                ),
            )
        credentialProtection?.let { body.put(uint(6), CborMap().put(text("credProtect"), uint(it.toLong()))) }
        body.put(uint(7), options)
        return byteArrayOf(Ctap2Protocol.COMMAND_MAKE_CREDENTIAL.toByte()) + encode(body)
    }

    fun getAssertion(application: String, clientDataHash: ByteArray, credentialId: ByteArray): ByteArray {
        require(OpenSshKeys.isApplication(application)) { "not an OpenSSH application" }
        require(clientDataHash.size == 32)
        val body = CborMap()
            .put(uint(1), text(application))
            .put(uint(2), ByteString(clientDataHash))
            .put(
                uint(3),
                CborArray().add(
                    CborMap().put(text("id"), ByteString(credentialId)).put(text("type"), text("public-key")),
                ),
            )
            .put(uint(5), CborMap().put(text("up"), SimpleValue.TRUE).put(text("uv"), SimpleValue.TRUE))
        return byteArrayOf(Ctap2Protocol.COMMAND_GET_ASSERTION.toByte()) + encode(body)
    }

    fun listSshKeys(): ByteArray = byteArrayOf(Ctap2Protocol.COMMAND_LIST_SSH_KEYS.toByte())

    fun parseSshKeyList(response: ByteArray): List<ResidentKey> {
        val keys = statusBody(response).get(uint(1)) as? CborArray ?: throw IllegalArgumentException("no key list")
        require(keys.dataItems.size <= MAX_RESIDENT_KEYS) { "too many keys" }
        return keys.dataItems.map { item ->
            val key = item as? CborMap ?: throw IllegalArgumentException("malformed key")
            val application = (key.get(uint(1)) as? UnicodeString)?.string
            require(application != null && OpenSshKeys.isApplication(application) && application.length < 256) {
                "not an OpenSSH application"
            }
            val algorithm = CoseAlgorithm.fromId((key.get(uint(3)) as? Number)?.value?.toInt() ?: 0)
            require(algorithm == CoseAlgorithm.ES256 || algorithm == CoseAlgorithm.EDDSA) { "unsupported key type" }
            val credentialId = (key.get(uint(2)) as? ByteString)?.bytes
            require(credentialId != null && credentialId.size in 16..1023) { "invalid key handle" }
            val publicKey = (key.get(uint(4)) as? ByteString)?.bytes ?: throw IllegalArgumentException("no public key")
            if (algorithm == CoseAlgorithm.ES256) HybridCrypto.decodeUncompressed(publicKey)
            else require(publicKey.size == 32) { "invalid Ed25519 key" }
            val userId = (key.get(uint(5)) as? ByteString)?.bytes ?: ByteArray(0)
            require(userId.size <= 64) { "invalid user ID" }
            val protection = (key.get(uint(6)) as? Number)?.value?.toInt() ?: 1
            require(protection in 1..3) { "invalid credProtect level" }
            ResidentKey(application, credentialId, algorithm, publicKey, userId, protection)
        }
    }

    /** A CTAP request as it travels in the encrypted tunnel. */
    fun tunnelMessage(request: ByteArray): ByteArray = byteArrayOf(MESSAGE_TYPE_CTAP.toByte()) + request

    /** The CTAP response inside a decrypted tunnel message. */
    fun fromTunnel(message: ByteArray): ByteArray {
        require(message.size >= 2 && message[0].toInt() == MESSAGE_TYPE_CTAP) { "not a CTAP message" }
        return message.copyOfRange(1, message.size)
    }

    /** What the phone sends right after the handshake. */
    fun parseInfo(postHandshake: ByteArray): Info {
        val outer = decodeMap(postHandshake)
        val info = decodeMap((outer.get(uint(1)) as? ByteString)?.bytes ?: throw IllegalArgumentException("no getInfo"))
        val options = info.get(uint(4)) as? CborMap
        return Info(userVerification = options?.get(text("uv")) == SimpleValue.TRUE)
    }

    fun parseCredential(
        response: ByteArray,
        application: String,
        clientDataHash: ByteArray,
        algorithm: CoseAlgorithm,
        credentialProtection: Int?,
    ): Credential {
        val map = statusBody(response)
        require((map.get(uint(1)) as? UnicodeString)?.string == "packed") { "the new key is not self-attested" }
        val authData = (map.get(uint(2)) as? ByteString)?.bytes ?: throw IllegalArgumentException("no authenticator data")
        val statement = map.get(uint(3)) as? CborMap ?: throw IllegalArgumentException("no attestation statement")
        require(statement.get(text("x5c")) == null) { "unexpected attestation certificate" }
        require((statement.get(text("alg")) as? Number)?.value?.toInt() == algorithm.id) { "attestation algorithm mismatch" }
        val attestationSignature = (statement.get(text("sig")) as? ByteString)?.bytes
            ?: throw IllegalArgumentException("no attestation signature")

        val flags = checkHeader(authData, application, AuthenticatorData.FLAG_ATTESTED_CREDENTIAL_DATA)
        require(authData.size >= 55) { "authenticator data too short" }
        val idLength = ((authData[53].toInt() and 0xff) shl 8) or (authData[54].toInt() and 0xff)
        require(idLength in 16..1023 && authData.size >= 55 + idLength) { "invalid credential ID" }
        val credentialId = authData.copyOfRange(55, 55 + idLength)
        val keyStart = 55 + idLength
        val keyEnd = CborBounds.end(authData, keyStart)
        val publicKey = publicKey(decodeMap(authData.copyOfRange(keyStart, keyEnd)), algorithm)

        val hasExtensions = flags and AuthenticatorData.FLAG_EXTENSION_DATA != 0
        if (credentialProtection == null) {
            require(!hasExtensions && keyEnd == authData.size) { "unrequested extension output" }
        } else {
            require(hasExtensions) { "credProtect was not applied" }
            val extensions = decodeMap(authData.copyOfRange(keyEnd, authData.size))
            require(extensions.keys.size == 1) { "unrequested extension output" }
            require((extensions.get(text("credProtect")) as? Number)?.value?.toInt() == credentialProtection) {
                "credProtect was not applied"
            }
        }

        require(verify(algorithm, publicKey, authData + clientDataHash, attestationSignature)) {
            "the self-attestation does not verify"
        }
        return Credential(algorithm, credentialId, publicKey, authData, attestationSignature)
    }

    fun parseAssertion(response: ByteArray, application: String, credentialId: ByteArray): Assertion {
        val map = statusBody(response)
        (map.get(uint(1)) as? CborMap)?.let { descriptor ->
            require(MessageDigest.isEqual((descriptor.get(text("id")) as? ByteString)?.bytes, credentialId)) {
                "the signature is for another key"
            }
        }
        val authData = (map.get(uint(2)) as? ByteString)?.bytes ?: throw IllegalArgumentException("no authenticator data")
        val signature = (map.get(uint(3)) as? ByteString)?.bytes ?: throw IllegalArgumentException("no signature")
        require(authData.size == 37) { "unexpected data in the signed authenticator data" }
        val flags = checkHeader(authData, application, 0)
        val counter = ((authData[33].toLong() and 0xff) shl 24) or ((authData[34].toLong() and 0xff) shl 16) or
            ((authData[35].toLong() and 0xff) shl 8) or (authData[36].toLong() and 0xff)
        return Assertion(flags, counter, signature)
    }

    /** r and s of a DER ECDSA signature, unsigned and without leading zero bytes. */
    fun ecdsaComponents(der: ByteArray): Pair<ByteArray, ByteArray> {
        val sequence = ASN1Sequence.getInstance(der)
        require(sequence.size() == 2 && sequence.encoded.contentEquals(der)) { "malformed ECDSA signature" }
        return unsigned(ASN1Integer.getInstance(sequence.getObjectAt(0)).positiveValue) to
            unsigned(ASN1Integer.getInstance(sequence.getObjectAt(1)).positiveValue)
    }

    private fun checkHeader(authData: ByteArray, application: String, extraFlags: Int): Int {
        require(authData.size >= 37) { "authenticator data too short" }
        require(MessageDigest.isEqual(authData.copyOfRange(0, 32), HybridCrypto.sha256(application.toByteArray()))) {
            "the answer is for another application"
        }
        val flags = authData[32].toInt() and 0xff
        val required = AuthenticatorData.FLAG_USER_PRESENT or AuthenticatorData.FLAG_USER_VERIFIED or extraFlags
        require(flags and required == required) { "the phone did not verify the user" }
        return flags
    }

    private fun publicKey(cose: CborMap, algorithm: CoseAlgorithm): ByteArray {
        require((cose.get(uint(3)) as? Number)?.value?.toInt() == algorithm.id) { "public key algorithm mismatch" }
        val x = (cose.get(NegativeInteger(-2)) as? ByteString)?.bytes ?: throw IllegalArgumentException("no public key")
        return when (algorithm) {
            CoseAlgorithm.ES256 -> {
                val y = (cose.get(NegativeInteger(-3)) as? ByteString)?.bytes ?: throw IllegalArgumentException("no y")
                require(x.size == 32 && y.size == 32) { "invalid P-256 coordinates" }
                val point = byteArrayOf(4) + x + y
                HybridCrypto.decodeUncompressed(point)
                point
            }
            CoseAlgorithm.EDDSA -> x.also { require(it.size == 32) { "invalid Ed25519 key" } }
            else -> throw IllegalArgumentException("unsupported algorithm")
        }
    }

    private fun verify(algorithm: CoseAlgorithm, publicKey: ByteArray, message: ByteArray, signature: ByteArray) =
        runCatching {
            when (algorithm) {
                CoseAlgorithm.ES256 -> Signature.getInstance("SHA256withECDSA").run {
                    initVerify(HybridCrypto.decodeUncompressed(publicKey))
                    update(message)
                    verify(signature)
                }
                CoseAlgorithm.EDDSA -> Ed25519Signer().run {
                    init(false, Ed25519PublicKeyParameters(publicKey, 0))
                    update(message, 0, message.size)
                    verifySignature(signature)
                }
                else -> false
            }
        }.getOrDefault(false)

    private fun statusBody(response: ByteArray): CborMap {
        require(response.isNotEmpty()) { "empty CTAP response" }
        val status = response[0].toInt() and 0xff
        if (status != Ctap2Protocol.STATUS_OK) throw Failure(status)
        return decodeMap(response.copyOfRange(1, response.size))
    }

    private fun decodeMap(bytes: ByteArray): CborMap {
        CborBounds.check(bytes)
        return CborDecoder.decode(bytes).singleOrNull() as? CborMap
            ?: throw IllegalArgumentException("not a CBOR map")
    }

    private fun unsigned(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        val first = bytes.indexOfFirst { it != 0.toByte() }
        return if (first <= 0) bytes else bytes.copyOfRange(first, bytes.size)
    }

    private fun encode(item: DataItem): ByteArray = ByteArrayOutputStream().also {
        CborEncoder(it).encode(item)
    }.toByteArray()

    private fun uint(value: Long) = UnsignedInteger(value)
    private fun text(value: String) = UnicodeString(value)
}
