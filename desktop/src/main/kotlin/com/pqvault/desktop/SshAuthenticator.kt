package com.pqvault.desktop

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.ByteString
import com.pqvault.core.hybrid.Ctap2Client
import com.pqvault.core.hybrid.Ctap2Protocol
import com.pqvault.core.hybrid.HybridCrypto
import com.pqvault.core.model.CoseAlgorithm
import com.pqvault.core.ssh.OpenSshKeys
import java.io.ByteArrayOutputStream

/** OpenSSH enrolments and signatures carried out by the phone, always with user verification. */
class SshAuthenticator(private val client: HybridClient, private val prompt: Prompt) {

    fun handle(request: HelperProtocol.Request): HelperProtocol.Response = try {
        require(OpenSshKeys.isApplication(request.application)) { "the application must start with ssh:" }
        when (request.operation) {
            HelperProtocol.OP_ENROLL -> enrol(request)
            HelperProtocol.OP_SIGN -> sign(request)
            else -> list()
        }
    } catch (failure: Ctap2Client.Failure) {
        prompt.failed(describe(failure.status))
        HelperProtocol.Response.Failed(error(failure.status))
    } catch (failure: HybridFailure) {
        prompt.failed(failure.message ?: "the request failed")
        HelperProtocol.Response.Failed(failure.error)
    } catch (failure: Exception) {
        prompt.failed(failure.message ?: "the request failed")
        HelperProtocol.Response.Failed(HelperProtocol.ERR_GENERAL)
    }

    private fun enrol(request: HelperProtocol.Request): HelperProtocol.Response {
        val algorithm = algorithm(request.algorithm)
        require(request.handle.size < USER_ID_SIZE) { "the user ID is too long" }
        val userId = request.handle.copyOf(USER_ID_SIZE)
        val resident = request.flags and OpenSshKeys.FLAG_RESIDENT_KEY != 0
        val verifyRequired = request.flags and OpenSshKeys.FLAG_USER_VERIFICATION_REQUIRED != 0
        val credentialProtection = when {
            verifyRequired -> 3
            resident -> 2
            else -> null
        }
        val clientDataHash = HybridCrypto.sha256(request.message)
        val response = client.exchange(
            Ctap2Client.makeCredential(
                request.application, clientDataHash, userId, algorithm, resident, credentialProtection,
            ),
            HybridClient.Purpose.Enrol,
        )
        val credential = Ctap2Client.parseCredential(
            response, request.application, clientDataHash, algorithm, credentialProtection,
        )
        prompt.done()
        return HelperProtocol.Response.Enrolled(
            flags = request.flags,
            publicKey = credential.publicKey,
            keyHandle = credential.credentialId,
            signature = credential.attestationSignature,
            authenticatorData = ByteArrayOutputStream().also {
                CborEncoder(it).encode(ByteString(credential.authenticatorData))
            }.toByteArray(),
        )
    }

    private fun sign(request: HelperProtocol.Request): HelperProtocol.Response {
        val algorithm = algorithm(request.algorithm)
        require(request.handle.isNotEmpty()) { "no key handle" }
        val response = client.exchange(
            Ctap2Client.getAssertion(request.application, HybridCrypto.sha256(request.message), request.handle),
            HybridClient.Purpose.SignIn,
        )
        val assertion = Ctap2Client.parseAssertion(response, request.application, request.handle)
        val (r, s) = when (algorithm) {
            CoseAlgorithm.ES256 -> Ctap2Client.ecdsaComponents(assertion.signature)
            else -> {
                require(assertion.signature.size == 64) { "malformed Ed25519 signature" }
                assertion.signature to ByteArray(0)
            }
        }
        prompt.done()
        return HelperProtocol.Response.Signed(assertion.flags, assertion.counter, r, s)
    }

    /** What `ssh-keygen -K` downloads: every resident SSH key, public parts only. */
    private fun list(): HelperProtocol.Response {
        val response = client.exchange(Ctap2Client.listSshKeys(), HybridClient.Purpose.ListKeys)
        val keys = try {
            Ctap2Client.parseSshKeyList(response)
        } catch (failure: Ctap2Client.Failure) {
            if (failure.status != Ctap2Protocol.STATUS_NO_CREDENTIALS) throw failure
            emptyList()
        }
        prompt.done()
        return HelperProtocol.Response.Listed(
            keys.map { key ->
                HelperProtocol.Response.Listed.Key(
                    algorithm = if (key.algorithm == CoseAlgorithm.ES256) HelperProtocol.ALG_ECDSA else HelperProtocol.ALG_ED25519,
                    application = key.application,
                    flags = OpenSshKeys.FLAG_USER_PRESENCE_REQUIRED or OpenSshKeys.FLAG_USER_VERIFICATION_REQUIRED or
                        OpenSshKeys.FLAG_RESIDENT_KEY,
                    publicKey = key.publicKey,
                    keyHandle = key.credentialId,
                    userId = key.userId,
                )
            },
        )
    }

    private fun algorithm(number: Int) =
        if (number == HelperProtocol.ALG_ECDSA) CoseAlgorithm.ES256 else CoseAlgorithm.EDDSA

    private fun error(status: Int) = when (status) {
        Ctap2Protocol.STATUS_NO_CREDENTIALS -> HelperProtocol.ERR_DEVICE_NOT_FOUND
        Ctap2Protocol.STATUS_CREDENTIAL_EXCLUDED -> HelperProtocol.ERR_CREDENTIAL_EXISTS
        Ctap2Protocol.STATUS_UNSUPPORTED_ALGORITHM, Ctap2Protocol.STATUS_UNSUPPORTED_OPTION ->
            HelperProtocol.ERR_UNSUPPORTED
        else -> HelperProtocol.ERR_GENERAL
    }

    private fun describe(status: Int) = when (status) {
        Ctap2Protocol.STATUS_NO_CREDENTIALS -> "this key is not in the vault on that phone"
        Ctap2Protocol.STATUS_CREDENTIAL_EXCLUDED -> "this key is already in the vault"
        Ctap2Protocol.STATUS_OPERATION_DENIED, Ctap2Protocol.STATUS_KEEPALIVE_CANCEL -> "refused on the phone"
        Ctap2Protocol.STATUS_UNSUPPORTED_OPTION -> "the phone could not verify you"
        Ctap2Protocol.STATUS_UNSUPPORTED_ALGORITHM -> "the phone does not support this key type"
        Ctap2Protocol.STATUS_KEY_STORE_FULL -> "the vault is full"
        else -> "the phone answered status 0x%02x".format(status)
    }

    private companion object {
        /** OpenSSH's user ID field: 32 bytes, the given value then zeros. */
        const val USER_ID_SIZE = 32
    }
}
