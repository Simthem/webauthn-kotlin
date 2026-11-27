package com.pqvault.desktop

import com.pqvault.core.hybrid.CableNoise
import com.pqvault.core.hybrid.CableTunnel
import com.pqvault.core.hybrid.Ctap2Protocol
import com.pqvault.core.hybrid.FidoQrCode
import com.pqvault.core.hybrid.HybridAdvert
import com.pqvault.core.hybrid.RemoteRequestPolicy
import com.pqvault.core.model.PasskeyEntry
import com.pqvault.core.webauthn.SoftwareAuthenticator
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/** The phone's side of a session, in memory, with the app's own protocol code. */
class PhoneSimulator(
    var verificationAvailable: Boolean = true,
    var approves: Boolean = true,
    /** Signs as a phone that skipped verification would, to show the computer refuses it. */
    var forgeUnverified: Boolean = false,
) : AdvertSource, TunnelConnector, Prompt {
    val vault = mutableListOf<PasskeyEntry>()
    val shownCodes = mutableListOf<String>()
    val stages = mutableListOf<HybridClient.Stage>()
    val failures = mutableListOf<String>()
    var completed = 0
    private val authenticator = SoftwareAuthenticator()
    private val routingId = byteArrayOf(0x01, 0x02, 0x03)
    private var qr: FidoQrCode.Payload? = null
    private var advertPlaintext: ByteArray? = null
    private var advertServiceData: ByteArray? = null

    override fun showCode(code: String, purpose: HybridClient.Purpose) {
        shownCodes += code
        val payload = requireNotNull(FidoQrCode.parse(code)) { "the phone could not read the code" }
        qr = payload
        val sealed = HybridAdvert.seal(payload.secret, routingId)
        advertPlaintext = sealed.plaintext
        advertServiceData = sealed.serviceData
    }

    override fun status(stage: HybridClient.Stage) {
        stages += stage
    }

    override fun done() {
        completed++
    }

    override fun failed(reason: String) {
        failures += reason
    }

    override fun await(accept: (ByteArray) -> HybridAdvert.Opened?, timeoutMillis: Long): HybridAdvert.Opened? {
        val strangerAdvert = HybridAdvert.seal(ByteArray(16) { 9 }, routingId).serviceData
        return accept(strangerAdvert) ?: accept(requireNotNull(advertServiceData))
    }

    override fun connect(url: String, timeoutMillis: Long): Tunnel {
        val payload = requireNotNull(qr)
        check(url == CableTunnel.connectUrl(payload.secret, 0, routingId)) { "unexpected tunnel $url" }
        val toComputer = LinkedBlockingQueue<ByteArray>()
        var noise: CableNoise? = null
        return object : Tunnel {
            override fun send(message: ByteArray) {
                val channel = noise
                if (channel == null) {
                    val psk = CableTunnel.psk(payload.secret, requireNotNull(advertPlaintext))
                    val handshake = CableNoise.respond(psk, payload.peerIdentity, message)
                    noise = handshake.transport
                    toComputer.put(handshake.response)
                    toComputer.put(handshake.transport.encrypt(Ctap2Protocol.postHandshakeMessage(verificationAvailable)))
                    return
                }
                val plaintext = channel.decrypt(message)
                check(plaintext[0].toInt() == 1) { "not a CTAP message" }
                val answer = answer(Ctap2Protocol.parse(plaintext.copyOfRange(1, plaintext.size)))
                toComputer.put(channel.encrypt(byteArrayOf(1) + answer))
            }

            override fun receive(timeoutMillis: Long): ByteArray =
                toComputer.poll(timeoutMillis, TimeUnit.MILLISECONDS) ?: throw HybridFailure("silent phone")

            override fun close() = Unit
        }
    }

    /** What VaultViewModel answers once the user has tapped and verified, or refused. */
    private fun answer(request: Ctap2Protocol.Request): ByteArray = when (request) {
        is Ctap2Protocol.Request.MakeCredential -> {
            when (val admission = RemoteRequestPolicy.admit(request, vault, verificationAvailable)) {
                is RemoteRequestPolicy.Creation.Refused -> Ctap2Protocol.error(admission.refusal.status)
                is RemoteRequestPolicy.Creation.Allowed -> if (!approves) {
                    Ctap2Protocol.error(Ctap2Protocol.STATUS_OPERATION_DENIED)
                } else {
                    val registration = RemoteRequestPolicy.register(
                        authenticator, request, admission.algorithm, verificationAvailable,
                    )
                    vault += registration.entry
                    Ctap2Protocol.makeCredentialResponse(registration)
                }
            }
        }
        is Ctap2Protocol.Request.GetAssertion -> {
            when (val selection = RemoteRequestPolicy.select(request, vault, verificationAvailable)) {
                is RemoteRequestPolicy.Assertion.Refused -> Ctap2Protocol.error(selection.refusal.status)
                is RemoteRequestPolicy.Assertion.Allowed -> if (!approves) {
                    Ctap2Protocol.error(Ctap2Protocol.STATUS_OPERATION_DENIED)
                } else {
                    val entry = selection.candidates.first()
                    val verified = verificationAvailable && !forgeUnverified
                    if (!forgeUnverified && !RemoteRequestPolicy.maySign(request, entry, verified)) {
                        Ctap2Protocol.error(Ctap2Protocol.STATUS_UNSUPPORTED_OPTION)
                    } else {
                        val assertion = authenticator.getAssertion(entry, request.clientDataHash, verified)
                        vault[vault.indexOf(entry)] = assertion.updatedEntry
                        Ctap2Protocol.getAssertionResponse(assertion, assertion.updatedEntry, false, verified)
                    }
                }
            }
        }
        Ctap2Protocol.Request.ListSshKeys -> {
            val keys = RemoteRequestPolicy.residentSshKeys(vault)
            when {
                !verificationAvailable -> Ctap2Protocol.error(Ctap2Protocol.STATUS_UNSUPPORTED_OPTION)
                keys.isEmpty() -> Ctap2Protocol.error(Ctap2Protocol.STATUS_NO_CREDENTIALS)
                !approves -> Ctap2Protocol.error(Ctap2Protocol.STATUS_OPERATION_DENIED)
                else -> Ctap2Protocol.sshKeyListResponse(keys)
            }
        }
        else -> Ctap2Protocol.error(Ctap2Protocol.STATUS_INVALID_COMMAND)
    }
}
