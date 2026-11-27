package com.pqvault.desktop

import com.pqvault.core.hybrid.CableNoise
import com.pqvault.core.hybrid.CableTunnel
import com.pqvault.core.hybrid.Ctap2Client
import com.pqvault.core.hybrid.FidoQrCode
import com.pqvault.core.hybrid.HybridAdvert
import com.pqvault.core.hybrid.HybridCrypto
import java.io.Closeable
import java.security.SecureRandom

/** Encrypted BLE service data seen nearby, offered until [accept] recognises one. */
fun interface AdvertSource {
    fun await(accept: (ByteArray) -> HybridAdvert.Opened?, timeoutMillis: Long): HybridAdvert.Opened?
}

interface Tunnel : Closeable {
    fun send(message: ByteArray)

    /** The next binary message, or an exception when the tunnel closed or time ran out. */
    fun receive(timeoutMillis: Long): ByteArray
}

fun interface TunnelConnector {
    fun connect(url: String, timeoutMillis: Long): Tunnel
}

interface Prompt {
    fun showCode(code: String, purpose: HybridClient.Purpose)
    fun status(stage: HybridClient.Stage)
    fun done()
    fun failed(reason: String)
}

class HybridFailure(message: String, val error: Int = HelperProtocol.ERR_GENERAL) : Exception(message)

/** One request to the phone: QR code, proximity proof, tunnel, handshake, one CTAP exchange. */
class HybridClient(
    private val adverts: AdvertSource,
    private val tunnels: TunnelConnector,
    private val prompt: Prompt,
    private val random: SecureRandom = SecureRandom(),
    private val timeoutMillis: Long = TIMEOUT_MILLIS,
) {
    enum class Stage { WaitingForPhone, Connecting, WaitingForApproval }

    enum class Purpose { Enrol, SignIn, ListKeys }

    fun exchange(request: ByteArray, purpose: Purpose): ByteArray {
        val deadline = System.currentTimeMillis() + timeoutMillis
        fun remaining() = (deadline - System.currentTimeMillis()).also {
            if (it <= 0) throw HybridFailure("the phone did not answer in time")
        }

        val identity = HybridCrypto.generateP256KeyPair()
        val secret = ByteArray(16).also(random::nextBytes)
        val hint = if (purpose == Purpose.Enrol) FidoQrCode.RequestType.MakeCredential else FidoQrCode.RequestType.GetAssertion
        prompt.showCode(FidoQrCode.encode(identity.public, secret, hint), purpose)
        prompt.status(Stage.WaitingForPhone)

        val advert = adverts.await({ HybridAdvert.open(secret, it) }, remaining())
            ?: throw HybridFailure("no phone answered the code nearby")
        val url = CableTunnel.connectUrl(secret, advert.tunnelDomainId, advert.routingId)
            ?: throw HybridFailure("the phone asked for an unknown tunnel service")

        prompt.status(Stage.Connecting)
        tunnels.connect(url, remaining()).use { tunnel ->
            val initiator = CableNoise.initiate(CableTunnel.psk(secret, advert.plaintext), identity)
            tunnel.send(initiator.message)
            val channel = initiator.finish(tunnel.receive(remaining()))
            val info = Ctap2Client.parseInfo(channel.decrypt(tunnel.receive(remaining())))
            if (!info.userVerification) {
                throw HybridFailure("the phone has no secure screen lock", HelperProtocol.ERR_UNSUPPORTED)
            }
            prompt.status(Stage.WaitingForApproval)
            tunnel.send(channel.encrypt(Ctap2Client.tunnelMessage(request)))
            return Ctap2Client.fromTunnel(channel.decrypt(tunnel.receive(remaining())))
        }
    }

    companion object {
        /** A little under the phone's own three minutes, so the phone is never left waiting. */
        const val TIMEOUT_MILLIS = 170_000L
    }
}
