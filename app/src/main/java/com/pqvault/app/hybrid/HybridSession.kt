package com.pqvault.app.hybrid

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.pqvault.core.hybrid.CableNoise
import com.pqvault.core.hybrid.Ctap2Protocol
import com.pqvault.core.hybrid.FidoQrCode
import com.pqvault.core.hybrid.HybridCrypto
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** One QR-initiated cross-device WebAuthn transaction. */
class HybridSession(
    context: Context,
    private val qr: FidoQrCode.Payload,
    private val userVerificationAvailable: Boolean,
    private val listener: Listener,
    private val client: OkHttpClient = defaultClient(),
) : WebSocketListener() {
    interface Listener {
        fun onStatus(status: Status)
        fun onRequest(request: Ctap2Protocol.Request)
        fun onFinished()
        fun onError(message: String)
    }

    enum class Status { Connecting, WaitingForComputer, SecuringConnection, WaitingForApproval }

    private val advertiser = HybridBleAdvertiser(context)
    private val handler = Handler(Looper.getMainLooper())
    private val finished = AtomicBoolean(false)
    private val lock = Any()
    private var socket: WebSocket? = null
    private var noise: CableNoise? = null
    private var handshakePsk: ByteArray? = null
    private var requestPending = false
    @Volatile private var responseSent = false

    fun start() {
        if (!qr.supportsWebSocket) {
            fail("This FIDO code does not offer the WebSocket transport")
            return
        }
        listener.onStatus(Status.Connecting)
        val tunnelId = HybridCrypto.derive(qr.secret, purpose = 2, length = 16).toHex()
        val request = Request.Builder()
            .url("wss://$DEFAULT_TUNNEL_DOMAIN/cable/new/$tunnelId")
            .header("Sec-WebSocket-Protocol", "fido.cable")
            .build()
        Log.d(TAG, "connecting to tunnel $DEFAULT_TUNNEL_DOMAIN")
        socket = client.newWebSocket(request, this)
        handler.postDelayed({ fail("The cross-device request timed out") }, SESSION_TIMEOUT_MS)
    }

    override fun onOpen(webSocket: WebSocket, response: Response) {
        Log.d(TAG, "tunnel open (${response.code}, protocol ${response.header("Sec-WebSocket-Protocol")})")
        val routingId = response.header(ROUTING_ID_HEADER)?.hexToBytes()
        if (routingId == null || routingId.size != 3) {
            fail("The tunnel did not return a valid routing ID")
            return
        }
        advertiser.start(qr.secret, routingId) { code ->
            fail("Bluetooth advertising failed ($code)")
        }.fold(
            onSuccess = { plaintextAdvert ->
                handshakePsk = HybridCrypto.derive(
                    secret = qr.secret,
                    salt = plaintextAdvert,
                    purpose = 3,
                    length = 32,
                )
                listener.onStatus(Status.WaitingForComputer)
            },
            onFailure = { fail(it.message ?: "Bluetooth advertising failed") },
        )
    }

    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
        Log.d(TAG, "tunnel message of ${bytes.size} bytes, secured=${noise != null}")
        runCatching { handleMessage(bytes.toByteArray()) }
            .onFailure {
                Log.w(TAG, "message handling failed", it)
                fail(it.message ?: "Invalid encrypted message")
            }
    }

    override fun onMessage(webSocket: WebSocket, text: String) {
        fail("The tunnel sent an unexpected text message")
    }

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        Log.w(TAG, "tunnel failed (http ${response?.code}, secured=${noise != null})", t)
        if (responseSent) finish() else fail(t.message ?: "The hybrid tunnel failed")
    }

    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
        Log.d(TAG, "tunnel closed ($code, $reason), responseSent=$responseSent")
        if (finished.compareAndSet(false, true)) {
            cleanup()
            if (responseSent) {
                listener.onFinished()
            } else {
                listener.onError("The hybrid tunnel closed before the request completed")
            }
        }
    }

    fun respond(ctapResponse: ByteArray) {
        synchronized(lock) {
            if (!requestPending) return
            requestPending = false
            sendEncrypted(byteArrayOf(MESSAGE_TYPE_CTAP.toByte()) + ctapResponse)
            responseSent = true
        }
    }

    fun cancelPending() {
        respond(Ctap2Protocol.error(Ctap2Protocol.STATUS_KEEPALIVE_CANCEL))
    }

    fun close() {
        if (finished.compareAndSet(false, true)) {
            socket?.close(1000, "cancelled")
            cleanup()
        }
    }

    private fun handleMessage(message: ByteArray) = synchronized(lock) {
        if (finished.get()) return
        val activeNoise = noise
        if (activeNoise == null) {
            listener.onStatus(Status.SecuringConnection)
            val psk = handshakePsk ?: error("hybrid proximity proof is not ready")
            val handshake = CableNoise.respond(psk, qr.peerIdentity, message)
            noise = handshake.transport
            advertiser.stop()

            check(socket?.send(handshake.response.toByteString()) == true) {
                "could not send the hybrid handshake"
            }
            val postHandshake = handshake.transport.encrypt(
                Ctap2Protocol.postHandshakeMessage(userVerificationAvailable),
            )
            check(socket?.send(postHandshake.toByteString()) == true) {
                "could not send hybrid capabilities"
            }
            Log.d(TAG, "handshake complete, post-handshake message sent")
            return
        }

        val plaintext = activeNoise.decrypt(message)
        require(plaintext.isNotEmpty()) { "empty hybrid tunnel message" }
        when (plaintext[0].toInt() and 0xff) {
            MESSAGE_TYPE_SHUTDOWN -> close()
            MESSAGE_TYPE_CTAP -> handleCtap(plaintext.copyOfRange(1, plaintext.size))
            else -> throw IllegalArgumentException("unsupported hybrid message type")
        }
    }

    private fun handleCtap(packet: ByteArray) {
        Log.d(TAG, "ctap command 0x${"%02x".format(packet.firstOrNull() ?: 0)}")
        val request = try {
            Ctap2Protocol.parse(packet)
        } catch (_: Exception) {
            sendEncrypted(
                byteArrayOf(MESSAGE_TYPE_CTAP.toByte()) +
                    Ctap2Protocol.error(Ctap2Protocol.STATUS_INVALID_CBOR),
            )
            return
        }
        when (request) {
            Ctap2Protocol.Request.GetInfo -> sendEncrypted(
                byteArrayOf(MESSAGE_TYPE_CTAP.toByte()) +
                    Ctap2Protocol.getInfoResponse(userVerificationAvailable),
            )
            Ctap2Protocol.Request.Selection -> sendEncrypted(
                byteArrayOf(MESSAGE_TYPE_CTAP.toByte()) + Ctap2Protocol.success(),
            )
            Ctap2Protocol.Request.Cancel -> {
                if (requestPending) {
                    requestPending = false
                }
                finish()
            }
            is Ctap2Protocol.Request.Unknown -> sendEncrypted(
                byteArrayOf(MESSAGE_TYPE_CTAP.toByte()) +
                    Ctap2Protocol.error(Ctap2Protocol.STATUS_INVALID_COMMAND),
            )
            is Ctap2Protocol.Request.MakeCredential,
            is Ctap2Protocol.Request.GetAssertion,
            -> {
                if (requestPending) {
                    sendEncrypted(
                        byteArrayOf(MESSAGE_TYPE_CTAP.toByte()) +
                            Ctap2Protocol.error(Ctap2Protocol.STATUS_OPERATION_DENIED),
                    )
                } else {
                    requestPending = true
                    listener.onStatus(Status.WaitingForApproval)
                    listener.onRequest(request)
                }
            }
        }
    }

    private fun sendEncrypted(plaintext: ByteArray) {
        val encrypted = noise?.encrypt(plaintext) ?: error("hybrid channel is not secured")
        check(socket?.send(encrypted.toByteString()) == true) { "could not send to the hybrid tunnel" }
    }

    private fun fail(message: String) {
        if (finished.compareAndSet(false, true)) {
            socket?.cancel()
            cleanup()
            listener.onError(message)
        }
    }

    private fun finish() {
        if (finished.compareAndSet(false, true)) {
            socket?.close(1000, "complete")
            cleanup()
            listener.onFinished()
        }
    }

    private fun cleanup() {
        handler.removeCallbacksAndMessages(null)
        advertiser.stop()
        socket = null
        noise = null
        handshakePsk?.fill(0)
        handshakePsk = null
    }

    private fun String.hexToBytes(): ByteArray? = runCatching {
        require(length % 2 == 0 && all { it.isDigit() || it.lowercaseChar() in 'a'..'f' })
        ByteArray(length / 2) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }.getOrNull()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

    companion object {
        private const val TAG = "HybridSession"
        private const val DEFAULT_TUNNEL_DOMAIN = "cable.ua5v.com"
        private const val ROUTING_ID_HEADER = "X-caBLE-Routing-ID"
        private const val MESSAGE_TYPE_SHUTDOWN = 0
        private const val MESSAGE_TYPE_CTAP = 1
        private const val SESSION_TIMEOUT_MS = 180_000L

        private fun defaultClient() = OkHttpClient.Builder()
            .pingInterval(20, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .build()
    }
}
