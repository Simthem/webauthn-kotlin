package com.pqvault.desktop

import com.pqvault.core.hybrid.CableTunnel
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/** The tunnel relay over a WebSocket. It only ever sees the Noise-encrypted records. */
class WebSocketTunnels(
    // No ping watchdog: the relay does not answer pings while the phone is being found.
    private val client: OkHttpClient = OkHttpClient.Builder().readTimeout(0, TimeUnit.MILLISECONDS).build(),
) : TunnelConnector {

    private sealed interface Event {
        data object Opened : Event
        class Message(val bytes: ByteArray) : Event
        class Ended(val reason: String) : Event
    }

    override fun connect(url: String, timeoutMillis: Long): Tunnel {
        require(url.startsWith("wss://")) { "the tunnel must use TLS" }
        val events = LinkedBlockingQueue<Event>()
        val socket = client.newWebSocket(
            Request.Builder().url(url).header("Sec-WebSocket-Protocol", CableTunnel.PROTOCOL).build(),
            object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    events.put(Event.Opened)
                }

                override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                    events.put(Event.Message(bytes.toByteArray()))
                }

                override fun onMessage(webSocket: WebSocket, text: String) {
                    events.put(Event.Ended("the tunnel sent an unexpected text message"))
                }

                override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                    events.put(Event.Ended("the tunnel closed"))
                }

                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    events.put(Event.Ended("the tunnel failed: ${t.message ?: response?.code}"))
                }
            },
        )
        when (val first = events.poll(timeoutMillis, TimeUnit.MILLISECONDS)) {
            Event.Opened -> Unit
            is Event.Ended -> {
                socket.cancel()
                throw HybridFailure(first.reason)
            }
            else -> {
                socket.cancel()
                throw HybridFailure("the tunnel did not open in time")
            }
        }

        return object : Tunnel {
            override fun send(message: ByteArray) {
                if (!socket.send(message.toByteString())) throw HybridFailure("the tunnel is closed")
            }

            override fun receive(timeoutMillis: Long): ByteArray =
                when (val event = events.poll(timeoutMillis, TimeUnit.MILLISECONDS)) {
                    is Event.Message -> event.bytes
                    is Event.Ended -> throw HybridFailure(event.reason)
                    else -> throw HybridFailure("the phone did not answer in time")
                }

            override fun close() {
                socket.close(1000, null)
            }
        }
    }
}
