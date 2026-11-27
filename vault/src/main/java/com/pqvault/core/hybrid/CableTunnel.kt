package com.pqvault.core.hybrid

/** Where the phone and the computer meet, and the handshake key derived from the QR secret. */
object CableTunnel {
    const val PROTOCOL = "fido.cable"
    const val ROUTING_ID_HEADER = "X-caBLE-Routing-ID"

    fun tunnelId(secret: ByteArray): ByteArray = HybridCrypto.derive(secret, purpose = 2, length = 16)

    /** Bound to both the QR secret and the advert the computer actually received. */
    fun psk(secret: ByteArray, advertPlaintext: ByteArray): ByteArray =
        HybridCrypto.derive(secret, salt = advertPlaintext, purpose = 3, length = 32)

    /** The two tunnel services every hybrid client knows by number. Others are refused. */
    fun domain(id: Int): String? = when (id) {
        0 -> "cable.ua5v.com"
        1 -> "cable.auth.com"
        else -> null
    }

    fun newTunnelUrl(secret: ByteArray, domainId: Int = 0): String =
        "wss://${requireNotNull(domain(domainId))}/cable/new/${hex(tunnelId(secret))}"

    fun connectUrl(secret: ByteArray, domainId: Int, routingId: ByteArray): String? {
        val domain = domain(domainId) ?: return null
        require(routingId.size == 3)
        return "wss://$domain/cable/connect/${hex(routingId)}/${hex(tunnelId(secret))}"
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
