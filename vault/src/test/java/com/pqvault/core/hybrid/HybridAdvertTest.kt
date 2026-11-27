package com.pqvault.core.hybrid

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class HybridAdvertTest {
    private val secret = ByteArray(16).also(SecureRandom()::nextBytes)
    private val routingId = byteArrayOf(0x0a, 0x0b, 0x0c)

    @Test
    fun `the computer reads the routing ID and tunnel domain the phone sealed`() {
        val sealed = HybridAdvert.seal(secret, routingId, tunnelDomainId = 1)
        val opened = HybridAdvert.open(secret, sealed.serviceData)

        assertThat(sealed.serviceData).hasLength(HybridAdvert.SERVICE_DATA_SIZE)
        assertThat(opened).isNotNull()
        assertThat(opened!!.routingId).isEqualTo(routingId)
        assertThat(opened.tunnelDomainId).isEqualTo(1)
        assertThat(opened.plaintext).isEqualTo(sealed.plaintext)
    }

    @Test
    fun `an advert sealed for another code or altered in flight is ignored`() {
        val sealed = HybridAdvert.seal(secret, routingId)
        val otherSecret = ByteArray(16).also(SecureRandom()::nextBytes)

        assertThat(HybridAdvert.open(otherSecret, sealed.serviceData)).isNull()
        for (index in sealed.serviceData.indices) {
            val altered = sealed.serviceData.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }
            assertThat(HybridAdvert.open(secret, altered)).isNull()
        }
        assertThat(HybridAdvert.open(secret, sealed.serviceData.copyOf(19))).isNull()
    }

    @Test
    fun `an advert that is not QR initiated is ignored even with a valid tag`() {
        val keys = HybridCrypto.derive(secret, purpose = 1, length = 64)
        val plaintext = ByteArray(16).also { it[0] = 1 }
        val ciphertext = HybridCrypto.aesEncryptBlock(keys.copyOfRange(0, 32), plaintext)
        val tag = HybridCrypto.hmacSha256(keys.copyOfRange(32, 64), ciphertext).copyOf(4)

        assertThat(HybridAdvert.open(secret, ciphertext + tag)).isNull()
    }

    @Test
    fun `the tunnel helpers keep the phone's URL and derive the handshake key from the advert`() {
        val tunnelId = HybridCrypto.derive(secret, purpose = 2, length = 16)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val advert = HybridAdvert.seal(secret, routingId).plaintext

        assertThat(CableTunnel.newTunnelUrl(secret)).isEqualTo("wss://cable.ua5v.com/cable/new/$tunnelId")
        assertThat(CableTunnel.connectUrl(secret, 0, routingId))
            .isEqualTo("wss://cable.ua5v.com/cable/connect/0a0b0c/$tunnelId")
        assertThat(CableTunnel.connectUrl(secret, 7, routingId)).isNull()
        assertThat(CableTunnel.psk(secret, advert))
            .isEqualTo(HybridCrypto.derive(secret, salt = advert, purpose = 3, length = 32))
    }
}
