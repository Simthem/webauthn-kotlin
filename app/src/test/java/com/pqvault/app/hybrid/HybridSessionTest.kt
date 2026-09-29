package com.pqvault.app.hybrid

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.Test

class HybridSessionTest {

    @Test
    fun `caBLE tunnel does not install an okhttp ping watchdog`() {
        val client = HybridSession.defaultClient()

        assertThat(client.pingIntervalMillis).isEqualTo(0)
        assertThat(client.readTimeoutMillis).isEqualTo(0)
    }
}
