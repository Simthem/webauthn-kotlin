package com.pqvault.app.diagnostics

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DiagnosticLogTest {
    @Test
    fun `diagnostics redact URLs and long token-like values`() {
        val value = DiagnosticLog.sanitize(
            "failed at wss://relay.example/path/0123456789abcdef0123456789abcdef token " +
                "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
        )

        assertFalse(value.contains("relay.example"))
        assertFalse(value.contains("abcdefghijklmnopqrstuvwxyz"))
        assertTrue(value.contains("<url-redacted>"))
        assertTrue(value.contains("<token-redacted>"))
    }
}
