package com.pqvault.desktop

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.Test

class CallerProcessTest {

    @Test
    fun `ssh is summarised as its destination and nothing after it`() {
        assertThat(CallerProcess.summarise("ssh", listOf("-p", "2222", "-v", "git@host.example", "cat", "secret")))
            .isEqualTo("ssh git@host.example")
        assertThat(CallerProcess.summarise("ssh", listOf("-oBatchMode=yes", "--", "host.example"))).isEqualTo("ssh host.example")
        assertThat(CallerProcess.summarise("ssh", listOf("-i", "key"))).isEqualTo("ssh")
    }

    @Test
    fun `other programs are named without their arguments`() {
        assertThat(CallerProcess.summarise("ssh-keygen", listOf("-Y", "sign", "-f", "key"))).isEqualTo("ssh-keygen")
    }
}
