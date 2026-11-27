package com.pqvault.core.ssh

import com.google.common.truth.Truth.assertThat
import com.pqvault.core.hybrid.Ctap2Client
import com.pqvault.core.hybrid.Ctap2Protocol
import com.pqvault.core.hybrid.HybridCrypto
import com.pqvault.core.hybrid.RemoteRequestPolicy
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream

class SshSignedDataTest {

    private fun ByteArrayOutputStream.string(bytes: ByteArray) {
        write(byteArrayOf((bytes.size ushr 24).toByte(), (bytes.size ushr 16).toByte(), (bytes.size ushr 8).toByte(), bytes.size.toByte()))
        write(bytes)
    }

    private fun ByteArrayOutputStream.string(text: String) = string(text.toByteArray())

    private fun login(user: String, method: String = "publickey", hostKey: ByteArray? = null) =
        ByteArrayOutputStream().apply {
            string(ByteArray(32) { 1 })
            write(50)
            string(user)
            string("ssh-connection")
            string(method)
            write(1)
            string("sk-ssh-ed25519@openssh.com")
            string(ByteArray(40) { 2 })
            hostKey?.let { string(it) }
        }.toByteArray()

    private fun signature(namespace: String) = ByteArrayOutputStream().apply {
        write("SSHSIG".toByteArray())
        string(namespace)
        string("")
        string("sha512")
        string(ByteArray(64) { 3 })
    }.toByteArray()

    @Test
    fun `a login names the user and, when host-bound, the server key`() {
        assertThat(SshSignedData.parse(login("git"))).isEqualTo(SshSignedData.Login("git", "ssh-connection", null))

        val hostKey = ByteArray(51) { 4 }
        val bound = SshSignedData.parse(login("git", "publickey-hostbound-v00@openssh.com", hostKey)) as SshSignedData.Login
        assertThat(bound.serverHostKey).startsWith("SHA256:")
    }

    @Test
    fun `a Git signature gives its namespace`() {
        assertThat(SshSignedData.parse(signature("git"))).isEqualTo(SshSignedData.Signature("git"))
    }

    @Test
    fun `anything else, or text that could mislead, is not identified`() {
        assertThat(SshSignedData.parse("ssh userauth".toByteArray())).isNull()
        assertThat(SshSignedData.parse(login("root‮git"))).isNull()
        assertThat(SshSignedData.parse(login("git") + byteArrayOf(0))).isNull()
        assertThat(SshSignedData.parse(signature("git\n"))).isNull()
    }

    @Test
    fun `the operation counts only when its hash is the signed one`() {
        val data = login("deploy")
        val request = Ctap2Protocol.parse(
            Ctap2Client.getAssertion("ssh:", HybridCrypto.sha256(data), ByteArray(32), data, "ssh host.example"),
        ) as Ctap2Protocol.Request.GetAssertion
        assertThat(RemoteRequestPolicy.sshOperation(request)).isEqualTo(SshSignedData.Login("deploy", "ssh-connection", null))
        assertThat(RemoteRequestPolicy.declaredCaller(request)).isEqualTo("ssh host.example")

        val lying = Ctap2Protocol.parse(
            Ctap2Client.getAssertion("ssh:", HybridCrypto.sha256(signature("git")), ByteArray(32), data),
        ) as Ctap2Protocol.Request.GetAssertion
        assertThat(RemoteRequestPolicy.sshOperation(lying)).isNull()
    }
}
