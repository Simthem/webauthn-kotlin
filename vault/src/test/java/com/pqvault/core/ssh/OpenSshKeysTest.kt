package com.pqvault.core.ssh

import com.google.common.truth.Truth.assertThat
import com.pqvault.core.format.Base64Url
import com.pqvault.core.model.CoseAlgorithm
import com.pqvault.core.webauthn.SoftwareAuthenticator
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

class OpenSshKeysTest {
    private val authenticator = SoftwareAuthenticator()

    private fun sshKey(
        algorithm: CoseAlgorithm = CoseAlgorithm.ES256,
        application: String = "ssh:",
        discoverable: Boolean = false,
    ) = authenticator.makeCredential(
        rpId = application,
        rpName = null,
        userHandle = ByteArray(32),
        userName = "openssh",
        userDisplayName = "openssh",
        clientDataHash = ByteArray(32),
        algorithm = algorithm,
        discoverable = discoverable,
    ).entry

    @Test
    fun `only applications starting with ssh are OpenSSH keys`() {
        assertThat(OpenSshKeys.isApplication("ssh:")).isTrue()
        assertThat(OpenSshKeys.isApplication("ssh:work")).isTrue()
        assertThat(OpenSshKeys.isApplication("github.com")).isFalse()
        assertThat(OpenSshKeys.isApplication("sshd.example.com")).isFalse()
    }

    @Test
    fun `the ECDSA public blob holds the type, curve, point and application`() {
        val entry = sshKey(application = "ssh:work")
        val blob = ByteBuffer.wrap(OpenSshKeys.publicKeyBlob(entry))

        assertThat(blob.string()).isEqualTo("sk-ecdsa-sha2-nistp256@openssh.com")
        assertThat(blob.string()).isEqualTo("nistp256")
        val point = blob.bytes()
        assertThat(point).hasLength(65)
        assertThat(point[0]).isEqualTo(4.toByte())
        assertThat(blob.string()).isEqualTo("ssh:work")
        assertThat(blob.hasRemaining()).isFalse()
    }

    @Test
    fun `the Ed25519 public blob holds the type, raw key and application`() {
        val entry = sshKey(algorithm = CoseAlgorithm.EDDSA)
        val blob = ByteBuffer.wrap(OpenSshKeys.publicKeyBlob(entry))

        assertThat(blob.string()).isEqualTo("sk-ssh-ed25519@openssh.com")
        assertThat(blob.bytes()).hasLength(32)
        assertThat(blob.string()).isEqualTo("ssh:")
        assertThat(blob.hasRemaining()).isFalse()
        assertThat(OpenSshKeys.label(entry)).isEqualTo("ED25519-SK")
        assertThat(OpenSshKeys.keyFileName(entry)).isEqualTo("id_ed25519_sk")
    }

    @Test
    fun `the fingerprint is the unpadded base64 SHA-256 of the blob`() {
        val entry = sshKey()
        val expected = Base64.getEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(OpenSshKeys.publicKeyBlob(entry)),
        )

        assertThat(OpenSshKeys.fingerprint(entry)).isEqualTo("SHA256:$expected")
    }

    @Test
    fun `the authorized_keys line drops control characters from the comment`() {
        val entry = sshKey()
        val line = OpenSshKeys.authorizedKeysLine(entry, "phone\nssh-rsa AAAA injected")

        assertThat(line).doesNotContain("\n")
        val fields = line.split(" ")
        assertThat(fields[0]).isEqualTo("sk-ecdsa-sha2-nistp256@openssh.com")
        assertThat(Base64.getDecoder().decode(fields[1])).isEqualTo(OpenSshKeys.publicKeyBlob(entry))
        assertThat(OpenSshKeys.authorizedKeysLine(entry, " ").split(" ")).hasSize(2)
    }

    @Test
    fun `the key file carries the key handle and flags but no private key`() {
        val entry = sshKey(discoverable = true)
        val file = OpenSshKeys.keyFile(entry, "pq-vault", SecureRandom())
        val lines = file.trimEnd().lines()

        assertThat(lines.first()).isEqualTo(OpenSshKeys.KEY_FILE_BEGIN)
        assertThat(lines.last()).isEqualTo(OpenSshKeys.KEY_FILE_END)
        assertThat(lines.drop(1).dropLast(1).all { it.length <= 70 }).isTrue()

        val decoded = Base64.getDecoder().decode(lines.drop(1).dropLast(1).joinToString(""))
        val buffer = ByteBuffer.wrap(decoded)
        val magic = ByteArray(15).also(buffer::get)
        assertThat(String(magic, Charsets.US_ASCII)).isEqualTo("openssh-key-v1\u0000")
        assertThat(buffer.string()).isEqualTo("none")
        assertThat(buffer.string()).isEqualTo("none")
        assertThat(buffer.bytes()).isEmpty()
        assertThat(buffer.int).isEqualTo(1)
        assertThat(buffer.bytes()).isEqualTo(OpenSshKeys.publicKeyBlob(entry))

        val private = ByteBuffer.wrap(buffer.bytes())
        assertThat(buffer.hasRemaining()).isFalse()
        assertThat(private.capacity() % 8).isEqualTo(0)
        assertThat(private.int).isEqualTo(private.int)
        assertThat(private.string()).isEqualTo("sk-ecdsa-sha2-nistp256@openssh.com")
        assertThat(private.string()).isEqualTo("nistp256")
        assertThat(private.bytes()).hasLength(65)
        assertThat(private.string()).isEqualTo("ssh:")
        assertThat(private.get().toInt() and 0xff).isEqualTo(0x25)
        assertThat(private.bytes()).isEqualTo(Base64Url.decode(entry.credentialId))
        assertThat(private.bytes()).isEmpty()
        assertThat(private.string()).isEqualTo("pq-vault")
        var padding = 1
        while (private.hasRemaining()) assertThat(private.get().toInt()).isEqualTo(padding++)

        val scalar = (
            KeyFactory.getInstance("EC")
                .generatePrivate(PKCS8EncodedKeySpec(Base64Url.decode(entry.privateKeyPkcs8))) as ECPrivateKey
            ).s.toByteArray().takeLast(32)
        assertThat(decoded.asList().windowed(scalar.size).any { it == scalar }).isFalse()
    }

    @Test
    fun `a non-resident key is exported without the resident flag`() {
        assertThat(OpenSshKeys.flags(sshKey(discoverable = false))).isEqualTo(0x05)
    }

    @Test
    fun `a website passkey is not an OpenSSH key`() {
        val passkey = sshKey(application = "github.com")

        assertThrows<IllegalArgumentException> { OpenSshKeys.publicKeyBlob(passkey) }
    }

    private fun ByteBuffer.bytes(): ByteArray = ByteArray(int).also(::get)

    private fun ByteBuffer.string(): String = String(bytes(), Charsets.UTF_8)

    @Test
    fun `the copied line makes the server require verification too`() {
        val entry = sshKey(algorithm = CoseAlgorithm.EDDSA)

        assertThat(OpenSshKeys.verifyRequiredLine(entry, "pq-vault"))
            .isEqualTo("verify-required " + OpenSshKeys.authorizedKeysLine(entry, "pq-vault"))
        assertThat(OpenSshKeys.rawPublicKey(entry)).hasLength(32)
        assertThat(OpenSshKeys.rawPublicKey(sshKey())).hasLength(65)
    }
}
