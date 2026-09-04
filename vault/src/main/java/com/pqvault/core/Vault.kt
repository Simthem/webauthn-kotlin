package com.pqvault.core

import com.pqvault.core.crypto.Argon2id
import com.pqvault.core.crypto.HybridKem
import com.pqvault.core.crypto.HybridSignature
import com.pqvault.core.crypto.XChaCha20Poly1305
import com.pqvault.core.format.Base64Url
import com.pqvault.core.format.KdfParams
import com.pqvault.core.format.Recipient
import com.pqvault.core.format.VaultContent
import com.pqvault.core.format.VaultFile
import com.pqvault.core.format.VaultHeader
import com.pqvault.core.model.DeviceRecord
import com.pqvault.core.model.PasskeyEntry
import com.pqvault.core.model.Tombstone
import kotlinx.serialization.json.Json
import java.security.SecureRandom

private const val PASSPHRASE_WRAP_AAD = "pqvault/recipient/passphrase/v1"
private const val DEVICE_WRAP_AAD = "pqvault/recipient/device/v1"
private const val WRAPPED_VMK_SIZE = XChaCha20Poly1305.KEY_SIZE + XChaCha20Poly1305.TAG_SIZE
private const val MIN_KDF_SALT_SIZE = 16
private const val MAX_KDF_SALT_SIZE = 64
private const val MAX_RECIPIENTS = 64

/**
 * Everything needed to read and modify a vault that has been successfully unlocked.
 *
 * The vault master key stays in memory for the lifetime of this object; call [close]
 * when locking so it does not linger.
 */
class UnlockedVault internal constructor(
    private val vmk: ByteArray,
    var vaultVersion: Long,
    private var recipients: MutableList<Recipient>,
    content: VaultContent,
    val signingPublicKeyEncoded: ByteArray,
) {
    var entries: MutableList<PasskeyEntry> = content.entries.toMutableList()
        private set
    var tombstones: MutableList<Tombstone> = content.tombstones.toMutableList()
        private set
    var devices: MutableList<DeviceRecord> = content.devices.toMutableList()
        private set

    private val signingPrivateKey: HybridSignature.PrivateKey =
        decodeSigningPrivateKey(content.signingPrivateKey)

    fun addOrReplace(entry: PasskeyEntry) {
        entries.removeAll { it.credentialId == entry.credentialId }
        tombstones.removeAll { it.credentialId == entry.credentialId }
        entries.add(entry)
    }

    fun delete(credentialId: String, now: Long = System.currentTimeMillis()) {
        if (entries.removeAll { it.credentialId == credentialId }) {
            tombstones.add(Tombstone(credentialId, now))
        }
    }

    /**
     * Replaces the contents with a merge result. Returns true when the remote side
     * actually contributed something, which is what decides whether the user is told
     * "synced" or "merged".
     */
    internal fun applyMerge(result: com.pqvault.core.merge.VaultMerge.Result): Boolean {
        val changed = entries.toSet() != result.entries.toSet() ||
            tombstones.toSet() != result.tombstones.toSet() ||
            devices.toSet() != result.devices.toSet()
        entries = result.entries.toMutableList()
        tombstones = result.tombstones.toMutableList()
        devices = result.devices.toMutableList()
        return changed
    }

    fun findByRpId(rpId: String): List<PasskeyEntry> = entries.filter { it.rpId == rpId }

    fun find(credentialId: String): PasskeyEntry? = entries.firstOrNull { it.credentialId == credentialId }

    /**
     * Grants a second device access by wrapping the vault key to its hybrid public key.
     * The passphrase is never involved, so a device can be enrolled without it, and
     * revoked later by dropping the recipient and rotating the vault key.
     */
    fun enrollDevice(
        deviceId: String,
        label: String,
        devicePublicKey: HybridKem.PublicKey,
        random: SecureRandom = SecureRandom(),
        now: Long = System.currentTimeMillis(),
    ) {
        val encapsulation = HybridKem.encapsulate(devicePublicKey, random)
        try {
            val wrapNonce = ByteArray(XChaCha20Poly1305.NONCE_SIZE).also { random.nextBytes(it) }
            val wrapped = XChaCha20Poly1305.seal(
                key = encapsulation.sharedSecret,
                nonce = wrapNonce,
                plaintext = vmk,
                aad = DEVICE_WRAP_AAD.toByteArray(),
            )
            recipients.removeAll { it is Recipient.Device && it.deviceId == deviceId }
            recipients.add(
                Recipient.Device(
                    deviceId = deviceId,
                    label = label,
                    kemPublicKey = Base64Url.encode(devicePublicKey.encoded()),
                    kemCiphertext = Base64Url.encode(encapsulation.ciphertext),
                    wrappedKey = Base64Url.encode(wrapped),
                    wrapNonce = Base64Url.encode(wrapNonce),
                ),
            )
            devices.removeAll { it.deviceId == deviceId }
            devices.add(DeviceRecord(deviceId, label, Base64Url.encode(devicePublicKey.encoded()), now))
        } finally {
            encapsulation.sharedSecret.fill(0)
        }
    }

    fun revokeDevice(deviceId: String) {
        recipients.removeAll { it is Recipient.Device && it.deviceId == deviceId }
        devices.removeAll { it.deviceId == deviceId }
    }

    /** The vault master key, for wrapping into a device-local biometric recipient. */
    fun exportMasterKeyForLocalWrapping(): ByteArray = vmk.copyOf()

    /** Serialises, encrypts, signs and frames the vault, bumping the version counter. */
    fun serialize(random: SecureRandom = SecureRandom()): ByteArray {
        check(vaultVersion < Long.MAX_VALUE) { "vault version counter exhausted" }
        vaultVersion += 1

        val content = VaultContent(
            entries = entries.toList(),
            tombstones = tombstones.toList(),
            devices = devices.toList(),
            signingPrivateKey = encodeSigningPrivateKey(signingPrivateKey),
        )
        val contentNonce = ByteArray(XChaCha20Poly1305.NONCE_SIZE).also { random.nextBytes(it) }

        val header = VaultHeader(
            vaultVersion = vaultVersion,
            contentNonce = Base64Url.encode(contentNonce),
            signingPublicKey = Base64Url.encode(signingPublicKeyEncoded),
            recipients = recipients.toList(),
        )
        val headerJson = Vault.json.encodeToString(VaultHeader.serializer(), header)

        val contentBytes = Vault.json.encodeToString(VaultContent.serializer(), content).toByteArray()
        val ciphertext = try {
            XChaCha20Poly1305.seal(
                key = vmk,
                nonce = contentNonce,
                plaintext = contentBytes,
                aad = VaultFile.contentAad(headerJson),
            )
        } finally {
            contentBytes.fill(0)
        }
        val signature = HybridSignature.sign(
            signingPrivateKey,
            VaultFile.signedBytes(headerJson, ciphertext),
        )
        return VaultFile.encode(headerJson, ciphertext, signature)
    }

    fun close() {
        vmk.fill(0)
        // The signing key is what makes a vault file authentic, so it is every bit as
        // worth clearing as the master key.
        signingPrivateKey.ed25519.fill(0)
        signingPrivateKey.mlDsaSeed.fill(0)
    }

    internal companion object {
        fun encodeSigningPrivateKey(key: HybridSignature.PrivateKey): String =
            Base64Url.encode(key.ed25519) + ":" + Base64Url.encode(key.mlDsaSeed)

        fun decodeSigningPrivateKey(encoded: String): HybridSignature.PrivateKey {
            val parts = encoded.split(":")
            require(parts.size == 2) { "malformed signing private key" }
            return HybridSignature.PrivateKey(Base64Url.decode(parts[0]), Base64Url.decode(parts[1]))
        }
    }
}

/**
 * Creating and unlocking vault files.
 *
 * Every failure mode is a distinct result rather than an exception, because they demand
 * very different responses from the UI: a wrong passphrase is a typo, but an invalid
 * signature or a rolled-back version means the sync server is lying to you and the user
 * must be told loudly rather than shown a retry box.
 */
object Vault {

    /**
     * Thrown by an unwrap step that has established the file is broken rather than the
     * key being wrong. It exists so [openInternal] can tell the two apart: reporting a
     * corrupt header as a wrong passphrase sends the user to retype something that was
     * never the problem.
     */
    internal class MalformedVaultContent(message: String) : Exception(message)

    internal val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        classDiscriminator = "type"
    }

    sealed class OpenResult {
        /**
         * [signingPublicKey] is returned so a first-time client can pin it. Every later
         * open must pass it back in, or rollback and substitution detection is toothless.
         */
        class Success(val vault: UnlockedVault, val signingPublicKey: ByteArray) : OpenResult()

        object WrongPassphrase : OpenResult()

        object NoMatchingRecipient : OpenResult()

        /** The file was modified, or truncated, after it was signed. */
        object SignatureInvalid : OpenResult()

        /** Signed by a key other than the one this client pinned: not our vault. */
        object UnknownSigner : OpenResult()

        /** A genuine but stale version: the hallmark of a replay by the sync server. */
        class Rollback(val fileVersion: Long, val lastSeenVersion: Long) : OpenResult()

        class Malformed(val reason: String) : OpenResult()
    }

    fun create(
        passphrase: CharArray,
        kdfParams: Argon2id.Params = Argon2id.MOBILE_DEFAULT,
        random: SecureRandom = SecureRandom(),
    ): UnlockedVault {
        val vmk = ByteArray(XChaCha20Poly1305.KEY_SIZE).also { random.nextBytes(it) }
        val signingKeyPair = HybridSignature.generateKeyPair(random)
        val passphraseRecipient = wrapForPassphrase(vmk, passphrase, kdfParams, random)

        return UnlockedVault(
            vmk = vmk,
            // Starts at zero so the first serialize() writes version 1.
            vaultVersion = 0,
            recipients = mutableListOf(passphraseRecipient),
            content = VaultContent(
                signingPrivateKey = UnlockedVault.encodeSigningPrivateKey(signingKeyPair.privateKey),
            ),
            signingPublicKeyEncoded = signingKeyPair.publicKey.encoded(),
        )
    }

    fun open(
        fileBytes: ByteArray,
        passphrase: CharArray,
        pinnedSigningKey: ByteArray? = null,
        lastSeenVersion: Long = 0,
    ): OpenResult = openInternal(fileBytes, pinnedSigningKey, lastSeenVersion) { header, _ ->
        val recipient = header.recipients.filterIsInstance<Recipient.Passphrase>().firstOrNull()
            ?: return@openInternal null
        if (recipient.kdf.algorithm != "argon2id") {
            throw MalformedVaultContent("unsupported KDF algorithm ${recipient.kdf.algorithm}")
        }
        // The cost parameters are attacker-reachable: they arrive in the file. Params
        // rejects anything absurd, and a failure here is a malformed file rather than a
        // wrong passphrase, so it must not be swallowed as one.
        val params = try {
            Argon2id.Params(
                memoryKib = recipient.kdf.memoryKib,
                iterations = recipient.kdf.iterations,
                parallelism = recipient.kdf.parallelism,
            )
        } catch (e: IllegalArgumentException) {
            throw MalformedVaultContent("unusable KDF parameters: ${e.message}")
        }
        val salt = decodeBase64Field(
            name = "KDF salt",
            encoded = recipient.kdf.salt,
            minSize = MIN_KDF_SALT_SIZE,
            maxSize = MAX_KDF_SALT_SIZE,
        )
        val wrapNonce = decodeBase64Field(
            name = "passphrase wrap nonce",
            encoded = recipient.wrapNonce,
            exactSize = XChaCha20Poly1305.NONCE_SIZE,
        )
        val wrappedKey = decodeBase64Field(
            name = "passphrase wrapped key",
            encoded = recipient.wrappedKey,
            exactSize = WRAPPED_VMK_SIZE,
        )
        val kek = Argon2id.derive(
            passphrase = passphrase,
            salt = salt,
            params = params,
        )
        try {
            XChaCha20Poly1305.open(
                key = kek,
                nonce = wrapNonce,
                ciphertext = wrappedKey,
                aad = PASSPHRASE_WRAP_AAD.toByteArray(),
            )
        } finally {
            kek.fill(0)
        }
    }

    /** Unlocks using an enrolled device's hybrid KEM key instead of the passphrase. */
    fun openWithDeviceKey(
        fileBytes: ByteArray,
        deviceId: String,
        devicePrivateKey: HybridKem.PrivateKey,
        devicePublicKey: HybridKem.PublicKey,
        pinnedSigningKey: ByteArray? = null,
        lastSeenVersion: Long = 0,
    ): OpenResult = openInternal(fileBytes, pinnedSigningKey, lastSeenVersion) { header, _ ->
        val recipient = header.recipients
            .filterIsInstance<Recipient.Device>()
            .firstOrNull { it.deviceId == deviceId }
            ?: return@openInternal null
        val enrolledPublicKey = decodeBase64Field(
            name = "device public key",
            encoded = recipient.kemPublicKey,
            exactSize = HybridKem.X25519_PUBLIC_SIZE + HybridKem.ML_KEM_768_PUBLIC_SIZE,
        )
        if (!enrolledPublicKey.contentEquals(devicePublicKey.encoded())) return@openInternal null
        val kemCiphertext = decodeBase64Field(
            name = "device KEM ciphertext",
            encoded = recipient.kemCiphertext,
            exactSize = HybridKem.X25519_PUBLIC_SIZE + HybridKem.ML_KEM_768_CIPHERTEXT_SIZE,
        )
        val wrapNonce = decodeBase64Field(
            name = "device wrap nonce",
            encoded = recipient.wrapNonce,
            exactSize = XChaCha20Poly1305.NONCE_SIZE,
        )
        val wrappedKey = decodeBase64Field(
            name = "device wrapped key",
            encoded = recipient.wrappedKey,
            exactSize = WRAPPED_VMK_SIZE,
        )
        val shared = HybridKem.decapsulate(
            devicePrivateKey,
            devicePublicKey,
            kemCiphertext,
        )
        try {
            XChaCha20Poly1305.open(
                key = shared,
                nonce = wrapNonce,
                ciphertext = wrappedKey,
                aad = DEVICE_WRAP_AAD.toByteArray(),
            )
        } finally {
            shared.fill(0)
        }
    }

    /** Unlocks with a vault master key recovered from a device-local biometric wrap. */
    fun openWithMasterKey(
        fileBytes: ByteArray,
        masterKey: ByteArray,
        pinnedSigningKey: ByteArray? = null,
        lastSeenVersion: Long = 0,
    ): OpenResult = openInternal(fileBytes, pinnedSigningKey, lastSeenVersion) { _, _ -> masterKey.copyOf() }

    /**
     * Shared open path. [unwrapVmk] returns the vault master key, or null when this
     * unlock method has no recipient in the file.
     *
     * The order of checks matters: the signer is pinned before the signature is checked,
     * because verifying a signature against a key the attacker also supplied proves
     * nothing at all.
     */
    private fun openInternal(
        fileBytes: ByteArray,
        pinnedSigningKey: ByteArray?,
        lastSeenVersion: Long,
        unwrapVmk: (VaultHeader, ByteArray) -> ByteArray?,
    ): OpenResult {
        val raw = try {
            VaultFile.decode(fileBytes)
        } catch (e: VaultFile.MalformedVaultException) {
            return OpenResult.Malformed(e.message ?: "malformed vault")
        }

        val header = try {
            json.decodeFromString(VaultHeader.serializer(), raw.headerJson)
        } catch (e: Exception) {
            return OpenResult.Malformed("unreadable header: ${e.message}")
        }

        if (header.formatVersion != VaultFile.FORMAT_VERSION) {
            return OpenResult.Malformed(
                "unsupported vault format version ${header.formatVersion}",
            )
        }
        if (header.vaultVersion < 0) return OpenResult.Malformed("negative vault version")
        if (header.recipients.size > MAX_RECIPIENTS) {
            return OpenResult.Malformed("too many vault recipients")
        }
        if (header.recipients.count { it is Recipient.Passphrase } > 1) {
            return OpenResult.Malformed("multiple passphrase recipients are not supported")
        }
        val deviceIds = header.recipients.filterIsInstance<Recipient.Device>().map { it.deviceId }
        if (deviceIds.size != deviceIds.toSet().size) {
            return OpenResult.Malformed("duplicate device recipients")
        }

        val signingPublicKeyBytes = try {
            Base64Url.decode(header.signingPublicKey)
        } catch (e: IllegalArgumentException) {
            return OpenResult.Malformed("unreadable signing public key")
        }

        if (pinnedSigningKey != null && !pinnedSigningKey.contentEquals(signingPublicKeyBytes)) {
            return OpenResult.UnknownSigner
        }

        val signingPublicKey = try {
            HybridSignature.PublicKey.decode(signingPublicKeyBytes)
        } catch (e: IllegalArgumentException) {
            return OpenResult.Malformed("unusable signing public key: ${e.message}")
        }
        val signatureValid = try {
            HybridSignature.verify(signingPublicKey, raw.signedBytes, raw.signature)
        } catch (_: RuntimeException) {
            false
        }
        if (!signatureValid) {
            return OpenResult.SignatureInvalid
        }

        if (header.vaultVersion < lastSeenVersion) {
            return OpenResult.Rollback(header.vaultVersion, lastSeenVersion)
        }

        val vmk = try {
            unwrapVmk(header, raw.contentAad)
        } catch (e: MalformedVaultContent) {
            return OpenResult.Malformed(e.message ?: "malformed vault")
        } catch (e: Exception) {
            null
        } ?: return if (header.recipients.isEmpty()) {
            OpenResult.NoMatchingRecipient
        } else {
            OpenResult.WrongPassphrase
        }

        if (vmk.size != XChaCha20Poly1305.KEY_SIZE) {
            vmk.fill(0)
            return OpenResult.Malformed("recovered vault key has an invalid size")
        }

        val contentNonce = try {
            decodeBase64Field(
                name = "content nonce",
                encoded = header.contentNonce,
                exactSize = XChaCha20Poly1305.NONCE_SIZE,
            )
        } catch (e: MalformedVaultContent) {
            vmk.fill(0)
            return OpenResult.Malformed(e.message ?: "malformed content nonce")
        }
        val plaintext = try {
            XChaCha20Poly1305.open(
                key = vmk,
                nonce = contentNonce,
                ciphertext = raw.content,
                aad = raw.contentAad,
            )
        } catch (e: RuntimeException) {
            vmk.fill(0)
            return OpenResult.Malformed("content could not be decrypted: ${e.message}")
        } ?: run {
            vmk.fill(0)
            return OpenResult.Malformed("content failed to authenticate under the recovered key")
        }

        val content = try {
            json.decodeFromString(VaultContent.serializer(), String(plaintext, Charsets.UTF_8))
        } catch (e: Exception) {
            vmk.fill(0)
            return OpenResult.Malformed("unreadable content: ${e.message}")
        } finally {
            plaintext.fill(0)
        }

        val unlocked = try {
            UnlockedVault(
                vmk = vmk,
                vaultVersion = header.vaultVersion,
                recipients = header.recipients.toMutableList(),
                content = content,
                signingPublicKeyEncoded = signingPublicKeyBytes.copyOf(),
            )
        } catch (e: RuntimeException) {
            vmk.fill(0)
            return OpenResult.Malformed("unusable decrypted content: ${e.message}")
        }

        return OpenResult.Success(
            vault = unlocked,
            signingPublicKey = signingPublicKeyBytes.copyOf(),
        )
    }

    private fun decodeBase64Field(
        name: String,
        encoded: String,
        exactSize: Int? = null,
        minSize: Int = exactSize ?: 0,
        maxSize: Int = exactSize ?: Int.MAX_VALUE,
    ): ByteArray {
        val decoded = try {
            Base64Url.decode(encoded)
        } catch (_: IllegalArgumentException) {
            throw MalformedVaultContent("$name is not valid base64url")
        }
        if (decoded.size !in minSize..maxSize) {
            val expected = exactSize?.let { "$it" } ?: "$minSize..$maxSize"
            throw MalformedVaultContent("$name must be $expected bytes, was ${decoded.size}")
        }
        return decoded
    }

    private fun wrapForPassphrase(
        vmk: ByteArray,
        passphrase: CharArray,
        kdfParams: Argon2id.Params,
        random: SecureRandom,
    ): Recipient.Passphrase {
        val salt = ByteArray(32).also { random.nextBytes(it) }
        val wrapNonce = ByteArray(XChaCha20Poly1305.NONCE_SIZE).also { random.nextBytes(it) }
        val kek = Argon2id.derive(passphrase, salt, kdfParams)
        try {
            return Recipient.Passphrase(
                kdf = KdfParams(
                    memoryKib = kdfParams.memoryKib,
                    iterations = kdfParams.iterations,
                    parallelism = kdfParams.parallelism,
                    salt = Base64Url.encode(salt),
                ),
                wrappedKey = Base64Url.encode(
                    XChaCha20Poly1305.seal(kek, wrapNonce, vmk, PASSPHRASE_WRAP_AAD.toByteArray()),
                ),
                wrapNonce = Base64Url.encode(wrapNonce),
            )
        } finally {
            kek.fill(0)
        }
    }
}
