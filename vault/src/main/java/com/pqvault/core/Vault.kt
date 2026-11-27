package com.pqvault.core

import com.pqvault.core.crypto.Argon2id
import com.pqvault.core.crypto.HybridKem
import com.pqvault.core.crypto.HybridSignature
import com.pqvault.core.crypto.XChaCha20Poly1305
import com.pqvault.core.format.Base64Url
import com.pqvault.core.format.KdfParams
import com.pqvault.core.format.Recipient
import com.pqvault.core.format.SigningKeyLink
import com.pqvault.core.format.VaultContent
import com.pqvault.core.format.VaultFile
import com.pqvault.core.format.VaultHeader
import com.pqvault.core.model.DeviceRecord
import com.pqvault.core.model.PasskeyEntry
import com.pqvault.core.model.RevokedDevice
import com.pqvault.core.model.Tombstone
import com.pqvault.core.ssh.OpenSshKeys
import com.pqvault.core.webauthn.SoftwareAuthenticator
import kotlinx.serialization.json.Json
import java.security.MessageDigest
import java.security.SecureRandom

private const val PASSPHRASE_WRAP_AAD = "pqvault/recipient/passphrase/v1"
private const val DEVICE_WRAP_AAD = "pqvault/recipient/device/v1"
private const val KEY_ROTATION_CONTEXT = "pqvault/signing-key-rotation/v1"
private const val WRAPPED_VMK_SIZE = XChaCha20Poly1305.KEY_SIZE + XChaCha20Poly1305.TAG_SIZE
private const val MIN_KDF_SALT_SIZE = 16
private const val MAX_KDF_SALT_SIZE = 64
private const val MAX_RECIPIENTS = 64
private const val MAX_KEY_CHAIN = 16

/**
 * Everything needed to read and modify a vault that has been successfully unlocked.
 *
 * The vault master key stays in memory for the lifetime of this object; call [close]
 * when locking so it does not linger.
 */
class UnlockedVault internal constructor(
    private var vmk: ByteArray,
    var vaultVersion: Long,
    private var recipients: MutableList<Recipient>,
    content: VaultContent,
    signingPublicKeyEncoded: ByteArray,
    signingKeyChain: List<SigningKeyLink> = emptyList(),
) {
    var signingPublicKeyEncoded: ByteArray = signingPublicKeyEncoded
        private set
    private var signingKeyChain: List<SigningKeyLink> = signingKeyChain

    var entries: MutableList<PasskeyEntry> = content.entries.toMutableList()
        private set
    var tombstones: MutableList<Tombstone> = content.tombstones.toMutableList()
        private set
    var devices: MutableList<DeviceRecord> = content.devices.toMutableList()
        private set
    var revokedDevices: MutableList<RevokedDevice> = content.revokedDevices.toMutableList()
        private set

    private var signingPrivateKey: HybridSignature.PrivateKey =
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
            devices.toSet() != result.devices.toSet() ||
            revokedDevices.toSet() != result.revokedDevices.toSet()
        entries = result.entries.toMutableList()
        tombstones = result.tombstones.toMutableList()
        devices = result.devices.toMutableList()
        revokedDevices = result.revokedDevices.toMutableList()
        recipients.removeAll { recipient ->
            recipient is Recipient.Device &&
                devices.none { it.deviceId == recipient.deviceId && it.kemPublicKey == recipient.kemPublicKey } &&
                revokedDevices.any { it.deviceId == recipient.deviceId && it.kemPublicKey == recipient.kemPublicKey }
        }
        return changed
    }

    /** True when [previousKey] handed over, directly or not, to this vault's signing key. */
    internal fun succeeds(previousKey: ByteArray): Boolean =
        Vault.chainLeadsTo(signingKeyChain, previousKey, signingPublicKeyEncoded)

    /**
     * Takes the keys and recipients of [remote], a copy whose keys were rotated after
     * this one's. Call before [applyMerge], inside [serializeChange].
     */
    internal fun adoptKeys(remote: UnlockedVault) {
        vmk = remote.vmk.copyOf()
        signingPrivateKey = HybridSignature.PrivateKey(
            remote.signingPrivateKey.ed25519.copyOf(),
            remote.signingPrivateKey.mlDsaSeed.copyOf(),
        )
        signingPublicKeyEncoded = remote.signingPublicKeyEncoded.copyOf()
        signingKeyChain = remote.signingKeyChain
        recipients = remote.recipients.toMutableList()
    }

    /**
     * Keeps the recipients another copy of this vault carries, so a device enrolled
     * elsewhere does not lose its access when this copy is the one pushed: the device
     * records are merged, and a record without its recipient opens nothing.
     *
     * Only a copy sealed with this very vault key may contribute, since its recipients
     * wrap that key, and only for a device it lists: a recipient no record accounts for
     * is not taken in. Nothing local is ever dropped here. For a device enrolled again,
     * the recipient matching its merged record wins. Call after [applyMerge].
     */
    internal fun mergeRecipients(remote: UnlockedVault) {
        if (!MessageDigest.isEqual(vmk, remote.vmk)) return
        val enrolledKeys = devices.associate { it.deviceId to it.kemPublicKey }
        val merged = LinkedHashMap<String, Recipient>()
        val remoteListed = remote.recipients.filter {
            it is Recipient.Passphrase ||
                (it is Recipient.Device && it.kemPublicKey == enrolledKeys[it.deviceId])
        }
        for (candidate in recipients + remoteListed) {
            val slot = when (candidate) {
                is Recipient.Passphrase -> "passphrase"
                is Recipient.Device -> "device:${candidate.deviceId}"
            }
            val kept = merged[slot]
            val matchesRecord = candidate is Recipient.Device &&
                candidate.kemPublicKey == enrolledKeys[candidate.deviceId]
            val keptMatchesRecord = kept is Recipient.Device &&
                kept.kemPublicKey == enrolledKeys[kept.deviceId]
            if (kept == null || (matchesRecord && !keptMatchesRecord)) merged[slot] = candidate
        }
        // A header the open path would refuse is worse than a device left to re-enrol.
        if (merged.size <= MAX_RECIPIENTS) recipients = merged.values.toMutableList()
    }

    /**
     * Signs with the stored copy of [credentialId] and keeps the raised counter in the
     * same step. A copy taken earlier, before a prompt for instance, may already be
     * behind: signing from it would hand a relying party the same counter twice, which
     * it takes for a cloned authenticator. Null when the passkey is gone.
     */
    fun recordAssertion(
        credentialId: String,
        sign: (PasskeyEntry) -> SoftwareAuthenticator.Assertion,
    ): SoftwareAuthenticator.Assertion? {
        val current = find(credentialId) ?: return null
        return sign(current).also { addOrReplace(it.updatedEntry) }
    }

    fun findByRpId(rpId: String): List<PasskeyEntry> = entries.filter { it.rpId == rpId }

    fun find(credentialId: String): PasskeyEntry? = entries.firstOrNull { it.credentialId == credentialId }

    /**
     * Grants a second device access by wrapping the vault key to its hybrid public key.
     * The passphrase is never involved, so a device can be enrolled without it.
     */
    fun enrollDevice(
        deviceId: String,
        label: String,
        devicePublicKey: HybridKem.PublicKey,
        random: SecureRandom = SecureRandom(),
        now: Long = System.currentTimeMillis(),
    ) {
        val recipient = wrapForDevice(vmk, deviceId, label, devicePublicKey, random)
        recipients.removeAll { it is Recipient.Device && it.deviceId == deviceId }
        recipients.add(recipient)
        devices.removeAll { it.deviceId == deviceId }
        devices.add(DeviceRecord(deviceId, label, recipient.kemPublicKey, now))
    }

    /**
     * Withdraws a device's access for good. The vault key and the signing key are both
     * replaced, the new vault key is wrapped for the passphrase and the remaining devices
     * only, and the old signing key signs over to the new one so the other devices accept
     * it. Every credential the device could read is marked exposed.
     *
     * Call inside [serializeChange]. Returns false, changing nothing, when [passphrase]
     * does not open this vault.
     */
    fun revokeDevice(
        deviceId: String,
        passphrase: CharArray,
        random: SecureRandom = SecureRandom(),
        now: Long = System.currentTimeMillis(),
    ): Boolean {
        val passphraseRecipient = recipients.filterIsInstance<Recipient.Passphrase>().singleOrNull()
            ?: throw IllegalStateException("vault has no passphrase recipient")
        val current = Vault.unwrapWithPassphrase(passphraseRecipient, passphrase) ?: return false
        val matches = MessageDigest.isEqual(current, vmk)
        current.fill(0)
        if (!matches) return false

        val revokedKey = devices.firstOrNull { it.deviceId == deviceId }?.kemPublicKey
            ?: recipients.filterIsInstance<Recipient.Device>().firstOrNull { it.deviceId == deviceId }?.kemPublicKey
            ?: throw IllegalArgumentException("unknown device")

        val nextVmk = ByteArray(XChaCha20Poly1305.KEY_SIZE).also { random.nextBytes(it) }
        val next = HybridSignature.generateKeyPair(random)
        val nextPublic = next.publicKey.encoded()
        val link = SigningKeyLink(
            previousKey = Base64Url.encode(signingPublicKeyEncoded),
            nextKey = Base64Url.encode(nextPublic),
            signature = Base64Url.encode(
                HybridSignature.sign(signingPrivateKey, Vault.rotationStatement(signingPublicKeyEncoded, nextPublic)),
            ),
        )
        val kdf = passphraseRecipient.kdf
        val nextRecipients = mutableListOf<Recipient>(
            Vault.wrapForPassphrase(
                nextVmk,
                passphrase,
                Argon2id.Params(kdf.memoryKib, kdf.iterations, kdf.parallelism),
                random,
            ),
        )
        recipients.filterIsInstance<Recipient.Device>().filter { it.deviceId != deviceId }.forEach {
            val publicKey = HybridKem.PublicKey.decode(Base64Url.decode(it.kemPublicKey))
            nextRecipients.add(wrapForDevice(nextVmk, it.deviceId, it.label, publicKey, random))
        }

        vmk = nextVmk
        signingPrivateKey = next.privateKey
        signingPublicKeyEncoded = nextPublic
        signingKeyChain = (signingKeyChain + link).takeLast(MAX_KEY_CHAIN)
        recipients = nextRecipients
        devices.removeAll { it.deviceId == deviceId }
        revokedDevices.removeAll { it.deviceId == deviceId && it.kemPublicKey == revokedKey }
        revokedDevices.add(RevokedDevice(deviceId, revokedKey, now))
        entries = entries.map { if (it.exposedAt == null) it.copy(exposedAt = now) else it }.toMutableList()
        return true
    }

    /** The credentials a revoked device may still hold. */
    fun exposedEntries(): List<PasskeyEntry> = entries.filter { it.exposedAt != null }

    /** The vault master key, for wrapping into a device-local biometric recipient. */
    fun exportMasterKeyForLocalWrapping(): ByteArray = vmk.copyOf()

    /**
     * Serialises, encrypts, signs and frames the vault, bumping the version counter.
     *
     * The counter only moves once the file exists: a vault too large for the format
     * throws [VaultFile.VaultTooLargeException] and keeps its version.
     */
    fun serialize(random: SecureRandom = SecureRandom()): ByteArray {
        check(vaultVersion < Long.MAX_VALUE) { "vault version counter exhausted" }
        val nextVersion = vaultVersion + 1

        val content = VaultContent(
            entries = entries.toList(),
            tombstones = tombstones.toList(),
            devices = devices.toList(),
            revokedDevices = revokedDevices.toList(),
            signingPrivateKey = encodeSigningPrivateKey(signingPrivateKey),
        )
        val contentNonce = ByteArray(XChaCha20Poly1305.NONCE_SIZE).also { random.nextBytes(it) }

        val features = requiredFeatures()
        val header = VaultHeader(
            formatVersion = if (features.isEmpty()) VaultFile.FORMAT_VERSION else VaultFile.FEATURES_FORMAT_VERSION,
            features = features,
            vaultVersion = nextVersion,
            contentNonce = Base64Url.encode(contentNonce),
            signingPublicKey = Base64Url.encode(signingPublicKeyEncoded),
            recipients = recipients.toList(),
            signingKeyChain = signingKeyChain,
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
        return VaultFile.encode(headerJson, ciphertext, signature).also { vaultVersion = nextVersion }
    }

    private fun requiredFeatures(): List<String> = buildList {
        if (entries.any(OpenSshKeys::isSshKey)) add(VaultFile.FEATURE_SSH_CREDENTIALS)
        if (signingKeyChain.isNotEmpty() || revokedDevices.isNotEmpty() || entries.any { it.exposedAt != null }) {
            add(VaultFile.FEATURE_DEVICE_REVOCATION)
        }
    }

    /**
     * Applies [change] and serialises the result, or leaves the vault exactly as it was
     * when that result cannot be produced, typically because it no longer fits the format.
     * Without the rollback the vault in memory would hold a passkey the file does not,
     * shown and usable until the next lock quietly dropped it.
     */
    fun serializeChange(random: SecureRandom = SecureRandom(), change: UnlockedVault.() -> Unit): ByteArray {
        val savedEntries = entries.toMutableList()
        val savedTombstones = tombstones.toMutableList()
        val savedDevices = devices.toMutableList()
        val savedRevoked = revokedDevices.toMutableList()
        val savedRecipients = recipients.toMutableList()
        val savedVersion = vaultVersion
        val savedVmk = vmk
        val savedSigningKey = signingPrivateKey
        val savedPublicKey = signingPublicKeyEncoded
        val savedChain = signingKeyChain
        return try {
            change()
            serialize(random).also {
                if (vmk !== savedVmk) wipe(savedVmk, savedSigningKey)
            }
        } catch (failure: Exception) {
            if (vmk !== savedVmk) wipe(vmk, signingPrivateKey)
            entries = savedEntries
            tombstones = savedTombstones
            devices = savedDevices
            revokedDevices = savedRevoked
            recipients = savedRecipients
            vaultVersion = savedVersion
            vmk = savedVmk
            signingPrivateKey = savedSigningKey
            signingPublicKeyEncoded = savedPublicKey
            signingKeyChain = savedChain
            throw failure
        }
    }

    fun close() = wipe(vmk, signingPrivateKey)

    internal companion object {
        fun wipe(vmk: ByteArray, signingKey: HybridSignature.PrivateKey) {
            vmk.fill(0)
            signingKey.ed25519.fill(0)
            signingKey.mlDsaSeed.fill(0)
        }

        fun wrapForDevice(
            vmk: ByteArray,
            deviceId: String,
            label: String,
            devicePublicKey: HybridKem.PublicKey,
            random: SecureRandom,
        ): Recipient.Device {
            val encapsulation = HybridKem.encapsulate(devicePublicKey, random)
            try {
                val wrapNonce = ByteArray(XChaCha20Poly1305.NONCE_SIZE).also { random.nextBytes(it) }
                val wrapped = XChaCha20Poly1305.seal(
                    key = encapsulation.sharedSecret,
                    nonce = wrapNonce,
                    plaintext = vmk,
                    aad = DEVICE_WRAP_AAD.toByteArray(),
                )
                return Recipient.Device(
                    deviceId = deviceId,
                    label = label,
                    kemPublicKey = Base64Url.encode(devicePublicKey.encoded()),
                    kemCiphertext = Base64Url.encode(encapsulation.ciphertext),
                    wrappedKey = Base64Url.encode(wrapped),
                    wrapNonce = Base64Url.encode(wrapNonce),
                )
            } finally {
                encapsulation.sharedSecret.fill(0)
            }
        }

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
        unwrapWithPassphrase(recipient, passphrase)
    }

    /** The vault key [recipient] wraps, or null when [passphrase] is not the one. */
    internal fun unwrapWithPassphrase(recipient: Recipient.Passphrase, passphrase: CharArray): ByteArray? {
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
        return try {
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

        val expectedFormat = if (header.features.isEmpty()) {
            VaultFile.FORMAT_VERSION
        } else {
            VaultFile.FEATURES_FORMAT_VERSION
        }
        if (header.formatVersion != expectedFormat) {
            return OpenResult.Malformed(
                "unsupported vault format version ${header.formatVersion}",
            )
        }
        val unknownFeatures = header.features.filter { it !in VaultFile.KNOWN_FEATURES }
        if (unknownFeatures.isNotEmpty()) {
            return OpenResult.Malformed(
                "this vault needs a newer PQ Vault release (${unknownFeatures.joinToString()})",
            )
        }
        if (header.signingKeyChain.size > MAX_KEY_CHAIN) {
            return OpenResult.Malformed("signing key chain too long")
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

        if (header.signingKeyChain.isNotEmpty() && header.signingKeyChain.last().nextKey != header.signingPublicKey) {
            return OpenResult.Malformed("signing key chain does not end at the signing key")
        }
        if (pinnedSigningKey != null && !pinnedSigningKey.contentEquals(signingPublicKeyBytes) &&
            !chainLeadsTo(header.signingKeyChain, pinnedSigningKey, signingPublicKeyBytes)
        ) {
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
                signingKeyChain = header.signingKeyChain,
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

    internal fun rotationStatement(previousKey: ByteArray, nextKey: ByteArray): ByteArray =
        KEY_ROTATION_CONTEXT.toByteArray() + previousKey + nextKey

    /**
     * True when [chain] holds an unbroken run of links from [from] to [to], each signed by
     * the key it retires. Links older than [from] are not looked at.
     */
    internal fun chainLeadsTo(chain: List<SigningKeyLink>, from: ByteArray, to: ByteArray): Boolean {
        val decoded = try {
            chain.map { Triple(Base64Url.decode(it.previousKey), Base64Url.decode(it.nextKey), Base64Url.decode(it.signature)) }
        } catch (_: IllegalArgumentException) {
            return false
        }
        val start = decoded.indexOfFirst { it.first.contentEquals(from) }
        if (start < 0) return false
        var current = from
        for ((previous, next, signature) in decoded.subList(start, decoded.size)) {
            if (!previous.contentEquals(current)) return false
            val valid = try {
                HybridSignature.verify(HybridSignature.PublicKey.decode(previous), rotationStatement(previous, next), signature)
            } catch (_: RuntimeException) {
                false
            }
            if (!valid) return false
            current = next
        }
        return current.contentEquals(to)
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

    internal fun wrapForPassphrase(
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
