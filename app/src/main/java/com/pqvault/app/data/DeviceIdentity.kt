package com.pqvault.app.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.pqvault.core.crypto.HybridKem
import java.io.File
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * This device's hybrid X25519+ML-KEM-768 identity.
 *
 * It exists so background sync can work without the passphrase. Merging requires opening
 * the *remote* vault, and asking for a passphrase every fifteen minutes is not sync, but
 * caching the passphrase would be worse. Instead the device enrols itself as a recipient
 * of the vault key, exactly like a second phone would, and unwraps its own copy.
 *
 * The private key is sealed under a Keystore key that is deliberately *not* biometric-
 * gated: a worker running while the screen is off cannot show a fingerprint prompt. That
 * is a real reduction in protection compared with the biometric path, and the mitigation
 * is that revoking this device from any other device makes the key useless.
 */
class DeviceIdentity(private val context: Context) {

    private val file: File get() = File(context.filesDir, "device_identity.bin")

    class Identity(
        val deviceId: String,
        val keyPair: HybridKem.KeyPair,
    )

    /**
     * The stored identity exists but will not decrypt, which in practice means the
     * Keystore key behind it is gone: a restore onto a different phone, or a factory
     * reset of the secure element.
     */
    class UnreadableIdentityException : Exception("the stored device identity cannot be decrypted")

    fun exists(): Boolean = file.exists()

    /**
     * Loads this device's identity, creating one on first call.
     *
     * An existing but unreadable file is an error rather than a cue to generate a new
     * one. Overwriting it would throw away the only key that opens this device's
     * recipient entry in the vault, silently demoting the phone to un-enrolled with
     * nothing in the UI to say why background sync had stopped working. The user needs to
     * be told to enrol again, which is a decision only they can make.
     */
    fun loadOrCreate(): Identity {
        if (file.exists()) {
            return load() ?: throw UnreadableIdentityException()
        }
        return generate()
    }

    /**
     * Discards any stored identity and generates a fresh one. Only ever called from an
     * explicit user action, because it costs this device its access to the vault until it
     * is re-enrolled from a device that still has it.
     */
    fun recreate(): Identity {
        clear()
        return generate()
    }

    private fun generate(): Identity {
        val identity = Identity(
            deviceId = UUID.randomUUID().toString(),
            keyPair = HybridKem.generateKeyPair(),
        )
        store(identity)
        return identity
    }

    private fun load(): Identity? = try {
        val stored = file.readBytes()
        val ivLength = stored[0].toInt() and 0xFF
        val iv = stored.copyOfRange(1, 1 + ivLength)
        val ciphertext = stored.copyOfRange(1 + ivLength, stored.size)
        val plaintext = Cipher.getInstance(TRANSFORMATION).run {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(GCM_TAG_BITS, iv))
            doFinal(ciphertext)
        }
        // deviceId \n publicKey \n privateKey, all base64url
        val parts = String(plaintext, Charsets.UTF_8).split("\n")
        if (parts.size != 3) {
            null
        } else {
            Identity(
                deviceId = parts[0],
                keyPair = HybridKem.KeyPair(
                    publicKey = HybridKem.PublicKey.decode(
                        com.pqvault.core.format.Base64Url.decode(parts[1]),
                    ),
                    privateKey = HybridKem.PrivateKey.decode(
                        com.pqvault.core.format.Base64Url.decode(parts[2]),
                    ),
                ),
            )
        }
    } catch (e: Exception) {
        null
    }

    private fun store(identity: Identity) {
        val plaintext = listOf(
            identity.deviceId,
            com.pqvault.core.format.Base64Url.encode(identity.keyPair.publicKey.encoded()),
            com.pqvault.core.format.Base64Url.encode(identity.keyPair.privateKey.encoded()),
        ).joinToString("\n").toByteArray(Charsets.UTF_8)

        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }
        val ciphertext = cipher.doFinal(plaintext)
        file.writeBytes(byteArrayOf(cipher.iv.size.toByte()) + cipher.iv + ciphertext)
    }

    fun clear() {
        file.delete()
        runCatching {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(KEY_ALIAS)
        }
    }

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        const val KEY_ALIAS = "pqvault_device_identity"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
    }
}
