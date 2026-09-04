package com.pqvault.app.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Small encrypted store for settings that are secret but not part of the vault.
 *
 * The WebDAV credentials cannot live inside the vault itself: you need them to fetch the
 * vault, and you need the vault to read them. So they sit here, encrypted under an
 * app-scoped Keystore key, not biometric-gated, because sync has to run in the
 * background without a fingerprint.
 *
 * The pinned signing key and the version watermarks live here too. They are not secret,
 * but they are exactly what an attacker would want to reset in order to slip a
 * rolled-back vault past us, so they get the same integrity protection.
 */
class SecureSettings(private val context: Context) {

    private val file: File get() = File(context.filesDir, "settings.bin")

    data class Settings(
        val webdavBaseUrl: String = "",
        val webdavUsername: String = "",
        val webdavAppPassword: String = "",
        val remotePath: String = "vault.pqvault",
        /** base64url of the hybrid signing public key, pinned on first open. */
        val pinnedSigningKey: String = "",
        /**
         * base64url SHA-256 of the key [pinnedSigningKey] will hold, carried by a pairing
         * code in its place.
         *
         * The key itself is a hybrid Ed25519 + ML-DSA-65 public key: 1984 bytes, which is
         * 2646 characters of base64url and puts the pairing payload at roughly 3800
         * characters against a hard QR ceiling of 2953. The digest is 43 characters and
         * pins exactly as tightly, because the key travels inside the vault header anyway
         * and the digest is what proves it is the right one.
         */
        val pinnedSigningKeyDigest: String = "",
        val lastSyncEtag: String = "",
        /**
         * Highest version this device has accepted *from the server*, and the watermark
         * the rollback check uses on the remote file. Only a successful sync may raise
         * it. Local edits bump the file's own counter without the server hearing about
         * it, so folding them in here would make the server's untouched copy look older
         * than what we had "accepted" and jam sync permanently: see [localVersion].
         */
        val lastSeenVersion: Long = 0,
        /**
         * Highest version of the *local* file, raised by every local write. Separate from
         * [lastSeenVersion] because it says nothing about what the server holds; it only
         * catches a local file that was restored from an older backup.
         */
        val localVersion: Long = 0,
        /**
         * Idle seconds before the vault locks itself, or 0 to only lock on demand.
         *
         * Three minutes by default. An unlocked vault in memory is the whole prize, and
         * "the user closed the app" is not a reliable event: Android may keep the process
         * alive for hours, and the credential provider can unlock it without any activity
         * being on screen at all.
         */
        val autoLockSeconds: Int = DEFAULT_AUTO_LOCK_SECONDS,
        /**
         * Google-format JSON listing browsers allowed to claim a web origin. Empty by
         * default: on a de-Googled phone we ship no implicit trust, and an unlisted
         * caller claiming an origin is refused outright.
         */
        val privilegedBrowserAllowlist: String = "",
    )

    fun load(): Settings {
        if (!file.exists()) return Settings()
        return try {
            val stored = file.readBytes()
            val ivLength = stored[0].toInt() and 0xFF
            val iv = stored.copyOfRange(1, 1 + ivLength)
            val ciphertext = stored.copyOfRange(1 + ivLength, stored.size)
            val cipher = Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(GCM_TAG_BITS, iv))
            }
            parse(String(cipher.doFinal(ciphertext), Charsets.UTF_8))
        } catch (e: Exception) {
            // A settings file we cannot read is treated as absent rather than fatal; the
            // user re-enters the server details and the vault itself is untouched.
            Settings()
        }
    }

    fun save(settings: Settings) {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }
        val plaintext = serialize(settings).toByteArray(Charsets.UTF_8)
        val ciphertext = cipher.doFinal(plaintext)
        file.writeBytes(byteArrayOf(cipher.iv.size.toByte()) + cipher.iv + ciphertext)
    }

    private fun serialize(s: Settings): String = listOf(
        s.webdavBaseUrl, s.webdavUsername, s.webdavAppPassword,
        s.remotePath, s.pinnedSigningKey, s.lastSyncEtag, s.lastSeenVersion.toString(),
        s.privilegedBrowserAllowlist, s.localVersion.toString(),
        s.pinnedSigningKeyDigest, s.autoLockSeconds.toString(),
    ).joinToString("\n") { it.replace("\n", " ") }

    private fun parse(text: String): Settings {
        val parts = text.split("\n")
        if (parts.size < 7) return Settings()
        val storedVersion = parts[6].toLongOrNull() ?: 0
        // Files written before localVersion existed kept a single counter that local
        // writes also raised, so it can sit above the version the server actually holds.
        // Reading it back as a remote watermark is what jams sync, so on those files we
        // demote it to the local counter and start the remote watermark again from zero:
        // the pinned signing key still refuses a vault that is not ours.
        val migrating = parts.size < 9
        return Settings(
            webdavBaseUrl = parts[0],
            webdavUsername = parts[1],
            webdavAppPassword = parts[2],
            remotePath = parts[3],
            pinnedSigningKey = parts[4],
            lastSyncEtag = parts[5],
            lastSeenVersion = if (migrating) 0 else storedVersion,
            privilegedBrowserAllowlist = parts.getOrElse(7) { "" },
            localVersion = if (migrating) storedVersion else parts[8].toLongOrNull() ?: 0,
            pinnedSigningKeyDigest = parts.getOrElse(9) { "" },
            // Fields appended later default rather than reset: an install that predates
            // auto-lock gets the same three minutes a fresh one would.
            autoLockSeconds = parts.getOrNull(10)?.toIntOrNull() ?: DEFAULT_AUTO_LOCK_SECONDS,
        )
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

    companion object {
        const val DEFAULT_AUTO_LOCK_SECONDS = 180

        /** The choices offered in settings, in the order they are shown. 0 means never. */
        val AUTO_LOCK_CHOICES = listOf(60, 180, 300, 900, 0)

        private const val KEY_ALIAS = "pqvault_settings"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
    }
}
