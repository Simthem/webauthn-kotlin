package com.pqvault.app.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.pqvault.app.R
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * Biometric unlock for the vault.
 *
 * This is the one place the Android Keystore is the right tool. It wraps the vault master
 * key in a hardware-bound AES key that only releases after a fingerprint, so the phone
 * can reopen the vault without the passphrase being typed or held anywhere.
 *
 * It wraps a *copy* and changes nothing about the vault file itself. The passphrase
 * stays the root of trust and the vault stays portable, the property the upstream
 * library lost by putting the passkeys themselves in the Keystore.
 * Losing this phone loses this shortcut, not the passkeys.
 */
class BiometricVaultLock(private val context: Context) {

    private val wrappedKeyFile: File
        get() = File(context.filesDir, "biometric_unlock.bin")

    sealed class UnlockResult {
        class Success(val masterKey: ByteArray) : UnlockResult()

        /** No biometric wrap has been set up yet. */
        object NotEnrolled : UnlockResult()

        /**
         * A new fingerprint was enrolled, so the Keystore permanently invalidated the
         * key. This is intended: someone who adds their own fingerprint to a stolen,
         * unlocked phone must not inherit vault access. The user re-enrols with the
         * passphrase.
         */
        object InvalidatedByNewBiometric : UnlockResult()

        object Cancelled : UnlockResult()

        class Failed(val message: String) : UnlockResult()
    }

    fun isAvailable(): Boolean =
        BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    fun isEnrolled(): Boolean = wrappedKeyFile.exists()

    fun clearEnrollment() {
        wrappedKeyFile.delete()
        runCatching { androidKeyStore().deleteEntry(KEY_ALIAS) }
    }

    /**
     * Wraps [masterKey] behind a fresh biometric-gated Keystore key. Requires a
     * successful biometric prompt so the key is provably usable before we rely on it.
     */
    suspend fun enroll(activity: FragmentActivity, masterKey: ByteArray): UnlockResult {
        return try {
            val secretKey = createKeystoreKey()
            val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, secretKey) }

            when (val auth = prompt(activity, cipher, enrolling = true)) {
                is PromptOutcome.Success -> {
                    val authenticated = auth.cipher
                    val ciphertext = authenticated.doFinal(masterKey)
                    val iv = authenticated.iv
                    // Layout: [iv length][iv][ciphertext]
                    wrappedKeyFile.writeBytes(byteArrayOf(iv.size.toByte()) + iv + ciphertext)
                    UnlockResult.Success(masterKey.copyOf())
                }
                PromptOutcome.Cancelled -> UnlockResult.Cancelled
                is PromptOutcome.Failed -> UnlockResult.Failed(auth.message)
            }
        } catch (e: Exception) {
            UnlockResult.Failed(e.message ?: "biometric setup failed")
        }
    }

    /** Prompts for a fingerprint and returns the vault master key on success. */
    suspend fun unlock(activity: FragmentActivity): UnlockResult {
        if (!wrappedKeyFile.exists()) return UnlockResult.NotEnrolled

        val stored = wrappedKeyFile.readBytes()
        if (stored.size < 2) return UnlockResult.Failed("biometric key file is corrupt")
        val ivLength = stored[0].toInt() and 0xFF
        if (stored.size < 1 + ivLength) return UnlockResult.Failed("biometric key file is corrupt")
        val iv = stored.copyOfRange(1, 1 + ivLength)
        val ciphertext = stored.copyOfRange(1 + ivLength, stored.size)

        val cipher = try {
            val key = androidKeyStore().getKey(KEY_ALIAS, null) as? SecretKey
                ?: return UnlockResult.NotEnrolled
            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            clearEnrollment()
            return UnlockResult.InvalidatedByNewBiometric
        } catch (e: Exception) {
            return UnlockResult.Failed(e.message ?: "could not prepare the biometric key")
        }

        return when (val auth = prompt(activity, cipher, enrolling = false)) {
            is PromptOutcome.Success -> try {
                UnlockResult.Success(auth.cipher.doFinal(ciphertext))
            } catch (e: Exception) {
                UnlockResult.Failed("the wrapped vault key failed to decrypt")
            }
            PromptOutcome.Cancelled -> UnlockResult.Cancelled
            is PromptOutcome.Failed -> UnlockResult.Failed(auth.message)
        }
    }

    private sealed class PromptOutcome {
        class Success(val cipher: Cipher) : PromptOutcome()
        object Cancelled : PromptOutcome()
        class Failed(val message: String) : PromptOutcome()
    }

    private suspend fun prompt(
        activity: FragmentActivity,
        cipher: Cipher,
        enrolling: Boolean,
    ): PromptOutcome = suspendCancellableCoroutine { continuation ->
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(
                context.getString(
                    if (enrolling) R.string.biometric_prompt_enable_title else R.string.biometric_prompt_unlock_title,
                ),
            )
            .setSubtitle(
                context.getString(
                    if (enrolling) {
                        R.string.biometric_prompt_enable_subtitle
                    } else {
                        R.string.biometric_prompt_unlock_subtitle
                    },
                ),
            )
            .setNegativeButtonText(context.getString(R.string.use_passphrase_instead))
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .build()

        val prompt = BiometricPrompt(
            activity,
            androidx.core.content.ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authenticatedCipher = result.cryptoObject?.cipher
                    if (authenticatedCipher == null) {
                        if (continuation.isActive) {
                            continuation.resume(PromptOutcome.Failed("no cipher returned by the prompt"))
                        }
                    } else if (continuation.isActive) {
                        continuation.resume(PromptOutcome.Success(authenticatedCipher))
                    }
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    if (!continuation.isActive) return
                    val cancelled = code == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                        code == BiometricPrompt.ERROR_USER_CANCELED ||
                        code == BiometricPrompt.ERROR_CANCELED
                    continuation.resume(
                        if (cancelled) PromptOutcome.Cancelled else PromptOutcome.Failed(message.toString()),
                    )
                }
                // onAuthenticationFailed is a single rejected finger, not a final answer:
                // the prompt stays up, so there is nothing to resume here.
            },
        )
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        continuation.invokeOnCancellation { prompt.cancelAuthentication() }
    }

    private fun androidKeyStore(): KeyStore =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun createKeystoreKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                // Every use needs a fresh fingerprint: a 0-second validity window means
                // an unlocked phone left on a desk does not keep handing out the key.
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                // Enrolling a new fingerprint destroys the key. Someone who adds a finger
                // to a stolen phone must not inherit vault access.
                .setInvalidatedByBiometricEnrollment(true)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        const val KEY_ALIAS = "pqvault_biometric_unlock"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
        const val BIOMETRIC_STRONG = BiometricManager.Authenticators.BIOMETRIC_STRONG
    }
}
