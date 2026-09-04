package com.pqvault.app.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.pqvault.app.R
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * Fresh local user verification before a remote WebAuthn signature is released.
 *
 * The answer comes from the Android Keystore, not from the prompt's callback.
 * [BiometricPrompt] reports success by invoking a method, and a method call is only as
 * trustworthy as the process it runs in: on a rooted phone `onAuthenticationSucceeded`
 * can be invoked without anyone touching the sensor. What that buys an attacker here is
 * an assertion signed for someone else's account, so a boolean is not enough evidence.
 *
 * The prompt therefore carries a [BiometricPrompt.CryptoObject] wrapping a key generated
 * with `setUserAuthenticationRequired`, and the caller is told `Verified` only once that
 * key has actually encrypted something. The key protects nothing at rest and holds no
 * secret; its only job is to be unusable until the user has authenticated for real. This
 * is the same guarantee [BiometricVaultLock] relies on, for the same reason.
 */
class HybridUserVerification(private val context: Context) {

    private val random = SecureRandom()

    sealed interface Result {
        data object Verified : Result
        data object Cancelled : Result
        data class Failed(val message: String) : Result
    }

    val isAvailable: Boolean
        get() = BiometricManager.from(context).canAuthenticate(AUTHENTICATORS) ==
            BiometricManager.BIOMETRIC_SUCCESS

    suspend fun verify(activity: FragmentActivity, relyingParty: String): Result {
        val cipher = try {
            initCipher()
        } catch (e: Exception) {
            return Result.Failed(e.message ?: context.getString(R.string.hybrid_verify_key_failed))
        }

        return when (val outcome = prompt(activity, relyingParty, cipher)) {
            is PromptOutcome.Success -> exerciseKey(outcome.cipher)
            PromptOutcome.Cancelled -> Result.Cancelled
            is PromptOutcome.Failed -> Result.Failed(outcome.message)
        }
    }

    /**
     * The step that makes the answer worth something. A callback invoked without a real
     * authentication hands back a cipher the Keystore never authorised, and `doFinal`
     * throws instead of returning bytes, so no path reaches [Result.Verified] without the
     * user having passed the prompt. The plaintext is random and discarded: what is being
     * checked is that the key was usable at all.
     */
    private fun exerciseKey(cipher: Cipher): Result = try {
        cipher.doFinal(ByteArray(CHALLENGE_BYTES).also { random.nextBytes(it) })
        Result.Verified
    } catch (_: Exception) {
        Result.Failed(context.getString(R.string.hybrid_verify_key_failed))
    }

    private fun initCipher(): Cipher = try {
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, verificationKey()) }
    } catch (_: KeyPermanentlyInvalidatedException) {
        // Enrolling a new fingerprint invalidates the key. Unlike the vault lock there is
        // nothing wrapped under it, so regenerating costs nothing: the next prompt simply
        // asks for the finger that now exists.
        deleteKey()
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, createKey()) }
    }

    private fun verificationKey(): SecretKey =
        androidKeyStore().getKey(KEY_ALIAS, null) as? SecretKey ?: createKey()

    private fun createKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                // Zero seconds of validity: every signature released needs its own
                // authentication, not one that happened at some point earlier in the
                // session. The same window the vault lock uses.
                .setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
                .build(),
        )
        return generator.generateKey()
    }

    private fun deleteKey() {
        runCatching { androidKeyStore().deleteEntry(KEY_ALIAS) }
    }

    private fun androidKeyStore(): KeyStore =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private sealed class PromptOutcome {
        class Success(val cipher: Cipher) : PromptOutcome()
        object Cancelled : PromptOutcome()
        class Failed(val message: String) : PromptOutcome()
    }

    private suspend fun prompt(
        activity: FragmentActivity,
        relyingParty: String,
        cipher: Cipher,
    ): PromptOutcome = suspendCancellableCoroutine { continuation ->
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(context.getString(R.string.hybrid_verify_title))
            .setSubtitle(context.getString(R.string.hybrid_verify_subtitle, relyingParty))
            // No negative button text on purpose: the builder rejects one when device
            // credentials are an allowed authenticator, because the system supplies its
            // own fallback in that case.
            .setAllowedAuthenticators(AUTHENTICATORS)
            .build()
        val prompt = BiometricPrompt(
            activity,
            androidx.core.content.ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (!continuation.isActive) return
                    val authenticated = result.cryptoObject?.cipher
                    continuation.resume(
                        if (authenticated == null) {
                            PromptOutcome.Failed(context.getString(R.string.hybrid_verify_key_failed))
                        } else {
                            PromptOutcome.Success(authenticated)
                        },
                    )
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
            },
        )
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        continuation.invokeOnCancellation { prompt.cancelAuthentication() }
    }

    private companion object {
        const val AUTHENTICATORS = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        const val KEY_ALIAS = "pqvault_hybrid_user_verification"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val CHALLENGE_BYTES = 32
    }
}
