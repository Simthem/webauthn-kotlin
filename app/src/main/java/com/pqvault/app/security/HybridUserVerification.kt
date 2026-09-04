package com.pqvault.app.security

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.pqvault.app.R
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/** Fresh local user verification before a remote WebAuthn signature is released. */
class HybridUserVerification(private val context: Context) {
    sealed interface Result {
        data object Verified : Result
        data object Cancelled : Result
        data class Failed(val message: String) : Result
    }

    val isAvailable: Boolean
        get() = BiometricManager.from(context).canAuthenticate(AUTHENTICATORS) ==
            BiometricManager.BIOMETRIC_SUCCESS

    suspend fun verify(activity: FragmentActivity, relyingParty: String): Result =
        suspendCancellableCoroutine { continuation ->
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(context.getString(R.string.hybrid_verify_title))
                .setSubtitle(context.getString(R.string.hybrid_verify_subtitle, relyingParty))
                .setAllowedAuthenticators(AUTHENTICATORS)
                .build()
            val prompt = BiometricPrompt(
                activity,
                androidx.core.content.ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (continuation.isActive) continuation.resume(Result.Verified)
                    }

                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        if (!continuation.isActive) return
                        val cancelled = code == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                            code == BiometricPrompt.ERROR_USER_CANCELED ||
                            code == BiometricPrompt.ERROR_CANCELED
                        continuation.resume(
                            if (cancelled) Result.Cancelled else Result.Failed(message.toString()),
                        )
                    }
                },
            )
            prompt.authenticate(info)
            continuation.invokeOnCancellation { prompt.cancelAuthentication() }
        }

    private companion object {
        const val AUTHENTICATORS = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
    }
}
