/*
 * Copyright 2024 LY Corporation
 *
 * LY Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.linecorp.webauthn.handler

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.hardware.biometrics.BiometricPrompt
import android.os.Bundle
import android.util.Log
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.IntentCompat
import com.linecorp.webauthn.model.Fido2PromptInfo
import java.lang.ref.WeakReference
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

class KeyguardManagerWrapper {

    class KeyguardNotSecuredException(message: String) : Exception(message)
    class DeviceCredentialIntentNotAvailableException(message: String) : Exception(message)
    class KeyguardManagerAuthenticationFailedException(val errorCode: Int?, message: String) : Exception(message)

    fun isSupported(context: Context): Boolean {
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return keyguardManager.isDeviceSecure
    }

    suspend fun authenticate(context: Context, fido2PromptInfo: Fido2PromptInfo?): Boolean {
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

        if (!keyguardManager.isKeyguardSecure) {
            throw KeyguardNotSecuredException("Keyguard not secured")
        }

        // Deprecated in API 29 in favour of BiometricPrompt with an allowed authenticator of
        // DEVICE_CREDENTIAL. That replacement needs an Activity to host the prompt, while this
        // wrapper is called with a plain Context and starts its own transparent Activity to
        // carry the result back. Migrating means rewriting that flow, which is the one path a
        // user takes to unlock a credential, so it is deliberately left for its own change.
        @Suppress("DEPRECATION")
        val intent = keyguardManager.createConfirmDeviceCredentialIntent(
            fido2PromptInfo?.title ?: "Device Credential Authentication",
            fido2PromptInfo?.description ?: "Input your Fingerprint or device credential to ensure it's you!"
        ) ?: throw DeviceCredentialIntentNotAvailableException("Device credential intent not available")

        Log.d("KeyguardManagerWrapper", "Starting AuthenticationActivity with intent")

        return suspendCancellableCoroutine { continuation ->
            val requestId = AuthenticationActivity.start(context, intent) { result, errorCode ->
                if (!continuation.isActive) {
                    return@start
                }
                if (result) {
                    Log.d("KeyguardManagerWrapper", "Authentication succeeded")
                    continuation.resume(true)
                } else {
                    Log.d("KeyguardManagerWrapper", "Authentication failed")
                    continuation.resumeWithException(
                        KeyguardManagerAuthenticationFailedException(
                            errorCode = errorCode,
                            message = "Authentication failed with errorCode: $errorCode"
                        )
                    )
                }
            }
            continuation.invokeOnCancellation {
                AuthenticationActivity.cancel(requestId)
            }
        }
    }

    class AuthenticationActivity : AppCompatActivity() {

        companion object {
            private const val EXTRA_AUTH_INTENT = "com.linecorp.webauthn.extra.AUTH_INTENT"
            private const val EXTRA_REQUEST_ID = "com.linecorp.webauthn.extra.REQUEST_ID"
            private val callbacks = ConcurrentHashMap<String, (Boolean, Int?) -> Unit>()
            private val activities = ConcurrentHashMap<String, WeakReference<AuthenticationActivity>>()

            internal fun start(context: Context, intent: Intent, callback: (Boolean, Int?) -> Unit): String {
                val requestId = UUID.randomUUID().toString()
                callbacks[requestId] = callback
                val activityIntent = Intent(context, AuthenticationActivity::class.java).apply {
                    putExtra(EXTRA_AUTH_INTENT, intent)
                    putExtra(EXTRA_REQUEST_ID, requestId)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                Log.d("AuthenticationActivity", "Starting activity with intent")
                try {
                    context.startActivity(activityIntent)
                } catch (error: Throwable) {
                    callbacks.remove(requestId)
                    throw error
                }
                return requestId
            }

            internal fun cancel(requestId: String) {
                callbacks.remove(requestId)
                activities.remove(requestId)?.get()?.let { activity ->
                    activity.runOnUiThread { activity.finish() }
                }
            }

            private fun isPending(requestId: String): Boolean = callbacks.containsKey(requestId)

            private fun attach(requestId: String, activity: AuthenticationActivity) {
                activities[requestId] = WeakReference(activity)
            }

            private fun detach(requestId: String, activity: AuthenticationActivity) {
                activities.computeIfPresent(requestId) { _, reference ->
                    if (reference.get() === activity) null else reference
                }
            }

            private fun complete(requestId: String, result: Boolean, errorCode: Int?) {
                activities.remove(requestId)
                callbacks.remove(requestId)?.invoke(result, errorCode)
            }
        }

        private var requestId: String? = null
        private var requestCompleted = false

        private val confirmCredential = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            Log.d("AuthenticationActivity", "Received result: ${result.resultCode}")
            when (result.resultCode) {
                RESULT_OK -> finishRequest(true, null)
                RESULT_CANCELED -> finishRequest(false, BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED)
                else -> finishRequest(false, BiometricPrompt.BIOMETRIC_ERROR_UNABLE_TO_PROCESS)
            }
            finish()
        }

        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            val pendingRequestId = intent.getStringExtra(EXTRA_REQUEST_ID)
            if (pendingRequestId == null || !isPending(pendingRequestId)) {
                finish()
                return
            }
            requestId = pendingRequestId
            attach(pendingRequestId, this)

            val authenticationIntent = IntentCompat.getParcelableExtra(intent, EXTRA_AUTH_INTENT, Intent::class.java)
            if (authenticationIntent != null) {
                Log.d("AuthenticationActivity", "Starting activity for result")
                confirmCredential.launch(authenticationIntent)
            } else {
                Log.d("AuthenticationActivity", "Intent is null, finishing activity")
                finishRequest(false, BiometricPrompt.BIOMETRIC_ERROR_UNABLE_TO_PROCESS)
                finish()
            }
        }

        override fun onDestroy() {
            if (!isChangingConfigurations && !requestCompleted) {
                finishRequest(false, BiometricPrompt.BIOMETRIC_ERROR_CANCELED)
            }
            requestId?.let { detach(it, this) }
            super.onDestroy()
        }

        private fun finishRequest(result: Boolean, errorCode: Int?) {
            if (requestCompleted) return
            requestCompleted = true
            requestId?.let { complete(it, result, errorCode) }
        }
    }
}
