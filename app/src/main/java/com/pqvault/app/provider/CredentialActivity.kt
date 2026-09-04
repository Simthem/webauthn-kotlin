package com.pqvault.app.provider

import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.annotation.RequiresApi
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import com.pqvault.app.R
import com.pqvault.app.data.SecureSettings
import com.pqvault.app.data.VaultRepository
import com.pqvault.app.security.BiometricVaultLock
import com.pqvault.core.format.Base64Url
import com.pqvault.core.model.CoseAlgorithm
import com.pqvault.core.webauthn.AuthenticatorData
import com.pqvault.core.webauthn.SoftwareAuthenticator
import com.pqvault.app.ui.screens.CredentialUnlockSheet
import com.pqvault.app.ui.theme.PqVaultTheme
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONArray
import org.json.JSONObject

/**
 * Handles the intents the system fires when the user picks our provider.
 *
 * Everything that needs the vault open, a fingerprint, or a signature happens here rather
 * than in the service: the service must answer the system's query in milliseconds and
 * cannot show UI.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CredentialActivity : AppCompatActivity() {

    private val authenticator = SoftwareAuthenticator()
    private val assetLinks = AssetLinksValidator()

    /** Drives the inline unlock sheet; null means no prompt is showing. */
    private val unlockPrompt = MutableStateFlow<UnlockPrompt?>(null)
    private var unlockWaiter: CancellableContinuation<Boolean>? = null

    class UnlockPrompt(val biometricsOffered: Boolean, val error: String?)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            PqVaultTheme {
                val prompt by unlockPrompt.collectAsState()
                prompt?.let {
                    CredentialUnlockSheet(
                        biometricsOffered = it.biometricsOffered,
                        error = it.error,
                        onPassphrase = ::submitPassphrase,
                        onBiometric = ::submitBiometric,
                        onCancel = { finishUnlock(false) },
                    )
                }
            }
        }

        when (intent.action) {
            ACTION_UNLOCK -> handleUnlock()
            ACTION_GET -> handleGet()
            ACTION_CREATE -> handleCreate()
            else -> finish()
        }
    }

    private fun handleUnlock() {
        lifecycleScope.launch {
            unlockVault()
            // The system re-queries the provider once we return, so there is nothing to
            // hand back here beyond having opened the vault.
            setResult(RESULT_OK)
            finish()
        }
    }

    /**
     * Opens the vault, asking the user however it can.
     *
     * Biometrics is tried first when it is set up, but it must never be the only route:
     * a phone with no enrolled fingerprint, or a key invalidated by a new enrolment,
     * would otherwise make every passkey in the vault permanently unusable from the
     * system picker. So the passphrase sheet is always available as a fallback.
     */
    private suspend fun unlockVault(): Boolean {
        val repository = VaultRepository.get(this)
        if (repository.isUnlocked) return true

        val lock = BiometricVaultLock(this)
        if (lock.isEnrolled() && lock.isAvailable()) {
            when (val result = lock.unlock(this)) {
                is BiometricVaultLock.UnlockResult.Success ->
                    if (repository.unlockWithMasterKey(result.masterKey)
                        is VaultRepository.UnlockOutcome.Success
                    ) {
                        return true
                    }
                // Anything else falls through to the passphrase sheet rather than failing.
                else -> Unit
            }
        }

        return suspendCancellableCoroutine { continuation ->
            unlockWaiter = continuation
            unlockPrompt.value = UnlockPrompt(
                biometricsOffered = lock.isEnrolled() && lock.isAvailable(),
                error = null,
            )
            continuation.invokeOnCancellation { unlockPrompt.value = null }
        }
    }

    private fun submitPassphrase(passphrase: String) {
        lifecycleScope.launch {
            when (VaultRepository.get(this@CredentialActivity).unlock(passphrase.toCharArray())) {
                is VaultRepository.UnlockOutcome.Success -> finishUnlock(true)
                is VaultRepository.UnlockOutcome.Untrusted ->
                    unlockPrompt.value = UnlockPrompt(false, getString(R.string.untrusted_signature))
                else ->
                    unlockPrompt.value = unlockPrompt.value?.let {
                        UnlockPrompt(it.biometricsOffered, getString(R.string.wrong_passphrase))
                    }
            }
        }
    }

    private fun submitBiometric() {
        lifecycleScope.launch {
            val lock = BiometricVaultLock(this@CredentialActivity)
            when (val result = lock.unlock(this@CredentialActivity)) {
                is BiometricVaultLock.UnlockResult.Success ->
                    if (VaultRepository.get(this@CredentialActivity)
                            .unlockWithMasterKey(result.masterKey) is VaultRepository.UnlockOutcome.Success
                    ) {
                        finishUnlock(true)
                    }
                is BiometricVaultLock.UnlockResult.InvalidatedByNewBiometric ->
                    unlockPrompt.value =
                        UnlockPrompt(false, getString(R.string.biometric_invalidated))
                else -> Unit
            }
        }
    }

    private fun finishUnlock(unlocked: Boolean) {
        unlockPrompt.value = null
        unlockWaiter?.let { if (it.isActive) it.resumeWith(Result.success(unlocked)) }
        unlockWaiter = null
    }

    private fun handleGet() {
        lifecycleScope.launch {
            val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
            val credentialId = intent.getStringExtra(EXTRA_CREDENTIAL_ID)
            if (request == null || credentialId == null) {
                failGet(getString(R.string.provider_bad_request))
                return@launch
            }
            if (!unlockVault()) {
                failGet(getString(R.string.unlock_cancelled))
                return@launch
            }

            val repository = VaultRepository.get(this@CredentialActivity)
            val entry = repository.entry(credentialId)
            if (entry == null) {
                failGet(getString(R.string.provider_no_passkey))
                return@launch
            }

            val option = request.credentialOptions
                .filterIsInstance<androidx.credentials.GetPublicKeyCredentialOption>()
                .firstOrNull()
            if (option == null) {
                failGet(getString(R.string.provider_bad_request))
                return@launch
            }

            val requestJson = JSONObject(option.requestJson)
            val challenge = requestJson.optString("challenge")

            val caller = CallerVerifier(privilegedAllowlist()).verify(request.callingAppInfo)
            if (caller is CallerVerifier.Result.Rejected) {
                failGet(getString(R.string.provider_caller_rejected, caller.reason))
                return@launch
            }
            val trusted = caller as CallerVerifier.Result.Trusted
            if (!checkAssetLinks(trusted, entry.rpId, allowWhenUnreachable = true)) {
                failGet(getString(R.string.provider_not_authorised, trusted.packageName, entry.rpId))
                return@launch
            }
            val origin = trusted.origin

            // A privileged caller (a browser) supplies the hash it already built, and we
            // must sign exactly that rather than reconstructing our own clientDataJSON.
            val providedHash = option.clientDataHash
            val clientDataJson = clientDataJson("webauthn.get", challenge, origin)
            val clientDataHash = providedHash ?: AuthenticatorData.sha256(clientDataJson.toByteArray())

            val assertion = authenticator.getAssertion(entry, clientDataHash)
            repository.upsert(assertion.updatedEntry)

            val responseJson = JSONObject().apply {
                put("id", entry.credentialId)
                put("rawId", entry.credentialId)
                put("type", "public-key")
                put("authenticatorAttachment", "platform")
                put("clientExtensionResults", JSONObject())
                put(
                    "response",
                    JSONObject().apply {
                        if (providedHash == null) {
                            put("clientDataJSON", Base64Url.encode(clientDataJson.toByteArray()))
                        }
                        put("authenticatorData", Base64Url.encode(assertion.authenticatorData))
                        put("signature", Base64Url.encode(assertion.signature))
                        put("userHandle", entry.userHandle)
                    },
                )
            }.toString()

            val result = Intent()
            PendingIntentHandler.setGetCredentialResponse(
                result,
                GetCredentialResponse(PublicKeyCredential(responseJson)),
            )
            setResult(RESULT_OK, result)
            finish()
        }
    }

    private fun handleCreate() {
        lifecycleScope.launch {
            val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
            val createRequest = request?.callingRequest as? androidx.credentials.CreatePublicKeyCredentialRequest
            if (createRequest == null) {
                failCreate(getString(R.string.provider_bad_request))
                return@launch
            }
            if (!unlockVault()) {
                failCreate(getString(R.string.unlock_cancelled))
                return@launch
            }

            val json = JSONObject(createRequest.requestJson)
            val rp: JSONObject? = json.optJSONObject("rp")
            val user: JSONObject? = json.optJSONObject("user")
            val rpId = rp?.optString("id").orEmpty()
            if (rp == null || user == null || rpId.isEmpty()) {
                failCreate(getString(R.string.provider_bad_request))
                return@launch
            }

            val algorithm = negotiateAlgorithm(json.optJSONArray("pubKeyCredParams"))
            if (algorithm == null) {
                failCreate(getString(R.string.provider_no_algorithm))
                return@launch
            }

            val challenge = json.optString("challenge")

            val caller = CallerVerifier(privilegedAllowlist()).verify(request.callingAppInfo)
            if (caller is CallerVerifier.Result.Rejected) {
                failCreate(getString(R.string.provider_caller_rejected, caller.reason))
                return@launch
            }
            val trusted = caller as CallerVerifier.Result.Trusted
            if (!checkAssetLinks(trusted, rpId, allowWhenUnreachable = false)) {
                failCreate(getString(R.string.provider_not_authorised, trusted.packageName, rpId))
                return@launch
            }
            val origin = trusted.origin
            val providedHash = createRequest.clientDataHash
            val clientDataJson = clientDataJson("webauthn.create", challenge, origin)
            val clientDataHash = providedHash ?: AuthenticatorData.sha256(clientDataJson.toByteArray())

            val registration = authenticator.makeCredential(
                rpId = rpId,
                rpName = rp.optString("name").takeIf { it.isNotEmpty() },
                userHandle = Base64Url.decode(user.optString("id")),
                userName = user.optString("name"),
                userDisplayName = user.optString("displayName").takeIf { it.isNotEmpty() },
                clientDataHash = clientDataHash,
                algorithm = algorithm,
            )
            VaultRepository.get(this@CredentialActivity).upsert(registration.entry)

            val responseJson = JSONObject().apply {
                put("id", registration.entry.credentialId)
                put("rawId", registration.entry.credentialId)
                put("type", "public-key")
                put("authenticatorAttachment", "platform")
                put("clientExtensionResults", JSONObject())
                put(
                    "response",
                    JSONObject().apply {
                        if (providedHash == null) {
                            put("clientDataJSON", Base64Url.encode(clientDataJson.toByteArray()))
                        }
                        put("attestationObject", Base64Url.encode(registration.attestationObject))
                        put("transports", JSONArray(listOf("internal", "hybrid")))
                    },
                )
            }.toString()

            val result = Intent()
            PendingIntentHandler.setCreateCredentialResponse(
                result,
                CreatePublicKeyCredentialResponse(responseJson),
            )
            setResult(RESULT_OK, result)
            finish()
        }
    }

    /**
     * Picks the algorithm from what the site offers. [CoseAlgorithm.negotiate] prefers
     * post-quantum when a site lists it, but the authenticator can only actually produce
     * ES256 today, so we fall back rather than fail.
     */
    private fun negotiateAlgorithm(params: JSONArray?): CoseAlgorithm? {
        val offered = buildList {
            for (i in 0 until (params?.length() ?: 0)) {
                params?.optJSONObject(i)?.let { add(it.optInt("alg")) }
            }
        }
        if (offered.isEmpty()) return CoseAlgorithm.ES256
        val negotiated = CoseAlgorithm.negotiate(offered) ?: return null
        return if (negotiated.postQuantum && offered.contains(CoseAlgorithm.ES256.id)) {
            CoseAlgorithm.ES256
        } else {
            negotiated
        }
    }

    private fun clientDataJson(type: String, challenge: String, origin: String): String =
        JSONObject().apply {
            put("type", type)
            put("challenge", challenge)
            put("origin", origin)
            put("crossOrigin", false)
        }.toString()

    private fun privilegedAllowlist(): String? =
        SecureSettings(this).load().privilegedBrowserAllowlist.takeIf { it.isNotBlank() }

    /**
     * Digital Asset Links check for native callers.
     *
     * A browser is skipped: it has already been verified against the privileged allowlist
     * and legitimately acts for many origins.
     *
     * [allowWhenUnreachable] is what an unfetchable statement file means, and the two
     * directions are genuinely different. Reading an existing passkey offline must keep
     * working: the credential was already bound to this caller, and stranding someone
     * without their logins because a site is down is a worse outcome than the residual
     * risk. Creating one is the opposite. Registration is inherently online, so a
     * statement file we cannot reach is a reason to stop rather than a normal offline
     * condition, and going ahead would mint a passkey for a caller no site has vouched
     * for.
     */
    private suspend fun checkAssetLinks(
        caller: CallerVerifier.Result.Trusted,
        rpId: String,
        allowWhenUnreachable: Boolean,
    ): Boolean {
        if (caller.isPrivilegedBrowser) return true
        var unreachable = false
        // A rotated app is authorised under any certificate in its proven lineage, and
        // the site may list whichever one it was told about first.
        for (fingerprint in caller.certificateFingerprintsHex) {
            when (assetLinks.validate(rpId, caller.packageName, fingerprint)) {
                is AssetLinksValidator.Result.Allowed -> return true
                is AssetLinksValidator.Result.Unavailable -> unreachable = true
                is AssetLinksValidator.Result.Denied -> Unit
            }
        }
        return unreachable && allowWhenUnreachable
    }

    private fun failGet(reason: String) {
        val result = Intent()
        PendingIntentHandler.setGetCredentialException(result, GetCredentialUnknownException(reason))
        setResult(RESULT_OK, result)
        finish()
    }

    private fun failCreate(reason: String) {
        val result = Intent()
        PendingIntentHandler.setCreateCredentialException(result, CreateCredentialUnknownException(reason))
        setResult(RESULT_OK, result)
        finish()
    }

    companion object {
        const val ACTION_UNLOCK = "com.pqvault.app.UNLOCK"
        const val ACTION_GET = "com.pqvault.app.GET"
        const val ACTION_CREATE = "com.pqvault.app.CREATE"
        const val EXTRA_CREDENTIAL_ID = "credential_id"
    }
}
