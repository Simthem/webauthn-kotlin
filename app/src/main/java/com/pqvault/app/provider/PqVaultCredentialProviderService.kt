package com.pqvault.app.provider

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import com.pqvault.app.R
import com.pqvault.app.data.VaultRepository
import org.json.JSONObject

/**
 * Makes the vault a system-wide passkey provider.
 *
 * This is the piece that turns a private vault into something browsers and other apps can
 * actually use, and it is what the upstream library never had: that library made an app
 * an authenticator for its *own* relying party, which cannot serve a passkey to Fennec or
 * to any other app on the phone.
 *
 * Introduced in Android 14 (API 34). The manifest declares the service unconditionally
 * and the system simply never binds it on older builds, so the app degrades to a
 * standalone syncing vault rather than failing to install.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class PqVaultCredentialProviderService : CredentialProviderService() {

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        try {
            val repository = VaultRepository.get(this)

            if (!repository.isInitialised) {
                callback.onResult(BeginGetCredentialResponse())
                return
            }

            // A locked vault must not reveal which sites the user has accounts on, so we
            // answer with an unlock action rather than a credential list. The system shows
            // it as "Unlock PQ Vault" and re-queries once the user has authenticated.
            if (!repository.isUnlocked) {
                callback.onResult(
                    BeginGetCredentialResponse(
                        authenticationActions = listOf(
                            AuthenticationAction(
                                title = getString(R.string.unlock_vault_title),
                                pendingIntent = pendingIntent(CredentialActivity.ACTION_UNLOCK, UNLOCK_REQUEST_CODE),
                            ),
                        ),
                    ),
                )
                return
            }

            val entries = request.beginGetCredentialOptions
                .filterIsInstance<BeginGetPublicKeyCredentialOption>()
                .flatMap { option -> entriesFor(option, repository) }

            callback.onResult(BeginGetCredentialResponse(credentialEntries = entries))
        } catch (e: Exception) {
            callback.onError(GetCredentialUnknownException(e.message))
        }
    }

    private fun entriesFor(
        option: BeginGetPublicKeyCredentialOption,
        repository: VaultRepository,
    ): List<PublicKeyCredentialEntry> {
        val rpId = rpIdOf(option.requestJson) ?: return emptyList()
        val allowed = allowedCredentialIds(option.requestJson)

        return repository.entriesFor(rpId)
            // An empty allowList means a discoverable-credential request: offer everything
            // we hold for the site. A populated one restricts us to what the site named.
            .filter { allowed.isEmpty() || it.credentialId in allowed }
            .mapIndexed { index, entry ->
                PublicKeyCredentialEntry.Builder(
                    context = this,
                    username = entry.userName,
                    pendingIntent = pendingIntent(
                        action = CredentialActivity.ACTION_GET,
                        requestCode = GET_REQUEST_CODE_BASE + index,
                        credentialId = entry.credentialId,
                    ),
                    beginGetPublicKeyCredentialOption = option,
                )
                    .setDisplayName(entry.userDisplayName ?: entry.rpName ?: entry.rpId)
                    .build()
            }
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (request !is BeginCreatePublicKeyCredentialRequest) {
            // Passwords and other credential types are not ours to store.
            callback.onResult(BeginCreateCredentialResponse())
            return
        }

        val repository = VaultRepository.get(this)
        callback.onResult(
            BeginCreateCredentialResponse(
                createEntries = listOf(
                    CreateEntry.Builder(
                        accountName = "PQ Vault",
                        pendingIntent = pendingIntent(CredentialActivity.ACTION_CREATE, CREATE_REQUEST_CODE),
                    )
                        .setDescription(
                            getString(
                                if (repository.isUnlocked) {
                                    R.string.provider_save_unlocked
                                } else {
                                    R.string.provider_save_locked
                                },
                            ),
                        )
                        .build(),
                ),
            ),
        )
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, androidx.credentials.exceptions.ClearCredentialException>,
    ) {
        VaultRepository.get(this).lock()
        callback.onResult(null)
    }

    private fun pendingIntent(action: String, requestCode: Int, credentialId: String? = null): PendingIntent {
        val intent = Intent(this, CredentialActivity::class.java)
            .setAction(action)
            .setPackage(packageName)
            .apply { credentialId?.let { putExtra(CredentialActivity.EXTRA_CREDENTIAL_ID, it) } }
        return PendingIntent.getActivity(
            this,
            requestCode,
            intent,
            // MUTABLE is required: the system injects the actual credential request into
            // this intent before launching it.
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    private fun rpIdOf(requestJson: String): String? = try {
        val json = JSONObject(requestJson)
        // Registration nests it under "rp"; authentication carries it at the top level.
        json.optJSONObject("rp")?.optString("id")?.takeIf { it.isNotEmpty() }
            ?: json.optString("rpId").takeIf { it.isNotEmpty() }
    } catch (e: org.json.JSONException) {
        null
    }

    private fun allowedCredentialIds(requestJson: String): Set<String> = try {
        val array = JSONObject(requestJson).optJSONArray("allowCredentials")
        buildSet {
            for (i in 0 until (array?.length() ?: 0)) {
                array?.optJSONObject(i)?.optString("id")?.takeIf { it.isNotEmpty() }?.let(::add)
            }
        }
    } catch (e: org.json.JSONException) {
        emptySet()
    }

    private companion object {
        const val UNLOCK_REQUEST_CODE = 1
        const val CREATE_REQUEST_CODE = 2
        const val GET_REQUEST_CODE_BASE = 100
    }
}
