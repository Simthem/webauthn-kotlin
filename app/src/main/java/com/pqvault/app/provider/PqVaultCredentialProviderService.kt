package com.pqvault.app.provider

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
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import com.pqvault.app.R
import com.pqvault.app.data.VaultRepository

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
            // it as "Unlock PQ Vault", and the activity behind it returns the list once the
            // vault is open: the system does not query the provider again.
            if (!repository.isUnlocked) {
                callback.onResult(
                    BeginGetCredentialResponse(
                        authenticationActions = listOf(
                            AuthenticationAction(
                                title = getString(R.string.unlock_vault_title),
                                pendingIntent = CredentialEntries.pendingIntent(
                                    this,
                                    CredentialActivity.ACTION_UNLOCK,
                                    UNLOCK_REQUEST_CODE,
                                ),
                            ),
                        ),
                    ),
                )
                return
            }

            callback.onResult(CredentialEntries.response(this, request, repository))
        } catch (e: Exception) {
            callback.onError(GetCredentialUnknownException(e.message))
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
                        pendingIntent = CredentialEntries.pendingIntent(
                            this,
                            CredentialActivity.ACTION_CREATE,
                            CREATE_REQUEST_CODE,
                        ),
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

    private companion object {
        const val UNLOCK_REQUEST_CODE = 1
        const val CREATE_REQUEST_CODE = 2
    }
}
