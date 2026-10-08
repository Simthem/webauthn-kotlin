package com.pqvault.app.provider

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.PublicKeyCredentialEntry
import com.pqvault.app.data.VaultRepository
import org.json.JSONObject

/**
 * The passkeys offered for a credential request, built the same way in both places that
 * answer one: the provider service when the vault is already open, and the unlock action
 * once the user has opened it. Android does not query the provider again after an
 * authentication action, so that action has to return the list itself.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
internal object CredentialEntries {

    private const val GET_REQUEST_CODE_BASE = 100

    /** Assumes an unlocked vault: a locked one has nothing it may reveal. */
    fun response(
        context: Context,
        request: BeginGetCredentialRequest,
        repository: VaultRepository,
    ): BeginGetCredentialResponse = BeginGetCredentialResponse(
        credentialEntries = request.beginGetCredentialOptions
            .filterIsInstance<BeginGetPublicKeyCredentialOption>()
            .flatMap { option -> entriesFor(context, option, repository) },
    )

    fun pendingIntent(
        context: Context,
        action: String,
        requestCode: Int,
        credentialId: String? = null,
    ): PendingIntent {
        val intent = Intent(context, CredentialActivity::class.java)
            .setAction(action)
            .setPackage(context.packageName)
            .apply { credentialId?.let { putExtra(CredentialActivity.EXTRA_CREDENTIAL_ID, it) } }
        return PendingIntent.getActivity(
            context,
            requestCode,
            intent,
            // MUTABLE is required: the system injects the actual credential request into
            // this intent before launching it.
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    private fun entriesFor(
        context: Context,
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
                    context = context,
                    username = entry.userName,
                    pendingIntent = pendingIntent(
                        context = context,
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
}
