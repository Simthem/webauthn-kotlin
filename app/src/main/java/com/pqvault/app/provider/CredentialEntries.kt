package com.pqvault.app.provider

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.PublicKeyCredentialEntry
import com.pqvault.app.R
import com.pqvault.app.data.SecureSettings
import com.pqvault.app.data.VaultRepository
import org.json.JSONObject

/**
 * The passkeys offered for a credential request, built the same way in both places that
 * answer one: the provider service when the vault is already open, and the unlock action
 * once the user has opened it. Android does not query the provider again after an
 * authentication action, so that action has to return the list itself.
 *
 * The account names in that list are only shown to callers entitled to the site: any app
 * may ask, and a list that appears or not would tell it where the user has accounts.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
internal object CredentialEntries {

    private const val OPEN_REQUEST_CODE = 1

    /** Whether a caller may see the accounts held for a site. */
    enum class Listing { ALLOWED, DENIED, UNKNOWN }

    /**
     * Assumes an unlocked vault: a locked one has nothing it may reveal. A site whose
     * caller is still [Listing.UNKNOWN] gets the "continue" action instead of its accounts,
     * whether the vault holds any or not, and the activity behind it decides.
     */
    fun response(
        context: Context,
        request: BeginGetCredentialRequest,
        repository: VaultRepository,
        listing: (rpId: String) -> Listing,
    ): BeginGetCredentialResponse {
        var undecided = false
        val entries = request.beginGetCredentialOptions
            .filterIsInstance<BeginGetPublicKeyCredentialOption>()
            .flatMap { option ->
                val rpId = ProviderRequestPolicy.parse(option.requestJson)
                    ?.let(ProviderRequestPolicy::rpIdOf)
                    ?: return@flatMap emptyList()
                when (listing(rpId)) {
                    Listing.ALLOWED -> entriesFor(context, option, rpId, repository)
                    Listing.DENIED -> emptyList()
                    Listing.UNKNOWN -> {
                        undecided = true
                        emptyList()
                    }
                }
            }
        return BeginGetCredentialResponse(
            credentialEntries = entries,
            authenticationActions = if (undecided) {
                listOf(openAction(context, R.string.provider_continue_title))
            } else {
                emptyList()
            },
        )
    }

    /**
     * What the provider service can tell without the network. A browser on the privileged
     * allowlist relays the page's origin, which must belong to the site. A native app needs
     * the site's Digital Asset Links, and only an answer already in the cache counts here.
     */
    fun listing(
        caller: CallerVerifier.Result?,
        rpId: String,
        assetLinks: AssetLinksValidator,
    ): Listing {
        val trusted = caller as? CallerVerifier.Result.Trusted ?: return Listing.DENIED
        if (trusted.isPrivilegedBrowser) {
            return if (ProviderRequestPolicy.originServes(trusted.origin, rpId)) Listing.ALLOWED else Listing.DENIED
        }
        val answers = trusted.certificateFingerprintsHex.map { fingerprint ->
            assetLinks.cached(rpId, trusted.packageName, fingerprint)
        }
        return when {
            answers.any { it is AssetLinksValidator.Result.Allowed } -> Listing.ALLOWED
            answers.all { it is AssetLinksValidator.Result.Denied } -> Listing.DENIED
            else -> Listing.UNKNOWN
        }
    }

    /** The browsers trusted to relay a web origin, as [CallerVerifier] expects them. */
    fun privilegedAllowlist(context: Context): String? =
        SecureSettings(context).load().privilegedBrowserAllowlist
            .takeIf { it.isNotBlank() }
            ?.let(InstalledBrowsers::upgradeAllowlist)

    /** Opens [CredentialActivity], which unlocks the vault if needed and checks the caller. */
    fun openAction(context: Context, title: Int) = AuthenticationAction(
        title = context.getString(title),
        pendingIntent = pendingIntent(context, CredentialActivity.ACTION_UNLOCK, OPEN_REQUEST_CODE),
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
        rpId: String,
        repository: VaultRepository,
    ): List<PublicKeyCredentialEntry> {
        val allowed = allowedCredentialIds(option.requestJson)

        return repository.entriesFor(rpId)
            // An empty allowList means a discoverable-credential request: offer everything
            // we hold for the site. A populated one restricts us to what the site named.
            .filter { allowed.isEmpty() || it.credentialId in allowed }
            .map { entry ->
                PublicKeyCredentialEntry.Builder(
                    context = context,
                    username = entry.userName,
                    // One intent per passkey: keyed by position, the next request's list
                    // would rewrite an entry still on screen to sign with another account.
                    pendingIntent = pendingIntent(
                        context = context,
                        action = CredentialActivity.ACTION_GET,
                        requestCode = entry.credentialId.hashCode(),
                        credentialId = entry.credentialId,
                    ),
                    beginGetPublicKeyCredentialOption = option,
                )
                    .setDisplayName(entry.userDisplayName ?: entry.rpName ?: entry.rpId)
                    .build()
            }
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
