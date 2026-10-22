package com.pqvault.app.provider

import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PublicKeyCredentialEntry
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.common.truth.Truth.assertThat
import com.pqvault.app.data.VaultRepository
import com.pqvault.core.webauthn.AuthenticatorData
import com.pqvault.core.webauthn.SoftwareAuthenticator
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * What the system's passkey picker receives from the provider service while the vault is
 * open, for callers that may or may not speak for the site.
 *
 * Creates its own vault and deletes it afterwards, so it refuses to run where one exists.
 */
@RunWith(AndroidJUnit4::class)
class BeginGetListingTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val repository = VaultRepository.get(context)
    private var created = false
    private lateinit var secondId: String

    @Before
    fun createVault(): Unit = runBlocking {
        assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
        assumeFalse("a vault already exists on this device", repository.isInitialised)
        repository.create("correct horse battery staple".toCharArray())
        created = true
        val registration = SoftwareAuthenticator().makeCredential(
            rpId = "github.com",
            rpName = "GitHub",
            userHandle = "user-handle".toByteArray(),
            userName = "simon",
            userDisplayName = "Simon",
            clientDataHash = AuthenticatorData.sha256("client data".toByteArray()),
        )
        repository.upsert(registration.entry)
        val second = SoftwareAuthenticator().makeCredential(
            rpId = "github.com",
            rpName = "GitHub",
            userHandle = "other-handle".toByteArray(),
            userName = "other",
            userDisplayName = "Other",
            clientDataHash = AuthenticatorData.sha256("client data".toByteArray()),
        )
        repository.upsert(second.entry)
        secondId = second.entry.credentialId
    }

    @After
    fun deleteVault(): Unit = runBlocking {
        if (!created) return@runBlocking
        repository.lockNow()
        repository.vaultFile.delete()
    }

    /** A caller signed with a real certificate, as the system describes it to providers. */
    private fun caller(packageName: String, origin: String? = null): CallingAppInfo {
        val signing = context.packageManager
            .getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            .signingInfo!!
        return CallingAppInfo(packageName, signing, origin)
    }

    private fun request(rpId: String, caller: CallingAppInfo, allowed: String? = null) = BeginGetCredentialRequest(
        listOf(
            BeginGetPublicKeyCredentialOption(
                Bundle(),
                "option",
                if (allowed == null) {
                    """{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","rpId":"$rpId"}"""
                } else {
                    """{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","rpId":"$rpId",""" +
                        """"allowCredentials":[{"type":"public-key","id":"$allowed"}]}"""
                },
            ),
        ),
        caller,
    )

    /** The service exactly as the system binds it. */
    private fun ask(request: BeginGetCredentialRequest): BeginGetCredentialResponse {
        val service = PqVaultCredentialProviderService()
        ContextWrapper::class.java
            .getDeclaredMethod("attachBaseContext", Context::class.java)
            .apply { isAccessible = true }
            .invoke(service, context)
        var answer: BeginGetCredentialResponse? = null
        service.onBeginGetCredentialRequest(
            request,
            CancellationSignal(),
            object : OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException> {
                override fun onResult(result: BeginGetCredentialResponse) {
                    answer = result
                }

                override fun onError(error: GetCredentialException) {
                    throw AssertionError(error)
                }
            },
        )
        return answer!!
    }

    @Test
    fun anAppTheSiteNeverVouchedForLearnsNothingAboutItsAccounts() {
        val stranger = caller("com.example.stranger")

        val held = ask(request("github.com", stranger))
        val absent = ask(request("nothing.example", stranger))

        // No account name, and the same answer whether the vault holds one or not.
        assertThat(held.credentialEntries).isEmpty()
        assertThat(held.authenticationActions).hasSize(1)
        assertThat(absent.credentialEntries).isEmpty()
        assertThat(absent.authenticationActions).hasSize(1)
        assertThat(held.authenticationActions[0].title).isEqualTo(absent.authenticationActions[0].title)
    }

    @Test
    fun anAppClaimingAWebOriginWithoutBeingATrustedBrowserGetsNothing() {
        val answer = ask(request("github.com", caller("com.example.fake.browser", "https://github.com")))

        assertThat(answer.credentialEntries).isEmpty()
        assertThat(answer.authenticationActions).isEmpty()
    }

    @Test
    fun anEntitledCallerStillSeesItsAccounts() {
        val stranger = caller("com.example.stranger")
        val answer = CredentialEntries.response(context, request("github.com", stranger), repository) {
            CredentialEntries.Listing.ALLOWED
        }

        assertThat(answer.credentialEntries).hasSize(2)
        assertThat(answer.authenticationActions).isEmpty()
    }

    @Test
    fun aLaterRequestNeverRepointsAnEntryStillOnScreen() {
        val stranger = caller("com.example.stranger")
        val both = CredentialEntries.response(context, request("github.com", stranger), repository) {
            CredentialEntries.Listing.ALLOWED
        }
        val onlySecond = CredentialEntries.response(
            context,
            request("github.com", stranger, allowed = secondId),
            repository,
        ) { CredentialEntries.Listing.ALLOWED }

        val shown = HashMap<String, android.app.PendingIntent>()
        for (entry in both.credentialEntries) {
            val passkey = entry as PublicKeyCredentialEntry
            shown[passkey.username.toString()] = passkey.pendingIntent
        }
        val later = onlySecond.credentialEntries[0] as PublicKeyCredentialEntry
        assertThat(later.username.toString()).isEqualTo("other")
        // The first list's "simon" entry keeps its own intent, distinct from the new one.
        assertThat(shown["simon"]).isNotEqualTo(later.pendingIntent)
        assertThat(shown["other"]).isEqualTo(later.pendingIntent)
    }
}
