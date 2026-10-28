package com.pqvault.app.provider

import android.content.Intent
import android.content.pm.PackageManager
import android.credentials.CredentialOption
import android.credentials.GetCredentialResponse
import android.os.Build
import android.os.Bundle
import android.service.credentials.CallingAppInfo
import android.service.credentials.CredentialProviderService
import android.service.credentials.GetCredentialRequest
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.common.truth.Truth.assertThat
import com.pqvault.app.data.VaultRepository
import com.pqvault.core.format.Base64Url
import com.pqvault.core.webauthn.AuthenticatorData
import com.pqvault.core.webauthn.SoftwareAuthenticator
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A sign-in through [CredentialActivity], with the request built as the system hands it to
 * the provider. The emulator has no network, so the site's statement file is unreachable,
 * which is the case where an existing passkey is still allowed.
 *
 * Creates its own vault and deletes it afterwards, so it refuses to run where one exists.
 */
@RunWith(AndroidJUnit4::class)
class ProviderClientDataTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val repository = VaultRepository.get(context)
    private val challenge = "c2lnbi1pbi1jaGFsbGVuZ2U"
    private var created = false
    private lateinit var credentialId: String

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
        credentialId = registration.entry.credentialId
    }

    @After
    fun deleteVault(): Unit = runBlocking {
        if (!created) return@runBlocking
        repository.lockNow()
        repository.vaultFile.delete()
    }

    /** What an app passes to Credential Manager, in the bundle form the provider receives. */
    private fun option(clientDataHash: ByteArray): CredentialOption {
        val data = Bundle().apply {
            putString(
                "androidx.credentials.BUNDLE_KEY_SUBTYPE",
                "androidx.credentials.BUNDLE_VALUE_SUBTYPE_GET_PUBLIC_KEY_CREDENTIAL_OPTION",
            )
            putString(
                "androidx.credentials.BUNDLE_KEY_REQUEST_JSON",
                """{"challenge":"$challenge","rpId":"github.com"}""",
            )
            putByteArray("androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH", clientDataHash)
        }
        return CredentialOption.Builder("androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL", data, data).build()
    }

    @Test
    fun anAppCannotHaveAWebOriginSignedByHandingOverItsHash() {
        // The hash of a clientDataJSON naming the site's web origin, which only a browser
        // relaying that page may claim.
        val forged = AuthenticatorData.sha256(
            JSONObject()
                .put("type", "webauthn.get")
                .put("challenge", challenge)
                .put("origin", "https://github.com")
                .toString()
                .toByteArray(),
        )
        val signing = context.packageManager
            .getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            .signingInfo!!
        val request = GetCredentialRequest(
            CallingAppInfo("com.example.stranger", signing),
            listOf(option(forged)),
        )
        val intent = Intent(context, CredentialActivity::class.java)
            .setAction(CredentialActivity.ACTION_GET)
            .putExtra(CredentialActivity.EXTRA_CREDENTIAL_ID, credentialId)
            .putExtra(CredentialProviderService.EXTRA_GET_CREDENTIAL_REQUEST, request)

        val result = ActivityScenario.launchActivityForResult<CredentialActivity>(intent).use { it.result }

        val response = result.resultData
            .getParcelableExtra(
                CredentialProviderService.EXTRA_GET_CREDENTIAL_RESPONSE,
                GetCredentialResponse::class.java,
            )
        assertThat(response).isNotNull()
        val json = JSONObject(
            response!!.credential.data.getString("androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON")!!,
        )
        val clientData = JSONObject(
            String(Base64Url.decode(json.getJSONObject("response").getString("clientDataJSON"))),
        )
        // Signed over clientDataJSON built here, with the app's own origin.
        assertThat(clientData.getString("origin")).startsWith("android:apk-key-hash:")
        assertThat(clientData.getString("challenge")).isEqualTo(challenge)
    }
}
