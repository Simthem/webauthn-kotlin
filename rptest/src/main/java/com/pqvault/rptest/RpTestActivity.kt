package com.pqvault.rptest

import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import java.security.SecureRandom

/**
 * Pretends to be a website asking for a passkey, so we can watch what the system picker
 * offers. The only thing being tested here is whether PQ Vault shows up at all.
 */
class RpTestActivity : AppCompatActivity() {

    private lateinit var output: TextView

    private fun challenge(): String {
        val bytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(40, 220, 40, 40)
        }
        output = TextView(this).apply { textSize = 13f; setTextIsSelectable(true) }

        root.addView(
            Button(this).apply {
                text = "Create a passkey"
                setOnClickListener { create() }
            },
        )
        root.addView(
            Button(this).apply {
                text = "Use a passkey"
                setOnClickListener { get() }
            },
        )
        root.addView(ScrollView(this).apply { addView(output) })
        setContentView(root)
    }

    private fun create() {
        val json = """
            {
              "rp": {"id": "pqvault.test", "name": "PQ Vault Test"},
              "user": {
                "id": "${challenge()}",
                "name": "simon",
                "displayName": "Simon"
              },
              "challenge": "${challenge()}",
              "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257}
              ],
              "authenticatorSelection": {
                "residentKey": "required",
                "userVerification": "preferred"
              }
            }
        """.trimIndent()

        lifecycleScope.launch {
            log("Create request sent...")
            runCatching {
                CredentialManager.create(this@RpTestActivity).createCredential(
                    context = this@RpTestActivity,
                    request = CreatePublicKeyCredentialRequest(json),
                )
            }.onSuccess {
                log("SUCCESS\n${it.data}")
            }.onFailure {
                log("FAILED: ${it::class.java.simpleName}\n${it.message}")
                Log.e("RpTest", "create failed", it)
            }
        }
    }

    private fun get() {
        val json = """
            {
              "challenge": "${challenge()}",
              "rpId": "pqvault.test",
              "userVerification": "preferred"
            }
        """.trimIndent()

        lifecycleScope.launch {
            log("Authentication request sent...")
            runCatching {
                CredentialManager.create(this@RpTestActivity).getCredential(
                    context = this@RpTestActivity,
                    request = GetCredentialRequest(listOf(GetPublicKeyCredentialOption(json))),
                )
            }.onSuccess {
                log("SUCCESS\n${it.credential.data}")
            }.onFailure {
                log("FAILED: ${it::class.java.simpleName}\n${it.message}")
                Log.e("RpTest", "get failed", it)
            }
        }
    }

    private fun log(text: String) {
        output.text = text
        Log.i("RpTest", text)
    }
}
