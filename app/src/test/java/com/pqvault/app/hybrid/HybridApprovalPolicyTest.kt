package com.pqvault.app.hybrid

import com.google.common.truth.Truth.assertThat
import com.pqvault.core.format.Base64Url
import com.pqvault.core.hybrid.Ctap2Protocol
import com.pqvault.core.model.PasskeyEntry
import org.junit.jupiter.api.Test

class HybridApprovalPolicyTest {
    private fun signIn(userVerification: Boolean) = Ctap2Protocol.Request.GetAssertion(
        rpId = "demo.yubico.com",
        clientDataHash = ByteArray(32),
        allowedCredentialIds = emptyList(),
        userVerification = userVerification,
    )

    private fun creation(userVerification: Boolean = false) = Ctap2Protocol.Request.MakeCredential(
        clientDataHash = ByteArray(32),
        rpId = "demo.yubico.com",
        rpName = "Yubico Demo",
        userHandle = byteArrayOf(1, 2, 3),
        userName = "alice",
        userDisplayName = "Alice",
        offeredAlgorithms = listOf(-7),
        excludedCredentialIds = emptyList(),
        residentKey = true,
        userVerification = userVerification,
    )

    private fun entry(
        rpId: String = "demo.yubico.com",
        userHandle: ByteArray = byteArrayOf(1, 2, 3),
        userName: String = "alice",
    ) = PasskeyEntry(
        credentialId = Base64Url.encode(ByteArray(32)),
        rpId = rpId,
        userHandle = Base64Url.encode(userHandle),
        userName = userName,
        privateKeyPkcs8 = "",
        publicKeySpki = "",
        createdAt = 0,
        updatedAt = 0,
    )

    @Test
    fun `security key style sign in still asks for local verification when available`() {
        val request = signIn(userVerification = false)

        assertThat(HybridApprovalPolicy.requiresVerification(request)).isFalse()
        assertThat(HybridApprovalPolicy.shouldVerify(request, verificationAvailable = true)).isTrue()
    }

    @Test
    fun `optional verification keeps sign in available without a secure lock`() {
        val request = signIn(userVerification = false)

        assertThat(HybridApprovalPolicy.shouldVerify(request, verificationAvailable = false)).isFalse()
        assertThat(HybridApprovalPolicy.requiresVerification(request)).isFalse()
    }

    @Test
    fun `required verification cannot become optional when local verification is unavailable`() {
        val request = signIn(userVerification = true)

        assertThat(HybridApprovalPolicy.shouldVerify(request, verificationAvailable = false)).isFalse()
        assertThat(HybridApprovalPolicy.requiresVerification(request)).isTrue()
    }

    @Test
    fun `registration also asks for local verification independently of site preference`() {
        assertThat(HybridApprovalPolicy.shouldVerify(creation(), verificationAvailable = true)).isTrue()
        assertThat(HybridApprovalPolicy.requiresVerification(creation(userVerification = true))).isTrue()
    }

    @Test
    fun `transport and capability commands never prompt for identity verification`() {
        listOf(
            Ctap2Protocol.Request.GetInfo,
            Ctap2Protocol.Request.Selection,
            Ctap2Protocol.Request.Cancel,
            Ctap2Protocol.Request.Unknown(0xff),
        ).forEach { request ->
            assertThat(HybridApprovalPolicy.shouldVerify(request, verificationAvailable = true)).isFalse()
        }
    }

    @Test
    fun `existing account warning uses stable user handle even after account renaming`() {
        assertThat(
            HybridApprovalPolicy.hasExistingAccount(creation(), listOf(entry(userName = "old-name"))),
        ).isTrue()
    }

    @Test
    fun `same name on another account or site does not trigger existing account warning`() {
        assertThat(
            HybridApprovalPolicy.hasExistingAccount(
                creation(),
                listOf(entry(rpId = "other.example"), entry(userHandle = byteArrayOf(4, 5, 6))),
            ),
        ).isFalse()
    }
}
