package com.pqvault.core.hybrid

import com.pqvault.core.format.Base64Url
import com.pqvault.core.model.CoseAlgorithm
import com.pqvault.core.model.PasskeyEntry
import com.pqvault.core.ssh.OpenSshKeys
import com.pqvault.core.ssh.SshSignedData
import com.pqvault.core.webauthn.SoftwareAuthenticator

/**
 * What a CTAP request from another device may do, checked before the user is asked and again
 * before anything is signed. A request for an `ssh:` application always needs verification.
 */
object RemoteRequestPolicy {
    enum class Refusal(val status: Int) {
        NO_ALGORITHM(Ctap2Protocol.STATUS_UNSUPPORTED_ALGORITHM),
        EXCLUDED(Ctap2Protocol.STATUS_CREDENTIAL_EXCLUDED),
        VERIFICATION_UNAVAILABLE(Ctap2Protocol.STATUS_UNSUPPORTED_OPTION),
        NO_CREDENTIALS(Ctap2Protocol.STATUS_NO_CREDENTIALS),
    }

    sealed interface Creation {
        data class Allowed(val algorithm: CoseAlgorithm) : Creation
        data class Refused(val refusal: Refusal) : Creation
    }

    sealed interface Assertion {
        data class Allowed(val candidates: List<PasskeyEntry>) : Assertion
        data class Refused(val refusal: Refusal) : Assertion
    }

    fun isSsh(request: Ctap2Protocol.Request): Boolean = when (request) {
        Ctap2Protocol.Request.ListSshKeys -> true
        is Ctap2Protocol.Request.MakeCredential -> OpenSshKeys.isApplication(request.rpId)
        is Ctap2Protocol.Request.GetAssertion -> OpenSshKeys.isApplication(request.rpId)
        else -> false
    }

    /**
     * The operation an SSH request signs, read from the bytes the computer sent only once
     * their hash is the one the signature covers. Null when it cannot be established.
     */
    fun sshOperation(request: Ctap2Protocol.Request.GetAssertion): SshSignedData? {
        val data = request.signedData ?: return null
        if (!isSsh(request) || !HybridCrypto.sha256(data).contentEquals(request.clientDataHash)) return null
        return SshSignedData.parse(data)
    }

    /** The computer's description of the command, fit for display but never verified. */
    fun declaredCaller(request: Ctap2Protocol.Request.GetAssertion): String? =
        request.declaredCaller?.takeIf { it.isNotBlank() && SshSignedData.displayable(it) }

    fun requiresVerification(request: Ctap2Protocol.Request.MakeCredential): Boolean =
        isSsh(request) || request.userVerification || request.credentialProtection == 3

    fun requiresVerification(request: Ctap2Protocol.Request.GetAssertion, entry: PasskeyEntry): Boolean =
        isSsh(request) || OpenSshKeys.isSshKey(entry) || request.userVerification ||
            entry.credentialProtection == 3 ||
            (entry.credentialProtection == 2 && request.allowedCredentialIds.isEmpty())

    /** [existing] is what the vault holds for the request's relying party or application. */
    fun admit(
        request: Ctap2Protocol.Request.MakeCredential,
        existing: List<PasskeyEntry>,
        verificationAvailable: Boolean,
    ): Creation {
        val algorithm = SoftwareAuthenticator.selectAlgorithm(request.offeredAlgorithms)
            ?: return Creation.Refused(Refusal.NO_ALGORITHM)
        val excluded = existing.any { entry ->
            entry.rpId == request.rpId && request.excludedCredentialIds.any { excludedId ->
                Base64Url.decode(entry.credentialId).contentEquals(excludedId)
            }
        }
        if (excluded) return Creation.Refused(Refusal.EXCLUDED)
        if (requiresVerification(request) && !verificationAvailable) {
            return Creation.Refused(Refusal.VERIFICATION_UNAVAILABLE)
        }
        return Creation.Allowed(algorithm)
    }

    /** The passkeys the user may pick from. A silent probe ("up": false) never gets one. */
    fun select(
        request: Ctap2Protocol.Request.GetAssertion,
        existing: List<PasskeyEntry>,
        verificationAvailable: Boolean,
    ): Assertion {
        if (!request.userPresence) return Assertion.Refused(Refusal.NO_CREDENTIALS)
        if ((isSsh(request) || request.userVerification) && !verificationAvailable) {
            return Assertion.Refused(Refusal.VERIFICATION_UNAVAILABLE)
        }
        val candidates = existing.filter { entry ->
            entry.rpId == request.rpId &&
                (if (request.allowedCredentialIds.isEmpty()) {
                    entry.discoverable
                } else {
                    request.allowedCredentialIds.any { allowed ->
                        Base64Url.decode(entry.credentialId).contentEquals(allowed)
                    }
                }) &&
                (verificationAvailable || !requiresVerification(request, entry))
        }
        return if (candidates.isEmpty()) {
            Assertion.Refused(Refusal.NO_CREDENTIALS)
        } else {
            Assertion.Allowed(candidates)
        }
    }

    /** The keys `ssh-keygen -K` may download: resident SSH keys, sent only after verification. */
    fun residentSshKeys(entries: List<PasskeyEntry>): List<PasskeyEntry> =
        entries.filter { OpenSshKeys.isSshKey(it) && it.discoverable }

    fun mayList(verified: Boolean): Boolean = verified

    fun mayCreate(request: Ctap2Protocol.Request.MakeCredential, verified: Boolean): Boolean =
        verified || !requiresVerification(request)

    fun maySign(request: Ctap2Protocol.Request.GetAssertion, entry: PasskeyEntry, verified: Boolean): Boolean =
        request.userPresence && entry.rpId == request.rpId &&
            (verified || !requiresVerification(request, entry))

    fun register(
        authenticator: SoftwareAuthenticator,
        request: Ctap2Protocol.Request.MakeCredential,
        algorithm: CoseAlgorithm,
        verified: Boolean,
    ): SoftwareAuthenticator.Registration {
        check(mayCreate(request, verified)) { "user verification is required for this credential" }
        val ssh = isSsh(request)
        return authenticator.makeCredential(
            rpId = request.rpId,
            rpName = request.rpName,
            userHandle = request.userHandle,
            userName = request.userName,
            userDisplayName = request.userDisplayName,
            clientDataHash = request.clientDataHash,
            algorithm = algorithm,
            userVerified = verified,
            credentialProtection = request.credentialProtection,
            discoverable = !ssh || request.residentKey,
            // OpenSSH checks a self-signed "packed" statement and refuses "none".
            selfAttestation = ssh,
        )
    }
}
