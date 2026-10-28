package com.pqvault.app.hybrid

import com.pqvault.core.format.Base64Url
import com.pqvault.core.hybrid.Ctap2Protocol
import com.pqvault.core.model.PasskeyEntry

/** Approval follows the received CTAP command, never a QR hint or an account label. */
internal object HybridApprovalPolicy {
    /**
     * A `fido:` link opened from outside the app may start a session only when none is
     * under way and no scanned code is waiting for the vault to unlock: any app or web
     * page can open such a link, and it must never swap its own request in for the one
     * the user scanned.
     */
    fun acceptsExternalLink(sessionUnderWay: Boolean, codeWaiting: Boolean): Boolean =
        !sessionUnderWay && !codeWaiting

    fun requiresVerification(request: Ctap2Protocol.Request): Boolean = when (request) {
        is Ctap2Protocol.Request.MakeCredential -> request.userVerification
        is Ctap2Protocol.Request.GetAssertion -> request.userVerification
        else -> false
    }

    // A site can omit UV for a security-key-style login. Still offer fresh local
    // verification when possible, with the same cancellation behavior as required UV.
    fun shouldVerify(request: Ctap2Protocol.Request, verificationAvailable: Boolean): Boolean =
        verificationAvailable && (request is Ctap2Protocol.Request.MakeCredential ||
            request is Ctap2Protocol.Request.GetAssertion)

    fun hasExistingAccount(
        request: Ctap2Protocol.Request.MakeCredential,
        entries: List<PasskeyEntry>,
    ): Boolean = entries.any { entry ->
        entry.rpId == request.rpId &&
            Base64Url.decode(entry.userHandle).contentEquals(request.userHandle)
    }
}
