package com.pqvault.desktop

/** What the user reads, on the terminal or in the window. */
object PromptText {
    const val TITLE = "PQ Vault"
    const val HOW_TO_SCAN = "Open PQ Vault and tap the QR scanner above the passkey list."

    fun heading(purpose: HybridClient.Purpose) = when (purpose) {
        HybridClient.Purpose.Enrol -> "PQ Vault: scan this code to create the SSH key on your phone."
        HybridClient.Purpose.SignIn -> "PQ Vault: scan this code to sign in with your phone."
        HybridClient.Purpose.ListKeys -> "PQ Vault: scan this code to download your SSH keys from your phone."
    }

    fun stage(stage: HybridClient.Stage) = when (stage) {
        HybridClient.Stage.WaitingForPhone -> "Waiting for the phone over Bluetooth..."
        HybridClient.Stage.Connecting -> "Phone found, connecting..."
        HybridClient.Stage.WaitingForApproval -> "Approve on the phone with your fingerprint or screen lock."
    }
}
