package com.pqvault.app.ui

import android.app.Application
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.pqvault.app.R
import com.pqvault.app.data.SecureSettings
import com.pqvault.app.data.VaultRepository
import com.pqvault.app.hybrid.HybridSession
import com.pqvault.app.notify.SyncNotifications
import com.pqvault.app.pairing.PairingPayload
import com.pqvault.app.provider.InstalledBrowsers
import com.pqvault.app.security.BiometricVaultLock
import com.pqvault.app.security.HybridUserVerification
import com.pqvault.app.sync.VaultSyncWorker
import com.pqvault.core.format.Base64Url
import com.pqvault.core.hybrid.Ctap2Protocol
import com.pqvault.core.hybrid.FidoQrCode
import com.pqvault.core.model.CoseAlgorithm
import com.pqvault.core.model.PasskeyEntry
import com.pqvault.core.sync.VaultSyncEngine
import com.pqvault.core.webauthn.SoftwareAuthenticator
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class VaultViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = VaultRepository.get(application)
    private val settingsStore = SecureSettings(application)
    private val biometrics = BiometricVaultLock(application)
    private val hybridVerification = HybridUserVerification(application)
    private val authenticator = SoftwareAuthenticator()
    private var hybridSession: HybridSession? = null
    private var pendingFidoCode: String? = null

    enum class Screen { Loading, Onboarding, Locked, Vault, Settings }

    enum class Overlay { None, PairingCode, PairingScan, FidoScan, Hybrid }

    enum class HybridPhase { Connecting, WaitingForComputer, Securing, Approval, Complete, Error }

    data class HybridPrompt(
        val request: Ctap2Protocol.Request,
        val candidates: List<PasskeyEntry> = emptyList(),
    )

    data class UiState(
        val screen: Screen = Screen.Loading,
        val entries: List<PasskeyEntry> = emptyList(),
        val settings: SecureSettings.Settings = SecureSettings.Settings(),
        val busy: Boolean = false,
        val message: String? = null,
        val error: String? = null,
        /** Set when the remote vault failed its integrity checks; deliberately sticky. */
        val securityAlert: String? = null,
        /**
         * True when the alert is a version rollback, the one refusal a restored-from-
         * backup server produces and that the user can legitimately accept. A bad
         * signature or an unknown signer never gets that option.
         */
        val securityAlertRecoverable: Boolean = false,
        val biometricsAvailable: Boolean = false,
        val biometricsEnrolled: Boolean = false,
        val deviceEnrolled: Boolean = false,
        val browsers: List<InstalledBrowsers.Browser> = emptyList(),
        val trustedBrowsers: Set<String> = emptySet(),
        val overlay: Overlay = Overlay.None,
        val pairingCode: String = "",
        val pairingError: String? = null,
        val fidoScanError: String? = null,
        val scanGeneration: Int = 0,
        val hybridPhase: HybridPhase = HybridPhase.Connecting,
        val hybridPrompt: HybridPrompt? = null,
        val hybridError: String? = null,
        /** The entry a delete confirmation is currently open for. */
        val pendingDeletion: PasskeyEntry? = null,
        /** True when this device is paired to a server but holds no vault yet. */
        val canRestore: Boolean = false,
    )

    private fun string(id: Int, vararg args: Any): String =
        getApplication<Application>().getString(id, *args)

    private fun plural(id: Int, quantity: Int, vararg args: Any): String =
        getApplication<Application>().resources.getQuantityString(id, quantity, *args)

    private fun describe(cause: VaultSyncEngine.Outcome.Untrusted): String =
        VaultRepository.describe(getApplication(), cause)

    private fun describe(reason: VaultSyncEngine.Outcome.Failure): String =
        VaultRepository.describe(getApplication(), reason)

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    init {
        refresh()
        // The vault can now close on its own when it goes idle, and nothing else would
        // tell the UI: without this the vault screen keeps showing a list it can no
        // longer read.
        viewModelScope.launch {
            repository.unlockedState.collect { refresh() }
        }
    }

    /** Defers the idle lock. Wired to every touch the activity sees. */
    fun touch() = repository.touch()

    /** Locks immediately if the app came back after the idle deadline had passed. */
    fun onResumed() {
        viewModelScope.launch { repository.lockIfIdle() }
    }

    private fun refresh() {
        _state.update {
            it.copy(
                screen = when {
                    !repository.isInitialised -> Screen.Onboarding
                    !repository.isUnlocked -> Screen.Locked
                    else -> Screen.Vault
                },
                entries = repository.allEntries().sortedBy { entry -> entry.rpId },
                settings = settingsStore.load(),
                biometricsAvailable = biometrics.isAvailable(),
                biometricsEnrolled = biometrics.isEnrolled(),
                deviceEnrolled = repository.isDeviceEnrolled(),
                canRestore = !repository.isInitialised &&
                    settingsStore.load().webdavBaseUrl.isNotBlank(),
                browsers = InstalledBrowsers.detect(getApplication()),
                trustedBrowsers = InstalledBrowsers.packagesIn(
                    settingsStore.load().privilegedBrowserAllowlist,
                ),
            )
        }
    }

    /**
     * Trusting a browser stores its package *and* the fingerprint read from the installed
     * APK right now, so a later update signed by a different key stops matching instead of
     * silently inheriting the trust.
     */
    fun toggleBrowser(packageName: String, trusted: Boolean) {
        val current = _state.value
        val next = if (trusted) {
            current.trustedBrowsers + packageName
        } else {
            current.trustedBrowsers - packageName
        }
        val allowlist = InstalledBrowsers.buildAllowlist(
            current.browsers.filter { it.packageName in next },
        )
        val saved = settingsStore.update { it.copy(privilegedBrowserAllowlist = allowlist) }
        _state.update { it.copy(trustedBrowsers = next, settings = saved) }
    }

    fun showPairingCode() {
        _state.update {
            it.copy(
                overlay = Overlay.PairingCode,
                pairingCode = PairingPayload.encode(settingsStore.load()),
            )
        }
    }

    fun startPairingScan() =
        _state.update { it.copy(overlay = Overlay.PairingScan, pairingError = null) }

    fun startFidoScan() =
        _state.update {
            it.copy(
                overlay = Overlay.FidoScan,
                fidoScanError = null,
                scanGeneration = it.scanGeneration + 1,
            )
        }

    fun closeOverlay() {
        if (_state.value.overlay == Overlay.Hybrid) hybridSession?.close()
        if (_state.value.overlay == Overlay.FidoScan) pendingFidoCode = null
        hybridSession = null
        _state.update {
            it.copy(
                overlay = Overlay.None,
                pairingError = null,
                fidoScanError = null,
                hybridPrompt = null,
                hybridError = null,
            )
        }
    }

    fun onPairingCodeScanned(text: String) {
        when (val result = PairingPayload.decode(text)) {
            is PairingPayload.ParseResult.Valid -> {
                val paired = settingsStore.update { PairingPayload.applyTo(it, result.payload) }
                VaultSyncWorker.schedule(getApplication())
                _state.update {
                    it.copy(
                        overlay = Overlay.None,
                        settings = paired,
                        message = string(R.string.pairing_success),
                    )
                }
            }
            is PairingPayload.ParseResult.Expired ->
                _state.update { it.copy(pairingError = string(R.string.pairing_expired)) }
            is PairingPayload.ParseResult.NotAPairingCode ->
                _state.update { it.copy(pairingError = string(R.string.pairing_invalid)) }
        }
    }

    /** Accepts both the in-app camera result and an Android `fido:` deep link. */
    fun openFidoCode(text: String) {
        val payload = FidoQrCode.parse(text)
        if (payload == null) {
            _state.update {
                it.copy(
                    fidoScanError = string(R.string.hybrid_invalid_code),
                    scanGeneration = it.scanGeneration + 1,
                )
            }
            return
        }
        if (!repository.isUnlocked) {
            pendingFidoCode = text
            _state.update { it.copy(message = string(R.string.hybrid_unlock_to_continue)) }
            return
        }
        beginHybridSession(payload)
    }

    fun onFidoPermissionDenied() {
        pendingFidoCode = null
        _state.update { it.copy(error = string(R.string.hybrid_permissions_denied)) }
    }

    fun approveHybrid(activity: FragmentActivity, credentialId: String? = null) {
        val prompt = _state.value.hybridPrompt ?: return
        val request = prompt.request
        viewModelScope.launch {
            _state.update { it.copy(busy = true, hybridError = null) }
            val rpId = when (request) {
                is Ctap2Protocol.Request.MakeCredential -> request.rpId
                is Ctap2Protocol.Request.GetAssertion -> request.rpId
                else -> return@launch
            }
            val verified = if (requiresUserVerification(request) && hybridVerification.isAvailable) {
                when (val result = hybridVerification.verify(activity, rpId)) {
                    HybridUserVerification.Result.Verified -> true
                    HybridUserVerification.Result.Cancelled -> {
                        _state.update { it.copy(busy = false) }
                        return@launch
                    }
                    is HybridUserVerification.Result.Failed -> {
                        _state.update { it.copy(busy = false, hybridError = result.message) }
                        return@launch
                    }
                }
            } else {
                false
            }

            // The computer or the user may cancel while Android's verification prompt is
            // open. Never create or update a credential for a request that has gone away.
            if (_state.value.hybridPrompt !== prompt || hybridSession == null) {
                _state.update { it.copy(busy = false) }
                return@launch
            }

            if (requiresUserVerification(request) && !verified) {
                hybridSession?.respond(Ctap2Protocol.error(Ctap2Protocol.STATUS_UNSUPPORTED_OPTION))
                _state.update {
                    it.copy(
                        busy = false,
                        hybridPhase = HybridPhase.Error,
                        hybridError = string(R.string.hybrid_uv_unavailable),
                        hybridPrompt = null,
                    )
                }
                return@launch
            }

            runCatching {
                when (request) {
                    is Ctap2Protocol.Request.MakeCredential -> {
                        val registration = authenticator.makeCredential(
                            rpId = request.rpId,
                            rpName = request.rpName,
                            userHandle = request.userHandle,
                            userName = request.userName,
                            userDisplayName = request.userDisplayName,
                            clientDataHash = request.clientDataHash,
                            algorithm = CoseAlgorithm.ES256,
                            userVerified = verified,
                        )
                        repository.upsert(registration.entry)
                        Ctap2Protocol.makeCredentialResponse(registration)
                    }
                    is Ctap2Protocol.Request.GetAssertion -> {
                        val entry = prompt.candidates.firstOrNull { it.credentialId == credentialId }
                            ?: prompt.candidates.singleOrNull()
                            ?: error(string(R.string.provider_no_passkey))
                        val assertion = authenticator.getAssertion(
                            entry = entry,
                            clientDataHash = request.clientDataHash,
                            userVerified = verified,
                        )
                        repository.upsert(assertion.updatedEntry)
                        Ctap2Protocol.getAssertionResponse(
                            assertion = assertion,
                            entry = assertion.updatedEntry,
                            includeUser = request.allowedCredentialIds.isEmpty(),
                            includeIdentifyingInformation = verified,
                        )
                    }
                    else -> error("unexpected CTAP request")
                }
            }.onSuccess { response ->
                hybridSession?.respond(response)
                refresh()
                _state.update {
                    it.copy(
                        busy = false,
                        hybridPhase = HybridPhase.Complete,
                        hybridPrompt = null,
                    )
                }
            }.onFailure { failure ->
                hybridSession?.respond(Ctap2Protocol.error(Ctap2Protocol.STATUS_OPERATION_DENIED))
                _state.update {
                    it.copy(
                        busy = false,
                        hybridPhase = HybridPhase.Error,
                        hybridError = failure.message ?: string(R.string.hybrid_failed),
                        hybridPrompt = null,
                    )
                }
            }
        }
    }

    fun rejectHybrid() {
        hybridSession?.respond(Ctap2Protocol.error(Ctap2Protocol.STATUS_OPERATION_DENIED))
        _state.update {
            it.copy(
                hybridPhase = HybridPhase.Error,
                hybridError = string(R.string.hybrid_rejected),
                hybridPrompt = null,
            )
        }
    }

    private fun beginHybridSession(payload: FidoQrCode.Payload) {
        hybridSession?.close()
        _state.update {
            it.copy(
                overlay = Overlay.Hybrid,
                fidoScanError = null,
                hybridPhase = HybridPhase.Connecting,
                hybridPrompt = null,
                hybridError = null,
            )
        }

        lateinit var started: HybridSession
        started = HybridSession(
            context = getApplication(),
            qr = payload,
            userVerificationAvailable = hybridVerification.isAvailable,
            listener = object : HybridSession.Listener {
                override fun onStatus(status: HybridSession.Status) {
                    if (hybridSession !== started) return
                    _state.update {
                        it.copy(
                            hybridPhase = when (status) {
                                HybridSession.Status.Connecting -> HybridPhase.Connecting
                                HybridSession.Status.WaitingForComputer -> HybridPhase.WaitingForComputer
                                HybridSession.Status.SecuringConnection -> HybridPhase.Securing
                                HybridSession.Status.WaitingForApproval -> HybridPhase.Approval
                            },
                        )
                    }
                }

                override fun onRequest(request: Ctap2Protocol.Request) {
                    if (hybridSession !== started) return
                    handleHybridRequest(request)
                }

                override fun onFinished() {
                    if (hybridSession !== started) return
                    _state.update {
                        if (it.hybridPhase == HybridPhase.Error) it else {
                            it.copy(hybridPhase = HybridPhase.Complete, hybridPrompt = null)
                        }
                    }
                }

                override fun onError(message: String) {
                    if (hybridSession !== started) return
                    _state.update {
                        it.copy(
                            hybridPhase = HybridPhase.Error,
                            hybridError = string(R.string.hybrid_failed_detail, message),
                            hybridPrompt = null,
                        )
                    }
                }
            },
        )
        hybridSession = started
        started.start()
    }

    private fun handleHybridRequest(request: Ctap2Protocol.Request) {
        when (request) {
            is Ctap2Protocol.Request.MakeCredential -> {
                if (CoseAlgorithm.ES256.id !in request.offeredAlgorithms) {
                    failHybridRequest(
                        Ctap2Protocol.STATUS_UNSUPPORTED_ALGORITHM,
                        string(R.string.provider_no_algorithm),
                    )
                    return
                }
                val excluded = repository.entriesFor(request.rpId).any { entry ->
                    request.excludedCredentialIds.any { excludedId ->
                        Base64Url.decode(entry.credentialId).contentEquals(excludedId)
                    }
                }
                if (excluded) {
                    failHybridRequest(
                        Ctap2Protocol.STATUS_CREDENTIAL_EXCLUDED,
                        string(R.string.hybrid_credential_exists),
                    )
                    return
                }
                if (request.userVerification && !hybridVerification.isAvailable) {
                    failHybridRequest(
                        Ctap2Protocol.STATUS_UNSUPPORTED_OPTION,
                        string(R.string.hybrid_uv_unavailable),
                    )
                    return
                }
                _state.update {
                    it.copy(
                        hybridPhase = HybridPhase.Approval,
                        hybridPrompt = HybridPrompt(request),
                    )
                }
            }
            is Ctap2Protocol.Request.GetAssertion -> {
                val candidates = repository.entriesFor(request.rpId).filter { entry ->
                    request.allowedCredentialIds.isEmpty() || request.allowedCredentialIds.any { allowed ->
                        Base64Url.decode(entry.credentialId).contentEquals(allowed)
                    }
                }
                if (candidates.isEmpty()) {
                    failHybridRequest(
                        Ctap2Protocol.STATUS_NO_CREDENTIALS,
                        string(R.string.provider_no_passkey),
                    )
                    return
                }
                if (request.userVerification && !hybridVerification.isAvailable) {
                    failHybridRequest(
                        Ctap2Protocol.STATUS_UNSUPPORTED_OPTION,
                        string(R.string.hybrid_uv_unavailable),
                    )
                    return
                }
                _state.update {
                    it.copy(
                        hybridPhase = HybridPhase.Approval,
                        hybridPrompt = HybridPrompt(request, candidates),
                    )
                }
            }
            else -> Unit
        }
    }

    private fun failHybridRequest(status: Int, message: String) {
        hybridSession?.respond(Ctap2Protocol.error(status))
        _state.update {
            it.copy(
                hybridPhase = HybridPhase.Error,
                hybridError = message,
                hybridPrompt = null,
            )
        }
    }

    private fun requiresUserVerification(request: Ctap2Protocol.Request): Boolean = when (request) {
        is Ctap2Protocol.Request.MakeCredential -> request.userVerification
        is Ctap2Protocol.Request.GetAssertion -> request.userVerification
        else -> false
    }

    private fun resumePendingFidoCode() {
        if (!repository.isUnlocked) return
        pendingFidoCode?.also {
            pendingFidoCode = null
            openFidoCode(it)
        }
    }

    fun dismissMessages() = _state.update { it.copy(message = null, error = null) }

    fun dismissSecurityAlert() =
        _state.update { it.copy(securityAlert = null, securityAlertRecoverable = false) }

    /**
     * The user has looked at the refusal and decided the server is legitimately behind,
     * which is what a restore from backup looks like from here. Only the rollback case
     * offers this, and only from an explicit tap.
     */
    fun acceptRemoteVersion() {
        viewModelScope.launch {
            repository.acceptRemoteVersion()
            _state.update {
                it.copy(
                    securityAlert = null,
                    securityAlertRecoverable = false,
                    message = string(R.string.security_alert_accepted),
                )
            }
            refresh()
        }
    }

    fun openSettings() = _state.update { it.copy(screen = Screen.Settings) }

    fun closeSettings() = _state.update {
        it.copy(screen = if (repository.isUnlocked) Screen.Vault else Screen.Locked)
    }

    /**
     * Pulls down the vault this device was paired to, rather than creating a new one.
     *
     * On success it enrols the device and pushes straight away: an enrolment that stays
     * on this phone is worth nothing, since background sync needs the *server* copy to
     * list this device as a recipient.
     */
    fun restoreVault(passphrase: String) {
        if (passphrase.isEmpty()) {
            _state.update { it.copy(error = string(R.string.restore_needs_passphrase)) }
            return
        }
        viewModelScope.launch {
            _state.update { it.copy(busy = true, error = null) }
            val chars = passphrase.toCharArray()
            val outcome = repository.restoreFromRemote(chars)
            chars.fill('\u0000')

            when (outcome) {
                is VaultRepository.RestoreOutcome.Success -> {
                    repository.enrollThisDevice()
                    _state.update { it.copy(busy = false, message = string(R.string.restore_success)) }
                    refresh()
                    syncNow()
                    resumePendingFidoCode()
                }
                is VaultRepository.RestoreOutcome.NotFound ->
                    _state.update { it.copy(busy = false, error = string(R.string.restore_not_found)) }
                is VaultRepository.RestoreOutcome.WrongPassphrase ->
                    _state.update { it.copy(busy = false, error = string(R.string.wrong_passphrase)) }
                is VaultRepository.RestoreOutcome.NotConfigured ->
                    _state.update { it.copy(busy = false, error = string(R.string.no_webdav_configured)) }
                is VaultRepository.RestoreOutcome.AlreadyInitialised ->
                    _state.update { it.copy(busy = false) }
                is VaultRepository.RestoreOutcome.Untrusted ->
                    _state.update {
                        it.copy(busy = false, securityAlert = outcome.reason, securityAlertRecoverable = false)
                    }
                is VaultRepository.RestoreOutcome.Failed ->
                    _state.update {
                        it.copy(busy = false, error = string(R.string.restore_failed, outcome.message))
                    }
            }
        }
    }

    fun setAutoLockSeconds(seconds: Int) {
        val updated = settingsStore.update { it.copy(autoLockSeconds = seconds) }
        repository.touch()
        _state.update { it.copy(settings = updated, message = string(R.string.settings_saved)) }
    }

    fun createVault(passphrase: String, confirmation: String) {
        if (passphrase.length < MIN_PASSPHRASE) {
            _state.update { it.copy(error = string(R.string.passphrase_too_short, MIN_PASSPHRASE)) }
            return
        }
        if (passphrase != confirmation) {
            _state.update { it.copy(error = string(R.string.passphrase_mismatch)) }
            return
        }
        viewModelScope.launch {
            _state.update { it.copy(busy = true, error = null) }
            val chars = passphrase.toCharArray()
            runCatching { repository.create(chars) }
                .onSuccess {
                    SyncNotifications(getApplication()).ensureChannels()
                    _state.update { it.copy(busy = false, message = string(R.string.vault_created)) }
                    refresh()
                    resumePendingFidoCode()
                }
                .onFailure { e ->
                    _state.update { it.copy(busy = false, error = e.message ?: string(R.string.vault_create_failed)) }
                }
            chars.fill('\u0000')
        }
    }

    fun unlock(passphrase: String) {
        viewModelScope.launch {
            _state.update { it.copy(busy = true, error = null) }
            val chars = passphrase.toCharArray()
            val outcome = repository.unlock(chars)
            chars.fill('\u0000')
            when (outcome) {
                is VaultRepository.UnlockOutcome.Success -> {
                    _state.update { it.copy(busy = false) }
                    refresh()
                    resumePendingFidoCode()
                }
                is VaultRepository.UnlockOutcome.WrongPassphrase ->
                    _state.update { it.copy(busy = false, error = string(R.string.wrong_passphrase)) }
                is VaultRepository.UnlockOutcome.NotInitialised -> {
                    _state.update { it.copy(busy = false) }
                    refresh()
                }
                is VaultRepository.UnlockOutcome.Untrusted ->
                    _state.update {
                        it.copy(busy = false, securityAlert = outcome.reason, securityAlertRecoverable = false)
                    }
            }
        }
    }

    fun unlockWithBiometrics(activity: FragmentActivity) {
        viewModelScope.launch {
            _state.update { it.copy(busy = true, error = null) }
            when (val result = biometrics.unlock(activity)) {
                is BiometricVaultLock.UnlockResult.Success -> {
                    repository.unlockWithMasterKey(result.masterKey)
                    result.masterKey.fill(0)
                    _state.update { it.copy(busy = false) }
                    refresh()
                    resumePendingFidoCode()
                }
                is BiometricVaultLock.UnlockResult.InvalidatedByNewBiometric ->
                    _state.update {
                        it.copy(
                            busy = false,
                            error = string(R.string.biometric_invalidated),
                        )
                    }
                is BiometricVaultLock.UnlockResult.Cancelled ->
                    _state.update { it.copy(busy = false) }
                is BiometricVaultLock.UnlockResult.NotEnrolled ->
                    _state.update { it.copy(busy = false, error = string(R.string.biometric_not_configured)) }
                is BiometricVaultLock.UnlockResult.Failed ->
                    _state.update { it.copy(busy = false, error = result.message) }
            }
        }
    }

    fun enableBiometrics(activity: FragmentActivity) {
        val masterKey = repository.masterKeyForBiometricWrap()
        if (masterKey == null) {
            _state.update { it.copy(error = string(R.string.unlock_first)) }
            return
        }
        viewModelScope.launch {
            try {
                when (val result = biometrics.enroll(activity, masterKey)) {
                    is BiometricVaultLock.UnlockResult.Success -> {
                        result.masterKey.fill(0)
                        _state.update { it.copy(message = string(R.string.biometric_enabled)) }
                        refresh()
                    }
                    is BiometricVaultLock.UnlockResult.Cancelled -> Unit
                    is BiometricVaultLock.UnlockResult.Failed ->
                        _state.update { it.copy(error = result.message) }
                    else -> Unit
                }
            } finally {
                // This is a copy of the vault master key. Whatever happened above, it has
                // no business outliving this call.
                masterKey.fill(0)
            }
        }
    }

    fun disableBiometrics() {
        biometrics.clearEnrollment()
        _state.update { it.copy(message = string(R.string.biometric_disabled)) }
        refresh()
    }

    fun lock() {
        viewModelScope.launch {
            hybridSession?.close()
            hybridSession = null
            _state.update {
                it.copy(
                    overlay = Overlay.None,
                    hybridPrompt = null,
                    hybridError = null,
                )
            }
            repository.lockNow()
            refresh()
        }
    }

    /** Names the entry the user asked to delete, or null when nothing is pending. */
    fun confirmDelete(credentialId: String) = _state.update {
        it.copy(pendingDeletion = it.entries.firstOrNull { entry -> entry.credentialId == credentialId })
    }

    fun cancelDelete() = _state.update { it.copy(pendingDeletion = null) }

    fun deleteEntry(credentialId: String) {
        viewModelScope.launch {
            repository.delete(credentialId)
            _state.update { it.copy(pendingDeletion = null, message = string(R.string.passkey_deleted)) }
            refresh()
        }
    }

    fun saveSettings(settings: SecureSettings.Settings) {
        val url = settings.webdavBaseUrl.trim()
        if (url.isNotEmpty()) {
            val problem = validateWebdavUrl(url)
            if (problem != null) {
                _state.update { it.copy(error = problem) }
                return
            }
        }
        settingsStore.save(settings)
        if (settings.webdavBaseUrl.isNotBlank()) {
            VaultSyncWorker.schedule(getApplication())
        } else {
            VaultSyncWorker.cancel(getApplication())
        }
        _state.update { it.copy(settings = settings, message = string(R.string.settings_saved)) }
    }

    /**
     * Returns why this URL cannot be used, or null when it is fine.
     *
     * Plain HTTP is refused rather than warned about: WebDAV here authenticates with
     * HTTP Basic, so an http:// server would put the app password on the wire in
     * base64 on every single sync. Android blocks the request anyway, but it does so
     * with a transport error long after the user has left this screen.
     */
    private fun validateWebdavUrl(url: String): String? {
        val parsed = runCatching { java.net.URI(url) }.getOrNull()
            ?: return string(R.string.webdav_url_malformed)
        return when {
            parsed.scheme == null || parsed.host.isNullOrBlank() ->
                string(R.string.webdav_url_malformed)
            !parsed.scheme.equals("https", ignoreCase = true) ->
                string(R.string.webdav_url_needs_https)
            else -> null
        }
    }

    fun syncNow(passphrase: String) {
        viewModelScope.launch {
            _state.update { it.copy(busy = true, error = null) }
            val chars = passphrase.toCharArray()
            val outcome = repository.sync(chars)
            chars.fill('\u0000')
            val update: UiState.() -> UiState = when (outcome) {
                is VaultSyncEngine.Outcome.Created -> {
                    { copy(busy = false, message = string(R.string.sync_uploaded, outcome.version)) }
                }
                is VaultSyncEngine.Outcome.Pushed -> {
                    { copy(busy = false, message = string(R.string.sync_pushed, outcome.version)) }
                }
                is VaultSyncEngine.Outcome.Merged -> {
                    {
                        copy(
                            busy = false,
                            message = if (outcome.conflicts.isEmpty()) {
                                string(R.string.sync_merged, outcome.version)
                            } else {
                                plural(
                                    R.plurals.sync_merged_conflicts,
                                    outcome.conflicts.size,
                                    outcome.version,
                                    outcome.conflicts.size,
                                )
                            },
                        )
                    }
                }
                is VaultSyncEngine.Outcome.RemoteUntrusted -> {
                    {
                        copy(
                            busy = false,
                            securityAlert = describe(outcome.cause),
                            securityAlertRecoverable = outcome.cause is
                                VaultSyncEngine.Outcome.Untrusted.Rollback,
                        )
                    }
                }
                is VaultSyncEngine.Outcome.RemoteUnreadable -> {
                    { copy(busy = false, error = string(R.string.sync_remote_unreadable)) }
                }
                is VaultSyncEngine.Outcome.Failed -> {
                    { copy(busy = false, error = describe(outcome.reason)) }
                }
            }
            _state.update(update)
            refresh()
        }
    }

    /**
     * Manual sync that uses this device's enrolled key, so the user is not asked for the
     * passphrase they already typed to unlock.
     */
    fun syncNow() {
        viewModelScope.launch {
            _state.update { it.copy(busy = true, error = null) }
            val outcome = repository.syncUnattended()
            _state.update { current ->
                when (outcome) {
                    is VaultSyncEngine.Outcome.Created ->
                        current.copy(busy = false, message = string(R.string.sync_uploaded, outcome.version))
                    is VaultSyncEngine.Outcome.Pushed ->
                        current.copy(busy = false, message = string(R.string.sync_pushed, outcome.version))
                    is VaultSyncEngine.Outcome.Merged ->
                        current.copy(
                            busy = false,
                            message = if (outcome.conflicts.isEmpty()) {
                            string(R.string.sync_merged, outcome.version)
                        } else {
                            plural(
                                R.plurals.sync_merged_conflicts,
                                outcome.conflicts.size,
                                outcome.version,
                                outcome.conflicts.size,
                            )
                        },
                        )
                    is VaultSyncEngine.Outcome.RemoteUntrusted ->
                        current.copy(
                            busy = false,
                            securityAlert = describe(outcome.cause),
                            securityAlertRecoverable = outcome.cause is
                                VaultSyncEngine.Outcome.Untrusted.Rollback,
                        )
                    is VaultSyncEngine.Outcome.RemoteUnreadable ->
                        current.copy(busy = false, error = string(R.string.sync_remote_unreadable))
                    is VaultSyncEngine.Outcome.Failed ->
                        current.copy(busy = false, error = describe(outcome.reason))
                }
            }
            // The repository adopts the vault the sync produced, so there is nothing
            // stale left behind and no reason to make the user unlock again.
            refresh()
        }
    }

    fun enrollThisDevice() {
        viewModelScope.launch {
            if (repository.enrollThisDevice()) {
                _state.update { it.copy(message = string(R.string.device_enrolled_message)) }
            } else {
                _state.update { it.copy(error = string(R.string.unlock_first)) }
            }
            refresh()
        }
    }

    private companion object {
        const val MIN_PASSPHRASE = 12
    }

    override fun onCleared() {
        hybridSession?.close()
        hybridSession = null
        super.onCleared()
    }
}
