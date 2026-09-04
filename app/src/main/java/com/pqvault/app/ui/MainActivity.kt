package com.pqvault.app.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.pqvault.app.notify.SyncNotifications
import com.pqvault.app.ui.screens.FidoScanScreen
import com.pqvault.app.ui.screens.HybridRequestScreen
import com.pqvault.app.ui.screens.OnboardingScreen
import com.pqvault.app.ui.screens.PairingCodeScreen
import com.pqvault.app.ui.screens.PairingScanScreen
import com.pqvault.app.ui.screens.SettingsScreen
import com.pqvault.app.ui.screens.UnlockScreen
import com.pqvault.app.ui.screens.VaultScreen
import com.pqvault.app.ui.theme.PqVaultTheme
import kotlinx.coroutines.delay

class MainActivity : AppCompatActivity() {

    private val model: VaultViewModel by viewModels()
    private var pendingFidoLink: String? = null

    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* Denied is survivable: sync still works, the user just is not told about it. */ }

    private val bluetoothAdvertisePermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        val link = pendingFidoLink
        pendingFidoLink = null
        if (granted && link != null) model.openFidoCode(link) else model.onFidoPermissionDenied()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SyncNotifications(this).ensureChannels()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent {
            PqVaultTheme {
                Surface(
                    modifier = Modifier
                        .fillMaxSize()
                        // Android 15 enforces edge-to-edge, so content would otherwise
                        // slide under the status and navigation bars.
                        .safeDrawingPadding(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    val state by model.state.collectAsStateWithLifecycle()

                    // Transient banners clear themselves so they do not pile up; the
                    // security alert deliberately does not, and must be dismissed.
                    LaunchedEffect(state.message, state.error) {
                        if (state.message != null || state.error != null) {
                            delay(4000)
                            model.dismissMessages()
                        }
                    }

                    when (state.screen) {
                        VaultViewModel.Screen.Loading -> Unit

                        VaultViewModel.Screen.Onboarding -> OnboardingScreen(
                            state = state,
                            onCreate = model::createVault,
                            onRestore = model::restoreVault,
                            onScanPairingCode = model::startPairingScan,
                        )

                        VaultViewModel.Screen.Locked -> UnlockScreen(
                            state = state,
                            onUnlock = model::unlock,
                            onBiometricUnlock = { model.unlockWithBiometrics(this@MainActivity) },
                            onDismissSecurityAlert = model::dismissSecurityAlert,
                        )

                        VaultViewModel.Screen.Vault -> VaultScreen(
                            state = state,
                            onSync = model::syncNow,
                            onScanFido = model::startFidoScan,
                            onLock = model::lock,
                            onSettings = model::openSettings,
                            onConfirmDelete = model::confirmDelete,
                            onCancelDelete = model::cancelDelete,
                            onDelete = model::deleteEntry,
                            onAcceptRemoteVersion = model::acceptRemoteVersion,
                            onDismissSecurityAlert = model::dismissSecurityAlert,
                        )

                        VaultViewModel.Screen.Settings -> SettingsScreen(
                            state = state,
                            onBack = model::closeSettings,
                            onSave = model::saveSettings,
                            onEnableBiometrics = { model.enableBiometrics(this@MainActivity) },
                            onDisableBiometrics = model::disableBiometrics,
                            onEnrollDevice = model::enrollThisDevice,
                            onToggleBrowser = model::toggleBrowser,
                            onShowPairingCode = model::showPairingCode,
                            onScanPairingCode = model::startPairingScan,
                            onAutoLockChange = model::setAutoLockSeconds,
                        )
                    }

                    // Pairing draws over whatever screen is showing rather than replacing
                    // it, so cancelling returns exactly where the user was.
                    when (state.overlay) {
                        VaultViewModel.Overlay.None -> Unit
                        VaultViewModel.Overlay.PairingCode -> PairingCodeScreen(
                            content = state.pairingCode,
                            onClose = model::closeOverlay,
                        )
                        VaultViewModel.Overlay.PairingScan -> PairingScanScreen(
                            error = state.pairingError,
                            onScanned = model::onPairingCodeScanned,
                            onClose = model::closeOverlay,
                        )
                        VaultViewModel.Overlay.FidoScan -> FidoScanScreen(
                            error = state.fidoScanError,
                            scanGeneration = state.scanGeneration,
                            onScanned = model::openFidoCode,
                            onClose = model::closeOverlay,
                        )
                        VaultViewModel.Overlay.Hybrid -> HybridRequestScreen(
                            state = state,
                            onApprove = { model.approveHybrid(this@MainActivity, it) },
                            onReject = model::rejectHybrid,
                            onClose = model::closeOverlay,
                        )
                    }
                }
            }
        }

        handleFidoIntent(intent)
    }

    /**
     * Every touch, key press and trackball event lands here before it reaches a view, so
     * it is the cheapest honest definition of "the user is still using the app" and what
     * the idle lock counts from.
     */
    override fun onUserInteraction() {
        super.onUserInteraction()
        model.touch()
    }

    override fun onResume() {
        super.onResume()
        // Coming back from the background is the case the ticking timer can miss: the
        // process may have been frozen for hours with its coroutines suspended, so the
        // deadline is re-checked against the clock rather than trusted to have fired.
        model.onResumed()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleFidoIntent(intent)
    }

    private fun handleFidoIntent(intent: Intent) {
        val link = intent.dataString?.takeIf {
            intent.action == Intent.ACTION_VIEW && it.startsWith("fido:/", ignoreCase = true)
        } ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_ADVERTISE) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            pendingFidoLink = link
            bluetoothAdvertisePermission.launch(Manifest.permission.BLUETOOTH_ADVERTISE)
        } else {
            model.openFidoCode(link)
        }
    }
}
