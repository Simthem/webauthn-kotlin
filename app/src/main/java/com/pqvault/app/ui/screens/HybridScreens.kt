package com.pqvault.app.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.pqvault.app.R
import com.pqvault.app.pairing.QrScannerView
import com.pqvault.app.ui.VaultViewModel
import com.pqvault.app.ui.components.BannerTone
import com.pqvault.app.ui.components.PqCard
import com.pqvault.app.ui.components.StatusBanner
import com.pqvault.core.hybrid.Ctap2Protocol

/** Camera overlay dedicated to the `FIDO:/` QR shown by another device. */
@Composable
fun FidoScanScreen(
    error: String?,
    scanGeneration: Int,
    onScanned: (String) -> Unit,
    onClose: () -> Unit,
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val permissions = remember {
        buildList {
            add(Manifest.permission.CAMERA)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                add(Manifest.permission.BLUETOOTH_ADVERTISE)
            }
        }
    }
    fun allGranted(): Boolean = permissions.all {
        ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
    }
    var granted by remember { mutableStateOf(allGranted()) }
    val request = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { granted = allGranted() }

    LaunchedEffect(Unit) {
        if (!granted) request.launch(permissions.toTypedArray())
    }

    Box(
        modifier = Modifier.fillMaxSize().background(Color.Black),
        contentAlignment = Alignment.Center,
    ) {
        if (granted) {
            QrScannerView(
                modifier = Modifier.fillMaxSize(),
                resetKey = scanGeneration,
                onScanned = onScanned,
            )
        }

        Column(
            modifier = Modifier.fillMaxSize().padding(24.dp),
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
            Column {
                Text(
                    stringResource(R.string.hybrid_scan_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = Color.White,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    stringResource(R.string.hybrid_scan_body),
                    style = MaterialTheme.typography.bodySmall,
                    color = Color.White.copy(alpha = 0.75f),
                )
                error?.let {
                    Spacer(Modifier.height(12.dp))
                    StatusBanner(it, BannerTone.Danger)
                }
            }

            Column {
                if (!granted) {
                    StatusBanner(
                        stringResource(R.string.hybrid_permissions),
                        BannerTone.Warning,
                    )
                    Spacer(Modifier.height(12.dp))
                    Button(
                        onClick = { request.launch(permissions.toTypedArray()) },
                        modifier = Modifier.fillMaxWidth(),
                        shape = MaterialTheme.shapes.small,
                    ) { Text(stringResource(R.string.hybrid_grant_permissions)) }
                    Spacer(Modifier.height(8.dp))
                }
                TextButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.close), color = Color.White)
                }
            }
        }
    }
}

/** Progress and explicit approval UI for a remote CTAP request. */
@Composable
fun HybridRequestScreen(
    state: VaultViewModel.UiState,
    onApprove: (String?) -> Unit,
    onReject: () -> Unit,
    onClose: () -> Unit,
) {
    Box(
        modifier = Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.88f)),
        contentAlignment = Alignment.Center,
    ) {
        Column(modifier = Modifier.padding(24.dp)) {
            PqCard {
                Text(
                    stringResource(R.string.hybrid_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(12.dp))

                when (state.hybridPhase) {
                    VaultViewModel.HybridPhase.Connecting,
                    VaultViewModel.HybridPhase.WaitingForComputer,
                    VaultViewModel.HybridPhase.Securing,
                    -> HybridProgress(state.hybridPhase)

                    VaultViewModel.HybridPhase.Approval -> {
                        val prompt = state.hybridPrompt
                        if (prompt != null) {
                            HybridApproval(prompt, state.busy, onApprove, onReject)
                        } else {
                            HybridProgress(VaultViewModel.HybridPhase.Securing)
                        }
                    }

                    VaultViewModel.HybridPhase.Complete -> StatusBanner(
                        stringResource(R.string.hybrid_complete),
                        BannerTone.Success,
                    )

                    VaultViewModel.HybridPhase.Error -> StatusBanner(
                        state.hybridError ?: stringResource(R.string.hybrid_failed),
                        BannerTone.Danger,
                    )
                }

                state.hybridError?.takeIf { state.hybridPhase != VaultViewModel.HybridPhase.Error }?.let {
                    Spacer(Modifier.height(12.dp))
                    StatusBanner(it, BannerTone.Danger)
                }
                Spacer(Modifier.height(14.dp))
                TextButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) {
                    Text(
                        stringResource(
                            if (state.hybridPhase == VaultViewModel.HybridPhase.Complete ||
                                state.hybridPhase == VaultViewModel.HybridPhase.Error
                            ) R.string.close else R.string.cancel,
                        ),
                    )
                }
            }
        }
    }
}

@Composable
private fun HybridProgress(phase: VaultViewModel.HybridPhase) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
        CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(14.dp))
        Text(
            stringResource(
                when (phase) {
                    VaultViewModel.HybridPhase.Connecting -> R.string.hybrid_connecting
                    VaultViewModel.HybridPhase.WaitingForComputer -> R.string.hybrid_waiting_computer
                    else -> R.string.hybrid_securing
                },
            ),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun HybridApproval(
    prompt: VaultViewModel.HybridPrompt,
    busy: Boolean,
    onApprove: (String?) -> Unit,
    onReject: () -> Unit,
) {
    when (val request = prompt.request) {
        is Ctap2Protocol.Request.MakeCredential -> {
            Text(
                stringResource(R.string.hybrid_create_question, request.rpName ?: request.rpId),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                stringResource(R.string.hybrid_account, request.userName.ifBlank { request.rpId }),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = { onApprove(null) },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (busy) CircularProgressIndicator(strokeWidth = 2.dp) else {
                    Text(stringResource(R.string.hybrid_create_action))
                }
            }
        }

        is Ctap2Protocol.Request.GetAssertion -> {
            Text(
                stringResource(R.string.hybrid_sign_question, request.rpId),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(10.dp))
            prompt.candidates.forEach { entry ->
                Button(
                    onClick = { onApprove(entry.credentialId) },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(entry.userDisplayName ?: entry.userName)
                }
                Spacer(Modifier.height(8.dp))
            }
        }

        else -> Unit
    }
    OutlinedButton(
        onClick = onReject,
        enabled = !busy,
        modifier = Modifier.fillMaxWidth(),
    ) { Text(stringResource(R.string.reject)) }
}
