package com.pqvault.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pqvault.app.ui.VaultViewModel
import com.pqvault.app.R
import com.pqvault.app.ui.components.BannerTone
import com.pqvault.app.ui.components.PqCard
import com.pqvault.app.ui.components.PqTextField
import com.pqvault.app.ui.components.StatusBanner
import com.pqvault.app.ui.theme.PqColors
import com.pqvault.app.ui.theme.PqIcons

@Composable
fun OnboardingScreen(
    state: VaultViewModel.UiState,
    onCreate: (String, String) -> Unit,
    onRestore: (String) -> Unit,
    onScanPairingCode: () -> Unit,
) {
    var passphrase by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
    ) {
        Spacer(Modifier.height(24.dp))
        Icon(
            PqIcons.Shield,
            contentDescription = null,
            tint = PqColors.Amber500,
            modifier = Modifier.size(44.dp),
        )
        Spacer(Modifier.height(16.dp))
        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.onBackground)
        Spacer(Modifier.height(6.dp))
        Text(
            stringResource(R.string.onboarding_tagline),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(Modifier.height(28.dp))
        FeatureRow(PqIcons.CloudSync, stringResource(R.string.feature_webdav_title), stringResource(R.string.feature_webdav_body))
        Spacer(Modifier.height(14.dp))
        FeatureRow(PqIcons.Shield, stringResource(R.string.feature_pq_title), stringResource(R.string.feature_pq_body))
        Spacer(Modifier.height(14.dp))
        FeatureRow(PqIcons.Fingerprint, stringResource(R.string.feature_biometric_title), stringResource(R.string.feature_biometric_body))

        Spacer(Modifier.height(28.dp))

        // A device that has scanned a pairing code is not starting from scratch: there is
        // already a vault on the server holding the passkeys it is meant to share. Making
        // "create" the only offer here is what leaves someone with two unrelated vaults
        // fighting over one file.
        if (state.canRestore) {
            PqCard {
                Text(
                    stringResource(R.string.restore_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    stringResource(R.string.restore_body),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(16.dp))
                PqTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = stringResource(R.string.passphrase),
                    isPassword = true,
                )
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = { onRestore(passphrase) },
                    enabled = !state.busy && passphrase.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth(),
                    shape = MaterialTheme.shapes.small,
                ) {
                    Icon(PqIcons.CloudSync, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.restore_action))
                }
            }
            Spacer(Modifier.height(20.dp))
            Text(
                stringResource(R.string.restore_or_create),
                style = MaterialTheme.typography.bodySmall,
                color = PqColors.Dark3,
            )
            Spacer(Modifier.height(12.dp))
        } else {
            OutlinedButton(
                onClick = onScanPairingCode,
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.small,
            ) {
                Icon(PqIcons.QrCodeScanner, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.onboarding_scan_pairing))
            }
            Spacer(Modifier.height(20.dp))
        }

        PqCard {
            Text(stringResource(R.string.create_vault_title), style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
            Spacer(Modifier.height(4.dp))
            Text(
                stringResource(R.string.create_vault_warning),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))
            PqTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = stringResource(R.string.passphrase),
                isPassword = true,
                supportingText = stringResource(R.string.passphrase_hint),
            )
            Spacer(Modifier.height(12.dp))
            PqTextField(
                value = confirmation,
                onValueChange = { confirmation = it },
                label = stringResource(R.string.confirm),
                isPassword = true,
                isError = confirmation.isNotEmpty() && confirmation != passphrase,
            )
            Spacer(Modifier.height(18.dp))
            Button(
                onClick = { onCreate(passphrase, confirmation) },
                enabled = !state.busy && passphrase.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.small,
            ) {
                if (state.busy) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(stringResource(R.string.creating))
                } else {
                    Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.create_vault))
                }
            }
        }

        state.error?.let {
            Spacer(Modifier.height(14.dp))
            StatusBanner(it, BannerTone.Danger)
        }
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun FeatureRow(icon: ImageVector, title: String, body: String) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
        Icon(icon, contentDescription = null, tint = PqColors.Amber500, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(14.dp))
        Column(verticalArrangement = Arrangement.Top) {
            Text(title, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onBackground)
            Text(body, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
