package com.pqvault.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
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
import androidx.compose.ui.unit.dp
import com.pqvault.app.ui.VaultViewModel
import com.pqvault.app.R
import com.pqvault.app.ui.components.BannerTone
import com.pqvault.app.ui.components.PqCard
import com.pqvault.app.ui.components.PqTextField
import com.pqvault.app.ui.components.SecurityAlertCard
import com.pqvault.app.ui.components.StatusBanner
import com.pqvault.app.ui.theme.PqColors
import com.pqvault.app.ui.theme.PqIcons

@Composable
fun UnlockScreen(
    state: VaultViewModel.UiState,
    onUnlock: (String) -> Unit,
    onBiometricUnlock: () -> Unit,
    onDismissSecurityAlert: () -> Unit,
) {
    var passphrase by remember { mutableStateOf("") }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(PqIcons.Shield, contentDescription = null, tint = PqColors.Amber500, modifier = Modifier.size(40.dp))
        Spacer(Modifier.height(14.dp))
        Text(stringResource(R.string.vault_locked), style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.onBackground)
        Spacer(Modifier.height(24.dp))

        state.securityAlert?.let {
            // A refusal reached while locked is always about the local file, never a
            // remote rollback the user could choose to accept, so no accept action here.
            SecurityAlertCard(reason = it, onAccept = null, onDismiss = onDismissSecurityAlert)
            Spacer(Modifier.height(16.dp))
        }

        PqCard {
            PqTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = stringResource(R.string.passphrase),
                isPassword = true,
            )
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = { onUnlock(passphrase) },
                enabled = !state.busy && passphrase.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.small,
            ) {
                if (state.busy) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                } else {
                    Icon(PqIcons.LockOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.unlock))
                }
            }

            if (state.biometricsEnrolled && state.biometricsAvailable) {
                Spacer(Modifier.height(10.dp))
                OutlinedButton(
                    onClick = onBiometricUnlock,
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth(),
                    shape = MaterialTheme.shapes.small,
                ) {
                    Icon(PqIcons.Fingerprint, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.fingerprint))
                }
            }
        }

        state.error?.let {
            Spacer(Modifier.height(14.dp))
            StatusBanner(it, BannerTone.Danger)
        }
    }
}
