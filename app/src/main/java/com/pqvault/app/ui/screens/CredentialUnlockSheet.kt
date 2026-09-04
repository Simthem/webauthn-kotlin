package com.pqvault.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.pqvault.app.R
import com.pqvault.app.ui.components.BannerTone
import com.pqvault.app.ui.components.PqCard
import com.pqvault.app.ui.components.PqTextField
import com.pqvault.app.ui.components.StatusBanner
import com.pqvault.app.ui.theme.PqColors
import com.pqvault.app.ui.theme.PqIcons

/**
 * Unlock prompt shown inside the credential provider flow.
 *
 * The system launches that activity transparently over whatever app asked for a passkey,
 * so this draws its own scrim and sits at the bottom, close to where the system sheet it
 * replaces was.
 */
@Composable
fun CredentialUnlockSheet(
    biometricsOffered: Boolean,
    error: String?,
    onPassphrase: (String) -> Unit,
    onBiometric: () -> Unit,
    onCancel: () -> Unit,
) {
    var passphrase by remember { mutableStateOf("") }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.6f)),
        contentAlignment = Alignment.BottomCenter,
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            PqCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        PqIcons.Shield,
                        contentDescription = null,
                        tint = PqColors.Amber500,
                        modifier = Modifier.size(22.dp),
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        stringResource(R.string.unlock_vault_title),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    stringResource(R.string.unlock_vault_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                error?.let {
                    Spacer(Modifier.height(12.dp))
                    StatusBanner(it, BannerTone.Danger)
                }

                Spacer(Modifier.height(16.dp))
                PqTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = stringResource(R.string.passphrase),
                    isPassword = true,
                )
                Spacer(Modifier.height(14.dp))
                Button(
                    onClick = { onPassphrase(passphrase) },
                    enabled = passphrase.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth(),
                    shape = MaterialTheme.shapes.small,
                ) {
                    Icon(PqIcons.LockOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.unlock))
                }

                if (biometricsOffered) {
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = onBiometric,
                        modifier = Modifier.fillMaxWidth(),
                        shape = MaterialTheme.shapes.small,
                    ) {
                        Icon(PqIcons.Fingerprint, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.fingerprint))
                    }
                }

                Spacer(Modifier.height(4.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    TextButton(onClick = onCancel) { Text(stringResource(R.string.cancel)) }
                }
            }
        }
    }
}
