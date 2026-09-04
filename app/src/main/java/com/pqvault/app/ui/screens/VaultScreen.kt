package com.pqvault.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pqvault.app.ui.VaultViewModel
import com.pqvault.app.R
import com.pqvault.app.ui.components.Badge
import com.pqvault.app.ui.components.BannerTone
import com.pqvault.app.ui.components.PqCard
import com.pqvault.app.ui.components.SecurityAlertCard
import com.pqvault.app.ui.components.StatusBanner
import com.pqvault.app.ui.theme.PqColors
import com.pqvault.app.ui.theme.PqIcons
import com.pqvault.core.model.PasskeyEntry

@Composable
fun VaultScreen(
    state: VaultViewModel.UiState,
    onSync: () -> Unit,
    onScanFido: () -> Unit,
    onLock: () -> Unit,
    onSettings: () -> Unit,
    onConfirmDelete: (String) -> Unit,
    onCancelDelete: () -> Unit,
    onDelete: (String) -> Unit,
    onAcceptRemoteVersion: () -> Unit,
    onDismissSecurityAlert: () -> Unit,
) {
    state.pendingDeletion?.let { entry ->
        DeleteConfirmationDialog(
            entry = entry,
            onConfirm = { onDelete(entry.credentialId) },
            onDismiss = onCancelDelete,
        )
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 20.dp, end = 8.dp, top = 20.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.my_passkeys), style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.onBackground)
                Text(
                    pluralStringResource(R.plurals.passkey_count, state.entries.size, state.entries.size),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            IconButton(onClick = onScanFido) {
                Icon(
                    PqIcons.QrCodeScanner,
                    contentDescription = stringResource(R.string.action_scan_fido),
                    tint = PqColors.Amber500,
                )
            }
            IconButton(onClick = onSync, enabled = !state.busy) {
                if (state.busy) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = PqColors.Amber500)
                } else {
                    Icon(
                        if (state.settings.webdavBaseUrl.isBlank()) PqIcons.CloudOff else PqIcons.CloudSync,
                        contentDescription = stringResource(R.string.action_sync),
                        tint = if (state.settings.webdavBaseUrl.isBlank()) PqColors.Dark3 else PqColors.Amber500,
                    )
                }
            }
            IconButton(onClick = onLock) {
                Icon(Icons.Default.Lock, contentDescription = stringResource(R.string.action_lock), tint = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            IconButton(onClick = onSettings) {
                Icon(Icons.Default.Settings, contentDescription = stringResource(R.string.action_settings), tint = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        Column(modifier = Modifier.padding(horizontal = 20.dp)) {
            state.securityAlert?.let {
                SecurityAlertCard(
                    reason = it,
                    onAccept = onAcceptRemoteVersion.takeIf { _ -> state.securityAlertRecoverable },
                    onDismiss = onDismissSecurityAlert,
                )
                Spacer(Modifier.height(10.dp))
            }
            state.error?.let {
                StatusBanner(it, BannerTone.Danger)
                Spacer(Modifier.height(10.dp))
            }
            state.message?.let {
                StatusBanner(it, BannerTone.Success)
                Spacer(Modifier.height(10.dp))
            }
            if (state.settings.webdavBaseUrl.isBlank()) {
                StatusBanner(
                    stringResource(R.string.no_cloud_configured),
                    BannerTone.Warning,
                )
                Spacer(Modifier.height(10.dp))
            }
        }

        if (state.entries.isEmpty()) {
            EmptyState()
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(horizontal = 20.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 24.dp, top = 6.dp),
            ) {
                items(state.entries, key = { it.credentialId }) { entry ->
                    PasskeyRow(entry, onDelete = { onConfirmDelete(entry.credentialId) })
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun PasskeyRow(entry: PasskeyEntry, onDelete: () -> Unit) {
    PqCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(PqIcons.Key, contentDescription = null, tint = PqColors.Amber500, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    entry.rpName ?: entry.rpId,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(entry.userName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            IconButton(onClick = onDelete) {
                Icon(Icons.Default.Delete, contentDescription = stringResource(R.string.action_delete), tint = PqColors.Dark3, modifier = Modifier.size(18.dp))
            }
        }
        Spacer(Modifier.height(10.dp))
        // A badge that no longer fits moves to the next line instead of being squeezed until its
        // label wraps one letter per line.
        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Badge(entry.rpId, PqColors.Dark2)
            Badge(entry.algorithm?.label ?: "alg ${entry.algorithmId}", PqColors.Amber300)
            if (entry.signCount > 0) {
                Badge(
                    pluralStringResource(R.plurals.usage_count, entry.signCount.toInt(), entry.signCount),
                    PqColors.Dark2,
                )
            }
        }
    }
}

/**
 * A passkey may be the only way in to an account, and deleting one propagates to every
 * synced device. A single mistaken tap on a small icon is not a decision anyone means to
 * make, so it is confirmed against the name of the site it belongs to.
 */
@Composable
private fun DeleteConfirmationDialog(
    entry: PasskeyEntry,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Default.Warning, contentDescription = null, tint = PqColors.Red) },
        title = { Text(stringResource(R.string.delete_passkey_title)) },
        text = {
            Text(
                stringResource(
                    R.string.delete_passkey_body,
                    entry.rpName ?: entry.rpId,
                    entry.userName,
                ),
            )
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.delete_passkey_confirm), color = PqColors.Red)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        },
    )
}

@Composable
private fun EmptyState() {
    Box(modifier = Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(PqIcons.Key, contentDescription = null, tint = PqColors.Dark4, modifier = Modifier.size(44.dp))
            Spacer(Modifier.height(14.dp))
            Text(stringResource(R.string.empty_title), style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(6.dp))
            Text(
                stringResource(R.string.empty_body),
                style = MaterialTheme.typography.bodySmall,
                color = PqColors.Dark3,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
            )
        }
    }
}
