package com.pqvault.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.pqvault.app.R
import com.pqvault.app.data.SecureSettings
import com.pqvault.app.provider.InstalledBrowsers
import com.pqvault.app.ui.VaultViewModel
import com.pqvault.app.ui.components.Badge
import com.pqvault.app.ui.components.BannerTone
import com.pqvault.app.ui.components.KeyValueRow
import com.pqvault.app.ui.components.PqCard
import com.pqvault.app.ui.components.PqTextField
import com.pqvault.app.ui.components.SectionLabel
import com.pqvault.app.ui.components.StatusBanner
import com.pqvault.app.ui.theme.PqColors
import com.pqvault.app.ui.theme.PqIcons

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SettingsScreen(
    state: VaultViewModel.UiState,
    onBack: () -> Unit,
    onSave: (SecureSettings.Settings) -> Unit,
    onEnableBiometrics: () -> Unit,
    onDisableBiometrics: () -> Unit,
    onEnrollDevice: () -> Unit,
    onToggleBrowser: (String, Boolean) -> Unit,
    onShowPairingCode: () -> Unit,
    onScanPairingCode: () -> Unit,
    onAutoLockChange: (Int) -> Unit,
) {
    var baseUrl by remember(state.settings) { mutableStateOf(state.settings.webdavBaseUrl) }
    var username by remember(state.settings) { mutableStateOf(state.settings.webdavUsername) }
    var appPassword by remember(state.settings) { mutableStateOf(state.settings.webdavAppPassword) }
    var remotePath by remember(state.settings) { mutableStateOf(state.settings.remotePath) }

    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 8.dp, end = 20.dp, top = 20.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack) {
                Icon(
                    Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = stringResource(R.string.back),
                    tint = MaterialTheme.colorScheme.onSurface,
                )
            }
            Text(
                stringResource(R.string.settings),
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onBackground,
            )
        }

        Column(modifier = Modifier.padding(horizontal = 20.dp)) {
            state.message?.let {
                StatusBanner(it, BannerTone.Success)
                Spacer(Modifier.height(12.dp))
            }
            state.error?.let {
                StatusBanner(it, BannerTone.Danger)
                Spacer(Modifier.height(12.dp))
            }

            SectionLabel(stringResource(R.string.section_webdav))
            Spacer(Modifier.height(8.dp))
            PqCard {
                PqTextField(
                    value = baseUrl,
                    onValueChange = { baseUrl = it },
                    label = stringResource(R.string.webdav_url),
                    placeholder = "https://cloud.example.org/remote.php/dav/files/me/Passkeys",
                    supportingText = stringResource(R.string.webdav_url_hint),
                )
                Spacer(Modifier.height(12.dp))
                PqTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = stringResource(R.string.webdav_user),
                )
                Spacer(Modifier.height(12.dp))
                PqTextField(
                    value = appPassword,
                    onValueChange = { appPassword = it },
                    label = stringResource(R.string.webdav_app_password),
                    isPassword = true,
                    supportingText = stringResource(R.string.webdav_app_password_hint),
                )
                Spacer(Modifier.height(12.dp))
                PqTextField(
                    value = remotePath,
                    onValueChange = { remotePath = it },
                    label = stringResource(R.string.webdav_filename),
                )
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = {
                        onSave(
                            state.settings.copy(
                                webdavBaseUrl = baseUrl.trim(),
                                webdavUsername = username.trim(),
                                webdavAppPassword = appPassword,
                                remotePath = remotePath.trim().ifEmpty { "vault.pqvault" },
                            ),
                        )
                    },
                    modifier = Modifier.fillMaxWidth(),
                    shape = MaterialTheme.shapes.small,
                ) { Text(stringResource(R.string.save)) }
            }

            Spacer(Modifier.height(22.dp))
            SectionLabel(stringResource(R.string.section_pairing))
            Spacer(Modifier.height(8.dp))
            PqCard {
                Text(
                    stringResource(R.string.pairing_explainer),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(14.dp))
                // Full width and stacked. Side by side, neither label survived an
                // ordinary phone width: both were ellipsised down to a word and a half,
                // which is precisely the text that says which button does what.
                OutlinedButton(
                    onClick = onShowPairingCode,
                    modifier = Modifier.fillMaxWidth(),
                    shape = MaterialTheme.shapes.small,
                    enabled = state.settings.webdavBaseUrl.isNotBlank(),
                ) {
                    Icon(PqIcons.QrCode, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(10.dp))
                    Text(stringResource(R.string.show_pairing_code))
                }
                Spacer(Modifier.height(8.dp))
                OutlinedButton(
                    onClick = onScanPairingCode,
                    modifier = Modifier.fillMaxWidth(),
                    shape = MaterialTheme.shapes.small,
                ) {
                    Icon(PqIcons.QrCodeScanner, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(10.dp))
                    Text(stringResource(R.string.scan_pairing_code))
                }
            }

            Spacer(Modifier.height(22.dp))
            SectionLabel(stringResource(R.string.section_device_security))
            Spacer(Modifier.height(8.dp))
            PqCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        PqIcons.Fingerprint,
                        contentDescription = null,
                        tint = PqColors.Amber500,
                        modifier = Modifier.size(20.dp),
                    )
                    Spacer(Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            stringResource(R.string.biometric_unlock),
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Text(
                            if (state.biometricsAvailable) {
                                stringResource(R.string.biometric_explainer)
                            } else {
                                stringResource(R.string.biometric_unavailable)
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = state.biometricsEnrolled,
                        onCheckedChange = { if (it) onEnableBiometrics() else onDisableBiometrics() },
                        enabled = state.biometricsAvailable,
                    )
                }
            }

            Spacer(Modifier.height(12.dp))
            PqCard {
                Text(
                    stringResource(R.string.auto_lock_title),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    stringResource(R.string.auto_lock_explainer),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    SecureSettings.AUTO_LOCK_CHOICES.forEach { seconds ->
                        FilterChip(
                            selected = state.settings.autoLockSeconds == seconds,
                            onClick = { onAutoLockChange(seconds) },
                            label = { Text(autoLockLabel(seconds)) },
                            shape = MaterialTheme.shapes.small,
                        )
                    }
                }
            }

            Spacer(Modifier.height(22.dp))
            SectionLabel(stringResource(R.string.section_background_sync))
            Spacer(Modifier.height(8.dp))
            PqCard {
                Text(
                    if (state.deviceEnrolled) {
                        stringResource(R.string.device_enrolled)
                    } else {
                        stringResource(R.string.device_not_enrolled)
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (!state.deviceEnrolled) {
                    Spacer(Modifier.height(12.dp))
                    OutlinedButton(
                        onClick = onEnrollDevice,
                        modifier = Modifier.fillMaxWidth(),
                        shape = MaterialTheme.shapes.small,
                    ) { Text(stringResource(R.string.enroll_device)) }
                }
            }

            Spacer(Modifier.height(22.dp))
            SectionLabel(stringResource(R.string.section_browsers))
            Spacer(Modifier.height(8.dp))
            PqCard {
                Text(
                    stringResource(R.string.browsers_explainer),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))

                if (state.browsers.isEmpty()) {
                    Text(
                        stringResource(R.string.browsers_none_found),
                        style = MaterialTheme.typography.bodySmall,
                        color = PqColors.Dark3,
                    )
                } else {
                    state.browsers.forEachIndexed { index, browser ->
                        if (index > 0) {
                            HorizontalDivider(color = MaterialTheme.colorScheme.outline)
                        }
                        BrowserRow(
                            browser = browser,
                            trusted = browser.packageName in state.trustedBrowsers,
                            onToggle = { onToggleBrowser(browser.packageName, it) },
                        )
                    }
                }
            }

            Spacer(Modifier.height(22.dp))
            SectionLabel(stringResource(R.string.section_crypto))
            Spacer(Modifier.height(8.dp))
            PqCard {
                KeyValueRow(stringResource(R.string.crypto_vault), "XChaCha20-Poly1305")
                KeyValueRow(stringResource(R.string.crypto_kdf), "Argon2id 64 MiB")
                KeyValueRow(stringResource(R.string.crypto_device_sharing), "X25519 + ML-KEM-768")
                KeyValueRow(stringResource(R.string.crypto_file_signature), "Ed25519 + ML-DSA-65")
                KeyValueRow(stringResource(R.string.crypto_passkey_signature), "ES256 (P-256)")
                Spacer(Modifier.height(8.dp))
                Text(
                    stringResource(R.string.crypto_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = PqColors.Dark3,
                )
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

/** "1 min", "15 min", or "Never" for the choice that disables the idle lock. */
@Composable
private fun autoLockLabel(seconds: Int): String = if (seconds == 0) {
    stringResource(R.string.auto_lock_never)
} else {
    stringResource(R.string.auto_lock_minutes, seconds / 60)
}

/**
 * One detected browser. The fingerprint is shown truncated so the user can compare it
 * against a published one without having to trust that we matched it correctly.
 */
@Composable
private fun BrowserRow(
    browser: InstalledBrowsers.Browser,
    trusted: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    browser.label,
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (browser.isDefault) {
                    Spacer(Modifier.width(8.dp))
                    Badge(stringResource(R.string.browser_default), color = PqColors.Amber300)
                }
            }
            Text(
                browser.packageName,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                browser.fingerprint.take(29) + "…",
                style = MaterialTheme.typography.bodySmall,
                color = PqColors.Dark3,
                maxLines = 1,
            )
        }
        Checkbox(checked = trusted, onCheckedChange = onToggle)
    }
}
