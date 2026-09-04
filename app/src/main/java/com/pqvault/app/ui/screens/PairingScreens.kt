package com.pqvault.app.ui.screens

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.view.WindowManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.pqvault.app.R
import com.pqvault.app.pairing.QrCode
import com.pqvault.app.pairing.QrScannerView
import com.pqvault.app.ui.components.BannerTone
import com.pqvault.app.ui.components.PqCard
import com.pqvault.app.ui.components.StatusBanner

/**
 * Sets FLAG_SECURE on the window for as long as the calling composable is on screen.
 */
@Composable
private fun SecureWhileVisible() {
    val context = LocalContext.current
    DisposableEffect(context) {
        // Compose is not guaranteed to hand back the Activity itself; a themed wrapper is
        // just as likely, and only the Activity owns a window to flag.
        var candidate: Context? = context
        while (candidate is ContextWrapper && candidate !is Activity) {
            candidate = candidate.baseContext
        }
        val window = (candidate as? Activity)?.window
        window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
}

/** Full-screen overlay showing the pairing QR for another device to scan. */
@Composable
fun PairingCodeScreen(content: String, onClose: () -> Unit) {
    val bitmap = remember(content) { QrCode.encode(content, 720) }

    // This QR carries the WebDAV app password in the clear: anything that can read the
    // screen can read the credential. FLAG_SECURE blocks screenshots and screen recording
    // and keeps the code out of the recent-apps thumbnail, and is lifted again the moment
    // the overlay closes so it does not affect the rest of the app.
    SecureWhileVisible()

    Box(
        modifier = Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.85f)),
        contentAlignment = Alignment.Center,
    ) {
        Column(modifier = Modifier.padding(24.dp)) {
            PqCard {
                Text(
                    stringResource(R.string.pairing_code_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    stringResource(R.string.pairing_code_body),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(16.dp))
                if (bitmap == null) {
                    StatusBanner(stringResource(R.string.pairing_code_too_large), BannerTone.Danger)
                } else {
                    Image(
                        bitmap = bitmap.asImageBitmap(),
                        contentDescription = stringResource(R.string.pairing_code_title),
                        modifier = Modifier
                            .fillMaxWidth()
                            .aspectRatio(1f)
                            // White quiet zone around the code; scanners need the contrast.
                            .clip(RoundedCornerShape(8.dp))
                            .background(Color.White)
                            .padding(12.dp),
                    )
                }
                Spacer(Modifier.height(12.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = onClose) { Text(stringResource(R.string.close)) }
                }
            }
        }
    }
}

/** Full-screen camera overlay that reads a pairing QR. */
@Composable
fun PairingScanScreen(
    error: String?,
    onScanned: (String) -> Unit,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    var granted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    val request = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted = it }

    LaunchedEffect(Unit) {
        if (!granted) request.launch(Manifest.permission.CAMERA)
    }

    Box(
        modifier = Modifier.fillMaxSize().background(Color.Black),
        contentAlignment = Alignment.Center,
    ) {
        if (granted) {
            QrScannerView(modifier = Modifier.fillMaxSize(), onScanned = onScanned)
        }

        Column(
            modifier = Modifier.fillMaxSize().padding(24.dp),
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
            Column {
                Text(
                    stringResource(R.string.pairing_scan_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = Color.White,
                )
                error?.let {
                    Spacer(Modifier.height(12.dp))
                    StatusBanner(it, BannerTone.Danger)
                }
            }

            Column {
                if (!granted) {
                    StatusBanner(stringResource(R.string.pairing_scan_permission), BannerTone.Warning)
                    Spacer(Modifier.height(12.dp))
                    Button(
                        onClick = { request.launch(Manifest.permission.CAMERA) },
                        modifier = Modifier.fillMaxWidth(),
                        shape = MaterialTheme.shapes.small,
                    ) { Text(stringResource(R.string.grant_camera)) }
                    Spacer(Modifier.height(8.dp))
                }
                TextButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.close), color = Color.White)
                }
            }
        }
    }
}
