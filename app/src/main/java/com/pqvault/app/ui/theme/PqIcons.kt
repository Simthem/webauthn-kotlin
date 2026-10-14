package com.pqvault.app.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.res.painterResource
import com.pqvault.app.R

/**
 * The handful of icons this app needs that are not in material-icons-core.
 *
 * They are hand-drawn vectors rather than a dependency on material-icons-extended, which
 * compiles roughly ten thousand icons into the app to serve the fifteen actually used.
 * R8 strips them in release builds, but a debug APK has no such luxury: pulling the
 * library in cost about 60 MB of dex, which is most of the install and every incremental
 * build. Icons that come from core (ArrowBack, Delete, Lock, Settings, Warning) are still
 * used directly from there.
 *
 * Painters from [painterResource], not ImageVector.vectorResource: in Compose 1.7 the
 * latter remembers its result per call site only, so every passkey row scrolling into
 * view opened and parsed ic_key.xml again on the main thread. painterResource goes
 * through Compose's ImageVectorCache and parses each drawable once per theme.
 */
object PqIcons {
    val Visibility: Painter
        @Composable get() = painterResource(R.drawable.ic_visibility)

    val VisibilityOff: Painter
        @Composable get() = painterResource(R.drawable.ic_visibility_off)

    val CloudOff: Painter
        @Composable get() = painterResource(R.drawable.ic_cloud_off)

    val CloudSync: Painter
        @Composable get() = painterResource(R.drawable.ic_cloud_sync)

    val Fingerprint: Painter
        @Composable get() = painterResource(R.drawable.ic_fingerprint)

    val Key: Painter
        @Composable get() = painterResource(R.drawable.ic_key)

    val LockOpen: Painter
        @Composable get() = painterResource(R.drawable.ic_lock_open)

    val Shield: Painter
        @Composable get() = painterResource(R.drawable.ic_shield)

    val QrCode: Painter
        @Composable get() = painterResource(R.drawable.ic_qr_code)

    val QrCodeScanner: Painter
        @Composable get() = painterResource(R.drawable.ic_qr_code_scanner)
}
