package com.pqvault.app.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.vectorResource
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
 */
object PqIcons {
    val Visibility: ImageVector
        @Composable get() = ImageVector.vectorResource(R.drawable.ic_visibility)

    val VisibilityOff: ImageVector
        @Composable get() = ImageVector.vectorResource(R.drawable.ic_visibility_off)

    val CloudOff: ImageVector
        @Composable get() = ImageVector.vectorResource(R.drawable.ic_cloud_off)

    val CloudSync: ImageVector
        @Composable get() = ImageVector.vectorResource(R.drawable.ic_cloud_sync)

    val Fingerprint: ImageVector
        @Composable get() = ImageVector.vectorResource(R.drawable.ic_fingerprint)

    val Key: ImageVector
        @Composable get() = ImageVector.vectorResource(R.drawable.ic_key)

    val LockOpen: ImageVector
        @Composable get() = ImageVector.vectorResource(R.drawable.ic_lock_open)

    val Shield: ImageVector
        @Composable get() = ImageVector.vectorResource(R.drawable.ic_shield)

    val QrCode: ImageVector
        @Composable get() = ImageVector.vectorResource(R.drawable.ic_qr_code)

    val QrCodeScanner: ImageVector
        @Composable get() = ImageVector.vectorResource(R.drawable.ic_qr_code_scanner)
}
