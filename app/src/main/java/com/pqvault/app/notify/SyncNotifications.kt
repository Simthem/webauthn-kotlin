package com.pqvault.app.notify

import android.Manifest
import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.pqvault.app.ui.MainActivity
import com.pqvault.app.R
import com.pqvault.core.merge.VaultMerge

/**
 * Notifications for vault sync.
 *
 * Two channels rather than one, because these carry very different weight. Routine sync
 * results are background noise and belong on a low-importance channel the user can mute.
 * A vault that fails its integrity checks is a security event: it means the WebDAV
 * server served something tampered with or replayed, and must be loud and unmutable in
 * practice, or the protection built into the format is wasted on a notification nobody
 * sees.
 */
class SyncNotifications(private val context: Context) {

    fun ensureChannels() {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_STATUS,
                context.getString(R.string.channel_sync_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply { description = context.getString(R.string.channel_sync_description) },
        )
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_SECURITY,
                context.getString(R.string.channel_security_name),
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                description = context.getString(R.string.channel_security_description)
                enableVibration(true)
            },
        )
    }

    /** Android 13+ will silently drop notifications without this runtime permission. */
    fun hasPermission(): Boolean =
        android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    fun syncSucceeded(entryCount: Int, merged: Boolean) {
        notify(
            id = ID_STATUS,
            channel = CHANNEL_STATUS,
            title = context.getString(
                if (merged) R.string.notif_vault_merged else R.string.notif_vault_synced,
            ),
            text = context.resources.getQuantityString(
                R.plurals.notif_passkeys_on_cloud,
                entryCount,
                entryCount,
            ),
            highPriority = false,
        )
    }

    fun conflictsResolved(conflicts: List<VaultMerge.Conflict>) {
        if (conflicts.isEmpty()) return
        notify(
            id = ID_STATUS,
            channel = CHANNEL_STATUS,
            title = context.resources.getQuantityString(
                R.plurals.notif_conflicts_resolved,
                conflicts.size,
                conflicts.size,
            ),
            text = context.getString(R.string.notif_conflicts_body),
            highPriority = false,
        )
    }

    fun syncFailed(reason: String) {
        notify(
            id = ID_STATUS,
            channel = CHANNEL_STATUS,
            title = context.getString(R.string.notif_sync_failed),
            text = reason,
            highPriority = false,
        )
    }

    /** The one notification the user must not miss. */
    fun remoteUntrusted(reason: String) {
        notify(
            id = ID_SECURITY,
            channel = CHANNEL_SECURITY,
            title = "\u26a0 " + context.getString(R.string.notif_remote_untrusted),
            text = reason,
            highPriority = true,
        )
    }

    @SuppressLint("MissingPermission") // hasPermission checks POST_NOTIFICATIONS immediately below.
    private fun notify(id: Int, channel: String, title: String, text: String, highPriority: Boolean) {
        if (!hasPermission()) return
        val notification = NotificationCompat.Builder(context, channel)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setPriority(
                if (highPriority) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_LOW,
            )
            // Especially for the security channel: being told the remote vault was
            // refused and then having the notification do nothing when tapped leaves the
            // user with a warning and nowhere to act on it.
            .setContentIntent(openApp())
            .setAutoCancel(true)
            .build()
        runCatching { NotificationManagerCompat.from(context).notify(id, notification) }
    }

    private fun openApp(): PendingIntent? {
        val intent = Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        return PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private companion object {
        const val CHANNEL_STATUS = "pqvault_sync_status"
        const val CHANNEL_SECURITY = "pqvault_security"
        const val ID_STATUS = 1001
        const val ID_SECURITY = 1002
    }
}
