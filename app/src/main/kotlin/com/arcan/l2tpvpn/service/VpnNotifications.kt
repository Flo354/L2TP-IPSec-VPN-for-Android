package com.arcan.l2tpvpn.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.arcan.l2tpvpn.R
import com.arcan.l2tpvpn.core.tunnel.TunnelInfo
import com.arcan.l2tpvpn.core.tunnel.TunnelState
import com.arcan.l2tpvpn.label
import com.arcan.l2tpvpn.ui.MainActivity

/**
 * Builds the ongoing notification the foreground service is required to show.
 *
 * The channel is created at low importance: the notification is a status line and a Disconnect
 * button, not something worth buzzing the phone over.
 */
internal class VpnNotifications(private val context: Context) {

    private val manager: NotificationManager =
        context.getSystemService(NotificationManager::class.java)

    fun ensureChannel() {
        val existing = manager.getNotificationChannel(CHANNEL_ID)
        if (existing != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = context.getString(R.string.notification_channel_description)
            setShowBadge(false)
            enableVibration(false)
            enableLights(false)
        }
        manager.createNotificationChannel(channel)
    }

    /** Renders the current state; call it again with new arguments to update in place. */
    fun build(
        state: TunnelState,
        detail: String?,
        info: TunnelInfo?,
        serverHost: String,
    ): Notification {
        val text = when {
            detail != null -> detail
            state == TunnelState.CONNECTED && info != null ->
                "${info.assignedAddress} via ${info.serverAddress}"
            serverHost.isNotBlank() -> serverHost
            else -> context.getString(R.string.notification_text_idle)
        }

        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle("${context.getString(R.string.app_name)} — ${state.label}")
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(openAppIntent())
            .addAction(
                R.drawable.ic_stat_vpn,
                context.getString(R.string.action_disconnect),
                disconnectIntent(),
            )
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setLocalOnly(true)
            .build()
    }

    fun update(notification: Notification) {
        runCatching { manager.notify(NOTIFICATION_ID, notification) }
    }

    private fun openAppIntent(): PendingIntent = PendingIntent.getActivity(
        context,
        REQUEST_OPEN,
        Intent(context, MainActivity::class.java)
            .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )

    /**
     * `getForegroundService` rather than `getService`: the tap can arrive while the app itself is
     * in the background, where a plain `startService` would be refused.
     */
    private fun disconnectIntent(): PendingIntent = PendingIntent.getForegroundService(
        context,
        REQUEST_DISCONNECT,
        Intent(context, L2tpVpnService::class.java).setAction(L2tpVpnService.ACTION_DISCONNECT),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )

    companion object {
        const val CHANNEL_ID = "vpn"
        const val NOTIFICATION_ID = 0x4C32 // 'L2'
        private const val REQUEST_OPEN = 1
        private const val REQUEST_DISCONNECT = 2
    }
}
