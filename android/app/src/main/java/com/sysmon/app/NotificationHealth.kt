package com.sysmon.app

import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.provider.Settings

/**
 * Diagnoses why alert notifications wouldn't be seen on this device.
 *
 * FCM can deliver a message to the phone (Firebase shows "Received")
 * while the OS silently refuses to display it: notifications disabled
 * for the app (Android 13+ opt-in, or user toggled off), the alerts
 * channel disabled, or the channel silenced by an earlier install —
 * Android snapshots channel importance at first creation, so code can't
 * raise it later. None of these produce any error anywhere, so the app
 * has to check and say so itself.
 */
object NotificationHealth {

    /** Human-readable reason alerts won't be seen, or null if healthy. */
    fun problem(context: Context): String? {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return null
        if (!manager.areNotificationsEnabled()) {
            return "Notifications are turned off for Sysmon — alerts will not appear"
        }
        val channel = manager.getNotificationChannel(
            context.getString(R.string.notification_channel_id)
        ) ?: return null // will be created on next app start; nothing to report
        return when {
            channel.importance == NotificationManager.IMPORTANCE_NONE ->
                "The Host Alerts notification channel is disabled — alerts will not appear"
            channel.importance < NotificationManager.IMPORTANCE_DEFAULT ->
                "The Host Alerts channel is set to silent — alerts won't pop up or make a sound"
            else -> null
        }
    }

    /**
     * Open the system notification settings — the channel's own page when
     * the app-level toggle is fine (channel problems are fixed there),
     * otherwise the app's notification page.
     */
    fun openSettings(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        val channelId = context.getString(R.string.notification_channel_id)
        val appEnabled = manager?.areNotificationsEnabled() == true
        val hasChannel = manager?.getNotificationChannel(channelId) != null
        val intent = if (appEnabled && hasChannel) {
            Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
                .putExtra(Settings.EXTRA_CHANNEL_ID, channelId)
        } else {
            Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
        }
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
    }
}
