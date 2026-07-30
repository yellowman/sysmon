package com.sysmon.app

import android.app.PendingIntent
import android.content.Intent
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

private const val TAG = "SysmonPush"

class MessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        val previous = FcmTokenStore.token
        Session.registerPushToken(token, replacing = previous)
    }

    override fun onMessageReceived(message: RemoteMessage) {
        // FCM displays notification payloads automatically when the app is
        // in the background. When foregrounded we need to post the
        // notification ourselves.
        val title = message.notification?.title ?: message.data["title"] ?: "sysmon"
        val body = message.notification?.body ?: message.data["body"] ?: return

        // Tapping the notification opens the app on the Alerts tab.
        val tapIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_NAVIGATE, MainActivity.NAV_ALERTS)
            message.data["hostname"]?.let { putExtra("hostname", it) }
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = NotificationCompat.Builder(this, getString(R.string.notification_channel_id))
            .setContentTitle(title)
            .setContentText(body)
            .setSmallIcon(R.drawable.ic_notification)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)

        val manager = NotificationManagerCompat.from(this)
        if (manager.areNotificationsEnabled()) {
            val id = message.messageId?.hashCode() ?: System.currentTimeMillis().toInt()
            try {
                manager.notify(id, builder.build())
                Log.d(TAG, "posted alert notification: $title")
            } catch (e: SecurityException) {
                // POST_NOTIFICATIONS not granted on Android 13+
                Log.w(TAG, "alert delivered but POST_NOTIFICATIONS not granted — dropped: $title", e)
                Session.pushStatus =
                    "Alert received but notifications are blocked — enable them in system settings"
            }
        } else {
            // Never fail silent: the message made it all the way to the
            // device and the OS refused to show it. Say so where the user
            // will see it (Settings tab) and in logcat.
            Log.w(TAG, "alert delivered but notifications are disabled for this app — dropped: $title")
            Session.pushStatus =
                "Alert received but notifications are blocked — enable them in system settings"
        }
    }
}
