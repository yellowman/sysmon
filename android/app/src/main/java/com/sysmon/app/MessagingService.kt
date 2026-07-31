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
        Log.d(TAG, "FCM message received: id=${message.messageId} " +
            "notification=${message.notification != null} data=${message.data.keys}")
        val title = message.notification?.title ?: message.data["title"] ?: "sysmon"
        val body = message.notification?.body ?: message.data["body"]
        if (body == null) {
            Log.w(TAG, "FCM message had no displayable body - ignoring (id=${message.messageId})")
            return
        }

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

        // Severity routing, mirroring the server's channel choice for
        // background (system-posted) notifications: CRITICAL is loud on
        // the alerts channel; warnings and recoveries land silently on
        // the low-importance channel.
        val critical = message.data["status"] == "CRITICAL"
        val channelId = if (critical) getString(R.string.notification_channel_id)
            else getString(R.string.notification_channel_warn_id)

        val builder = NotificationCompat.Builder(this, channelId)
            .setContentTitle(title)
            .setContentText(body)
            .setSmallIcon(R.drawable.ic_notification)
            .setPriority(
                if (critical) NotificationCompat.PRIORITY_HIGH
                else NotificationCompat.PRIORITY_LOW
            )
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)

        val manager = NotificationManagerCompat.from(this)
        if (manager.areNotificationsEnabled()) {
            // Tag by host so a newer notification replaces the older one:
            // the quiet WARN disappears the moment the CRIT (or the
            // recovery) for that host arrives.
            val tag = message.data["object_name"] ?: message.data["hostname"] ?: message.messageId ?: "sysmon"
            try {
                manager.notify(tag, 0, builder.build())
                Log.d(TAG, "posted ${if (critical) "critical" else "quiet"} notification [$tag]: $title")
            } catch (e: SecurityException) {
                // POST_NOTIFICATIONS not granted on Android 13+
                Log.w(TAG, "alert delivered but POST_NOTIFICATIONS not granted - dropped: $title", e)
                Session.pushStatus =
                    "Alert received but notifications are blocked - enable them in system settings"
            }
        } else {
            // Never fail silent: the message made it all the way to the
            // device and the OS refused to show it. Say so where the user
            // will see it (Settings tab) and in logcat.
            Log.w(TAG, "alert delivered but notifications are disabled for this app - dropped: $title")
            Session.pushStatus =
                "Alert received but notifications are blocked - enable them in system settings"
        }
    }
}
