package com.sysmon.app

import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

class MessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        Session.registerPushToken(token)
    }

    override fun onMessageReceived(message: RemoteMessage) {
        super.onMessageReceived(message)
        // FCM displays notification payloads automatically when the app is
        // in the background. When foregrounded we need to post the
        // notification ourselves.
        val title = message.notification?.title ?: message.data["title"] ?: "sysmon"
        val body = message.notification?.body ?: message.data["body"] ?: return

        val builder = NotificationCompat.Builder(this, getString(R.string.notification_channel_id))
            .setContentTitle(title)
            .setContentText(body)
            .setSmallIcon(R.drawable.ic_notification)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)

        val manager = NotificationManagerCompat.from(this)
        if (manager.areNotificationsEnabled()) {
            val id = message.messageId?.hashCode() ?: System.currentTimeMillis().toInt()
            try {
                manager.notify(id, builder.build())
            } catch (_: SecurityException) {
                // POST_NOTIFICATIONS not granted on Android 13+
            }
        }
    }
}
