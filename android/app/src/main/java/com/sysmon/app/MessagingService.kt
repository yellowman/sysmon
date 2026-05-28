package com.sysmon.app

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

class MessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        Session.registerPushToken(token)
    }

    override fun onMessageReceived(message: RemoteMessage) {
        // FCM displays the notification payload automatically via the
        // default channel meta-data declared in the manifest.
        super.onMessageReceived(message)
    }
}
