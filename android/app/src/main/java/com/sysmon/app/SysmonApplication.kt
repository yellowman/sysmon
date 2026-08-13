package com.sysmon.app

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build

class SysmonApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Session.init(this)
        FcmTokenStore.init(this)
        createNotificationChannel()
        // The daily token health check runs only for a signed-in
        // install - no sysmon to talk to, nothing to check. Login and
        // logout flip it (see Session); this covers process restarts,
        // and clears work a since-logged-out (or older) build left
        // scheduled.
        if (Session.isLoggedIn()) {
            PushHealthWorker.schedule(this)
        } else {
            PushHealthWorker.cancel(this)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java) ?: return
            // Critical alerts: loud - sound and heads-up.
            manager.createNotificationChannel(
                NotificationChannel(
                    getString(R.string.notification_channel_id),
                    getString(R.string.notification_channel_name),
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = getString(R.string.notification_channel_description)
                }
            )
            // Warnings and recoveries: silent - no sound, no heads-up,
            // just a quiet entry in the shade. The server routes each
            // push to the matching channel by severity.
            manager.createNotificationChannel(
                NotificationChannel(
                    getString(R.string.notification_channel_warn_id),
                    getString(R.string.notification_channel_warn_name),
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = getString(R.string.notification_channel_warn_description)
                }
            )
        }
    }
}
