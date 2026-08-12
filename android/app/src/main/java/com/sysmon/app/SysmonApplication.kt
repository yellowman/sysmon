package com.sysmon.app

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

class SysmonApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Session.init(this)
        FcmTokenStore.init(this)
        createNotificationChannel()
        schedulePushHealthCheck()
    }

    // Once a day, in a system-batched window with network available,
    // re-run the push registration handshake so a token FCM has killed
    // renews itself without waiting for the next app launch. KEEP so
    // every launch doesn't reset the 24h clock.
    private fun schedulePushHealthCheck() {
        val request = PeriodicWorkRequestBuilder<PushHealthWorker>(24, TimeUnit.HOURS)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build()
            )
            .build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            PushHealthWorker.NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            request
        )
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
