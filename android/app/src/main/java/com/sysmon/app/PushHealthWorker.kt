package com.sysmon.app

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters

/**
 * The scheduled half of dead-token recovery: once a day, re-run the
 * push registration handshake in the background.
 *
 * Re-subscribing IS the check - the server's reply carries the verdict
 * when FCM refused this token since the last send (UNREGISTERED is only
 * ever told to the sender; the SDK on this phone keeps serving the dead
 * token from cache) - and Session.syncPushToken already renews on that
 * verdict. So a phone that sits in a drawer for a day heals without
 * anyone opening the app, instead of silently missing alerts until the
 * next launch.
 *
 * WorkManager batches this into the system's deferred-work windows: one
 * small network exchange a day, no wakeups of its own.
 */
class PushHealthWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        // Nothing to check without a login and a token: the FIRST
        // registration belongs to the foreground flow, which can prompt
        // for permission and talk to the user.
        if (!Session.isLoggedIn()) return Result.success()
        val token = FcmTokenStore.token ?: return Result.success()
        return if (Session.syncPushToken(token)) Result.success() else Result.retry()
    }

    companion object {
        const val NAME = "push-health"
    }
}
