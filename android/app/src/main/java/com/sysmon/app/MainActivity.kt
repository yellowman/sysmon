package com.sysmon.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import com.google.firebase.messaging.FirebaseMessaging
import com.sysmon.app.ui.RootScreen
import com.sysmon.app.ui.theme.SysmonTheme

class MainActivity : ComponentActivity() {

    private val pushPermissionRequest =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) {
                Session.pushStatus = null
                registerForFcm()
            } else {
                Session.pushStatus = "Notifications denied — enable in system settings"
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SysmonTheme {
                RootScreen(onLoggedIn = { requestPushPermission() })
            }
        }
        if (Session.isLoggedIn()) requestPushPermission()
        handlePushIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handlePushIntent(intent)
    }

    // A launch from a tapped notification carries our EXTRA_NAVIGATE (from
    // a foreground-posted notification) or the FCM data payload's
    // "hostname" key (when the system posts a background notification and
    // adds the data fields to the launch intent). Either way, jump to the
    // Alerts tab.
    private fun handlePushIntent(intent: Intent?) {
        val extras = intent?.extras ?: return
        val fromPush = extras.getString(EXTRA_NAVIGATE) == NAV_ALERTS ||
            extras.containsKey("hostname")
        if (fromPush) {
            Session.requestNavigateToAlerts()
            // Consume the extras: on rotation the recreated activity gets
            // this same intent back, and without stripping them every
            // config change re-fired the jump — yanking the user back to
            // the Alerts tab forever after one notification tap.
            intent.removeExtra(EXTRA_NAVIGATE)
            intent.removeExtra("hostname")
        }
    }

    companion object {
        const val EXTRA_NAVIGATE = "navigate"
        const val NAV_ALERTS = "alerts"
    }

    private fun requestPushPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (granted) {
                registerForFcm()
            } else {
                pushPermissionRequest.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        } else {
            registerForFcm()
        }
    }

    private fun registerForFcm() {
        FirebaseMessaging.getInstance().token.addOnCompleteListener { task ->
            if (!task.isSuccessful) {
                Session.pushStatus = "FCM token unavailable"
                return@addOnCompleteListener
            }
            val token = task.result ?: return@addOnCompleteListener
            val previous = FcmTokenStore.token
            Session.registerPushToken(token, replacing = previous)
        }
    }
}
