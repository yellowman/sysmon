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
import androidx.lifecycle.lifecycleScope
import com.google.firebase.messaging.FirebaseMessaging
import com.sysmon.app.ui.RootScreen
import com.sysmon.app.ui.theme.SysmonTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private val pushPermissionRequest =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) {
                Session.pushStatus = null
                registerForFcm()
            } else {
                Session.pushStatus = "Notifications denied - enable in system settings"
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
        handleOIDCCallback(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handlePushIntent(intent)
        handleOIDCCallback(intent)
    }

    override fun onResume() {
        super.onResume()
        // "Not registered" on the Settings tab is local knowledge: logged
        // in with no stored FCM token - the launch-time fetch failed (a
        // Play Services hiccup) or notifications were denied and granted
        // later in system settings. Act on it at the next foreground
        // instead of waiting for a cold start. Never prompt from here -
        // a permission dialog on every resume is nagging - so only
        // proceed when permission is already granted.
        if (Session.isLoggedIn() && FcmTokenStore.token == null && hasPushPermission()) {
            registerForFcm()
        }
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
            // config change re-fired the jump - yanking the user back to
            // the Alerts tab forever after one notification tap.
            intent.removeExtra(EXTRA_NAVIGATE)
            intent.removeExtra("hostname")
        }
    }

    private fun handleOIDCCallback(intent: Intent?) {
        if (intent?.action != Intent.ACTION_VIEW) return
        val uri = intent.data ?: return
        if (uri.scheme != "sysmon" || uri.host != "auth" || uri.path != "/callback") return
        intent.data = null
        val code = uri.getQueryParameter("code")
        if (code.isNullOrEmpty()) {
            Session.loginNote = "Incomplete SSO callback"
            return
        }
        lifecycleScope.launch {
            runCatching { Session.completeOIDC(code) }
                .onSuccess { requestPushPermission() }
                .onFailure { Session.loginNote = it.message ?: "SSO sign-in failed" }
        }
    }

    companion object {
        const val EXTRA_NAVIGATE = "navigate"
        const val NAV_ALERTS = "alerts"
    }

    private fun hasPushPermission(): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(
                this, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED

    private fun requestPushPermission() {
        if (hasPushPermission()) {
            registerForFcm()
        } else {
            pushPermissionRequest.launch(Manifest.permission.POST_NOTIFICATIONS)
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
