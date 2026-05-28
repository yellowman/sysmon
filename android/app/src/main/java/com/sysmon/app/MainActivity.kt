package com.sysmon.app

import android.Manifest
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
            if (granted) registerForFcm()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SysmonTheme {
                RootScreen(onLoggedIn = { requestPushPermission() })
            }
        }
        if (Session.isLoggedIn()) requestPushPermission()
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
            if (!task.isSuccessful) return@addOnCompleteListener
            val token = task.result ?: return@addOnCompleteListener
            Session.registerPushToken(token)
        }
    }
}
