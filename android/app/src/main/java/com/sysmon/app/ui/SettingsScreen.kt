package com.sysmon.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.sysmon.app.Api
import com.sysmon.app.FcmTokenStore
import com.sysmon.app.NotificationHealth
import com.sysmon.app.Session
import com.sysmon.app.ui.theme.MonoMedium
import com.sysmon.app.ui.theme.SysmonColors
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@Composable
fun SettingsScreen(onLogout: () -> Unit) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var message by remember { mutableStateOf<String?>(null) }
    var sending by remember { mutableStateOf(false) }
    val fcmToken = FcmTokenStore.token
    val pushStatus = Session.pushStatus

    // Re-check on every resume: the user may have just come back from the
    // system settings the warning banner sends them to.
    var notifProblem by remember { mutableStateOf<String?>(null) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        notifProblem = NotificationHealth.problem(context)
    }

    LaunchedEffect(message) {
        if (message != null) {
            delay(4000)
            message = null
        }
    }

    // Scrollable so every row stays reachable in landscape / small screens.
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
    ) {
        TopHeader(title = "Settings", subtitle = "Account and notifications")

        SectionHeader(label = "Account")
        InfoRow("Server", Session.serverUrl.ifEmpty { "—" })
        InfoRow("User", Session.username.ifEmpty { "—" })
        InfoRow("Role", Session.role.uppercase().ifEmpty { "—" })

        SectionHeader(label = "Device")
        InfoRow(
            "Push token",
            fcmToken?.let { it.take(16) + "…" } ?: "Not registered"
        )

        SectionHeader(label = "Notifications")
        notifProblem?.let {
            WarningBanner(it, actionLabel = "Open notification settings") {
                NotificationHealth.openSettings(context)
            }
        }
        if (pushStatus != null) {
            Text(
                text = pushStatus,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp)
            )
        }
        ButtonRow(
            label = if (sending) "Sending…" else "Send Test Notification",
            enabled = !sending && fcmToken != null,
            primary = false
        ) {
            sending = true
            message = null
            scope.launch {
                val current = FcmTokenStore.token
                if (current == null) {
                    message = "No FCM token"
                    sending = false
                    return@launch
                }
                runCatching { Api.sendTestPush(current) }
                    .onSuccess { warning ->
                        message = warning ?: "Sent — check your notifications"
                    }
                    .onFailure { message = it.message ?: "Failed" }
                sending = false
            }
        }

        if (message != null) {
            Text(
                text = message!!,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp)
            )
        }

        SectionHeader(label = "Session")
        ButtonRow(label = "Sign Out", primary = true, danger = true) {
            onLogout()
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Card {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 14.dp),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = label.uppercase(),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = value,
                style = MonoMedium,
                color = MaterialTheme.colorScheme.onBackground
            )
        }
    }
}

@Composable
private fun ButtonRow(
    label: String,
    enabled: Boolean = true,
    primary: Boolean = false,
    danger: Boolean = false,
    onClick: () -> Unit
) {
    Box(modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp)) {
        if (primary) {
            Button(
                onClick = onClick,
                enabled = enabled,
                shape = RoundedCornerShape(4.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (danger) SysmonColors.Down else MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
            ) {
                Text(label.uppercase(), style = MaterialTheme.typography.labelLarge)
            }
        } else {
            OutlinedButton(
                onClick = onClick,
                enabled = enabled,
                shape = RoundedCornerShape(4.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
            ) {
                Text(label.uppercase(), style = MaterialTheme.typography.labelLarge)
            }
        }
    }
}
