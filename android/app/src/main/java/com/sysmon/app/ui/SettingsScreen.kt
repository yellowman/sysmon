package com.sysmon.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.google.firebase.messaging.FirebaseMessaging
import com.sysmon.app.Api
import com.sysmon.app.Session
import com.sysmon.app.ui.theme.MonoMedium
import com.sysmon.app.ui.theme.SysmonColors
import kotlinx.coroutines.launch

@Composable
fun SettingsScreen(onLogout: () -> Unit) {
    val scope = rememberCoroutineScope()
    var message by remember { mutableStateOf<String?>(null) }
    var sending by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxWidth()) {
        TopHeader(title = "Settings", subtitle = "Account and notifications")

        SectionHeader(label = "Account")
        InfoRow("Server", Session.serverUrl)
        InfoRow("User", Session.username)
        InfoRow("Role", Session.role.ifEmpty { "—" })

        SectionHeader(label = "Notifications")
        ButtonRow(
            label = if (sending) "Sending..." else "Send Test Notification",
            enabled = !sending,
            primary = false
        ) {
            sending = true
            scope.launch {
                FirebaseMessaging.getInstance().token.addOnCompleteListener { task ->
                    val token = task.result
                    if (token == null) {
                        message = "No FCM token available"
                        sending = false
                        return@addOnCompleteListener
                    }
                    scope.launch {
                        runCatching { Api.sendTestPush(token) }
                            .onSuccess { message = "Sent!" }
                            .onFailure { message = it.message }
                        sending = false
                    }
                }
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
