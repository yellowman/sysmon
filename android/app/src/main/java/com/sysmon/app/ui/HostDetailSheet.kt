package com.sysmon.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.sysmon.app.Api
import com.sysmon.app.Host
import com.sysmon.app.Session
import com.sysmon.app.StatusStore
import com.sysmon.app.formatUptime
import com.sysmon.app.ui.theme.MonoSmall
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HostDetailSheet(host: Host, onDismiss: () -> Unit) {
    var acking by remember { mutableStateOf(false) }
    var ackNote by remember { mutableStateOf<String?>(null) }
    // The note is required: the server refuses an anonymous ack.
    var ackText by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    val isAdmin = Session.role == "admin"

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp)
                .padding(bottom = 32.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                StatusDot(host.overallStatus, pulse = host.isDown && !host.paused)
                Text(
                    text = "  ${host.hostname}",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onBackground
                )
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = host.overallStatus,
                    style = MaterialTheme.typography.labelMedium,
                    color = statusColor(host.overallStatus)
                )
                if (host.paused) {
                    Text(
                        text = "PAUSED",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            if (host.description.isNotEmpty()) DetailRow("DESCRIPTION", host.description)
            if (host.ip.isNotEmpty()) DetailRow("ADDRESS", host.ip, mono = true)
            if (host.contact.isNotEmpty()) DetailRow("CONTACT", host.contact)
            val duration = when {
                host.isDown && host.timeFailed > 0 -> "down ${formatUptime(host.timeFailed)}"
                host.isOK && host.timeUp > 0 -> "up ${formatUptime(host.timeUp)}"
                else -> null
            }
            if (duration != null) DetailRow("DURATION", duration)
            DetailRow("FAIL / OK COUNT", "${host.downCount} / ${host.upCount}")

            if (host.acked && !host.isOK) {
                DetailRow("ACKNOWLEDGED", "off the active board until it recovers")
                if (isAdmin) {
                    OutlinedButton(
                        onClick = {
                            acking = true
                            ackNote = null
                            scope.launch {
                                runCatching { Api.unackHost(host.objectName.ifEmpty { host.hostname }) }
                                    .onSuccess {
                                        ackNote = "Un-acknowledged - back on the active board."
                                        StatusStore.refreshNow()
                                    }
                                    .onFailure { ackNote = it.message ?: "Un-acknowledge failed" }
                                acking = false
                            }
                        },
                        enabled = !acking,
                        shape = RoundedCornerShape(4.dp)
                    ) {
                        Text(if (acking) "WORKING..." else "UN-ACKNOWLEDGE")
                    }
                }
            }
            if (isAdmin && !host.isOK && !host.paused && !host.acked) {
                OutlinedTextField(
                    value = ackText,
                    onValueChange = { ackText = it },
                    label = { Text("Ack note (required) - say what you know") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2
                )
                Button(
                    onClick = {
                        acking = true
                        ackNote = null
                        scope.launch {
                            runCatching { Api.ackHost(host.objectName.ifEmpty { host.hostname }, ackText.trim()) }
                                .onSuccess {
                                    ackNote = "Acknowledged."
                                    StatusStore.refreshNow()
                                }
                                .onFailure { ackNote = it.message ?: "Acknowledge failed" }
                            acking = false
                        }
                    },
                    enabled = !acking && ackText.isNotBlank(),
                    shape = RoundedCornerShape(4.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    if (acking) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary
                        )
                    } else {
                        Text("ACKNOWLEDGE", style = MaterialTheme.typography.labelLarge)
                    }
                }
            }
            ackNote?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String, mono: Boolean = false) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = if (mono) MonoSmall else MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onBackground
        )
    }
}
