package com.sysmon.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.sysmon.app.Host
import com.sysmon.app.StatusStore
import kotlinx.coroutines.launch

@Composable
fun AlertsScreen() {
    var refreshing by remember { mutableStateOf(false) }
    var selectedHost by remember { mutableStateOf<Host?>(null) }
    val scope = rememberCoroutineScope()

    val alerts = StatusStore.alerts

    Column(modifier = Modifier.fillMaxSize()) {
        TopHeader(
            title = "Alerts",
            subtitle = "Hosts requiring attention",
            refreshing = refreshing,
            onRefresh = {
                scope.launch {
                    refreshing = true
                    StatusStore.refreshNow()
                    refreshing = false
                }
            }
        )

        if (StatusStore.daemon?.paused == true) {
            PausedBanner()
        }

        StatsRow(StatusStore.stats)

        SectionHeader(
            label = "Active",
            accent = if (alerts.isEmpty()) null
                else "${alerts.size} ALERT${if (alerts.size == 1) "" else "S"}"
        )

        when {
            StatusStore.loading && StatusStore.hosts.isEmpty() -> CenteredSpinner()
            StatusStore.error != null && StatusStore.hosts.isEmpty() ->
                ErrorBanner(StatusStore.error!!)
            alerts.isEmpty() -> EmptyState("All systems operational")
            else -> LazyColumn(
                verticalArrangement = Arrangement.spacedBy(0.dp)
            ) {
                items(alerts, key = { it.objectName.ifEmpty { it.hostname } }) { host ->
                    HostRow(host, onClick = { selectedHost = host })
                }
            }
        }
    }

    selectedHost?.let { host ->
        HostDetailSheet(host = host, onDismiss = { selectedHost = null })
    }
}
