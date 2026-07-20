package com.sysmon.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.sysmon.app.Api
import com.sysmon.app.Session
import com.sysmon.app.StatusResponse
import kotlinx.coroutines.launch

@Composable
fun AlertsScreen() {
    var loading by remember { mutableStateOf(true) }
    var refreshing by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<StatusResponse?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    suspend fun refresh() {
        runCatching { Api.status() }
            .onSuccess {
                status = it
                error = null
                Session.alertCount = it.hosts.count { h -> !h.isOK }
            }
            .onFailure { error = it.message }
        loading = false
        refreshing = false
    }

    LaunchedEffect(Unit) { refresh() }

    // Re-fetch when the app returns to the foreground so the badge and
    // alert list stay in sync without requiring a manual refresh.
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        scope.launch {
            refreshing = true
            refresh()
        }
    }

    val alerts = status?.hosts.orEmpty().filter { !it.isOK }

    Column(modifier = Modifier.fillMaxSize()) {
        TopHeader(
            title = "Alerts",
            subtitle = "Hosts requiring attention",
            refreshing = refreshing,
            onRefresh = {
                scope.launch {
                    refreshing = true
                    refresh()
                }
            }
        )

        if (status?.daemon?.paused == true) {
            PausedBanner()
        }

        StatsRow(status?.statistics)

        SectionHeader(
            label = "Active",
            accent = if (alerts.isEmpty()) null
                else "${alerts.size} ALERT${if (alerts.size == 1) "" else "S"}"
        )

        when {
            loading && status == null -> CenteredSpinner()
            error != null -> ErrorBanner(error!!)
            alerts.isEmpty() -> EmptyState("All systems operational")
            else -> LazyColumn(
                verticalArrangement = Arrangement.spacedBy(0.dp)
            ) {
                items(alerts, key = { it.objectName.ifEmpty { it.hostname } }) { host ->
                    HostRow(host)
                }
            }
        }
    }
}
