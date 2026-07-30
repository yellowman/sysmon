package com.sysmon.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.sysmon.app.Host
import com.sysmon.app.NotificationHealth
import com.sysmon.app.StatusStore
import kotlinx.coroutines.launch

@Composable
fun AlertsScreen() {
    var refreshing by remember { mutableStateOf(false) }
    var selectedHost by remember { mutableStateOf<Host?>(null) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    // Re-check on every resume: the user may have just come back from the
    // system settings this banner sends them to.
    var notifProblem by remember { mutableStateOf<String?>(null) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        notifProblem = NotificationHealth.problem(context)
    }

    val alerts = StatusStore.alerts

    Column(modifier = Modifier.fillMaxSize()) {
        TopHeader(
            title = "Alerts",
            subtitle = "Hosts requiring attention",
            refreshing = refreshing,
            live = StatusStore.error == null,
            onRefresh = {
                scope.launch {
                    refreshing = true
                    StatusStore.refreshNow()
                    refreshing = false
                }
            }
        )

        notifProblem?.let {
            WarningBanner(it, actionLabel = "Open notification settings") {
                NotificationHealth.openSettings(context)
            }
        }

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
            alerts.isEmpty() -> AllClearCard(
                total = StatusStore.stats?.total ?: StatusStore.hosts.size
            )
            else -> LazyColumn(
                verticalArrangement = Arrangement.spacedBy(0.dp)
            ) {
                items(alerts, key = { it.objectName.ifEmpty { it.hostname } }) { host ->
                    Box(modifier = Modifier.animateItem()) {
                        HostRow(host, onClick = { selectedHost = host })
                    }
                }
            }
        }
    }

    selectedHost?.let { host ->
        HostDetailSheet(host = host, onDismiss = { selectedHost = null })
    }
}
