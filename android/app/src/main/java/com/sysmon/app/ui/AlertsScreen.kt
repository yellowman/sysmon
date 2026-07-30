package com.sysmon.app.ui

import androidx.compose.foundation.layout.Box
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

    // One LazyColumn for the whole page (header included) so everything
    // scrolls as a unit and stays reachable in landscape.
    LazyColumn(modifier = Modifier.fillMaxSize()) {
        item {
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
        }

        notifProblem?.let { problem ->
            item {
                WarningBanner(problem, actionLabel = "Open notification settings") {
                    NotificationHealth.openSettings(context)
                }
            }
        }

        if (StatusStore.daemon?.paused == true) {
            item { PausedBanner() }
        }

        item { StatsRow(StatusStore.stats) }

        item {
            SectionHeader(
                label = "Active",
                accent = if (alerts.isEmpty()) null
                    else "${alerts.size} ALERT${if (alerts.size == 1) "" else "S"}"
            )
        }

        when {
            StatusStore.loading && StatusStore.hosts.isEmpty() ->
                item { CenteredSpinner() }
            StatusStore.error != null && StatusStore.hosts.isEmpty() ->
                item { ErrorBanner(StatusStore.error!!) }
            alerts.isEmpty() ->
                item { AllClearCard(total = StatusStore.stats?.total ?: StatusStore.hosts.size) }
            else -> items(alerts, key = { it.objectName.ifEmpty { it.hostname } }) { host ->
                Box(modifier = Modifier.animateItem()) {
                    HostRow(host, onClick = { selectedHost = host })
                }
            }
        }
    }

    selectedHost?.let { host ->
        HostDetailSheet(host = host, onDismiss = { selectedHost = null })
    }
}
