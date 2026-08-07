package com.sysmon.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.sysmon.app.Host
import com.sysmon.app.NotificationHealth
import com.sysmon.app.StatusStore
import kotlinx.coroutines.launch

private enum class AlertSort(val label: String) {
    TIME_DOWN("DOWN TIME"),
    NAME("NAME"),
    IP("IP")
}

// Numeric-aware sort key for IPv4 ("9.x" must precede "10.x"); other
// address forms fall back to plain string order.
private fun ipSortable(ip: String): String {
    val parts = ip.split(".")
    return if (parts.size == 4 && parts.all { it.toIntOrNull() != null })
        parts.joinToString(".") { it.padStart(3, '0') }
    else ip
}

@Composable
fun AlertsScreen() {
    var refreshing by remember { mutableStateOf(false) }
    var selectedHost by remember { mutableStateOf<Host?>(null) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    // For TIME_DOWN, ascending = smallest time_failed first = newest
    // outage on top (the default view). Tapping the active chip flips it.
    var sortKey by rememberSaveable { mutableStateOf(AlertSort.TIME_DOWN) }
    var ascending by rememberSaveable { mutableStateOf(true) }

    // Re-check on every resume: the user may have just come back from the
    // system settings this banner sends them to.
    var notifProblem by remember { mutableStateOf<String?>(null) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        notifProblem = NotificationHealth.problem(context)
    }

    // The active board is the unacked; acked alerts are triaged into
    // their own section below - still down, still listed, out of the way.
    val alerts = StatusStore.unackedAlerts
    val acked = StatusStore.ackedAlerts
    val sortedAlerts = run {
        val base = when (sortKey) {
            AlertSort.TIME_DOWN -> alerts.sortedBy { it.timeFailed }
            AlertSort.NAME -> alerts.sortedBy { it.hostname.lowercase() }
            AlertSort.IP -> alerts.sortedBy { ipSortable(it.ip) }
        }
        if (ascending) base else base.reversed()
    }

    // One LazyColumn for the whole page (header included) so everything
    // scrolls as a unit and stays reachable in landscape.
    LazyColumn(modifier = Modifier.fillMaxSize()) {
        item {
            TopHeader(
                title = "Alerts",
                subtitle = "Hosts requiring attention",
                refreshing = refreshing,
                live = !StatusStore.offline,
                degraded = StatusStore.degraded,
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

        if (alerts.size > 1) {
            item {
                SortBar(
                    sortKey = sortKey,
                    ascending = ascending,
                    onSelect = { key ->
                        if (key == sortKey) ascending = !ascending
                        else { sortKey = key; ascending = true }
                    }
                )
            }
        }

        when {
            StatusStore.loading && StatusStore.hosts.isEmpty() ->
                item { CenteredSpinner() }
            StatusStore.error != null && StatusStore.hosts.isEmpty() ->
                item { ErrorBanner(StatusStore.error!!) }
            alerts.isEmpty() && acked.isEmpty() ->
                item {
                    AllClearCard(
                        total = StatusStore.stats?.total ?: StatusStore.hosts.size,
                        degraded = StatusStore.degraded
                    )
                }
            else -> items(sortedAlerts, key = { it.objectName.ifEmpty { it.hostname } }) { host ->
                Box(modifier = Modifier.animateItem()) {
                    HostRow(host, onClick = { selectedHost = host })
                }
            }
        }

        if (acked.isNotEmpty()) {
            item {
                SectionHeader(
                    label = "Acknowledged",
                    accent = "${acked.size}"
                )
            }
            items(acked, key = { "ack-" + it.objectName.ifEmpty { it.hostname } }) { host ->
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

@Composable
private fun SortBar(
    sortKey: AlertSort,
    ascending: Boolean,
    onSelect: (AlertSort) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp)
            .padding(bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(
            text = "SORT",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        AlertSort.values().forEach { key ->
            val active = key == sortKey
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .clip(RoundedCornerShape(50))
                    .background(
                        if (active) MaterialTheme.colorScheme.surfaceVariant
                        else Color.Transparent
                    )
                    .border(
                        1.dp,
                        if (active) MaterialTheme.colorScheme.outline
                        else Color.Transparent,
                        RoundedCornerShape(50)
                    )
                    .clickable { onSelect(key) }
                    .padding(horizontal = 10.dp, vertical = 5.dp)
            ) {
                Text(
                    text = key.label + if (active) (if (ascending) "  ↑" else "  ↓") else "",
                    style = MaterialTheme.typography.labelMedium,
                    color = if (active) MaterialTheme.colorScheme.onBackground
                        else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
