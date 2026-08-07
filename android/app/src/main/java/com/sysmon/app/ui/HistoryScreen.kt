package com.sysmon.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
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
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.sysmon.app.Api
import com.sysmon.app.HistoryEvent
import com.sysmon.app.formatUptime
import com.sysmon.app.relativeTime
import kotlinx.coroutines.launch

private enum class HistoryFilter(val label: String) {
    ALL("ALL"),
    DOWNS("DOWNS"),
    RECOVERIES("RECOVERIES")
}

@Composable
fun HistoryScreen() {
    var events by remember { mutableStateOf<List<HistoryEvent>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    var refreshing by remember { mutableStateOf(false) }
    var filter by rememberSaveable { mutableStateOf(HistoryFilter.ALL) }
    var windowDays by rememberSaveable { mutableStateOf(false) }  // false = 48h, true = 30d
    val scope = rememberCoroutineScope()

    // Ages advance on their own clock: rows only recompose when state
    // changes, and without this a quiet screen froze every "1d ago" at
    // whatever it said when the data last arrived.
    var clock by remember { mutableStateOf(0L) }
    LaunchedEffect(Unit) {
        while (true) {
            kotlinx.coroutines.delay(30_000)
            clock = System.currentTimeMillis()
        }
    }

    suspend fun fetch() {
        runCatching { Api.history(window = if (windowDays) "30d" else "48h") }
            .onSuccess { events = it; error = null }
            .onFailure { error = it.message }
        loading = false
        refreshing = false
    }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        scope.launch { fetch() }
    }
    LaunchedEffect(windowDays) { fetch() }

    val filtered = when (filter) {
        HistoryFilter.ALL -> events
        HistoryFilter.DOWNS -> events.filter { it.newStatus != "OK" }
        HistoryFilter.RECOVERIES -> events.filter { it.newStatus == "OK" }
    }

    LazyColumn(modifier = Modifier.fillMaxSize()) {
        item {
            TopHeader(
                title = "History",
                subtitle = if (windowDays) "Transitions, last 30 days" else "Transitions, last 48 hours",
                refreshing = refreshing,
                onRefresh = {
                    scope.launch {
                        refreshing = true
                        fetch()
                    }
                }
            )
        }

        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp)
                    .padding(bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "SHOW",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                HistoryFilter.values().forEach { key ->
                    val active = key == filter
                    Row(
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
                            .clickable { filter = key }
                            .padding(horizontal = 10.dp, vertical = 5.dp)
                    ) {
                        Text(
                            text = key.label,
                            style = MaterialTheme.typography.labelMedium,
                            color = if (active) MaterialTheme.colorScheme.onBackground
                                else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Spacer(modifier = Modifier.weight(1f))
                listOf(false to "48H", true to "30D").forEach { (days, label) ->
                    val active = windowDays == days
                    Row(
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
                            .clickable { windowDays = days }
                            .padding(horizontal = 10.dp, vertical = 5.dp)
                    ) {
                        Text(
                            text = label,
                            style = MaterialTheme.typography.labelMedium,
                            color = if (active) MaterialTheme.colorScheme.onBackground
                                else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        when {
            loading && events.isEmpty() -> item { CenteredSpinner() }
            error != null && events.isEmpty() -> item { ErrorBanner(error!!) }
            filtered.isEmpty() -> item {
                EmptyState(
                    if (events.isEmpty()) "No transitions in the last " + (if (windowDays) "30 days" else "48 hours")
                    else "No events match the filter"
                )
            }
            else -> itemsIndexed(filtered) { _, ev ->
                HistoryRow(ev, clock)
            }
        }
    }
}

@Composable
private fun HistoryRow(ev: HistoryEvent, clock: Long) {
    Card {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            StatusDot(ev.newStatus)
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = ev.objectName.ifEmpty { ev.hostname },
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onBackground,
                        modifier = Modifier.weight(1f)
                    )
                    Text(
                        // clock in the expression makes the age
                        // recompose on the ticker, not only on new data.
                        text = clock.let { relativeTime(ev.timestamp) },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text(
                        text = ev.prevStatus,
                        style = MaterialTheme.typography.labelMedium,
                        color = statusColor(ev.prevStatus)
                    )
                    Text(
                        text = "→",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = ev.newStatus,
                        style = MaterialTheme.typography.labelMedium,
                        color = statusColor(ev.newStatus)
                    )
                    Spacer(modifier = Modifier.weight(1f))
                    if (ev.prevDuration > 0) {
                        Text(
                            text = "was ${ev.prevStatus.lowercase()} ${formatUptime(ev.prevDuration)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}
