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
    val scope = rememberCoroutineScope()

    suspend fun fetch() {
        runCatching { Api.history() }
            .onSuccess { events = it; error = null }
            .onFailure { error = it.message }
        loading = false
        refreshing = false
    }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        scope.launch { fetch() }
    }

    val filtered = when (filter) {
        HistoryFilter.ALL -> events
        HistoryFilter.DOWNS -> events.filter { it.newStatus != "OK" }
        HistoryFilter.RECOVERIES -> events.filter { it.newStatus == "OK" }
    }

    LazyColumn(modifier = Modifier.fillMaxSize()) {
        item {
            TopHeader(
                title = "History",
                subtitle = "Recent up/down transitions",
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
            }
        }

        when {
            loading && events.isEmpty() -> item { CenteredSpinner() }
            error != null && events.isEmpty() -> item { ErrorBanner(error!!) }
            filtered.isEmpty() -> item {
                EmptyState(
                    if (events.isEmpty()) "No transitions recorded yet"
                    else "No events match the filter"
                )
            }
            else -> itemsIndexed(filtered) { _, ev ->
                HistoryRow(ev)
            }
        }
    }
}

@Composable
private fun HistoryRow(ev: HistoryEvent) {
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
                        text = relativeTime(ev.timestamp),
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
