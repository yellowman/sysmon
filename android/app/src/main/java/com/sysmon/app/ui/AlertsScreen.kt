package com.sysmon.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.sysmon.app.Api
import com.sysmon.app.Host
import com.sysmon.app.StatusResponse
import com.sysmon.app.ui.theme.SysmonColors

@Composable
fun AlertsScreen() {
    var loading by remember { mutableStateOf(true) }
    var status by remember { mutableStateOf<StatusResponse?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        runCatching { Api.fetchStatus() }
            .onSuccess { status = it; error = null }
            .onFailure { error = it.message }
        loading = false
    }

    Column(modifier = Modifier.fillMaxSize()) {
        TopHeader(title = "Alerts", subtitle = "Hosts requiring attention")

        val downHosts = status?.hosts.orEmpty().filter {
            it.state.equals("down", ignoreCase = true) ||
                it.state.equals("unknown", ignoreCase = true)
        }

        StatsRow(status?.stats)

        SectionHeader(
            label = "Active",
            accent = if (downHosts.isEmpty()) null else "${downHosts.size} ALERT${if (downHosts.size == 1) "" else "S"}"
        )

        when {
            loading -> CenteredSpinner()
            error != null -> ErrorBanner(error!!)
            downHosts.isEmpty() -> EmptyState("All systems operational")
            else -> LazyColumn {
                items(downHosts, key = { it.hostname }) { host ->
                    HostRow(host)
                }
            }
        }
    }
}

@Composable
fun TopHeader(title: String, subtitle: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(
            text = "SYSMON",
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = title,
            style = MaterialTheme.typography.displayMedium,
            color = MaterialTheme.colorScheme.onBackground
        )
        Text(
            text = subtitle,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
fun StatsRow(stats: com.sysmon.app.Stats?) {
    val s = stats ?: return
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Box(modifier = Modifier.weight(1f)) { StatTile("UP", s.upHosts.toString(), SysmonColors.Up) }
        Box(modifier = Modifier.weight(1f)) { StatTile("DOWN", s.downHosts.toString(), SysmonColors.Down) }
        Box(modifier = Modifier.weight(1f)) { StatTile("TOTAL", s.totalHosts.toString()) }
    }
}

@Composable
fun CenteredSpinner() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(32.dp),
        contentAlignment = Alignment.Center
    ) {
        CircularProgressIndicator(
            strokeWidth = 2.dp,
            color = MaterialTheme.colorScheme.primary
        )
    }
}

@Suppress("unused")
private fun ignore(host: Host) {}
