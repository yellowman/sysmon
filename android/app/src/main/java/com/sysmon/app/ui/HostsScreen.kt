package com.sysmon.app.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.sysmon.app.Host
import com.sysmon.app.StatusStore
import kotlinx.coroutines.launch

@Composable
fun HostsScreen() {
    var refreshing by remember { mutableStateOf(false) }
    var search by rememberSaveable { mutableStateOf("") }
    var selectedHost by remember { mutableStateOf<Host?>(null) }
    val scope = rememberCoroutineScope()

    val hosts = StatusStore.hosts
    val filtered = if (search.isEmpty()) hosts
        else hosts.filter {
            it.hostname.contains(search, ignoreCase = true) ||
                it.objectName.contains(search, ignoreCase = true) ||
                it.description.contains(search, ignoreCase = true) ||
                it.ip.contains(search, ignoreCase = true)
        }

    // One LazyColumn for the whole page (header and search included) so
    // everything scrolls as a unit and stays reachable in landscape.
    LazyColumn(modifier = Modifier.fillMaxSize()) {
        item {
            TopHeader(
                title = "Hosts",
                subtitle = "${hosts.size} monitored",
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

        if (hosts.isNotEmpty()) {
            item {
                OutlinedTextField(
                    value = search,
                    onValueChange = { search = it },
                    placeholder = { Text("Filter…") },
                    singleLine = true,
                    shape = RoundedCornerShape(4.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp)
                )
            }
        }

        item {
            SectionHeader(
                label = "All hosts",
                accent = if (search.isEmpty()) null else "${filtered.size} OF ${hosts.size}"
            )
        }

        when {
            StatusStore.loading && hosts.isEmpty() -> item { CenteredSpinner() }
            StatusStore.error != null && hosts.isEmpty() ->
                item { ErrorBanner(StatusStore.error!!) }
            filtered.isEmpty() -> item {
                EmptyState(if (search.isEmpty()) "No hosts configured" else "No matches")
            }
            else -> items(
                filtered,
                key = { it.objectName.ifEmpty { it.hostname } }
            ) { host ->
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
