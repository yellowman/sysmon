package com.sysmon.app.ui

import androidx.compose.foundation.layout.Column
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.sysmon.app.Host
import com.sysmon.app.StatusStore
import kotlinx.coroutines.launch

@Composable
fun HostsScreen() {
    var refreshing by remember { mutableStateOf(false) }
    var search by remember { mutableStateOf("") }
    var selectedHost by remember { mutableStateOf<Host?>(null) }
    val scope = rememberCoroutineScope()

    val hosts = StatusStore.hosts
    val filtered = if (search.isEmpty()) hosts
        else hosts.filter {
            it.hostname.contains(search, ignoreCase = true) ||
                it.description.contains(search, ignoreCase = true) ||
                it.ip.contains(search, ignoreCase = true)
        }

    Column(modifier = Modifier.fillMaxSize()) {
        TopHeader(
            title = "Hosts",
            subtitle = "${hosts.size} monitored",
            refreshing = refreshing,
            onRefresh = {
                scope.launch {
                    refreshing = true
                    StatusStore.refreshNow()
                    refreshing = false
                }
            }
        )

        if (hosts.isNotEmpty()) {
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

        SectionHeader(
            label = "All hosts",
            accent = if (search.isEmpty()) null else "${filtered.size} OF ${hosts.size}"
        )

        when {
            StatusStore.loading && hosts.isEmpty() -> CenteredSpinner()
            StatusStore.error != null && hosts.isEmpty() -> ErrorBanner(StatusStore.error!!)
            filtered.isEmpty() -> EmptyState(
                if (search.isEmpty()) "No hosts configured" else "No matches"
            )
            else -> LazyColumn {
                items(
                    filtered,
                    key = { it.objectName.ifEmpty { it.hostname } }
                ) { host ->
                    HostRow(host, onClick = { selectedHost = host })
                }
            }
        }
    }

    selectedHost?.let { host ->
        HostDetailSheet(host = host, onDismiss = { selectedHost = null })
    }
}
