package com.sysmon.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.sysmon.app.Api
import com.sysmon.app.Host

@Composable
fun HostsScreen() {
    var loading by remember { mutableStateOf(true) }
    var hosts by remember { mutableStateOf<List<Host>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        runCatching { Api.fetchHosts() }
            .onSuccess { hosts = it; error = null }
            .onFailure { error = it.message }
        loading = false
    }

    Column(modifier = Modifier.fillMaxSize()) {
        TopHeader(
            title = "Hosts",
            subtitle = "${hosts.size} monitored"
        )
        SectionHeader(label = "All hosts")
        when {
            loading -> CenteredSpinner()
            error != null -> ErrorBanner(error!!)
            hosts.isEmpty() -> EmptyState("No hosts configured")
            else -> LazyColumn {
                items(hosts.sortedBy { it.hostname }, key = { it.hostname }) { host ->
                    HostRow(host)
                }
            }
        }
    }
}
