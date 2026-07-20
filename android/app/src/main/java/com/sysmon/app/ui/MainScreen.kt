package com.sysmon.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.sysmon.app.Session
import com.sysmon.app.StatusStore

enum class Tab(val label: String, val icon: ImageVector) {
    Alerts("ALERTS", Icons.Outlined.Notifications),
    Hosts("HOSTS", Icons.Outlined.Storage),
    Settings("SETTINGS", Icons.Outlined.Settings)
}

@Composable
fun MainScreen(onLogout: () -> Unit) {
    var selectedTab by remember { mutableStateOf(Tab.Alerts) }

    // A tapped push notification bumps this counter; jump to Alerts.
    LaunchedEffect(Session.pushNavigateToAlerts) {
        if (Session.pushNavigateToAlerts > 0) {
            selectedTab = Tab.Alerts
        }
    }

    // One poller feeds every tab (and the badge). Run it while the app is
    // foreground; pause it when backgrounded to save battery/data.
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { StatusStore.start() }
    LifecycleEventEffect(Lifecycle.Event.ON_STOP) { StatusStore.stop() }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        bottomBar = {
            NavigationBar(
                containerColor = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface
            ) {
                Tab.values().forEach { tab ->
                    NavigationBarItem(
                        selected = selectedTab == tab,
                        onClick = { selectedTab = tab },
                        icon = {
                            if (tab == Tab.Alerts) {
                                AlertBadgedIcon(
                                    icon = tab.icon,
                                    count = Session.alertCount,
                                    contentDescription = tab.label
                                )
                            } else {
                                Icon(tab.icon, contentDescription = tab.label)
                            }
                        },
                        label = {
                            Text(
                                text = tab.label,
                                style = MaterialTheme.typography.labelMedium
                            )
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = MaterialTheme.colorScheme.primary,
                            selectedTextColor = MaterialTheme.colorScheme.primary,
                            unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            indicatorColor = MaterialTheme.colorScheme.background
                        )
                    )
                }
            }
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .background(MaterialTheme.colorScheme.background)
        ) {
            Column(modifier = Modifier.fillMaxSize()) {
                when (selectedTab) {
                    Tab.Alerts -> AlertsScreen()
                    Tab.Hosts -> HostsScreen()
                    Tab.Settings -> SettingsScreen(onLogout)
                }
            }
        }
    }
}
