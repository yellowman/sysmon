package com.sysmon.app.ui

import androidx.compose.runtime.Composable
import com.sysmon.app.Session

@Composable
fun RootScreen(onLoggedIn: () -> Unit) {
    // Session.token is mutableStateOf — Compose recomposes on change,
    // so this is the only source of truth for "are we logged in".
    if (Session.token.isNotEmpty()) {
        MainScreen(onLogout = { Session.logout() })
    } else {
        LoginScreen(onSuccess = onLoggedIn)
    }
}
