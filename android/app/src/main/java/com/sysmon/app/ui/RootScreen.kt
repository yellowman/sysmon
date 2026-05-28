package com.sysmon.app.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.runtime.LaunchedEffect
import com.sysmon.app.Session

@Composable
fun RootScreen(onLoggedIn: () -> Unit) {
    var loggedIn by remember { mutableStateOf(Session.isLoggedIn()) }

    LaunchedEffect(Unit) {
        snapshotFlow { Session.token }.collect { token ->
            loggedIn = token.isNotEmpty()
        }
    }

    if (loggedIn) {
        MainScreen(onLogout = { Session.logout(); loggedIn = false })
    } else {
        LoginScreen(onSuccess = {
            loggedIn = true
            onLoggedIn()
        })
    }
}
