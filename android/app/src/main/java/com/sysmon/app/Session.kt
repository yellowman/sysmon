package com.sysmon.app

import android.content.Context
import android.content.SharedPreferences
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

object Session {
    private const val KEY_SERVER = "server_url"
    private const val KEY_TOKEN = "session_token"
    private const val KEY_USERNAME = "username"
    private const val KEY_ROLE = "role"

    private lateinit var prefs: SharedPreferences
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    var serverUrl by mutableStateOf("")
        private set
    var token by mutableStateOf("")
        private set
    var username by mutableStateOf("")
        private set
    var role by mutableStateOf("")
        private set

    fun init(context: Context) {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        prefs = EncryptedSharedPreferences.create(
            context,
            "sysmon_secure_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
        serverUrl = prefs.getString(KEY_SERVER, "") ?: ""
        token = prefs.getString(KEY_TOKEN, "") ?: ""
        username = prefs.getString(KEY_USERNAME, "") ?: ""
        role = prefs.getString(KEY_ROLE, "") ?: ""
    }

    fun isLoggedIn(): Boolean = token.isNotEmpty() && serverUrl.isNotEmpty()

    fun isAdmin(): Boolean = role == "admin"

    suspend fun login(server: String, user: String, pass: String) {
        val normalized = server.trim().trimEnd('/')
        require(normalized.startsWith("http://") || normalized.startsWith("https://")) {
            "Server URL must start with http:// or https://"
        }
        val response = Api.login(normalized, user, pass)
        serverUrl = normalized
        token = response.token
        username = response.username
        role = response.role
        prefs.edit()
            .putString(KEY_SERVER, normalized)
            .putString(KEY_TOKEN, response.token)
            .putString(KEY_USERNAME, response.username)
            .putString(KEY_ROLE, response.role)
            .apply()
    }

    fun logout() {
        scope.launch { runCatching { Api.logout() } }
        token = ""
        username = ""
        role = ""
        prefs.edit()
            .remove(KEY_TOKEN)
            .remove(KEY_USERNAME)
            .remove(KEY_ROLE)
            .apply()
    }

    fun handleUnauthorized() {
        token = ""
        prefs.edit().remove(KEY_TOKEN).apply()
    }

    fun registerPushToken(fcmToken: String) {
        if (!isLoggedIn()) return
        scope.launch {
            runCatching {
                Api.subscribePush(fcmToken)
            }
        }
    }
}
