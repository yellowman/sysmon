package com.sysmon.app

import android.content.Context
import android.content.SharedPreferences
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.firebase.messaging.FirebaseMessaging
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await

object Session {
    private const val KEY_SERVER = "server_url"
    private const val KEY_TOKEN = "session_token"
    private const val KEY_USERNAME = "username"
    private const val KEY_ROLE = "role"

    private lateinit var prefs: SharedPreferences
    private lateinit var appContext: Context
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    var serverUrl by mutableStateOf("")
        private set
    var token by mutableStateOf("")
        private set
    var username by mutableStateOf("")
        private set
    var role by mutableStateOf("")
        private set

    // Surfaced in the UI but not persisted.
    var pushStatus by mutableStateOf<String?>(null)
    var loginNote by mutableStateOf<String?>(null)
    var alertCount by mutableStateOf(0)

    // Bumped whenever a push notification is tapped; MainScreen observes
    // this to jump to the Alerts tab. A monotonic counter (rather than a
    // Boolean) so repeated taps re-trigger navigation each time.
    var pushNavigateToAlerts by mutableStateOf(0)
        private set

    fun requestNavigateToAlerts() {
        pushNavigateToAlerts++
    }

    fun init(context: Context) {
        appContext = context.applicationContext
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

    // The persisted role is whatever the login response said, possibly
    // versions ago - a session predating role storage has none at all,
    // and every admin control would stay hidden while the server still
    // says admin. Ask the server and correct the stored copy.
    suspend fun refreshIdentity() {
        if (!isLoggedIn()) return
        runCatching { Api.me() }.onSuccess { me ->
            if (me.username.isNotEmpty()) {
                username = me.username
                role = me.role
                prefs.edit()
                    .putString(KEY_USERNAME, me.username)
                    .putString(KEY_ROLE, me.role)
                    .apply()
            }
        }
    }

    // Normalize a user-entered server URL: trim, default to https://, drop trailing slash.
    fun normalize(raw: String): String {
        var s = raw.trim()
        val lower = s.lowercase()
        if (!lower.startsWith("http://") && !lower.startsWith("https://")) {
            s = "https://$s"
        }
        while (s.endsWith("/")) s = s.dropLast(1)
        return s
    }

    suspend fun login(server: String, user: String, pass: String) {
        val normalized = normalize(server)
        require(normalized.length > "https://".length) { "Server URL is required" }
        loginNote = null
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
        // Now there is a sysmon to talk to, the daily token health
        // check has something to check.
        PushHealthWorker.schedule(appContext)
    }

    fun logout() {
        val serverSnap = serverUrl
        val tokenSnap = token
        val fcmSnap = FcmTokenStore.token

        // Flip UI to LoginScreen immediately
        token = ""
        username = ""
        role = ""
        alertCount = 0
        StatusStore.reset()
        prefs.edit()
            .remove(KEY_TOKEN)
            .remove(KEY_USERNAME)
            .remove(KEY_ROLE)
            .apply()

        // No login, nothing for the daily token check to check.
        PushHealthWorker.cancel(appContext)

        // Best-effort backend cleanup with snapshotted credentials
        scope.launch {
            if (tokenSnap.isEmpty() || serverSnap.isEmpty()) return@launch
            runCatching {
                if (fcmSnap != null) {
                    Api.unsubscribePush(serverSnap, tokenSnap, fcmSnap)
                }
                Api.logout(serverSnap, tokenSnap)
            }
        }
    }

    fun handleUnauthorized() {
        token = ""
        username = ""
        role = ""
        alertCount = 0
        StatusStore.reset()
        loginNote = "Session expired - please sign in again"
        prefs.edit()
            .remove(KEY_TOKEN)
            .remove(KEY_USERNAME)
            .remove(KEY_ROLE)
            .apply()
    }

    /**
     * Register a (possibly rotated) FCM token with the backend. If [replacing]
     * is non-null and differs from [fcmToken], the previous subscription is
     * unsubscribed first so the backend doesn't end up with orphaned entries
     * after Firebase rotates the token.
     *
     * If the server answers that FCM has declared this token UNREGISTERED
     * (uninstall/reinstall races, backup-restore to a new device, the
     * 270-day inactivity purge, a Google-side invalidation), the Firebase
     * SDK on this phone is the one party that doesn't know: getToken()
     * keeps returning the dead token from cache and onNewToken never
     * fires. The only escape is deleteToken() + getToken(), which mints a
     * genuinely new token - so do that, once, and re-register. The
     * renewal flag on [syncPushToken] marks the second pass, so a token
     * that is somehow *still* refused (project mismatch, Firebase
     * trouble) surfaces as an error instead of looping.
     */
    fun registerPushToken(fcmToken: String, replacing: String? = null) {
        FcmTokenStore.update(fcmToken)
        if (!isLoggedIn()) return
        scope.launch { syncPushToken(fcmToken, replacing) }
    }

    /**
     * The suspend core of registration, also the body of the daily
     * background health check (PushHealthWorker): re-subscribing IS the
     * check, because the server's reply carries the dead-token verdict.
     * Returns true when the subscription is in good standing on return
     * (including after a successful renewal).
     */
    suspend fun syncPushToken(
        fcmToken: String,
        replacing: String? = null,
        renewal: Boolean = false
    ): Boolean {
        FcmTokenStore.update(fcmToken)
        if (!isLoggedIn()) return false
        val serverSnap = serverUrl
        val tokenSnap = token
        // Best-effort: the replaced subscription may already be gone
        // (admin kicked it, or a competing registration cleaned it
        // up) - that must not fail the new registration.
        if (replacing != null && replacing != fcmToken &&
            serverSnap.isNotEmpty() && tokenSnap.isNotEmpty()
        ) {
            runCatching { Api.unsubscribePush(serverSnap, tokenSnap, replacing) }
        }
        val response = try {
            Api.subscribePush(fcmToken)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            pushStatus = "Push registration failed: ${e.message ?: "unknown error"}"
            return false
        }
        return if (response.tokenStatus == "invalid") {
            if (renewal) {
                pushStatus = "Push token renewal failed - the server still reports the new token invalid"
                false
            } else {
                pushStatus = "Push token expired - requesting a new one…"
                renewFcmToken(dead = fcmToken)
            }
        } else {
            pushStatus = "Push registered"
            true
        }
    }

    // Force the Firebase SDK to abandon its cached token and mint a fresh
    // one, then register it (replacing the dead subscription). onNewToken
    // may also fire for the fresh token; both paths converge on the same
    // registration, which is idempotent per token.
    private suspend fun renewFcmToken(dead: String): Boolean {
        val fresh = try {
            val messaging = FirebaseMessaging.getInstance()
            messaging.deleteToken().await()
            messaging.token.await()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            pushStatus = "Push token renewal failed: ${e.message ?: "unknown error"}"
            return false
        }
        return syncPushToken(fresh, replacing = dead, renewal = true)
    }
}
