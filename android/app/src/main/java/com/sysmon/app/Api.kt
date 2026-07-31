package com.sysmon.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

object Api {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        // Go marshals nil slices/maps as JSON null; without coercion a
        // "changed": null in an idle delta throws and every quiet poll
        // failed. Coerce null to the field's default instead.
        coerceInputValues = true
    }

    class HttpError(val status: Int, message: String) : IOException(message)

    // --- Unauthenticated ---
    suspend fun login(server: String, user: String, pass: String): LoginResponse =
        withContext(Dispatchers.IO) {
            val body = json.encodeToString(LoginRequest(user, pass))
            val response = rawRequest("$server/api/auth/login", "POST", body, null)
            json.decodeFromString(LoginResponse.serializer(), response)
        }

    // --- Implicit auth (reads from Session) ---
    suspend fun status(): StatusResponse = withContext(Dispatchers.IO) {
        val response = authedRequest("/api/monitoring/status", "GET", null)
        json.decodeFromString(StatusResponse.serializer(), response)
    }

    suspend fun statusDelta(since: Long): StatusDelta = withContext(Dispatchers.IO) {
        val response = authedRequest("/api/monitoring/status?since=$since", "GET", null)
        json.decodeFromString(StatusDelta.serializer(), response)
    }

    suspend fun hosts(): List<Host> = withContext(Dispatchers.IO) {
        val response = authedRequest("/api/monitoring/hosts", "GET", null)
        json.decodeFromString(ListSerializer(Host.serializer()), response)
    }

    // Acknowledge an active alert. Admin-only on the server.
    suspend fun ackHost(objectName: String) = withContext(Dispatchers.IO) {
        val escaped = java.net.URLEncoder.encode(objectName, "UTF-8").replace("+", "%20")
        authedRequest("/api/monitoring/ack/$escaped", "POST", null)
    }

    suspend fun subscribePush(fcmToken: String) = withContext(Dispatchers.IO) {
        val body = json.encodeToString(
            SubscribeRequest(
                platform = "android",
                deviceToken = fcmToken,
                label = "Android (${android.os.Build.MODEL})"
            )
        )
        authedRequest("/api/push/subscribe", "POST", body)
    }

    // Returns the server's warning, if any (e.g. "push is disabled - this
    // test was delivered but real alerts are not being sent").
    suspend fun sendTestPush(fcmToken: String): String? = withContext(Dispatchers.IO) {
        val body = json.encodeToString(mapOf("device_token" to fcmToken))
        val response = authedRequest("/api/push/test", "POST", body)
        runCatching {
            json.decodeFromString(TestPushResponse.serializer(), response).warning
        }.getOrNull()
    }

    // --- Explicit auth (for logout cleanup after Session is cleared) ---
    suspend fun logout(server: String, sessionToken: String) = withContext(Dispatchers.IO) {
        rawRequest("$server/api/auth/logout", "POST", null, sessionToken)
    }

    suspend fun unsubscribePush(server: String, sessionToken: String, fcmToken: String) =
        withContext(Dispatchers.IO) {
            val body = json.encodeToString(mapOf("device_token" to fcmToken))
            rawRequest("$server/api/push/subscribe", "DELETE", body, sessionToken)
        }

    // --- Internals ---
    private fun authedRequest(path: String, method: String, body: String?): String {
        val server = Session.serverUrl
        val token = Session.token
        if (server.isEmpty() || token.isEmpty()) {
            throw HttpError(401, "Not logged in")
        }
        return rawRequest("$server$path", method, body, token)
    }

    private fun rawRequest(
        url: String,
        method: String,
        body: String?,
        token: String?
    ): String {
        return try {
            doRequest(url, method, body, token)
        } catch (e: IOException) {
            // HttpURLConnection reuses pooled keep-alive sockets the server
            // may have already closed, surfacing as "unexpected end of
            // stream" / resets on an otherwise healthy connection -
            // endemic with fast polling. One immediate retry gets a fresh
            // socket. Only for GETs (idempotent) and only for transport
            // errors, never HTTP-level errors the server actually sent.
            if (e is HttpError || method != "GET") throw e
            doRequest(url, method, body, token)
        }
    }

    private fun doRequest(
        url: String,
        method: String,
        body: String?,
        token: String?
    ): String {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = method
            conn.connectTimeout = 15000
            conn.readTimeout = 30000
            conn.setRequestProperty("Accept", "application/json")
            if (token != null) {
                conn.setRequestProperty("Authorization", "Bearer $token")
            }
            if (body != null) {
                conn.setRequestProperty("Content-Type", "application/json")
                conn.doOutput = true
                conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val status = conn.responseCode
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader()?.use { it.readText() } ?: ""
            // A 401 from /api/auth/login is just "bad credentials" -
            // don't clear the session and let the server's message
            // ("Invalid credentials") propagate. For every other path
            // a 401 means the bearer is dead, so clear state and bounce
            // back to the login screen.
            if (status == 401 && !url.endsWith("/api/auth/login")) {
                Session.handleUnauthorized()
            }
            if (status !in 200..299) {
                val message = runCatching {
                    json.decodeFromString(ApiError.serializer(), text).let {
                        it.message.ifEmpty { it.error }
                    }
                }.getOrNull() ?: "HTTP $status"
                throw HttpError(status, message.ifEmpty { "HTTP $status" })
            }
            return text
        } finally {
            conn.disconnect()
        }
    }
}
