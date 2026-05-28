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

    suspend fun hosts(): List<Host> = withContext(Dispatchers.IO) {
        val response = authedRequest("/api/monitoring/hosts", "GET", null)
        json.decodeFromString(ListSerializer(Host.serializer()), response)
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

    suspend fun sendTestPush(fcmToken: String) = withContext(Dispatchers.IO) {
        val body = json.encodeToString(mapOf("device_token" to fcmToken))
        authedRequest("/api/push/test", "POST", body)
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
            if (status == 401) {
                Session.handleUnauthorized()
                throw HttpError(401, "Session expired. Please log in again.")
            }
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader()?.use { it.readText() } ?: ""
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
