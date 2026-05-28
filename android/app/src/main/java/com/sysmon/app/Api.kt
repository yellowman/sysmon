package com.sysmon.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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

    suspend fun login(server: String, user: String, pass: String): LoginResponse =
        withContext(Dispatchers.IO) {
            val body = json.encodeToString(LoginRequest(user, pass))
            val response = rawRequest(
                url = "$server/api/auth/login",
                method = "POST",
                body = body,
                token = null
            )
            json.decodeFromString(LoginResponse.serializer(), response)
        }

    suspend fun logout() = withContext(Dispatchers.IO) {
        authedRequest("/api/auth/logout", "POST", null)
    }

    suspend fun fetchStatus(): StatusResponse = withContext(Dispatchers.IO) {
        val response = authedRequest("/api/status", "GET", null)
        json.decodeFromString(StatusResponse.serializer(), response)
    }

    suspend fun fetchHosts(): List<Host> = withContext(Dispatchers.IO) {
        val response = authedRequest("/api/hosts", "GET", null)
        runCatching { json.decodeFromString<List<Host>>(response) }
            .getOrElse { fetchStatus().hosts }
    }

    suspend fun subscribePush(fcmToken: String): SubscribeResponse =
        withContext(Dispatchers.IO) {
            val body = json.encodeToString(
                SubscribeRequest(
                    platform = "fcm",
                    deviceToken = fcmToken,
                    description = "Android (${android.os.Build.MODEL})"
                )
            )
            val response = authedRequest("/api/push/subscribe", "POST", body)
            json.decodeFromString(SubscribeResponse.serializer(), response)
        }

    suspend fun unsubscribePush(fcmToken: String) = withContext(Dispatchers.IO) {
        val body = json.encodeToString(
            mapOf("device_token" to fcmToken)
        )
        authedRequest("/api/push/unsubscribe", "POST", body)
    }

    suspend fun sendTestPush(fcmToken: String) = withContext(Dispatchers.IO) {
        val body = json.encodeToString(mapOf("device_token" to fcmToken))
        authedRequest("/api/push/test", "POST", body)
    }

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
            if (body != null) {
                conn.setRequestProperty("Content-Type", "application/json")
                conn.doOutput = true
            }
            if (token != null) {
                conn.setRequestProperty("Authorization", "Bearer $token")
            }
            if (body != null) {
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
                        it.error.ifEmpty { it.message }
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
