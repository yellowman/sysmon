package com.sysmon.app

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class LoginRequest(val username: String, val password: String)

@Serializable
data class LoginResponse(
    val token: String,
    val username: String,
    val role: String,
    @SerialName("expires_at") val expiresAt: Long? = null
)

@Serializable
data class Host(
    val hostname: String,
    val ip: String = "",
    val state: String = "unknown",
    val acknowledged: Boolean = false,
    @SerialName("last_check") val lastCheck: Long = 0,
    @SerialName("last_change") val lastChange: Long = 0,
    @SerialName("response_time") val responseTime: Double = 0.0,
    val description: String = "",
    val contact: String = ""
)

@Serializable
data class DaemonInfo(
    val version: String = "",
    val uptime: Long = 0,
    val pid: Int = 0
)

@Serializable
data class Stats(
    @SerialName("total_hosts") val totalHosts: Int = 0,
    @SerialName("up_hosts") val upHosts: Int = 0,
    @SerialName("down_hosts") val downHosts: Int = 0,
    @SerialName("unknown_hosts") val unknownHosts: Int = 0,
    @SerialName("acknowledged") val acknowledged: Int = 0
)

@Serializable
data class StatusResponse(
    val daemon: DaemonInfo = DaemonInfo(),
    val stats: Stats = Stats(),
    val hosts: List<Host> = emptyList()
)

@Serializable
data class SubscribeRequest(
    val platform: String,
    @SerialName("device_token") val deviceToken: String,
    val description: String = "Android device"
)

@Serializable
data class SubscribeResponse(
    val ok: Boolean = false,
    @SerialName("api_key") val apiKey: String = ""
)

@Serializable
data class ApiError(val error: String = "", val message: String = "")
