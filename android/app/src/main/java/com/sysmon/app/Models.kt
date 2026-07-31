package com.sysmon.app

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class LoginRequest(val username: String, val password: String)

@Serializable
data class LoginResponse(
    val token: String,
    val username: String,
    val role: String
)

@Serializable
data class Host(
    @SerialName("object_name") val objectName: String = "",
    val hostname: String,
    val description: String = "",
    @SerialName("ipv4_address") val ipv4: String = "",
    @SerialName("ipv6_address") val ipv6: String = "",
    @SerialName("overall_status") val overallStatus: String = "OK",
    val contact: String = "",
    val paused: Boolean = false,
    @SerialName("down_count") val downCount: Long = 0,
    @SerialName("up_count") val upCount: Long = 0,
    @SerialName("time_up") val timeUp: Long = 0,
    @SerialName("time_failed") val timeFailed: Long = 0
) {
    val ip: String get() = ipv4.ifEmpty { ipv6 }
    val isDown: Boolean get() = overallStatus == "CRITICAL"
    val isWarning: Boolean get() = overallStatus == "WARNING"
    val isOK: Boolean get() = overallStatus == "OK"
}

@Serializable
data class DaemonInfo(
    val version: String = "",
    @SerialName("uptime_seconds") val uptimeSeconds: Long = 0,
    val pid: Int = 0,
    val paused: Boolean = false
)

@Serializable
data class Stats(
    @SerialName("total_hosts") val total: Int = 0,
    @SerialName("healthy_hosts") val healthy: Int = 0,
    @SerialName("warning_hosts") val warning: Int = 0,
    @SerialName("critical_hosts") val critical: Int = 0
)

@Serializable
data class StatusResponse(
    val daemon: DaemonInfo = DaemonInfo(),
    val statistics: Stats = Stats(),
    val hosts: List<Host> = emptyList(),
    val rev: Long = 0
)

// Response to GET /api/monitoring/status?since=<rev>: only the hosts that
// changed since the client's last revision, so live polling stays cheap.
@Serializable
data class StatusDelta(
    val rev: Long = 0,
    val full: Boolean = false,
    val daemon: DaemonInfo = DaemonInfo(),
    val statistics: Stats = Stats(),
    val changed: List<Host> = emptyList(),
    val removed: List<String> = emptyList()
)

@Serializable
data class SubscribeRequest(
    val platform: String,
    @SerialName("device_token") val deviceToken: String,
    val label: String = ""
)

@Serializable
data class ApiError(val error: String = "", val message: String = "")

@Serializable
data class TestPushResponse(val status: String = "", val warning: String? = null)

@Serializable
data class HistoryEvent(
    val timestamp: String = "",
    @SerialName("object_name") val objectName: String = "",
    val hostname: String = "",
    val description: String = "",
    @SerialName("prev_status") val prevStatus: String = "",
    @SerialName("new_status") val newStatus: String = "",
    @SerialName("prev_duration_seconds") val prevDuration: Long = 0
)

@Serializable
data class HistoryResponse(
    val events: List<HistoryEvent> = emptyList(),
    val available: Boolean = true
)

fun relativeTime(iso: String): String = runCatching {
    val secs = java.time.Duration.between(
        java.time.Instant.parse(iso), java.time.Instant.now()
    ).seconds
    if (secs < 5) "just now" else formatUptime(secs) + " ago"
}.getOrDefault(iso)

fun formatUptime(seconds: Long): String {
    if (seconds <= 0) return "0s"
    val d = seconds / 86400
    val h = (seconds % 86400) / 3600
    val m = (seconds % 3600) / 60
    val s = seconds % 60
    return when {
        d > 0 -> if (h > 0) "${d}d ${h}h" else "${d}d"
        h > 0 -> if (m > 0) "${h}h ${m}m" else "${h}h"
        m > 0 -> if (s > 0) "${m}m ${s}s" else "${m}m"
        else -> "${s}s"
    }
}
