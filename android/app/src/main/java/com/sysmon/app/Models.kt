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
    // A human said "I know": paging is suppressed until recovery.
    val acked: Boolean = false,
    @SerialName("down_count") val downCount: Long = 0,
    @SerialName("up_count") val upCount: Long = 0,
    @SerialName("time_up") val timeUp: Long = 0,
    @SerialName("time_failed") val timeFailed: Long = 0,
    // Present only for the checks that measure something: an rtt object
    // has rtt, a pktloss object has packetLoss, an snmp object has snmp.
    // Null everywhere else, which is what tells the UI not to draw a row.
    val rtt: RttStats? = null,
    @SerialName("packet_loss") val packetLoss: PacketLossStats? = null,
    val snmp: SnmpStats? = null
) {
    val ip: String get() = ipv4.ifEmpty { ipv6 }
    val isDown: Boolean get() = overallStatus == "CRITICAL"
    val isWarning: Boolean get() = overallStatus == "WARNING"
    val isOK: Boolean get() = overallStatus == "OK"
}

/**
 * What an rtt check last measured, in milliseconds.
 *
 * threshold/jitterThreshold are the operator's own limits, carried so a
 * value can be judged against what they said was acceptable rather than
 * against a number picked here. Zero means unset.
 */
@Serializable
data class RttStats(
    @SerialName("min_ms") val minMs: Double = 0.0,
    @SerialName("avg_ms") val avgMs: Double = 0.0,
    @SerialName("max_ms") val maxMs: Double = 0.0,
    @SerialName("jitter_ms") val jitterMs: Double = 0.0,
    val replies: Int = 0,
    val probes: Int = 0,
    @SerialName("threshold_ms") val thresholdMs: Int = 0,
    @SerialName("jitter_threshold_ms") val jitterThresholdMs: Int = 0
) {
    /** Replies short of probes is the loss an average hides. */
    val lostProbes: Int get() = (probes - replies).coerceAtLeast(0)
}

/** What a pktloss check last counted. Tolerance is a packet count. */
@Serializable
data class PacketLossStats(
    val sent: Int = 0,
    val received: Int = 0,
    val lost: Int = 0,
    @SerialName("loss_pct") val lossPct: Double = 0.0,
    val tolerance: Int = 0
)

/** What an SNMP object last reported about itself. */
@Serializable
data class SnmpStats(
    // The device's own uptime, in TimeTicks (hundredths of a second).
    @SerialName("sysuptime_ticks") val sysUpTimeTicks: Long = 0,
    @SerialName("last_response") val lastResponse: Long = 0
)

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
data class MeResponse(
    val username: String = "",
    val role: String = ""
)

@Serializable
data class StatusResponse(
    val daemon: DaemonInfo = DaemonInfo(),
    val statistics: Stats = Stats(),
    val hosts: List<Host> = emptyList(),
    val rev: Long = 0,
    // -1 = an older server that does not report fleet coverage.
    @SerialName("sites_total") val sitesTotal: Int = -1,
    @SerialName("sites_reachable") val sitesReachable: Int = -1
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
    val removed: List<String> = emptyList(),
    @SerialName("sites_total") val sitesTotal: Int = -1,
    @SerialName("sites_reachable") val sitesReachable: Int = -1
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
