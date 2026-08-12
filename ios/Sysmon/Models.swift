import Foundation

struct LoginResponse: Codable {
    let token: String
    let username: String
    let role: String
}

// Response to POST /api/push/subscribe. tokenStatus is "invalid" when
// the server already knows - from FCM's UNREGISTERED verdict on a past
// send - that the token just registered is dead. That's the app's cue
// to delete the cached token and mint a fresh one: FCM only ever
// reports a dead token to the sender, so the device can't find out any
// other way. Older servers omit the field.
struct SubscribeResponse: Codable {
    let status: String?
    let tokenStatus: String?
    let message: String?

    enum CodingKeys: String, CodingKey {
        case status, message
        case tokenStatus = "token_status"
    }
}

struct Host: Codable, Identifiable, Equatable {
    let objectName: String?
    let hostname: String
    let description: String?
    let ipv4Address: String?
    let ipv6Address: String?
    let overallStatus: String
    let paused: Bool?
    // A human has claimed this alert: it moves off the active board
    // until the host recovers. Paging is unaffected.
    let acked: Bool?
    let downCount: Int64
    let upCount: Int64
    let timeUp: Int64?
    let timeFailed: Int64?
    // Present only for the checks that measure something: an rtt object
    // has rtt, a pktloss object has packetLoss, an snmp object has snmp.
    // nil everywhere else, which is what tells the UI not to draw a row.
    let rtt: RTTStats?
    let packetLoss: PacketLossStats?
    let snmp: SNMPStats?

    var id: String { objectName ?? hostname }
    var isPaused: Bool { paused ?? false }
    var ip: String {
        if let v4 = ipv4Address, !v4.isEmpty { return v4 }
        if let v6 = ipv6Address, !v6.isEmpty { return v6 }
        return ""
    }
    var isDown: Bool { overallStatus == "CRITICAL" }
    var isWarning: Bool { overallStatus == "WARNING" }
    var isOK: Bool { overallStatus == "OK" }

    enum CodingKeys: String, CodingKey {
        case objectName = "object_name"
        case hostname
        case description
        case ipv4Address = "ipv4_address"
        case ipv6Address = "ipv6_address"
        case overallStatus = "overall_status"
        case paused
        case acked
        case downCount = "down_count"
        case upCount = "up_count"
        case timeUp = "time_up"
        case timeFailed = "time_failed"
        case rtt
        case packetLoss = "packet_loss"
        case snmp
    }
}

/// What an rtt check last measured, in milliseconds.
///
/// `thresholdMs`/`jitterThresholdMs` are the operator's own limits,
/// carried so a value can be judged against what they said was
/// acceptable rather than a number picked here. Zero means unset.
struct RTTStats: Codable, Equatable {
    let minMs: Double
    let avgMs: Double
    let maxMs: Double
    let jitterMs: Double
    let replies: Int
    let probes: Int
    let thresholdMs: Int?
    let jitterThresholdMs: Int?

    /// Replies short of probes is the loss an average hides.
    var lostProbes: Int { max(0, probes - replies) }

    enum CodingKeys: String, CodingKey {
        case minMs = "min_ms"
        case avgMs = "avg_ms"
        case maxMs = "max_ms"
        case jitterMs = "jitter_ms"
        case replies
        case probes
        case thresholdMs = "threshold_ms"
        case jitterThresholdMs = "jitter_threshold_ms"
    }
}

/// What a pktloss check last counted. `tolerance` is a packet count.
struct PacketLossStats: Codable, Equatable {
    let sent: Int
    let received: Int
    let lost: Int
    let lossPct: Double
    let tolerance: Int?

    enum CodingKeys: String, CodingKey {
        case sent, received, lost
        case lossPct = "loss_pct"
        case tolerance
    }
}

/// What an SNMP object last reported about itself.
struct SNMPStats: Codable, Equatable {
    /// The device's own uptime, in TimeTicks (hundredths of a second).
    let sysUpTimeTicks: Int64?
    let lastResponse: Int64?

    enum CodingKeys: String, CodingKey {
        case sysUpTimeTicks = "sysuptime_ticks"
        case lastResponse = "last_response"
    }
}

struct DaemonInfo: Codable, Equatable {
    let version: String
    let uptimeSeconds: Int64
    let pid: Int
    let paused: Bool

    enum CodingKeys: String, CodingKey {
        case version
        case uptimeSeconds = "uptime_seconds"
        case pid
        case paused
    }
}

struct Stats: Codable, Equatable {
    let totalHosts: Int
    let healthyHosts: Int
    let warningHosts: Int
    let criticalHosts: Int

    enum CodingKeys: String, CodingKey {
        case totalHosts = "total_hosts"
        case healthyHosts = "healthy_hosts"
        case warningHosts = "warning_hosts"
        case criticalHosts = "critical_hosts"
    }
}

struct MeResponse: Codable {
    let username: String
    let role: String
}

struct StatusResponse: Codable {
    let daemon: DaemonInfo?
    let hosts: [Host]
    let statistics: Stats
    let rev: Int64?
    // nil = an older server that does not report fleet coverage.
    let sitesReachable: Int?

    enum CodingKeys: String, CodingKey {
        case daemon, hosts, statistics, rev
        case sitesReachable = "sites_reachable"
    }
}

// Response to GET /api/monitoring/status?since=<rev>: only the hosts that
// changed since the client's last revision, so live polling stays cheap.
struct StatusDelta: Codable {
    let rev: Int64
    let full: Bool
    let daemon: DaemonInfo?
    let statistics: Stats
    // Optional: Go marshals a nil slice as JSON null, and an idle delta
    // has no changes - a non-optional array would fail to decode there.
    let changed: [Host]?
    let removed: [String]?
    let sitesReachable: Int?

    enum CodingKeys: String, CodingKey {
        case rev, full, daemon, statistics, changed, removed
        case sitesReachable = "sites_reachable"
    }
}

// One observed host state transition, from /api/monitoring/history.
struct HistoryEvent: Codable, Identifiable, Equatable {
    let timestamp: String
    let objectName: String
    let hostname: String
    let description: String?
    let prevStatus: String
    let newStatus: String
    let prevDuration: Int64?

    var id: String { timestamp + objectName + prevStatus + newStatus }

    enum CodingKeys: String, CodingKey {
        case timestamp
        case objectName = "object_name"
        case hostname
        case description
        case prevStatus = "prev_status"
        case newStatus = "new_status"
        case prevDuration = "prev_duration_seconds"
    }
}

struct HistoryResponse: Codable {
    let events: [HistoryEvent]?
    let available: Bool?
}

private let isoParser = ISO8601DateFormatter()

func relativeTime(_ iso: String) -> String {
    guard let date = isoParser.date(from: iso) else { return iso }
    let secs = Int64(Date().timeIntervalSince(date))
    if secs < 5 { return "just now" }
    return formatUptime(secs) + " ago"
}

struct APIError: Error {
    let status: Int
    let message: String
}

func formatUptime(_ seconds: Int64) -> String {
    guard seconds > 0 else { return "0s" }
    let d = seconds / 86400
    let h = (seconds % 86400) / 3600
    let m = (seconds % 3600) / 60
    let s = seconds % 60
    if d > 0 { return h > 0 ? "\(d)d \(h)h" : "\(d)d" }
    if h > 0 { return m > 0 ? "\(h)h \(m)m" : "\(h)h" }
    if m > 0 { return s > 0 ? "\(m)m \(s)s" : "\(m)m" }
    return "\(s)s"
}
