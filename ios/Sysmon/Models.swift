import Foundation

struct LoginResponse: Codable {
    let token: String
    let username: String
    let role: String
}

struct Host: Codable, Identifiable, Equatable {
    let objectName: String?
    let hostname: String
    let description: String?
    let ipv4Address: String?
    let ipv6Address: String?
    let overallStatus: String
    let paused: Bool?
    let downCount: Int64
    let upCount: Int64
    let timeUp: Int64?
    let timeFailed: Int64?

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
        case downCount = "down_count"
        case upCount = "up_count"
        case timeUp = "time_up"
        case timeFailed = "time_failed"
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

struct StatusResponse: Codable {
    let daemon: DaemonInfo?
    let hosts: [Host]
    let statistics: Stats
    let rev: Int64?
}

// Response to GET /api/monitoring/status?since=<rev>: only the hosts that
// changed since the client's last revision, so live polling stays cheap.
struct StatusDelta: Codable {
    let rev: Int64
    let full: Bool
    let daemon: DaemonInfo?
    let statistics: Stats
    let changed: [Host]
    let removed: [String]?
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
