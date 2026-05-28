import Foundation

struct LoginResponse: Codable {
    let token: String
    let username: String
    let role: String
}

struct Host: Codable, Identifiable {
    let objectName: String?
    let hostname: String
    let description: String?
    let overallStatus: String
    let downCount: Int64
    let upCount: Int64
    let timeUp: Int64?
    let timeFailed: Int64?

    var id: String { objectName ?? hostname }
    var isDown: Bool { overallStatus == "CRITICAL" }
    var isWarning: Bool { overallStatus == "WARNING" }
    var isOK: Bool { overallStatus == "OK" }

    enum CodingKeys: String, CodingKey {
        case objectName = "object_name"
        case hostname
        case description
        case overallStatus = "overall_status"
        case downCount = "down_count"
        case upCount = "up_count"
        case timeUp = "time_up"
        case timeFailed = "time_failed"
    }
}

struct DaemonInfo: Codable {
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

struct Stats: Codable {
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
}

struct SubscribeResponse: Codable {
    let status: String
    let apiKey: String

    enum CodingKeys: String, CodingKey {
        case status
        case apiKey = "api_key"
    }
}

struct APIError: Error {
    let status: Int
    let message: String
}

func formatUptime(_ seconds: Int64) -> String {
    let d = seconds / 86400
    let h = (seconds % 86400) / 3600
    let m = (seconds % 3600) / 60
    let s = seconds % 60
    if d > 0 { return "\(d)d \(h)h \(m)m" }
    if h > 0 { return "\(h)h \(m)m \(s)s" }
    if m > 0 { return "\(m)m \(s)s" }
    return "\(s)s"
}
