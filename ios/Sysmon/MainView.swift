import SwiftUI
import UserNotifications

struct MainView: View {
    @EnvironmentObject var session: Session
    @State private var tab: Tab = .alerts

    enum Tab { case alerts, hosts, settings }

    var body: some View {
        TabView(selection: $tab) {
            AlertsView()
                .tabItem { Label("Alerts", systemImage: "bell") }
                .badge(session.alertCount)
                .tag(Tab.alerts)
            HostsView()
                .tabItem { Label("Hosts", systemImage: "server.rack") }
                .tag(Tab.hosts)
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gearshape") }
                .tag(Tab.settings)
        }
        .tint(.black)
        .onReceive(NotificationCenter.default.publisher(for: .sysmonPushTapped)) { _ in
            tab = .alerts
        }
    }
}

func statusColor(_ status: String) -> Color {
    switch status {
    case "OK": return .green
    case "WARNING": return .orange
    case "CRITICAL": return .red
    default: return .gray
    }
}

struct AlertsView: View {
    @EnvironmentObject var session: Session
    @Environment(\.scenePhase) private var scenePhase
    @State private var hosts: [Host] = []
    @State private var stats: Stats?
    @State private var daemon: DaemonInfo?
    @State private var loading = true
    @State private var error: String?
    @State private var refreshKey = UUID()

    var alerts: [Host] { hosts.filter { !$0.isOK } }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if daemon?.paused == true {
                        PausedBanner()
                            .padding(.horizontal, 16)
                            .padding(.top, 8)
                    }
                    if let s = stats {
                        StatGrid(stats: s)
                            .padding(.horizontal, 16)
                            .padding(.top, 8)
                    }

                    SectionHeader(
                        "ACTIVE",
                        accent: alerts.isEmpty ? nil
                            : "\(alerts.count) ALERT\(alerts.count == 1 ? "" : "S")"
                    )
                    .padding(.horizontal, 16)
                    .padding(.top, 8)

                    if loading && hosts.isEmpty {
                        ProgressView().frame(maxWidth: .infinity).padding(.vertical, 40)
                    } else if let err = error {
                        ErrorBox(message: err) { refreshKey = UUID() }
                            .padding(.horizontal, 16)
                    } else if alerts.isEmpty {
                        EmptyState(icon: "checkmark.circle", text: "All hosts healthy")
                            .padding(.vertical, 40)
                    } else {
                        VStack(spacing: 8) {
                            ForEach(alerts) { HostRow(host: $0) }
                        }
                        .padding(.horizontal, 16)
                    }
                }
            }
            .navigationTitle("Alerts")
            .navigationBarTitleDisplayMode(.inline)
            .refreshable { await refresh() }
            .task(id: refreshKey) { await refresh() }
            .onChange(of: scenePhase) { phase in
                if phase == .active { refreshKey = UUID() }
            }
        }
    }

    private func refresh() async {
        let api = API(baseURL: session.serverURL, token: session.token)
        do {
            let status: StatusResponse = try await api.get("/api/monitoring/status")
            hosts = status.hosts
            stats = status.statistics
            daemon = status.daemon
            error = nil
            let count = hosts.filter { !$0.isOK }.count
            session.alertCount = count
            try? await UNUserNotificationCenter.current().setBadgeCount(count)
        } catch let e as APIError {
            error = e.message
        } catch {
            error = "Connection failed"
        }
        loading = false
    }
}

struct HostsView: View {
    @EnvironmentObject var session: Session
    @Environment(\.scenePhase) private var scenePhase
    @State private var hosts: [Host] = []
    @State private var search = ""
    @State private var loading = true
    @State private var error: String?
    @State private var refreshKey = UUID()

    var filtered: [Host] {
        if search.isEmpty { return hosts }
        let q = search.lowercased()
        return hosts.filter {
            $0.hostname.lowercased().contains(q) ||
            ($0.description?.lowercased().contains(q) ?? false) ||
            $0.ip.lowercased().contains(q)
        }
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 0) {
                    if !hosts.isEmpty {
                        TextField("Filter...", text: $search)
                            .textFieldStyle(SysmonFieldStyle())
                            .padding(.horizontal, 16)
                            .padding(.vertical, 8)
                    }
                    if loading && hosts.isEmpty {
                        ProgressView().padding(.vertical, 40)
                    } else if let err = error {
                        ErrorBox(message: err) { refreshKey = UUID() }
                            .padding(16)
                    } else if filtered.isEmpty {
                        EmptyState(
                            icon: "magnifyingglass",
                            text: search.isEmpty ? "No hosts" : "No matches"
                        )
                        .padding(.vertical, 40)
                    } else {
                        VStack(spacing: 8) {
                            ForEach(filtered) { HostRow(host: $0) }
                        }
                        .padding(.horizontal, 16)
                    }
                }
            }
            .navigationTitle("Hosts")
            .navigationBarTitleDisplayMode(.inline)
            .refreshable { await refresh() }
            .task(id: refreshKey) { await refresh() }
            .onChange(of: scenePhase) { phase in
                if phase == .active { refreshKey = UUID() }
            }
        }
    }

    private func refresh() async {
        let api = API(baseURL: session.serverURL, token: session.token)
        do {
            let list: [Host] = try await api.get("/api/monitoring/hosts")
            hosts = list
            error = nil
        } catch let e as APIError {
            error = e.message
        } catch {
            error = "Connection failed"
        }
        loading = false
    }
}

struct HostRow: View {
    let host: Host
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            StatusDot(status: host.overallStatus)
                .padding(.top, 5)
            VStack(alignment: .leading, spacing: 2) {
                Text(host.hostname)
                    .font(.system(size: 14, weight: .semibold))
                if let desc = host.description, !desc.isEmpty {
                    Text(desc)
                        .font(.system(size: 12))
                        .foregroundColor(.gray)
                }
                if !host.ip.isEmpty {
                    Text(host.ip)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.gray)
                }
                HStack(spacing: 8) {
                    Text(host.overallStatus)
                        .font(.system(size: 9, weight: .bold))
                        .tracking(0.5)
                        .foregroundColor(statusColor(host.overallStatus))
                    if host.isPaused {
                        Text("PAUSED")
                            .font(.system(size: 9, weight: .bold))
                            .tracking(0.5)
                            .foregroundColor(.white)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Color.gray)
                            .cornerRadius(3)
                    }
                    if host.isDown, let tf = host.timeFailed, tf > 0 {
                        Text("down \(formatUptime(tf))")
                            .font(.system(size: 10))
                            .foregroundColor(.gray)
                    } else if host.isOK, let tu = host.timeUp, tu > 0 {
                        Text("up \(formatUptime(tu))")
                            .font(.system(size: 10))
                            .foregroundColor(.gray)
                    }
                }
            }
            Spacer()
        }
        .padding(.vertical, 6)
    }
}

struct StatusDot: View {
    let status: String
    var body: some View {
        Circle()
            .fill(statusColor(status))
            .frame(width: 8, height: 8)
    }
}

struct StatGrid: View {
    let stats: Stats
    var body: some View {
        HStack(spacing: 8) {
            StatTile(label: "TOTAL", value: stats.totalHosts, color: .primary)
            StatTile(label: "OK", value: stats.healthyHosts, color: .green)
            StatTile(label: "WARN", value: stats.warningHosts, color: .orange)
            StatTile(label: "CRIT", value: stats.criticalHosts, color: .red)
        }
    }
}

struct StatTile: View {
    let label: String
    let value: Int
    let color: Color
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 9, weight: .bold))
                .tracking(1)
                .foregroundColor(.gray)
            Text("\(value)")
                .font(.system(size: 24, weight: .heavy))
                .tracking(-0.5)
                .foregroundColor(color)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color(white: 0.98))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(white: 0.92)))
        .cornerRadius(10)
    }
}

struct SectionHeader: View {
    let text: String
    let accent: String?
    init(_ text: String, accent: String? = nil) {
        self.text = text
        self.accent = accent
    }
    var body: some View {
        HStack {
            Text(text)
                .font(.system(size: 11, weight: .bold))
                .tracking(1.5)
                .foregroundColor(.gray)
            Spacer()
            if let accent {
                Text(accent)
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundColor(.gray)
            }
        }
    }
}

struct ErrorBox: View {
    let message: String
    let retry: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(message)
                .font(.system(size: 13))
                .foregroundColor(.red)
            Button("RETRY", action: retry)
                .font(.system(size: 11, weight: .semibold))
                .tracking(1)
                .foregroundColor(.white)
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .background(Color.black)
                .cornerRadius(6)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.red.opacity(0.06))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.red.opacity(0.2)))
        .cornerRadius(10)
    }
}

struct PausedBanner: View {
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "pause.circle.fill")
                .font(.system(size: 14))
            Text("Monitoring paused — the daemon is not running checks")
                .font(.system(size: 12, weight: .medium))
            Spacer()
        }
        .foregroundColor(.orange)
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.1))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.orange.opacity(0.3)))
        .cornerRadius(10)
    }
}

struct EmptyState: View {
    let icon: String
    let text: String
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 36))
                .foregroundColor(Color(white: 0.7))
            Text(text)
                .font(.system(size: 13))
                .foregroundColor(.gray)
        }
        .frame(maxWidth: .infinity)
    }
}
