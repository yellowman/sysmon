import SwiftUI
import UserNotifications

struct MainView: View {
    @EnvironmentObject var session: Session
    @Environment(\.scenePhase) private var scenePhase
    @State private var tab: Tab = .alerts
    private let store = StatusStore.shared

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
        // One poller feeds every tab (and the badge). Run it while the app
        // is foreground; pause it in the background to save battery/data.
        .onAppear { store.start() }
        .onChange(of: scenePhase) { phase in
            if phase == .active { store.start() } else { store.stop() }
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
    @ObservedObject private var store = StatusStore.shared

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if store.daemon?.paused == true {
                        PausedBanner()
                            .padding(.horizontal, 16)
                            .padding(.top, 8)
                    }
                    if let s = store.stats {
                        StatGrid(stats: s)
                            .padding(.horizontal, 16)
                            .padding(.top, 8)
                    }

                    SectionHeader(
                        "ACTIVE",
                        accent: store.alerts.isEmpty ? nil
                            : "\(store.alerts.count) ALERT\(store.alerts.count == 1 ? "" : "S")"
                    )
                    .padding(.horizontal, 16)
                    .padding(.top, 8)

                    if store.loading && store.hosts.isEmpty {
                        ProgressView().frame(maxWidth: .infinity).padding(.vertical, 40)
                    } else if let err = store.error, store.hosts.isEmpty {
                        ErrorBox(message: err) { Task { await store.refreshNow() } }
                            .padding(.horizontal, 16)
                    } else if store.alerts.isEmpty {
                        EmptyState(icon: "checkmark.circle", text: "All hosts healthy")
                            .padding(.vertical, 40)
                    } else {
                        VStack(spacing: 8) {
                            ForEach(store.alerts) { host in
                                NavigationLink { HostDetailView(host: host) }
                                    label: { HostRow(host: host) }
                                    .buttonStyle(.plain)
                            }
                        }
                        .padding(.horizontal, 16)
                    }
                }
            }
            .navigationTitle("Alerts")
            .navigationBarTitleDisplayMode(.inline)
            .refreshable { await store.refreshNow() }
        }
    }
}

struct HostsView: View {
    @ObservedObject private var store = StatusStore.shared
    @State private var search = ""

    var filtered: [Host] {
        if search.isEmpty { return store.hosts }
        let q = search.lowercased()
        return store.hosts.filter {
            $0.hostname.lowercased().contains(q) ||
            ($0.description?.lowercased().contains(q) ?? false) ||
            $0.ip.lowercased().contains(q)
        }
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 0) {
                    if !store.hosts.isEmpty {
                        TextField("Filter...", text: $search)
                            .textFieldStyle(SysmonFieldStyle())
                            .padding(.horizontal, 16)
                            .padding(.vertical, 8)
                    }
                    if store.loading && store.hosts.isEmpty {
                        ProgressView().padding(.vertical, 40)
                    } else if let err = store.error, store.hosts.isEmpty {
                        ErrorBox(message: err) { Task { await store.refreshNow() } }
                            .padding(16)
                    } else if filtered.isEmpty {
                        EmptyState(
                            icon: "magnifyingglass",
                            text: search.isEmpty ? "No hosts" : "No matches"
                        )
                        .padding(.vertical, 40)
                    } else {
                        VStack(spacing: 8) {
                            ForEach(filtered) { host in
                                NavigationLink { HostDetailView(host: host) }
                                    label: { HostRow(host: host) }
                                    .buttonStyle(.plain)
                            }
                        }
                        .padding(.horizontal, 16)
                    }
                }
            }
            .navigationTitle("Hosts")
            .navigationBarTitleDisplayMode(.inline)
            .refreshable { await store.refreshNow() }
        }
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
            Image(systemName: "chevron.right")
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(Color(white: 0.7))
                .padding(.top, 4)
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

struct HostDetailView: View {
    let host: Host
    @EnvironmentObject var session: Session
    @State private var acking = false
    @State private var ackNote: String?

    private var isAdmin: Bool { session.role == "admin" }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 10) {
                    StatusDot(status: host.overallStatus)
                    Text(host.overallStatus)
                        .font(.system(size: 13, weight: .bold))
                        .tracking(0.5)
                        .foregroundColor(statusColor(host.overallStatus))
                    if host.isPaused {
                        Text("PAUSED")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(.white)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Color.gray).cornerRadius(3)
                    }
                }

                VStack(alignment: .leading, spacing: 12) {
                    if let desc = host.description, !desc.isEmpty {
                        DetailRow(label: "DESCRIPTION", value: desc)
                    }
                    if !host.ip.isEmpty {
                        DetailRow(label: "ADDRESS", value: host.ip, mono: true)
                    }
                    if host.isDown, let tf = host.timeFailed, tf > 0 {
                        DetailRow(label: "DOWN FOR", value: formatUptime(tf))
                    } else if host.isOK, let tu = host.timeUp, tu > 0 {
                        DetailRow(label: "UP FOR", value: formatUptime(tu))
                    }
                    DetailRow(label: "FAIL COUNT", value: "\(host.downCount)")
                    DetailRow(label: "OK COUNT", value: "\(host.upCount)")
                }

                if isAdmin && !host.isOK && !host.isPaused {
                    Button(action: ack) {
                        Text(acking ? "ACKNOWLEDGING..." : "ACKNOWLEDGE")
                            .font(.system(size: 13, weight: .semibold))
                            .tracking(1)
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                            .background(acking ? Color.gray : Color.black)
                            .cornerRadius(8)
                    }
                    .disabled(acking)
                }
                if let note = ackNote {
                    Text(note)
                        .font(.system(size: 12))
                        .foregroundColor(.gray)
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle(host.hostname)
        .navigationBarTitleDisplayMode(.inline)
    }

    private func ack() {
        acking = true
        ackNote = nil
        Task {
            let api = API(baseURL: session.serverURL, token: session.token)
            do {
                try await api.ackHost(objectName: host.id)
                ackNote = "Acknowledged — sysmond will suppress further alerts."
            } catch let e as APIError {
                ackNote = e.message
            } catch {
                ackNote = "Acknowledge failed"
            }
            acking = false
        }
    }
}

struct DetailRow: View {
    let label: String
    let value: String
    var mono: Bool = false
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label)
                .font(.system(size: 9, weight: .bold))
                .tracking(1)
                .foregroundColor(.gray)
            Text(value)
                .font(.system(size: 14, design: mono ? .monospaced : .default))
                .foregroundColor(.primary)
        }
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
