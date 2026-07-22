import SwiftUI

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
        .tint(Theme.ink)
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
                            .transition(.opacity.combined(with: .move(edge: .top)))
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
                        AllClearCard(total: store.stats?.totalHosts ?? store.hosts.count)
                            .padding(.horizontal, 16)
                            .padding(.top, 8)
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
                .animation(.spring(response: 0.35, dampingFraction: 0.85), value: store.hosts)
            }
            .background(Theme.paper)
            .navigationTitle("Alerts")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    LivePill(offline: store.error != nil)
                }
            }
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
                        HStack(spacing: 8) {
                            Image(systemName: "magnifyingglass")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(Theme.faint)
                            TextField("Filter hosts...", text: $search)
                                .font(.system(size: 14))
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                            if !search.isEmpty {
                                Button { search = "" } label: {
                                    Image(systemName: "xmark.circle.fill")
                                        .font(.system(size: 14))
                                        .foregroundColor(Theme.faint)
                                }
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                        .background(Theme.surfaceSubtle)
                        .cornerRadius(10)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.hairline, lineWidth: 1))
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
                        .padding(.top, 4)
                        .animation(.spring(response: 0.35, dampingFraction: 0.85), value: store.hosts)
                    }
                }
            }
            .background(Theme.paper)
            .navigationTitle("Hosts")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    LivePill(offline: store.error != nil)
                }
            }
            .refreshable { await store.refreshNow() }
        }
    }
}

struct HostRow: View {
    let host: Host
    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            StatusDot(status: host.overallStatus, pulse: host.isDown && !host.isPaused)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(host.hostname)
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundColor(Theme.ink)
                    if host.isPaused {
                        Text("PAUSED")
                            .font(.system(size: 8, weight: .bold))
                            .tracking(0.5)
                            .foregroundColor(Theme.subtle)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 2)
                            .background(Capsule().fill(Theme.surfaceSubtle))
                            .overlay(Capsule().stroke(Theme.hairline, lineWidth: 1))
                    }
                }
                if let desc = host.description, !desc.isEmpty {
                    Text(desc)
                        .font(.system(size: 12))
                        .foregroundColor(Theme.subtle)
                        .lineLimit(1)
                }
                HStack(spacing: 8) {
                    Text(host.overallStatus)
                        .font(.system(size: 9, weight: .bold))
                        .tracking(0.8)
                        .foregroundColor(statusColor(host.overallStatus))
                    if !host.ip.isEmpty {
                        Text(host.ip)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(Theme.faint)
                    }
                    if host.isDown, let tf = host.timeFailed, tf > 0 {
                        Text("· down \(formatUptime(tf))")
                            .font(.system(size: 10))
                            .foregroundColor(Theme.down)
                    } else if host.isOK, let tu = host.timeUp, tu > 0 {
                        Text("· up \(formatUptime(tu))")
                            .font(.system(size: 10))
                            .foregroundColor(Theme.faint)
                    }
                }
            }
            Spacer(minLength: 8)
            Image(systemName: "chevron.right")
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(Theme.faint)
        }
        .card()
    }
}

// The good news, said loudly: shown when zero hosts are alerting.
struct AllClearCard: View {
    let total: Int
    var body: some View {
        VStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(Theme.up.opacity(0.12))
                    .frame(width: 64, height: 64)
                Image(systemName: "checkmark")
                    .font(.system(size: 26, weight: .bold))
                    .foregroundColor(Theme.up)
            }
            Text("All systems operational")
                .font(.system(size: 17, weight: .semibold, design: .serif))
                .foregroundColor(Theme.ink)
            if total > 0 {
                Text("\(total) host\(total == 1 ? "" : "s") monitored · nothing needs you")
                    .font(.system(size: 12))
                    .foregroundColor(Theme.subtle)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 32)
        .background(Theme.surface)
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Theme.hairline, lineWidth: 1))
        .cornerRadius(12)
        .shadow(color: Color.black.opacity(0.04), radius: 6, x: 0, y: 2)
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
            VStack(alignment: .leading, spacing: 16) {
                // Status hero
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 10) {
                        StatusDot(status: host.overallStatus,
                                  pulse: host.isDown && !host.isPaused)
                        Text(host.overallStatus)
                            .font(.system(size: 14, weight: .bold))
                            .tracking(1)
                            .foregroundColor(statusColor(host.overallStatus))
                        if host.isPaused {
                            Text("PAUSED")
                                .font(.system(size: 9, weight: .bold))
                                .tracking(0.5)
                                .foregroundColor(Theme.subtle)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Capsule().fill(Theme.surfaceSubtle))
                                .overlay(Capsule().stroke(Theme.hairline, lineWidth: 1))
                        }
                        Spacer()
                    }
                    if host.isDown, let tf = host.timeFailed, tf > 0 {
                        Text("Down for \(formatUptime(tf))")
                            .font(.system(size: 21, weight: .bold, design: .serif))
                            .foregroundColor(Theme.ink)
                    } else if host.isOK, let tu = host.timeUp, tu > 0 {
                        Text("Up for \(formatUptime(tu))")
                            .font(.system(size: 21, weight: .bold, design: .serif))
                            .foregroundColor(Theme.ink)
                    }
                }
                .card(padding: 16)

                SectionHeader("DETAILS")
                VStack(alignment: .leading, spacing: 14) {
                    if let desc = host.description, !desc.isEmpty {
                        DetailRow(label: "DESCRIPTION", value: desc)
                    }
                    if !host.ip.isEmpty {
                        DetailRow(label: "ADDRESS", value: host.ip, mono: true)
                    }
                    DetailRow(label: "FAIL COUNT", value: "\(host.downCount)")
                    DetailRow(label: "OK COUNT", value: "\(host.upCount)")
                }
                .card(padding: 16)

                if isAdmin && !host.isOK && !host.isPaused {
                    Button(action: ack) {
                        Text(acking ? "ACKNOWLEDGING..." : "ACKNOWLEDGE")
                    }
                    .buttonStyle(SlabButtonStyle(enabled: !acking))
                    .disabled(acking)
                    .padding(.top, 4)
                }
                if let note = ackNote {
                    Text(note)
                        .font(.system(size: 12))
                        .foregroundColor(Theme.subtle)
                        .transition(.opacity)
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Theme.paper)
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
                .foregroundColor(Theme.subtle)
            Text(value)
                .font(.system(size: 14, design: mono ? .monospaced : .default))
                .foregroundColor(Theme.ink)
        }
    }
}

struct StatGrid: View {
    let stats: Stats
    var body: some View {
        HStack(spacing: 8) {
            StatTile(label: "TOTAL", value: stats.totalHosts, color: Theme.ink)
            StatTile(label: "OK", value: stats.healthyHosts, color: Theme.up)
            StatTile(label: "WARN", value: stats.warningHosts, color: Theme.warn)
            StatTile(label: "CRIT", value: stats.criticalHosts, color: Theme.down)
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
                .foregroundColor(Theme.subtle)
            Text("\(value)")
                .font(.system(size: 26, weight: .heavy))
                .tracking(-0.5)
                .foregroundColor(value == 0 && label != "TOTAL" ? Theme.faint : color)
                .contentTransition(.numericText())
                .animation(.spring(response: 0.3, dampingFraction: 0.8), value: value)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Theme.surface)
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Theme.hairline, lineWidth: 1))
        .cornerRadius(12)
        .shadow(color: Color.black.opacity(0.04), radius: 6, x: 0, y: 2)
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
                .foregroundColor(Theme.subtle)
            Spacer()
            if let accent {
                Text(accent)
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundColor(Theme.subtle)
            }
        }
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
        .foregroundColor(Theme.warn)
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.warn.opacity(0.1))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.warn.opacity(0.3)))
        .cornerRadius(10)
    }
}

struct ErrorBox: View {
    let message: String
    let retry: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "wifi.exclamationmark")
                    .font(.system(size: 13, weight: .semibold))
                Text(message)
                    .font(.system(size: 13))
            }
            .foregroundColor(Theme.down)
            Button("RETRY", action: retry)
                .font(.system(size: 11, weight: .semibold))
                .tracking(1)
                .foregroundColor(Theme.onInk)
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .background(Theme.ink)
                .cornerRadius(6)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.down.opacity(0.06))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.down.opacity(0.2)))
        .cornerRadius(10)
    }
}

struct EmptyState: View {
    let icon: String
    let text: String
    var body: some View {
        VStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(Theme.surfaceSubtle)
                    .frame(width: 56, height: 56)
                Image(systemName: icon)
                    .font(.system(size: 22))
                    .foregroundColor(Theme.faint)
            }
            Text(text)
                .font(.system(size: 13))
                .foregroundColor(Theme.subtle)
        }
        .frame(maxWidth: .infinity)
    }
}
