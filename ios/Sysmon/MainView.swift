import SwiftUI

struct MainView: View {
    @EnvironmentObject var session: Session
    @Environment(\.scenePhase) private var scenePhase
    @State private var tab: Tab = .alerts
    private let store = StatusStore.shared

    enum Tab { case alerts, hosts, history, settings }

    var body: some View {
        TabView(selection: $tab) {
            AlertsView()
                .tabItem { Label("Alerts", systemImage: "bell") }
                .badge(session.alertCount)
                .tag(Tab.alerts)
            HostsView()
                .tabItem { Label("Hosts", systemImage: "server.rack") }
                .tag(Tab.hosts)
            HistoryView()
                .tabItem { Label("History", systemImage: "clock.arrow.circlepath") }
                .tag(Tab.history)
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
        .task { await session.refreshIdentity() }
        .onChange(of: scenePhase) { phase in
            if phase == .active { store.start() } else { store.stop() }
        }
    }
}

enum AlertSortKey: String, CaseIterable {
    case timeDown, name, ip

    var label: String {
        switch self {
        case .timeDown: return "Time down"
        case .name: return "Name"
        case .ip: return "IP address"
        }
    }
}

// Numeric-aware sort key for IPv4 ("9.x" must precede "10.x"); other
// address forms fall back to plain string order.
func ipSortable(_ ip: String) -> String {
    let parts = ip.split(separator: ".")
    if parts.count == 4, parts.allSatisfy({ Int($0) != nil }) {
        return parts.map { String(format: "%03d", Int($0)!) }.joined(separator: ".")
    }
    return ip
}

struct AlertsView: View {
    @ObservedObject private var store = StatusStore.shared
    @State private var sortKey: AlertSortKey = .timeDown
    // For timeDown, ascending = smallest time_failed first = newest
    // outage on top (the default view).
    @State private var sortAscending = true

    var sortedAlerts: [Host] {
        let base: [Host]
        switch sortKey {
        case .timeDown:
            base = store.unackedAlerts.sorted { ($0.timeFailed ?? 0) < ($1.timeFailed ?? 0) }
        case .name:
            base = store.unackedAlerts.sorted { $0.hostname.lowercased() < $1.hostname.lowercased() }
        case .ip:
            base = store.unackedAlerts.sorted { ipSortable($0.ip) < ipSortable($1.ip) }
        }
        return sortAscending ? base : base.reversed()
    }

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
                        accent: store.unackedAlerts.isEmpty ? nil
                            : "\(store.unackedAlerts.count) ALERT\(store.unackedAlerts.count == 1 ? "" : "S")"
                    )
                    .padding(.horizontal, 16)
                    .padding(.top, 8)

                    if store.loading && store.hosts.isEmpty {
                        ProgressView().frame(maxWidth: .infinity).padding(.vertical, 40)
                    } else if let err = store.error, store.hosts.isEmpty {
                        ErrorBox(message: err) { Task { await store.refreshNow() } }
                            .padding(.horizontal, 16)
                    } else if store.unackedAlerts.isEmpty && store.ackedAlerts.isEmpty {
                        AllClearCard(total: store.stats?.totalHosts ?? store.hosts.count,
                                     degraded: store.degraded)
                            .padding(.horizontal, 16)
                            .padding(.top, 8)
                    } else {
                        VStack(spacing: 8) {
                            ForEach(sortedAlerts) { host in
                                NavigationLink { HostDetailView(host: host) }
                                    label: { HostRow(host: host) }
                                    .buttonStyle(.plain)
                            }
                        }
                        .padding(.horizontal, 16)
                    }

                    if !store.ackedAlerts.isEmpty {
                        SectionHeader("ACKNOWLEDGED", accent: "\(store.ackedAlerts.count)")
                            .padding(.horizontal, 16)
                            .padding(.top, 8)
                        VStack(spacing: 8) {
                            ForEach(store.ackedAlerts) { host in
                                NavigationLink { HostDetailView(host: host) }
                                    label: { HostRow(host: host) }
                                    .buttonStyle(.plain)
                            }
                        }
                        .padding(.horizontal, 16)
                        .opacity(0.7)
                    }
                }
                .animation(.spring(response: 0.35, dampingFraction: 0.85), value: store.hosts)
            }
            .background(Theme.paper)
            .navigationTitle("Alerts")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    LivePill(offline: store.offline, degraded: store.degraded)
                    Menu {
                        ForEach(AlertSortKey.allCases, id: \.self) { key in
                            Button {
                                if sortKey == key {
                                    sortAscending.toggle()
                                } else {
                                    sortKey = key
                                    sortAscending = true
                                }
                            } label: {
                                HStack {
                                    Text(key.label)
                                    if sortKey == key {
                                        Image(systemName: sortAscending ? "arrow.up" : "arrow.down")
                                    }
                                }
                            }
                        }
                    } label: {
                        Image(systemName: "arrow.up.arrow.down")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundColor(Theme.subtle)
                    }
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
                    LivePill(offline: store.offline, degraded: store.degraded)
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
                    if !host.siteTag.isEmpty {
                        SiteTag(name: host.siteTag)
                    }
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
                MetricsRow(host: host)
            }
            Spacer(minLength: 8)
            Image(systemName: "chevron.right")
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(Theme.faint)
        }
        .card()
    }
}

/// Latency, jitter and loss, for the checks that measure them.
///
/// Renders nothing for an ordinary ping or tcp object, so a list of
/// plain hosts looks exactly as it did. A latency check exists to make
/// numbers, and until now the apps showed only up or down for it.
struct MetricsRow: View {
    let host: Host

    var body: some View {
        if host.rtt != nil || host.packetLoss != nil || host.snmp != nil {
            HStack(spacing: 10) {
                if let r = host.rtt {
                    Text(String(format: "%.2fms", r.avgMs))
                        .font(.system(size: 10, weight: .medium, design: .monospaced))
                        .foregroundColor(metricColor(r.avgMs, r.thresholdMs, warn: 150, bad: 400))
                    Text(String(format: "±%.2fms", r.jitterMs))
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(metricColor(r.jitterMs, r.jitterThresholdMs, warn: 30, bad: 100))
                    // Probes that never came back: the loss an average hides.
                    if r.lostProbes > 0 {
                        Text("\(r.replies)/\(r.probes)")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(Theme.down)
                    }
                }
                if let l = host.packetLoss {
                    Text(String(format: "%.1f%% loss", l.lossPct))
                        .font(.system(size: 10, weight: .medium, design: .monospaced))
                        .foregroundColor(lossColor(l))
                }
                if let s = host.snmp, let ticks = s.sysUpTimeTicks, ticks > 0 {
                    Text("up \(formatTicks(ticks))")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(Theme.faint)
                }
            }
        }
    }

    /// How alarming is a measured value?
    ///
    /// The operator's own threshold decides it when there is one: at or
    /// past it is the down colour, and the last 20% of the approach is a
    /// warning. With no threshold there is nothing to be relative to, so
    /// the absolutes come from what the numbers mean - 150ms is ITU-T
    /// G.114's guidance for voice, 30ms of jitter is where call quality
    /// suffers.
    private func metricColor(_ value: Double, _ threshold: Int?, warn: Double, bad: Double) -> Color {
        if let t = threshold, t > 0 {
            if value >= Double(t) { return Theme.down }
            if value >= Double(t) * 0.8 { return Theme.warn }
            return Theme.faint
        }
        if value >= bad { return Theme.down }
        if value >= warn { return Theme.warn }
        return Theme.faint
    }

    /// Tolerance is a packet count, so compare like for like.
    private func lossColor(_ l: PacketLossStats) -> Color {
        if let tol = l.tolerance, tol > 0 {
            if l.lost > tol { return Theme.down }
            if l.lost == tol { return Theme.warn }
            return Theme.faint
        }
        if l.lossPct >= 5 { return Theme.down }
        if l.lossPct >= 1 { return Theme.warn }
        return Theme.faint
    }

    /// sysUpTime is TimeTicks: hundredths of a second, which nobody reads.
    private func formatTicks(_ ticks: Int64) -> String {
        let secs = ticks / 100
        let d = secs / 86400, h = (secs % 86400) / 3600, m = (secs % 3600) / 60
        if d > 0 { return "\(d)d \(h)h" }
        if h > 0 { return "\(h)h \(m)m" }
        return "\(m)m"
    }
}

// The good news, said loudly: shown when zero hosts are alerting.
// Unless nothing is reporting - zero alerts from zero daemons is not
// good news, and this card must not dress it as some.
struct AllClearCard: View {
    let total: Int
    var degraded: Bool = false
    private var tone: Color { degraded ? Theme.warn : Theme.up }
    var body: some View {
        VStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(tone.opacity(0.12))
                    .frame(width: 64, height: 64)
                Image(systemName: degraded ? "exclamationmark.triangle" : "checkmark")
                    .font(.system(size: 26, weight: .bold))
                    .foregroundColor(tone)
            }
            Text(degraded ? "No monitoring daemon connected" : "All systems operational")
                .font(.system(size: 17, weight: .semibold, design: .serif))
                .foregroundColor(Theme.ink)
            if degraded {
                Text("The server is up, but no sysmond is reporting to it")
                    .font(.system(size: 12))
                    .foregroundColor(Theme.subtle)
            } else if total > 0 {
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
    @State private var ackText = ""
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

                if (host.acked ?? false) && !host.isOK {
                    Text("ACKNOWLEDGED · off the active board until it recovers")
                        .font(.system(size: 11, weight: .bold))
                        .tracking(0.5)
                        .foregroundColor(Theme.subtle)
                        .padding(.top, 4)
                    if isAdmin {
                        Button(action: unack) {
                            Text(acking ? "WORKING..." : "UN-ACKNOWLEDGE")
                        }
                        .buttonStyle(SlabButtonStyle(enabled: !acking))
                        .disabled(acking)
                    }
                } else if isAdmin && !host.isOK && !host.isPaused {
                    TextField("Ack note (required) - say what you know",
                              text: $ackText, axis: .vertical)
                        .lineLimit(2...4)
                        .textFieldStyle(.roundedBorder)
                        .padding(.top, 4)
                    Button(action: ack) {
                        Text(acking ? "ACKNOWLEDGING..." : "ACKNOWLEDGE")
                    }
                    .buttonStyle(SlabButtonStyle(enabled: !acking && !ackText.trimmingCharacters(in: .whitespaces).isEmpty))
                    .disabled(acking || ackText.trimmingCharacters(in: .whitespaces).isEmpty)
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

    private func unack() {
        acking = true
        ackNote = nil
        Task {
            let api = API(baseURL: session.serverURL, token: session.token)
            do {
                try await api.unackHost(objectName: host.id)
                ackNote = "Un-acknowledged - back on the active board."
            } catch let e as APIError {
                ackNote = e.message
            } catch {
                ackNote = "Un-acknowledge failed"
            }
            acking = false
        }
    }

    private func ack() {
        acking = true
        ackNote = nil
        Task {
            let api = API(baseURL: session.serverURL, token: session.token)
            do {
                try await api.ackHost(objectName: host.id,
                                      note: ackText.trimmingCharacters(in: .whitespaces))
                ackNote = "Acknowledged - sysmond will suppress further alerts."
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
            Text("Monitoring paused - the daemon is not running checks")
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
