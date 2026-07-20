import Foundation
import UserNotifications

// StatusStore is the single source of truth for live monitoring state.
//
// Rather than each screen fetching /api/monitoring/status on its own timer,
// one poller keeps a host map warm and both the Alerts and Hosts screens
// observe it. The first fetch pulls the full status; every subsequent poll
// asks for only what changed via ?since=<rev>, so a steady-state poll
// transfers a near-empty delta instead of the whole host list.
@MainActor
final class StatusStore: ObservableObject {
    static let shared = StatusStore()

    @Published private(set) var hosts: [Host] = []
    @Published private(set) var stats: Stats?
    @Published private(set) var daemon: DaemonInfo?
    @Published private(set) var error: String?
    @Published private(set) var loading = true

    // Poll cadence while the app is foregrounded.
    private let pollInterval: UInt64 = 5_000_000_000 // 5s

    private var rev: Int64 = 0
    private var hostIndex: [String: Host] = [:]
    private var pollTask: Task<Void, Never>?

    var alerts: [Host] { hosts.filter { !$0.isOK } }

    // Begin (or resume) polling. Idempotent — safe to call on every
    // scene-active transition and view appearance.
    func start() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in await self?.pollLoop() }
    }

    // Pause polling (app backgrounded). Retains the last known state so the
    // UI doesn't flash empty when we resume.
    func stop() {
        pollTask?.cancel()
        pollTask = nil
    }

    // Force an immediate fetch (pull-to-refresh). Uses the delta path when
    // we already have a revision, so a refresh is just as cheap as a poll.
    func refreshNow() async {
        await fetch()
    }

    private func pollLoop() async {
        await fetch()
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: pollInterval)
            if Task.isCancelled { break }
            await fetch()
        }
    }

    private func fetch() async {
        guard let session = Session.shared, let token = session.token,
              !session.serverURL.isEmpty else { return }
        let api = API(baseURL: session.serverURL, token: token)
        do {
            if rev == 0 {
                let status: StatusResponse = try await api.get("/api/monitoring/status")
                applyFull(status.hosts, stats: status.statistics,
                          daemon: status.daemon, rev: status.rev ?? 0)
            } else {
                let delta: StatusDelta =
                    try await api.get("/api/monitoring/status?since=\(rev)")
                applyDelta(delta)
            }
            error = nil
        } catch let e as APIError {
            error = e.message
        } catch {
            error = "Connection failed"
        }
        loading = false
        publishAlertCount()
    }

    private func applyFull(_ list: [Host], stats: Stats, daemon: DaemonInfo?, rev: Int64) {
        hostIndex = Dictionary(list.map { ($0.id, $0) }, uniquingKeysWith: { _, b in b })
        self.stats = stats
        self.daemon = daemon
        self.rev = rev
        rebuildHosts()
    }

    private func applyDelta(_ d: StatusDelta) {
        if d.full {
            applyFull(d.changed, stats: d.statistics, daemon: d.daemon, rev: d.rev)
            return
        }
        for h in d.changed { hostIndex[h.id] = h }
        for name in d.removed ?? [] { hostIndex.removeValue(forKey: name) }
        stats = d.statistics
        daemon = d.daemon
        rev = d.rev
        rebuildHosts()
    }

    private func rebuildHosts() {
        hosts = hostIndex.values.sorted { $0.hostname < $1.hostname }
    }

    private func publishAlertCount() {
        let count = alerts.count
        Session.shared?.alertCount = count
        Task { try? await UNUserNotificationCenter.current().setBadgeCount(count) }
    }

    // Clear all state on logout so a subsequent login starts from a full
    // fetch rather than deltas against a stale revision.
    func reset() {
        stop()
        rev = 0
        hostIndex = [:]
        hosts = []
        stats = nil
        daemon = nil
        error = nil
        loading = true
    }
}
