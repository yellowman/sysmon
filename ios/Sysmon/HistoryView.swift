import SwiftUI

// Alert history: every host state transition the server has observed,
// newest first, with All / Downs / Recoveries filtering.
struct HistoryView: View {
    @EnvironmentObject var session: Session
    @State private var events: [HistoryEvent] = []
    @State private var loading = true
    @State private var errorMsg: String?
    @State private var filter: HistoryFilter = .all
    @State private var window: HistoryWindow = .twoDays
    // Ages advance on their own clock: rows only re-render when state
    // changes, and without this a quiet screen froze every "1d ago" at
    // whatever it said when the data last arrived.
    @State private var now = Date()
    private let clock = Timer.publish(every: 30, on: .main, in: .common).autoconnect()

    enum HistoryFilter: String, CaseIterable {
        case all = "All"
        case downs = "Downs"
        case recoveries = "Recoveries"
    }

    enum HistoryWindow: String, CaseIterable {
        case twoDays = "48h"
        case month = "30d"
    }

    var filtered: [HistoryEvent] {
        switch filter {
        case .all: return events
        case .downs: return events.filter { $0.newStatus != "OK" }
        case .recoveries: return events.filter { $0.newStatus == "OK" }
        }
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Picker("Filter", selection: $filter) {
                        ForEach(HistoryFilter.allCases, id: \.self) { f in
                            Text(f.rawValue).tag(f)
                        }
                    }
                    .pickerStyle(.segmented)
                    .padding(.horizontal, 16)
                    .padding(.top, 8)

                    Picker("Window", selection: $window) {
                        ForEach(HistoryWindow.allCases, id: \.self) { w in
                            Text(w.rawValue).tag(w)
                        }
                    }
                    .pickerStyle(.segmented)
                    .padding(.horizontal, 16)

                    if loading && events.isEmpty {
                        ProgressView().frame(maxWidth: .infinity).padding(.vertical, 40)
                    } else if let err = errorMsg, events.isEmpty {
                        ErrorBox(message: err) { Task { await fetch() } }
                            .padding(.horizontal, 16)
                    } else if filtered.isEmpty {
                        EmptyState(
                            icon: "clock.arrow.circlepath",
                            text: events.isEmpty
                                ? "No transitions in the last \(window == .month ? "30 days" : "48 hours")"
                                : "No events match the filter"
                        )
                        .padding(.vertical, 40)
                    } else {
                        VStack(spacing: 8) {
                            ForEach(filtered) { ev in
                                HistoryRow(event: ev, now: now)
                            }
                        }
                        .padding(.horizontal, 16)
                    }
                }
            }
            .background(Theme.paper)
            .navigationTitle("History")
            .navigationBarTitleDisplayMode(.inline)
            .refreshable { await fetch() }
            .task { await fetch() }
            .onChange(of: window) { _ in Task { await fetch() } }
            .onReceive(clock) { now = $0 }
        }
    }

    private func fetch() async {
        let api = API(baseURL: session.serverURL, token: session.token)
        do {
            let r: HistoryResponse = try await api.get("/api/monitoring/history?limit=300&window=\(window.rawValue)")
            events = r.events ?? []
            errorMsg = nil
        } catch let e as APIError {
            errorMsg = e.message
        } catch {
            self.errorMsg = "Connection failed"
        }
        loading = false
    }
}

struct HistoryRow: View {
    let event: HistoryEvent
    // Passed so the row re-renders on the parent's clock; the value
    // itself is not used - relativeTime reads the real time.
    var now: Date = Date()

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            StatusDot(status: event.newStatus)
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(event.objectName.isEmpty ? event.hostname : event.objectName)
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundColor(Theme.ink)
                    Spacer()
                    Text(relativeTime(event.timestamp))
                        .font(.system(size: 11))
                        .foregroundColor(Theme.subtle)
                }
                HStack(spacing: 6) {
                    Text(event.prevStatus)
                        .font(.system(size: 9, weight: .bold))
                        .tracking(0.5)
                        .foregroundColor(statusColor(event.prevStatus))
                    Image(systemName: "arrow.right")
                        .font(.system(size: 8, weight: .semibold))
                        .foregroundColor(Theme.faint)
                    Text(event.newStatus)
                        .font(.system(size: 9, weight: .bold))
                        .tracking(0.5)
                        .foregroundColor(statusColor(event.newStatus))
                    Spacer()
                    if let dur = event.prevDuration, dur > 0 {
                        Text("was \(event.prevStatus.lowercased()) \(formatUptime(dur))")
                            .font(.system(size: 10))
                            .foregroundColor(Theme.subtle)
                    }
                }
            }
        }
        .card()
    }
}
