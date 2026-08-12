import SwiftUI
import UserNotifications

@main
struct SysmonApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var session = Session()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(session)
                .onChange(of: scenePhase) { phase in
                    // "Not registered" is local knowledge - logged in
                    // with no stored push token. Re-check at every
                    // foreground instead of waiting for a cold start.
                    if phase == .active {
                        Task { await session.refreshPushRegistrationIfNeeded() }
                    }
                    // Each backgrounding re-arms the daily token health
                    // check (BGTaskScheduler requests don't persist a
                    // fired slot; the handler also re-arms after a run).
                    if phase == .background {
                        AppDelegate.schedulePushHealthCheck()
                    }
                }
        }
    }
}

struct RootView: View {
    @EnvironmentObject var session: Session

    var body: some View {
        Group {
            if session.token == nil {
                LoginView()
            } else {
                MainView()
            }
        }
    }
}
