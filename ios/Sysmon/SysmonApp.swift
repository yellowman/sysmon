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
                    // Each backgrounding makes sure a daily token health
                    // check is pending. The call is a no-op when one is
                    // already queued (submitting again would reset its
                    // 24h clock) or when nobody is logged in.
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
