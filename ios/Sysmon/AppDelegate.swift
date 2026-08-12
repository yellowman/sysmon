import UIKit
import UserNotifications
import BackgroundTasks
import FirebaseCore
import FirebaseMessaging
import os

extension Notification.Name {
    static let sysmonPushTapped = Notification.Name("SysmonPushTapped")
}

class AppDelegate: NSObject, UIApplicationDelegate {
    // True when a GoogleService-Info.plist is bundled and Firebase is
    // active. iOS pushes then ride FCM (Firebase relays to APNs via the
    // auth key uploaded in its console) and we register the FCM token
    // with the server. Without the plist the app falls back to direct
    // APNs: the raw device token is registered and the server sends via
    // its cert-based APNs client. CI builds have no plist, so this also
    // keeps unconfigured builds from crashing in FirebaseApp.configure().
    private(set) static var firebaseEnabled = false

    // The daily push-token health check. Must match Info.plist's
    // BGTaskSchedulerPermittedIdentifiers entry.
    static let pushHealthTaskID = "com.sysmon.app.push-health"

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        if Bundle.main.path(forResource: "GoogleService-Info", ofType: "plist") != nil {
            FirebaseApp.configure()
            Messaging.messaging().delegate = self
            AppDelegate.firebaseEnabled = true
        }
        UNUserNotificationCenter.current().delegate = NotificationDelegate.shared
        // Handlers must be registered before launching finishes; the
        // actual requests are submitted whenever the app backgrounds.
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: Self.pushHealthTaskID, using: nil
        ) { task in
            guard let refresh = task as? BGAppRefreshTask else {
                task.setTaskCompleted(success: false)
                return
            }
            AppDelegate.handlePushHealth(refresh)
        }
        return true
    }

    // Ask for the next slot ~24h out. iOS treats this as an earliest
    // bound, not a schedule - the run itself rides the system's app
    // refresh budget, so it can slip. Combined with the launch-time and
    // foreground checks, a slipped slot costs nothing but delay.
    //
    // Two gates, both load-bearing:
    //  - No stored login, no request: an app installed but pointed at
    //    no sysmon has nothing to check.
    //  - Never replace a pending request. Submitting the same
    //    identifier again resets its earliestBeginDate to now+24h, so
    //    re-arming on every backgrounding would perpetually defer the
    //    task on any phone used more than once a day - the clock-reset
    //    bug the Android side avoids with ExistingPeriodicWorkPolicy.KEEP.
    static func schedulePushHealthCheck() {
        guard Session.hasPersistedLogin() else { return }
        BGTaskScheduler.shared.getPendingTaskRequests { pending in
            guard !pending.contains(where: { $0.identifier == pushHealthTaskID }) else { return }
            let request = BGAppRefreshTaskRequest(identifier: pushHealthTaskID)
            request.earliestBeginDate = Date(timeIntervalSinceNow: 24 * 60 * 60)
            try? BGTaskScheduler.shared.submit(request)
        }
    }

    static func handlePushHealth(_ task: BGAppRefreshTask) {
        // Re-arm before doing anything: an expired or crashed run must
        // not also cost tomorrow's slot. (Our own request stopped being
        // pending the moment it launched, so this submits.)
        schedulePushHealthCheck()

        // Completion must happen exactly once. The expiration handler
        // races the work: cancellation is cooperative, and a swallowed
        // CancellationError lets the work run on to its own completion
        // after the expiration path has already reported - completing a
        // BGTask twice is a documented programming error.
        let completed = OSAllocatedUnfairLock(initialState: false)
        func complete(_ success: Bool) {
            let first = completed.withLock { (done: inout Bool) -> Bool in
                if done { return false }
                done = true
                return true
            }
            if first { task.setTaskCompleted(success: success) }
        }

        // The expiration handler is installed before the work starts,
        // so an early expiration always has something to cancel.
        var work: Task<Void, Never>?
        task.expirationHandler = {
            work?.cancel()
            complete(false)
        }
        work = Task { @MainActor in
            // A cold background launch connects no scene, so the
            // SwiftUI-owned Session was never built and Session.shared
            // is nil - and a terminated app is precisely the
            // phone-in-a-drawer case this task exists for. Build a
            // Session from the persisted credentials (its init reads
            // UserDefaults and the Keychain) for the duration of the
            // check.
            let session = Session.shared ?? Session()
            await session.dailyPushHealthCheck()
            complete(true)
        }
    }

    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        if AppDelegate.firebaseEnabled {
            // Hand the APNs token to Firebase; the FCM registration token
            // arrives via MessagingDelegate and that's what we register.
            Messaging.messaging().apnsToken = deviceToken
            return
        }
        let newToken = deviceToken.map { String(format: "%02x", $0) }.joined()
        let previousToken = DeviceTokenStore.shared.token
        DeviceTokenStore.shared.update(newToken)
        Task {
            await Session.shared?.registerPushToken(newToken, replacing: previousToken)
        }
    }

    func application(_ application: UIApplication,
                     didFailToRegisterForRemoteNotificationsWithError error: Error) {
        print("APNs registration failed: \(error)")
    }
}

extension AppDelegate: MessagingDelegate {
    func messaging(_ messaging: Messaging, didReceiveRegistrationToken fcmToken: String?) {
        guard let fcmToken else { return }
        Task { @MainActor in
            let previous = DeviceTokenStore.shared.token
            DeviceTokenStore.shared.update(fcmToken)
            await Session.shared?.registerPushToken(fcmToken, replacing: previous)
        }
    }
}

class NotificationDelegate: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NotificationDelegate()

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound, .list])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        // Tapped a notification - route to the Alerts tab.
        NotificationCenter.default.post(name: .sysmonPushTapped, object: nil)
        completionHandler()
    }
}

final class DeviceTokenStore: ObservableObject {
    static let shared = DeviceTokenStore()
    private static let key = "sysmon_device_token"

    @Published private(set) var token: String?

    private init() {
        self.token = UserDefaults.standard.string(forKey: Self.key)
    }

    @MainActor
    func update(_ newToken: String?) {
        token = newToken
        if let newToken {
            UserDefaults.standard.set(newToken, forKey: Self.key)
        } else {
            UserDefaults.standard.removeObject(forKey: Self.key)
        }
    }
}
