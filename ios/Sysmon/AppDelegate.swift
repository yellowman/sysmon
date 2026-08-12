import UIKit
import UserNotifications
import BackgroundTasks
import FirebaseCore
import FirebaseMessaging

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
    static func schedulePushHealthCheck() {
        let request = BGAppRefreshTaskRequest(identifier: pushHealthTaskID)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 24 * 60 * 60)
        try? BGTaskScheduler.shared.submit(request)
    }

    static func handlePushHealth(_ task: BGAppRefreshTask) {
        // Re-arm before doing anything: an expired or crashed run must
        // not also cost tomorrow's slot.
        schedulePushHealthCheck()
        let work = Task { @MainActor in
            await Session.shared?.dailyPushHealthCheck()
            task.setTaskCompleted(success: true)
        }
        task.expirationHandler = {
            work.cancel()
            task.setTaskCompleted(success: false)
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
