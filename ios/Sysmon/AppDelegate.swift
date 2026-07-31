import UIKit
import UserNotifications
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

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        if Bundle.main.path(forResource: "GoogleService-Info", ofType: "plist") != nil {
            FirebaseApp.configure()
            Messaging.messaging().delegate = self
            AppDelegate.firebaseEnabled = true
        }
        UNUserNotificationCenter.current().delegate = NotificationDelegate.shared
        return true
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
