import UIKit
import UserNotifications

extension Notification.Name {
    static let sysmonPushTapped = Notification.Name("SysmonPushTapped")
}

class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = NotificationDelegate.shared
        return true
    }

    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
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
        // Tapped a notification — route to the Alerts tab.
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
