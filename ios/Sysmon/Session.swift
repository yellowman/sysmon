import Foundation
import SwiftUI
import UIKit
import UserNotifications

@MainActor
class Session: ObservableObject {
    static private(set) weak var shared: Session?

    @Published var serverURL: String {
        didSet { UserDefaults.standard.set(serverURL, forKey: "sysmon_server_url") }
    }
    @Published var token: String? {
        didSet {
            if let t = token {
                KeychainHelper.save("sysmon_token", value: t)
            } else {
                KeychainHelper.delete("sysmon_token")
            }
        }
    }
    @Published var username: String? {
        didSet { UserDefaults.standard.set(username, forKey: "sysmon_username") }
    }
    @Published var role: String? {
        didSet { UserDefaults.standard.set(role, forKey: "sysmon_role") }
    }
    @Published var pushStatus: String?
    @Published var loginNote: String?
    @Published var alertCount: Int = 0

    init() {
        self.serverURL = UserDefaults.standard.string(forKey: "sysmon_server_url") ?? ""
        self.username = UserDefaults.standard.string(forKey: "sysmon_username")
        self.role = UserDefaults.standard.string(forKey: "sysmon_role")
        self.token = KeychainHelper.load("sysmon_token")
        Session.shared = self

        // After app reinstall, the Keychain entry persists while
        // UserDefaults is wiped. Treat that mismatched state as logged
        // out so the app doesn't get stuck calling APIs against an
        // empty server URL.
        if token != nil && serverURL.isEmpty {
            self.token = nil
            self.username = nil
            self.role = nil
            return
        }

        // Refresh APNs registration on cold launch so the system
        // delivers the current device token (which may have rotated
        // since last run) via AppDelegate.didRegister.
        if token != nil {
            UIApplication.shared.registerForRemoteNotifications()
        }
    }

    // Normalize a user-entered server URL: trim, default to https://, drop trailing slash.
    static func normalize(_ raw: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if !s.lowercased().hasPrefix("http://") && !s.lowercased().hasPrefix("https://") {
            s = "https://" + s
        }
        while s.hasSuffix("/") { s.removeLast() }
        return s
    }

    func login(username: String, password: String) async throws {
        loginNote = nil
        let api = API(baseURL: serverURL, token: nil)
        let resp: LoginResponse = try await api.post("/api/auth/login",
            body: ["username": username, "password": password])
        self.token = resp.token
        self.username = resp.username
        self.role = resp.role
        pushStatus = nil

        // Request push permission and let APNs callback deliver the fresh
        // device token via AppDelegate.didRegisterForRemoteNotifications.
        await requestPushPermission()
    }

    func logout() {
        let serverSnapshot = serverURL
        let tokenSnapshot = token
        let pushTokenSnapshot = DeviceTokenStore.shared.token

        // Flip UI to LoginView immediately
        token = nil
        username = nil
        role = nil
        alertCount = 0
        StatusStore.shared.reset()
        Task { try? await UNUserNotificationCenter.current().setBadgeCount(0) }

        // Best-effort backend cleanup
        Task {
            guard let auth = tokenSnapshot, !serverSnapshot.isEmpty else { return }
            let api = API(baseURL: serverSnapshot, token: auth)
            if let push = pushTokenSnapshot {
                _ = try? await api.unsubscribePush(deviceToken: push)
            }
            _ = try? await api.logout()
        }
    }

    func handleUnauthorized() {
        token = nil
        username = nil
        role = nil
        loginNote = "Session expired — please sign in again"
    }

    func requestPushPermission() async {
        let granted = (try? await UNUserNotificationCenter.current()
            .requestAuthorization(options: [.alert, .sound, .badge])) ?? false
        if granted {
            UIApplication.shared.registerForRemoteNotifications()
        } else {
            pushStatus = "Notifications denied — enable in iOS Settings"
        }
    }

    func registerPushToken(_ deviceToken: String, replacing previous: String? = nil) async {
        guard let auth = token, !serverURL.isEmpty else { return }
        let api = API(baseURL: serverURL, token: auth)

        // Clean up the previous subscription if APNs rotated the token.
        if let previous, previous != deviceToken {
            _ = try? await api.unsubscribePush(deviceToken: previous)
        }

        do {
            try await api.subscribePush(deviceToken: deviceToken,
                                        label: UIDevice.current.name)
            pushStatus = "Push registered"
        } catch let e as APIError {
            pushStatus = "Push registration failed: \(e.message)"
        } catch {
            pushStatus = "Push registration failed"
        }
    }
}

enum KeychainHelper {
    static func save(_ key: String, value: String) {
        let data = value.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }

    static func load(_ key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func delete(_ key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
    }
}
