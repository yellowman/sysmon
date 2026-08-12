import Foundation
import SwiftUI
import UIKit
import UserNotifications
import FirebaseMessaging

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

    // The persisted role is whatever the login response said, possibly
    // versions ago - a session predating role storage has none, and every
    // admin control stays hidden while the server still says admin. Ask
    // the server and correct the stored copy.
    func refreshIdentity() async {
        guard token != nil, !serverURL.isEmpty else { return }
        let api = API(baseURL: serverURL, token: token)
        if let me: MeResponse = try? await api.get("/api/auth/me"),
           !me.username.isEmpty {
            self.username = me.username
            self.role = me.role
        }
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
        loginNote = "Session expired - please sign in again"
    }

    func requestPushPermission() async {
        let granted = (try? await UNUserNotificationCenter.current()
            .requestAuthorization(options: [.alert, .sound, .badge])) ?? false
        if granted {
            UIApplication.shared.registerForRemoteNotifications()
        } else {
            pushStatus = "Notifications denied - enable in iOS Settings"
        }
    }

    // "Not registered" on the Settings tab is local knowledge: logged in
    // with no stored push token - the launch-time registration failed or
    // notification permission arrived after it. Act on it when the app
    // foregrounds instead of waiting for a cold start. Never prompts:
    // registration is only re-requested when authorization was already
    // granted, so this is silent and idempotent.
    func refreshPushRegistrationIfNeeded() async {
        guard token != nil, DeviceTokenStore.shared.token == nil else { return }
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        guard settings.authorizationStatus == .authorized
            || settings.authorizationStatus == .provisional else { return }
        UIApplication.shared.registerForRemoteNotifications()
    }

    // Tokens we already tried to renew this launch. Breaks any loop
    // where the "renewed" token comes back identical - e.g. the
    // direct-APNs fallback usually re-delivers the same token, and its
    // delegate callback re-enters registerPushToken with no way to mark
    // the call as a renewal pass.
    private var renewalAttempted = Set<String>()

    /// Register a (possibly rotated) push token with the backend. If the
    /// server answers that FCM has declared this token UNREGISTERED
    /// (uninstall/reinstall, restore to a new device, the 270-day
    /// inactivity purge, a Google-side invalidation), the Firebase SDK on
    /// this device is the one party that doesn't know: it keeps serving
    /// the dead token from cache and the MessagingDelegate never fires.
    /// The only escape is deleteToken() + token(), which mints a
    /// genuinely new one - so do that, once per token per launch, and
    /// re-register.
    func registerPushToken(_ deviceToken: String, replacing previous: String? = nil) async {
        guard let auth = token, !serverURL.isEmpty else { return }
        let api = API(baseURL: serverURL, token: auth)

        // Clean up the previous subscription if the token rotated.
        // Best-effort: it may already be gone (admin kicked it, or a
        // competing registration cleaned it up).
        if let previous, previous != deviceToken {
            _ = try? await api.unsubscribePush(deviceToken: previous)
        }

        do {
            let response = try await api.subscribePush(deviceToken: deviceToken,
                                                       label: UIDevice.current.name)
            if response.tokenStatus == "invalid" {
                if renewalAttempted.contains(deviceToken) {
                    pushStatus = "Push token renewal failed - the server still reports the token invalid"
                } else {
                    renewalAttempted.insert(deviceToken)
                    pushStatus = "Push token expired - requesting a new one…"
                    await renewPushToken(dead: deviceToken)
                }
            } else {
                pushStatus = "Push registered"
            }
        } catch let e as APIError {
            pushStatus = "Push registration failed: \(e.message)"
        } catch {
            pushStatus = "Push registration failed"
        }
    }

    // Force a fresh push token after the server reports the registered
    // one dead. Firebase-relayed builds hold an FCM token: deleteToken()
    // + token() mints a genuinely new one. The MessagingDelegate may also
    // observe the fresh token; both paths converge on registerPushToken,
    // which is idempotent per token. Direct-APNs builds have no
    // client-side delete - just ask the system again and let AppDelegate
    // register whatever comes back.
    private func renewPushToken(dead: String) async {
        guard AppDelegate.firebaseEnabled else {
            UIApplication.shared.registerForRemoteNotifications()
            return
        }
        do {
            let messaging = Messaging.messaging()
            try await messaging.deleteToken()
            let fresh = try await messaging.token()
            DeviceTokenStore.shared.update(fresh)
            await registerPushToken(fresh, replacing: dead)
        } catch {
            pushStatus = "Push token renewal failed: \(error.localizedDescription)"
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
