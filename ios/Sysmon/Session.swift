import Foundation
import SwiftUI
import UIKit

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
    @Published var apiKey: String? {
        didSet {
            if let k = apiKey { KeychainHelper.save("sysmon_api_key", value: k) }
            else { KeychainHelper.delete("sysmon_api_key") }
        }
    }

    init() {
        self.serverURL = UserDefaults.standard.string(forKey: "sysmon_server_url") ?? ""
        self.username = UserDefaults.standard.string(forKey: "sysmon_username")
        self.role = UserDefaults.standard.string(forKey: "sysmon_role")
        self.token = KeychainHelper.load("sysmon_token")
        self.apiKey = KeychainHelper.load("sysmon_api_key")
        Session.shared = self
    }

    func login(username: String, password: String) async throws {
        let api = API(baseURL: serverURL, token: nil)
        let resp: LoginResponse = try await api.post("/api/auth/login",
            body: ["username": username, "password": password])
        self.token = resp.token
        self.username = resp.username
        self.role = resp.role

        // Request push permission and register
        await requestPushPermission()
        if let deviceToken = DeviceTokenStore.shared.token {
            await registerPushToken(deviceToken)
        }
    }

    func logout() {
        Task {
            if let t = token, !serverURL.isEmpty {
                _ = try? await API(baseURL: serverURL, token: t).post("/api/auth/logout", body: [String: String]())
            }
            token = nil
            username = nil
            role = nil
            apiKey = nil
        }
    }

    func requestPushPermission() async {
        let granted = (try? await UNUserNotificationCenter.current()
            .requestAuthorization(options: [.alert, .sound, .badge])) ?? false
        if granted {
            await MainActor.run { UIApplication.shared.registerForRemoteNotifications() }
        }
    }

    func registerPushToken(_ deviceToken: String) async {
        guard let token = token, !serverURL.isEmpty else { return }
        let api = API(baseURL: serverURL, token: token)
        let body: [String: String] = [
            "device_token": deviceToken,
            "platform": "ios",
            "label": UIDevice.current.name
        ]
        do {
            let resp: SubscribeResponse = try await api.post("/api/push/subscribe", body: body)
            self.apiKey = resp.apiKey
        } catch {
            print("push subscribe failed: \(error)")
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
