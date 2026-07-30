import SwiftUI
import UIKit

struct SettingsView: View {
    @EnvironmentObject var session: Session
    @ObservedObject private var deviceTokens = DeviceTokenStore.shared
    @State private var sending = false
    @State private var statusMessage: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    section("ACCOUNT") {
                        row("Username", session.username ?? "—")
                        row("Role", (session.role ?? "—").uppercased())
                        row("Server", session.serverURL.isEmpty ? "—" : session.serverURL)
                    }

                    section("DEVICE") {
                        row("Push token",
                            deviceTokens.token.map { String($0.prefix(16)) + "…" } ?? "Not registered")
                        if let push = session.pushStatus {
                            Text(push).font(.system(size: 11)).foregroundColor(Theme.subtle)
                            if push.localizedCaseInsensitiveContains("denied") {
                                Button("Open iOS Settings") {
                                    if let url = URL(string: UIApplication.openSettingsURLString) {
                                        UIApplication.shared.open(url)
                                    }
                                }
                                .font(.system(size: 11, weight: .semibold))
                                .tracking(0.5)
                                .foregroundColor(Theme.ink)
                                .padding(.top, 2)
                            }
                        }
                        if let msg = statusMessage {
                            Text(msg).font(.system(size: 11)).foregroundColor(Theme.subtle)
                        }
                        Button(action: sendTest) {
                            Text(sending ? "SENDING..." : "SEND TEST NOTIFICATION")
                        }
                        .buttonStyle(SlabButtonStyle(enabled: canTest))
                        .disabled(!canTest)
                        .padding(.top, 4)
                    }

                    section("SESSION") {
                        Button(action: { session.logout() }) {
                            Text("SIGN OUT")
                                .font(.system(size: 11, weight: .semibold))
                                .tracking(1)
                                .foregroundColor(Theme.down)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 10)
                                .background(Theme.down.opacity(0.08))
                                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.down.opacity(0.3)))
                                .cornerRadius(8)
                        }
                    }
                }
                .padding(16)
            }
            .background(Theme.paper)
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .onChange(of: statusMessage) { msg in
                guard msg != nil else { return }
                Task {
                    try? await Task.sleep(nanoseconds: 4_000_000_000)
                    statusMessage = nil
                }
            }
        }
    }

    private var canTest: Bool {
        !sending && deviceTokens.token != nil
    }

    private func sendTest() {
        guard let token = deviceTokens.token else { return }
        sending = true
        statusMessage = nil
        Task {
            let api = API(baseURL: session.serverURL, token: session.token)
            do {
                try await api.sendTestPush(deviceToken: token)
                statusMessage = "Test push sent — check your notifications"
            } catch let e as APIError {
                statusMessage = "Failed: \(e.message)"
            } catch {
                statusMessage = "Connection failed"
            }
            sending = false
        }
    }

    @ViewBuilder
    private func section<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.system(size: 10, weight: .bold))
                .tracking(1.5)
                .foregroundColor(Theme.subtle)
            VStack(alignment: .leading, spacing: 12) { content() }
                .card()
        }
    }

    @ViewBuilder
    private func row(_ key: String, _ value: String) -> some View {
        HStack(alignment: .top) {
            Text(key)
                .font(.system(size: 12))
                .foregroundColor(Theme.subtle)
            Spacer()
            Text(value)
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(Theme.ink)
                .multilineTextAlignment(.trailing)
                .lineLimit(2)
                .truncationMode(.middle)
        }
    }
}
