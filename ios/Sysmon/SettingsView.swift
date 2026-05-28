import SwiftUI
import UIKit

struct SettingsView: View {
    @EnvironmentObject var session: Session
    @State private var sending = false
    @State private var statusMessage: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    section("ACCOUNT") {
                        row("Username", session.username ?? "—")
                        row("Role", (session.role ?? "—").uppercased())
                        row("Server", session.serverURL)
                    }

                    section("DEVICE") {
                        row("Push token",
                            DeviceTokenStore.shared.token.map { String($0.prefix(16)) + "…" } ?? "Not registered")
                        if let msg = statusMessage {
                            Text(msg).font(.system(size: 11)).foregroundColor(.gray)
                        }
                        Button(action: sendTest) {
                            Text(sending ? "SENDING..." : "SEND TEST NOTIFICATION")
                                .font(.system(size: 11, weight: .semibold))
                                .tracking(1)
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 10)
                                .background(canTest ? Color.black : Color.gray.opacity(0.3))
                                .cornerRadius(8)
                        }
                        .disabled(!canTest)
                        .padding(.top, 4)
                    }

                    section("SESSION") {
                        Button(action: session.logout) {
                            Text("SIGN OUT")
                                .font(.system(size: 11, weight: .semibold))
                                .tracking(1)
                                .foregroundColor(.red)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 10)
                                .background(Color.red.opacity(0.08))
                                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.red.opacity(0.3)))
                                .cornerRadius(8)
                        }
                    }
                }
                .padding(16)
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var canTest: Bool {
        !sending && DeviceTokenStore.shared.token != nil
    }

    private func sendTest() {
        guard let token = DeviceTokenStore.shared.token else { return }
        sending = true
        statusMessage = nil
        Task {
            let api = API(baseURL: session.serverURL, token: session.token)
            do {
                let _: EmptyResponse = try await api.post(
                    "/api/push/test",
                    body: ["device_token": token]
                )
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
                .foregroundColor(.gray)
            VStack(alignment: .leading, spacing: 12) { content() }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(white: 0.98))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(white: 0.92)))
                .cornerRadius(10)
        }
    }

    @ViewBuilder
    private func row(_ key: String, _ value: String) -> some View {
        HStack(alignment: .top) {
            Text(key)
                .font(.system(size: 12))
                .foregroundColor(.gray)
            Spacer()
            Text(value)
                .font(.system(size: 12, design: .monospaced))
                .multilineTextAlignment(.trailing)
                .lineLimit(2)
                .truncationMode(.middle)
        }
    }
}
