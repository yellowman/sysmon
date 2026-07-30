import SwiftUI

struct LoginView: View {
    @EnvironmentObject var session: Session
    @State private var serverURL = ""
    @State private var username = ""
    @State private var password = ""
    @State private var loading = false
    @State private var error: String?

    private var displayMessage: String? { session.loginNote ?? error }

    var body: some View {
        ZStack {
            Theme.paper.ignoresSafeArea()

            VStack(spacing: 0) {
                Spacer()

                // Wordmark
                HStack(spacing: 0) {
                    Text("sys")
                        .fontWeight(.black)
                        .foregroundColor(Theme.ink)
                    Text("mon")
                        .fontWeight(.regular)
                        .foregroundColor(Theme.subtle)
                }
                .font(.system(size: 34, design: .serif))
                .tracking(-0.5)

                HStack(spacing: 6) {
                    Circle()
                        .fill(Theme.up)
                        .frame(width: 5, height: 5)
                    Text("NETWORK MONITORING")
                        .font(.system(size: 10, weight: .semibold))
                        .tracking(2.5)
                        .foregroundColor(Theme.subtle)
                }
                .padding(.top, 8)
                .padding(.bottom, 40)

                VStack(spacing: 14) {
                    if let msg = displayMessage {
                        HStack(spacing: 8) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.system(size: 11))
                            Text(msg)
                                .font(.system(size: 12))
                        }
                        .foregroundColor(Theme.down)
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Theme.down.opacity(0.08))
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.down.opacity(0.2)))
                        .cornerRadius(8)
                        .transition(.opacity)
                    }

                    FieldLabel("SERVER")
                    TextField("sysmon.example.com", text: $serverURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .textFieldStyle(SysmonFieldStyle())

                    FieldLabel("USERNAME")
                    TextField("", text: $username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .textFieldStyle(SysmonFieldStyle())

                    FieldLabel("PASSWORD")
                    SecureField("", text: $password)
                        .textFieldStyle(SysmonFieldStyle())

                    Button(action: login) {
                        Text(loading ? "SIGNING IN..." : "SIGN IN")
                    }
                    .buttonStyle(SlabButtonStyle(enabled: canSubmit))
                    .disabled(!canSubmit)
                    .padding(.top, 8)
                }
                .padding(.horizontal, 32)

                Spacer()
                Spacer()
            }
            .animation(.easeOut(duration: 0.2), value: displayMessage)
        }
        .onAppear {
            serverURL = session.serverURL
            username = session.username ?? ""
        }
    }

    private var canSubmit: Bool {
        !loading && !serverURL.isEmpty && !username.isEmpty && !password.isEmpty
    }

    private func login() {
        guard canSubmit else { return }
        loading = true
        error = nil
        session.loginNote = nil
        let normalized = Session.normalize(serverURL)
        session.serverURL = normalized
        serverURL = normalized
        Task {
            do {
                try await session.login(username: username, password: password)
            } catch let e as APIError {
                error = e.message
            } catch {
                error = "Connection failed"
            }
            loading = false
        }
    }
}

struct FieldLabel: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text)
            .font(.system(size: 10, weight: .semibold))
            .tracking(1.5)
            .foregroundColor(Theme.subtle)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct SysmonFieldStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .font(.system(size: 14))
            .padding(.horizontal, 12)
            .padding(.vertical, 11)
            .background(Theme.surfaceSubtle)
            .cornerRadius(8)
            .overlay(RoundedRectangle(cornerRadius: 8)
                .stroke(Theme.hairline, lineWidth: 1))
    }
}
