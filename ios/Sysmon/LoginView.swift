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
        VStack(spacing: 0) {
            Spacer()

            HStack(spacing: 0) {
                Text("sys").fontWeight(.heavy)
                Text("mon").fontWeight(.regular).foregroundColor(Color(white: 0.45))
            }
            .font(.system(size: 28))
            .tracking(-0.5)

            Text("NETWORK MONITORING")
                .font(.system(size: 10, weight: .semibold))
                .tracking(2)
                .foregroundColor(.gray)
                .padding(.top, 4)
                .padding(.bottom, 40)

            VStack(spacing: 14) {
                if let msg = displayMessage {
                    Text(msg)
                        .font(.system(size: 12))
                        .foregroundColor(.red)
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.red.opacity(0.08))
                        .cornerRadius(8)
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
                        .font(.system(size: 13, weight: .semibold))
                        .tracking(1)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                        .background(canSubmit ? Color.black : Color.gray.opacity(0.3))
                        .cornerRadius(8)
                }
                .disabled(!canSubmit)
                .padding(.top, 8)
            }
            .padding(.horizontal, 32)

            Spacer()
            Spacer()
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
            .foregroundColor(.gray)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct SysmonFieldStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .font(.system(size: 14))
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(Color(white: 0.97))
            .cornerRadius(8)
            .overlay(RoundedRectangle(cornerRadius: 8)
                .stroke(Color(white: 0.9), lineWidth: 1))
    }
}
