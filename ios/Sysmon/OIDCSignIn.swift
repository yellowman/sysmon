import AuthenticationServices
import CryptoKit
import Foundation
import Security
import UIKit

@MainActor
final class OIDCSignIn: NSObject, ASWebAuthenticationPresentationContextProviding {
    private var browser: ASWebAuthenticationSession?

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }.first { $0.isKeyWindow } ?? ASPresentationAnchor()
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    func signIn(serverURL: String) async throws -> LoginResponse {
        guard let server = URL(string: serverURL), server.host != nil,
              server.user == nil, server.password == nil, server.query == nil, server.fragment == nil,
              server.path.isEmpty || server.path == "/",
              server.scheme == "https" || (server.scheme == "http" && server.host == "localhost") else {
            throw APIError(status: 0, message: "SSO requires an HTTPS server URL")
        }
        var random = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else {
            throw APIError(status: 0, message: "Could not start secure sign-in")
        }
        let verifier = base64URL(Data(random))
        let challenge = base64URL(Data(SHA256.hash(data: Data(verifier.utf8))))
        var start = URLComponents(url: server.appendingPathComponent("auth/login"), resolvingAgainstBaseURL: false)!
        start.queryItems = [URLQueryItem(name: "mobile_challenge", value: challenge)]
        let code: String = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, Error>) in
            let flow = ASWebAuthenticationSession(url: start.url!, callbackURLScheme: "sysmon") { callback, error in
                Task { @MainActor in
                    self.browser = nil
                    if let error { continuation.resume(throwing: error); return }
                    guard let callback, callback.scheme == "sysmon", callback.host == "auth", callback.path == "/callback",
                          let code = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems?
                            .first(where: { $0.name == "code" })?.value, !code.isEmpty else {
                        continuation.resume(throwing: APIError(status: 0, message: "Invalid SSO callback"))
                        return
                    }
                    continuation.resume(returning: code)
                }
            }
            flow.presentationContextProvider = self
            browser = flow
            if !flow.start() {
                browser = nil
                continuation.resume(throwing: APIError(status: 0, message: "Could not open SSO sign-in"))
            }
        }
        return try await API(baseURL: serverURL, token: nil).post("/api/auth/mobile-exchange",
            body: ["code": code, "verifier": verifier])
    }
}
