import Foundation

struct API {
    let baseURL: String
    let token: String?

    private static let decoder = JSONDecoder()
    private static let encoder = JSONEncoder()

    // Dedicated URLSession that ignores cookies — we authenticate with
    // Bearer tokens and don't want the login-set sysmon_session cookie
    // shadowing our Authorization header on every request.
    private static let session: URLSession = {
        let config = URLSessionConfiguration.default
        config.httpCookieAcceptPolicy = .never
        config.httpShouldSetCookies = false
        config.httpCookieStorage = nil
        return URLSession(configuration: config)
    }()

    func get<T: Decodable>(_ path: String) async throws -> T {
        let data = try await send(path, method: "GET", body: Optional<EmptyBody>.none)
        return try Self.decoder.decode(T.self, from: data)
    }

    func post<T: Decodable, B: Encodable>(_ path: String, body: B) async throws -> T {
        let data = try await send(path, method: "POST", body: body)
        return try Self.decoder.decode(T.self, from: data)
    }

    func postVoid<B: Encodable>(_ path: String, body: B) async throws {
        _ = try await send(path, method: "POST", body: body)
    }

    func deleteVoid<B: Encodable>(_ path: String, body: B) async throws {
        _ = try await send(path, method: "DELETE", body: body)
    }

    // Domain helpers
    func logout() async throws {
        try await postVoid("/api/auth/logout", body: EmptyBody())
    }

    func subscribePush(deviceToken: String, label: String) async throws {
        try await postVoid("/api/push/subscribe", body: [
            "device_token": deviceToken,
            "platform": "ios",
            "label": label
        ])
    }

    func unsubscribePush(deviceToken: String) async throws {
        try await deleteVoid("/api/push/subscribe", body: ["device_token": deviceToken])
    }

    func sendTestPush(deviceToken: String) async throws {
        try await postVoid("/api/push/test", body: ["device_token": deviceToken])
    }

    private func send<B: Encodable>(_ path: String, method: String, body: B?) async throws -> Data {
        guard let url = URL(string: baseURL + path) else {
            throw APIError(status: 0, message: "Invalid URL")
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            req.httpBody = try Self.encoder.encode(body)
        }

        let (data, resp) = try await Self.session.data(for: req)
        guard let http = resp as? HTTPURLResponse else {
            throw APIError(status: 0, message: "Invalid response")
        }
        // A 401 from /api/auth/login means bad credentials — surface the
        // server's actual message ("Invalid credentials") rather than
        // pretending a session expired. For every other path, a 401 means
        // the bearer token is dead so clear session state and bounce to
        // the login screen.
        if http.statusCode == 401 && path != "/api/auth/login" {
            await MainActor.run { Session.shared?.handleUnauthorized() }
        }
        if !(200..<300).contains(http.statusCode) {
            let msg = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["message"] as? String
                ?? "Request failed (\(http.statusCode))"
            throw APIError(status: http.statusCode, message: msg)
        }
        return data
    }
}

struct EmptyBody: Encodable {}
