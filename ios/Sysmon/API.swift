import Foundation

struct API {
    let baseURL: String
    let token: String?

    private static let decoder = JSONDecoder()
    private static let encoder = JSONEncoder()

    // Dedicated URLSession that ignores cookies - we authenticate with
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

    // The reply can carry a verdict on the token itself (see
    // SubscribeResponse). The HTTP call succeeding means the
    // subscription is stored; a body that doesn't decode (older server)
    // just means "no verdict", not a failed subscribe.
    @discardableResult
    func subscribePush(deviceToken: String, label: String) async throws -> SubscribeResponse {
        let data = try await send("/api/push/subscribe", method: "POST", body: [
            "device_token": deviceToken,
            "platform": "ios",
            "label": label
        ])
        return (try? Self.decoder.decode(SubscribeResponse.self, from: data))
            ?? SubscribeResponse(status: nil, tokenStatus: nil, message: nil)
    }

    func unsubscribePush(deviceToken: String) async throws {
        try await deleteVoid("/api/push/subscribe", body: ["device_token": deviceToken])
    }

    // Returns the server's warning, if any (e.g. "push is disabled - this
    // test was delivered but real alerts are not being sent").
    func sendTestPush(deviceToken: String) async throws -> String? {
        let data = try await send("/api/push/test", method: "POST",
                                  body: ["device_token": deviceToken])
        let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        return obj?["warning"] as? String
    }

    // Acknowledge an active alert. Admin-only on the server; the caller
    // gates the UI on role but the server is the real authority.
    // The server refuses an ack without a note: triage means saying
    // what you know, not just clicking.
    func ackHost(objectName: String, note: String) async throws {
        let escaped = objectName.addingPercentEncoding(
            withAllowedCharacters: .urlPathAllowed) ?? objectName
        try await postVoid("/api/monitoring/ack/\(escaped)", body: ["note": note])
    }

    // The inverse: the alert returns to the active board.
    func unackHost(objectName: String) async throws {
        let escaped = objectName.addingPercentEncoding(
            withAllowedCharacters: .urlPathAllowed) ?? objectName
        try await postVoid("/api/monitoring/unack/\(escaped)", body: EmptyBody())
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
        // A 401 from /api/auth/login means bad credentials - surface the
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
