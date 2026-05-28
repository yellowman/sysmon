import Foundation

struct API {
    let baseURL: String
    let token: String?

    private static let decoder = JSONDecoder()
    private static let encoder = JSONEncoder()

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

        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse else {
            throw APIError(status: 0, message: "Invalid response")
        }
        if http.statusCode == 401 {
            await MainActor.run { Session.shared?.handleUnauthorized() }
            throw APIError(status: 401, message: "Session expired")
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
