import Foundation

struct API {
    let baseURL: String
    let token: String?

    private var decoder: JSONDecoder {
        let d = JSONDecoder()
        return d
    }

    func get<T: Decodable>(_ path: String) async throws -> T {
        try await request(path, method: "GET", body: Optional<EmptyBody>.none)
    }

    func post<T: Decodable, B: Encodable>(_ path: String, body: B) async throws -> T {
        try await request(path, method: "POST", body: body)
    }

    func delete<T: Decodable, B: Encodable>(_ path: String, body: B) async throws -> T {
        try await request(path, method: "DELETE", body: body)
    }

    private func request<T: Decodable, B: Encodable>(_ path: String, method: String, body: B?) async throws -> T {
        guard let url = URL(string: baseURL + path) else {
            throw APIError(status: 0, message: "Invalid URL")
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token = token {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let body = body {
            req.httpBody = try JSONEncoder().encode(body)
        }

        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse else {
            throw APIError(status: 0, message: "Invalid response")
        }
        if http.statusCode == 401 {
            // Session expired — bounce to login on the main actor
            await MainActor.run { Session.shared?.token = nil }
            throw APIError(status: 401, message: "Session expired")
        }
        if !(200..<300).contains(http.statusCode) {
            let msg = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["message"] as? String ?? "Request failed"
            throw APIError(status: http.statusCode, message: msg)
        }
        if T.self == EmptyResponse.self {
            return EmptyResponse() as! T
        }
        return try decoder.decode(T.self, from: data)
    }
}

struct EmptyBody: Encodable {}
struct EmptyResponse: Decodable {}
