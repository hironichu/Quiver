import Foundation
import HTTP3

struct OIDCTokenSet: Sendable, Equatable {
    var accessToken: String?
    var idToken: String?
    var refreshToken: String?
    var tokenType: String?
    var scope: String?
    var expiresAt: Date?

    func validationToken() -> String? {
        if let idToken, !idToken.isEmpty {
            return idToken
        }
        if let accessToken, !accessToken.isEmpty {
            return accessToken
        }
        return nil
    }

    func shouldRefresh(leewaySeconds: Int) -> Bool {
        guard let expiresAt else { return false }
        return expiresAt <= Date().addingTimeInterval(TimeInterval(max(0, leewaySeconds)))
    }
}

struct OIDCServerSessionRecord: Sendable, Equatable {
    let sessionID: String
    let createdAt: Date
    var updatedAt: Date
    var tokenSet: OIDCTokenSet
    var userInfoClaims: [String: HTTP3SessionValue]?
    var userInfoFetchedAt: Date?
}

actor OIDCServerSessionStore {
    static let shared = OIDCServerSessionStore()

    private var records: [String: OIDCServerSessionRecord] = [:]

    func create(tokenSet: OIDCTokenSet) -> OIDCServerSessionRecord {
        let now = Date()
        let sessionID = makeSessionID()
        let record = OIDCServerSessionRecord(
            sessionID: sessionID,
            createdAt: now,
            updatedAt: now,
            tokenSet: tokenSet,
            userInfoClaims: nil,
            userInfoFetchedAt: nil
        )
        records[sessionID] = record
        return record
    }

    func get(sessionID: String) -> OIDCServerSessionRecord? {
        records[sessionID]
    }

    func update(sessionID: String, tokenSet: OIDCTokenSet) -> OIDCServerSessionRecord? {
        guard var existing = records[sessionID] else { return nil }
        existing.tokenSet = tokenSet
        existing.updatedAt = Date()
        records[sessionID] = existing
        return existing
    }

    func mutate(
        sessionID: String,
        transform: @Sendable (inout OIDCServerSessionRecord) -> Void
    ) -> OIDCServerSessionRecord? {
        guard var existing = records[sessionID] else { return nil }
        transform(&existing)
        existing.updatedAt = Date()
        records[sessionID] = existing
        return existing
    }

    func delete(sessionID: String) {
        records.removeValue(forKey: sessionID)
    }

    private func makeSessionID() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: UInt8.min...UInt8.max)
        }

        return Data(bytes)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
