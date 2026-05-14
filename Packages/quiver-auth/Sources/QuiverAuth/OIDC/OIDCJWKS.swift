import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

actor OIDCJWKSCache {
    static let shared = OIDCJWKSCache()

    private struct CacheEntry {
        let expiresAt: Date
        let jwks: OIDCJWKS
    }

    private var entries: [String: CacheEntry] = [:]

    func getJWKS(url: URL, ttlSeconds: Int) async throws -> OIDCJWKS {
        let cacheKey = url.absoluteString
        if let cached = entries[cacheKey], cached.expiresAt > Date() {
            return cached.jwks
        }

        let (data, _) = try await URLSession.shared.data(from: url)
        let decoded = try JSONDecoder().decode(OIDCJWKS.self, from: data)
        let expiry = Date().addingTimeInterval(TimeInterval(max(1, ttlSeconds)))
        entries[cacheKey] = CacheEntry(expiresAt: expiry, jwks: decoded)
        return decoded
    }
}
