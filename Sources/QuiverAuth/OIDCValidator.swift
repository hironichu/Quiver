import Foundation
import JWTKit

struct OIDCPrincipal: Sendable {
    let subject: String
    let email: String?
}

enum OIDCValidationResult: Sendable {
    case valid(OIDCPrincipal)
    case invalid(reason: String)
}

struct OIDCValidator: Sendable {
    let configuration: OIDCConfiguration

    func validate(token: String) async -> OIDCValidationResult {
        guard let claimsJSON = decodeClaims(token: token) else {
            return .invalid(reason: "invalid JWT encoding")
        }

        do {
            try await verifySignature(token: token)
        } catch {
            if !configuration.allowUnverifiedSignature {
                return .invalid(reason: "invalid signature: \(error)")
            }
        }

        if let issuer = configuration.issuer,
            let tokenIssuer = claimsJSON["iss"] as? String,
            tokenIssuer != issuer
        {
            return .invalid(reason: "issuer mismatch")
        }

        if let expectedAudience = configuration.audience,
            !audienceContains(expectedAudience: expectedAudience, claims: claimsJSON)
        {
            return .invalid(reason: "audience mismatch")
        }

        let now = Int(Date().timeIntervalSince1970)
        let skew = max(0, configuration.clockSkewSeconds)

        if let exp = numericClaim("exp", in: claimsJSON), now > exp + skew {
            return .invalid(reason: "token expired")
        }

        if let nbf = numericClaim("nbf", in: claimsJSON), now + skew < nbf {
            return .invalid(reason: "token not active yet")
        }

        guard let subject = claimsJSON["sub"] as? String, !subject.isEmpty else {
            return .invalid(reason: "missing subject")
        }

        let email = claimsJSON["email"] as? String
        return .valid(OIDCPrincipal(subject: subject, email: email))
    }

    private func verifySignature(token: String) async throws {
        struct SignatureOnlyPayload: JWTPayload {
            func verify(using _: some JWTAlgorithm) throws {}
        }

        let keys = JWTKeyCollection()
        var hasAnyVerifier = false

        if let secret = configuration.hs256SharedSecret, !secret.isEmpty {
            await keys.add(hmac: HMACKey(from: secret), digestAlgorithm: .sha256)
            hasAnyVerifier = true
        }

        if let jwks = try await resolveJWKsIfConfigured() {
            let jwksData = try JSONEncoder().encode(jwks)
            guard let jwksJSON = String(data: jwksData, encoding: .utf8) else {
                throw NSError(
                    domain: "QuiverAuth.OIDCValidator",
                    code: 30,
                    userInfo: [NSLocalizedDescriptionKey: "failed to encode JWKS JSON"]
                )
            }
            _ = try await keys.add(jwksJSON: jwksJSON)
            hasAnyVerifier = true
        }

        guard hasAnyVerifier else {
            throw NSError(
                domain: "QuiverAuth.OIDCValidator",
                code: 31,
                userInfo: [NSLocalizedDescriptionKey: "no JWT verifier configured (set HS secret or JWKS)"]
            )
        }

        _ = try await keys.verify(token, as: SignatureOnlyPayload.self)
    }

    private func decodeClaims(token: String) -> [String: Any]? {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { return nil }
        guard let payloadData = decodeBase64URL(String(parts[1])) else { return nil }
        return try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any]
    }

    private func resolveJWKsIfConfigured() async throws -> OIDCJWKS? {
        if !configuration.staticJWKs.isEmpty {
            return OIDCJWKS(keys: configuration.staticJWKs)
        }

        guard let rawURL = configuration.jwksURL, !rawURL.isEmpty else {
            return nil
        }

        guard let url = URL(string: rawURL) else {
            throw NSError(
                domain: "QuiverAuth.OIDCValidator",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "jwksURL is required for non-HS256 signature verification"]
            )
        }

        do {
            return try await OIDCJWKSCache.shared.getJWKS(
                url: url,
                ttlSeconds: configuration.jwksCacheTTLSeconds
            )
        } catch {
            throw NSError(
                domain: "QuiverAuth.OIDCValidator",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "failed to fetch JWKS: \(error)"]
            )
        }
    }

    private func decodeBase64URL(_ value: String) -> Data? {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64)
    }

    private func numericClaim(_ name: String, in claims: [String: Any]) -> Int? {
        if let intValue = claims[name] as? Int {
            return intValue
        }
        if let doubleValue = claims[name] as? Double {
            return Int(doubleValue)
        }
        if let stringValue = claims[name] as? String, let intValue = Int(stringValue) {
            return intValue
        }
        return nil
    }

    private func audienceContains(expectedAudience: String, claims: [String: Any]) -> Bool {
        if let aud = claims["aud"] as? String {
            return aud == expectedAudience
        }
        if let audArray = claims["aud"] as? [String] {
            return audArray.contains(expectedAudience)
        }
        return false
    }
}