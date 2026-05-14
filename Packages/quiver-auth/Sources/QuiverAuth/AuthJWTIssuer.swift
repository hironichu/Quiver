import Foundation
import Crypto
import HTTP3

/// Issues compact HS256 JWTs for application-owned authentication flows.
///
/// The issued token shape intentionally matches what `OIDCValidator` already accepts:
/// `sub`, optional `iss`, optional `aud`, `iat`, `exp`, and any additional typed claims.
public struct AuthJWTIssuer: Sendable {
    private let configuration: AuthJWTIssuerConfiguration

    /// Creates a JWT issuer from signing and default-claim configuration.
    public init(configuration: AuthJWTIssuerConfiguration) {
        self.configuration = configuration
    }

    /// Issues a signed JWT for an authenticated principal.
    ///
    /// - Parameters:
    ///   - principal: The principal that becomes the JWT subject.
    ///   - expiresIn: Optional lifetime override. Defaults to `AuthJWTIssuerConfiguration.defaultTTL`.
    ///   - additionalClaims: Extra JSON-compatible claims to merge into the token payload.
    /// - Returns: A compact JWT signed with HS256.
    public func issueToken(
        for principal: AuthPrincipal,
        expiresIn: Duration? = nil,
        additionalClaims: [String: HTTP3SessionValue] = [:]
    ) throws -> String {
        guard !configuration.hs256SharedSecret.isEmpty else {
            throw NSError(
                domain: "QuiverAuth.AuthJWTIssuer",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "hs256SharedSecret is required"]
            )
        }

        let now = Date()
        let ttl = expiresIn ?? configuration.defaultTTL
        let expiresAt = now.addingTimeInterval(TimeInterval(ttl.wholeSecondsRoundedUp))

        var header: [String: HTTP3SessionValue] = [
            "alg": .string("HS256"),
            "typ": .string("JWT"),
        ]
        if let keyID = configuration.keyID, !keyID.isEmpty {
            header["kid"] = .string(keyID)
        }

        var payload = additionalClaims
        for (key, value) in principal.claims where payload[key] == nil {
            payload[key] = value
        }
        payload["sub"] = .string(principal.subject)
        payload["source"] = .string(principal.source)
        payload["iat"] = .number(floor(now.timeIntervalSince1970))
        payload["exp"] = .number(floor(expiresAt.timeIntervalSince1970))
        if let email = principal.email, !email.isEmpty {
            payload["email"] = .string(email)
        }
        if let issuer = configuration.issuer, !issuer.isEmpty {
            payload["iss"] = .string(issuer)
        }
        if let audience = configuration.audience, !audience.isEmpty {
            payload["aud"] = .string(audience)
        }

        let headerPart = try base64URLJSON(header)
        let payloadPart = try base64URLJSON(payload)
        let signingInput = "\(headerPart).\(payloadPart)"
        let key = SymmetricKey(data: Data(configuration.hs256SharedSecret.utf8))
        let signature = HMAC<SHA256>.authenticationCode(for: Data(signingInput.utf8), using: key)
        return "\(signingInput).\(quiverAuthBase64URL(Data(signature)))"
    }

    private func base64URLJSON(_ object: [String: HTTP3SessionValue]) throws -> String {
        let data = try JSONEncoder().encode(object)
        return quiverAuthBase64URL(data)
    }
}
