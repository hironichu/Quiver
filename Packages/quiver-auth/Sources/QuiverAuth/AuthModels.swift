import Foundation
import HTTP3

/// The authenticated identity produced by QuiverAuth.
public struct AuthPrincipal: Sendable, Equatable {
    /// Stable subject identifier for the authenticated user or service.
    public let subject: String
    /// Optional email address associated with the principal.
    public let email: String?
    /// Source that authenticated the principal, such as `oidc`, `cookie`, or a custom validator name.
    public let source: String
    /// Additional typed claims associated with the principal.
    public let claims: [String: HTTP3SessionValue]

    /// Creates an authenticated principal.
    public init(
        subject: String,
        email: String? = nil,
        source: String,
        claims: [String: HTTP3SessionValue] = [:]
    ) {
        self.subject = subject
        self.email = email
        self.source = source
        self.claims = claims
    }
}

/// Default typed session payload attached by `HTTP3AuthGuard`.
public struct QuiverAuthSession: Codable, Sendable, Equatable {
    /// Stable subject identifier for the authenticated principal.
    public let subject: String
    /// Source that authenticated the principal.
    public let source: String
    /// Optional email address associated with the principal.
    public let email: String?
    /// Auth claims written into the session payload.
    public let claims: [String: HTTP3SessionValue]

    /// Creates a default QuiverAuth session payload.
    public init(
        subject: String,
        source: String,
        email: String?,
        claims: [String: HTTP3SessionValue]
    ) {
        self.subject = subject
        self.source = source
        self.email = email
        self.claims = claims
    }
}

/// The result of evaluating a request against an auth policy.
public enum AuthDecision: Sendable, Equatable {
    /// Allow the request and expose the authenticated principal.
    case allow(AuthPrincipal)
    /// Deny the request with an HTTP status code and diagnostic reason.
    case deny(status: Int, reason: String)
}

/// Context passed to custom auth validators.
public struct AuthValidationContext: Sendable {
    /// Request being authenticated.
    public let request: HTTP3Request
    /// Credentials extracted from the request.
    public let snapshot: AuthCredentialSnapshot
    /// Whether the request arrived through a trusted Quiver gateway path.
    public let isFromGateway: Bool

    /// Creates a validation context for a custom auth validator.
    public init(
        request: HTTP3Request,
        snapshot: AuthCredentialSnapshot,
        isFromGateway: Bool
    ) {
        self.request = request
        self.snapshot = snapshot
        self.isFromGateway = isFromGateway
    }
}

/// A custom authentication hook used by `AuthPolicy`.
public struct AuthValidator: Sendable {
    /// Human-readable validator name used in logs and diagnostics.
    public let name: String

    private let validateHandler: @Sendable (AuthValidationContext) async -> AuthDecision?

    /// Creates a custom validator closure.
    public init(
        name: String,
        validate: @escaping @Sendable (AuthValidationContext) async -> AuthDecision?
    ) {
        self.name = name
        self.validateHandler = validate
    }

    /// Evaluates the validator for a request context.
    public func validate(_ context: AuthValidationContext) async -> AuthDecision? {
        await validateHandler(context)
    }
}

/// Credentials extracted from a request before policy evaluation.
public struct AuthCredentialSnapshot: Sendable {
    /// Bearer token found in a configured authorization header.
    public let bearerToken: String?
    /// Header name that supplied the forwarded identity, when present.
    public let identityHeaderName: String?
    /// Forwarded identity header value, when present.
    public let identityHeaderValue: String?
    /// Forwarded email header value, when present.
    public let emailHeaderValue: String?
    /// Parsed request cookies as `(name, value)` pairs.
    public let cookies: [(String, String)]

    /// Creates a credential snapshot.
    public init(
        bearerToken: String?,
        identityHeaderName: String?,
        identityHeaderValue: String?,
        emailHeaderValue: String?,
        cookies: [(String, String)]
    ) {
        self.bearerToken = bearerToken
        self.identityHeaderName = identityHeaderName
        self.identityHeaderValue = identityHeaderValue
        self.emailHeaderValue = emailHeaderValue
        self.cookies = cookies
    }

    /// Returns the value of the first parsed cookie with the given name.
    public func cookieValue(named name: String) -> String? {
        cookies.first(where: { $0.0 == name })?.1
    }

    /// Returns whether a non-empty cookie with the given name is present.
    public func hasCookie(named name: String) -> Bool {
        guard let value = cookieValue(named: name) else { return false }
        return !value.isEmpty
    }
}

/// Policy mode controlling which authentication signals are accepted.
public enum AuthMode: Sendable {
    /// Only custom validators may authenticate requests.
    case customOnly
    /// Only trusted forwarded identity or cookie-session signals may authenticate requests.
    case forwardOnly
    /// Only OIDC/JWT signals may authenticate requests.
    case oidcOnly
    /// Custom validators, OIDC/JWT, and forwarded signals are evaluated in order.
    case composite

    /// Parses a common string representation into an auth mode.
    public init?(rawValue: String) {
        switch rawValue.lowercased() {
        case "custom", "customonly", "user", "application":
            self = .customOnly
        case "forward", "forwardonly", "proxy":
            self = .forwardOnly
        case "oidc", "jwt", "oidconly":
            self = .oidcOnly
        case "composite", "hybrid":
            self = .composite
        default:
            return nil
        }
    }
}

/// A server-side generic auth session stored by an `AuthSessionStore`.
public struct AuthSessionRecord: Sendable, Equatable {
    /// Opaque session identifier stored in the session cookie.
    public var sessionID: String
    /// Principal associated with the session.
    public var principal: AuthPrincipal
    /// Creation timestamp.
    public var createdAt: Date
    /// Last update timestamp.
    public var updatedAt: Date
    /// Optional expiration timestamp.
    public var expiresAt: Date?

    /// Creates a stored auth session record.
    public init(
        sessionID: String,
        principal: AuthPrincipal,
        createdAt: Date,
        updatedAt: Date,
        expiresAt: Date? = nil
    ) {
        self.sessionID = sessionID
        self.principal = principal
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.expiresAt = expiresAt
    }

    /// Whether the session is expired at the current time.
    public var isExpired: Bool {
        guard let expiresAt else { return false }
        return expiresAt <= Date()
    }
}

/// Storage interface for generic server-side auth sessions.
public protocol AuthSessionStore: Sendable {
    /// Creates a session for a principal.
    func create(principal: AuthPrincipal, expiresAt: Date?) async throws -> AuthSessionRecord
    /// Loads a session by identifier, returning `nil` when it does not exist or is expired.
    func get(sessionID: String) async throws -> AuthSessionRecord?
    /// Updates the principal and expiration for an existing session.
    func update(sessionID: String, principal: AuthPrincipal, expiresAt: Date?) async throws -> AuthSessionRecord?
    /// Deletes a session by identifier.
    func delete(sessionID: String) async throws
}

/// In-memory session store suitable for development, tests, and single-process demos.
public actor InMemoryAuthSessionStore: AuthSessionStore {
    /// Shared in-memory store instance.
    public static let shared = InMemoryAuthSessionStore()

    private var records: [String: AuthSessionRecord] = [:]

    /// Creates an empty in-memory session store.
    public init() {}

    /// Creates a session record for a principal.
    public func create(principal: AuthPrincipal, expiresAt: Date? = nil) -> AuthSessionRecord {
        let now = Date()
        let record = AuthSessionRecord(
            sessionID: makeSessionID(),
            principal: principal,
            createdAt: now,
            updatedAt: now,
            expiresAt: expiresAt
        )
        records[record.sessionID] = record
        return record
    }

    /// Loads a non-expired session record by identifier.
    public func get(sessionID: String) -> AuthSessionRecord? {
        guard let record = records[sessionID] else { return nil }
        if record.isExpired {
            records.removeValue(forKey: sessionID)
            return nil
        }
        return record
    }

    /// Updates a session record when it exists.
    public func update(
        sessionID: String,
        principal: AuthPrincipal,
        expiresAt: Date? = nil
    ) -> AuthSessionRecord? {
        guard var record = records[sessionID] else { return nil }
        record.principal = principal
        record.updatedAt = Date()
        record.expiresAt = expiresAt
        records[sessionID] = record
        return record
    }

    /// Deletes a session record by identifier.
    public func delete(sessionID: String) {
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

/// The `SameSite` attribute for cookies emitted by QuiverAuth.
///
/// Use this instead of raw strings so invalid `SameSite` values are caught at compile time.
public enum AuthCookieSameSite: String, Sendable, Codable, CaseIterable {
    /// Send the cookie on same-site requests and top-level cross-site navigations.
    case lax = "Lax"
    /// Send the cookie only for same-site requests.
    case strict = "Strict"
    /// Send the cookie in all contexts. Browsers require `Secure` for this mode.
    case none = "None"
}

/// Convenience duration factories for auth cookie and JWT lifetimes.
public extension Duration {
    /// Creates a duration from whole minutes.
    static func minutes(_ value: Int64) -> Duration {
        .seconds(value * 60)
    }

    /// Creates a duration from whole hours.
    static func hours(_ value: Int64) -> Duration {
        .seconds(value * 60 * 60)
    }

    /// Creates a duration from whole days.
    static func days(_ value: Int64) -> Duration {
        .seconds(value * 24 * 60 * 60)
    }
}

/// Shared options used when QuiverAuth emits a session cookie.
public struct AuthCookieConfiguration: Sendable, Equatable {
    /// Cookie name, for example `quiver-auth-session` or `z-token`.
    public var name: String
    /// Cookie path attribute. Defaults to `/` for application-wide sessions.
    public var path: String
    /// Optional cookie lifetime. `nil` creates a browser-session cookie.
    public var maxAge: Duration?
    /// Whether to include the `Secure` attribute.
    public var secure: Bool
    /// Whether to include the `HttpOnly` attribute.
    public var httpOnly: Bool
    /// The typed `SameSite` attribute.
    public var sameSite: AuthCookieSameSite

    /// Creates typed cookie attributes for a `Set-Cookie` header.
    public init(
        name: String,
        path: String = "/",
        maxAge: Duration? = .days(7),
        secure: Bool = true,
        httpOnly: Bool = true,
        sameSite: AuthCookieSameSite = .lax
    ) {
        self.name = name
        self.path = path
        self.maxAge = maxAge
        self.secure = secure
        self.httpOnly = httpOnly
        self.sameSite = sameSite
    }
}

/// A concrete `Set-Cookie` value builder.
public struct AuthCookie: Sendable, Equatable {
    /// Cookie attributes shared across issued and clearing cookies.
    public var configuration: AuthCookieConfiguration
    /// Cookie value to write.
    public var value: String

    /// Creates a cookie value from typed cookie attributes.
    public init(configuration: AuthCookieConfiguration, value: String) {
        self.configuration = configuration
        self.value = value
    }

    /// The value to use for a `Set-Cookie` response header.
    public var headerValue: String {
        var parts = ["\(configuration.name)=\(value)"]
        parts.append("Path=\(configuration.path)")
        if let maxAge = configuration.maxAge {
            parts.append("Max-Age=\(maxAge.wholeSecondsRoundedUp)")
        }
        if configuration.secure { parts.append("Secure") }
        if configuration.httpOnly { parts.append("HttpOnly") }
        parts.append("SameSite=\(configuration.sameSite.rawValue)")
        return parts.joined(separator: "; ")
    }

    /// A cookie with the same attributes that clears the browser value immediately.
    public var clearing: AuthCookie {
        var clearingConfiguration = configuration
        clearingConfiguration.maxAge = .seconds(0)
        return AuthCookie(configuration: clearingConfiguration, value: "")
    }
}

extension Duration {
    var wholeSecondsRoundedUp: Int {
        guard self > .zero else { return 0 }
        let components = components
        let extraSecond = components.attoseconds > 0 ? 1 : 0
        return Int(clamping: components.seconds) + extraSecond
    }
}

func quiverAuthBase64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func quiverAuthDecodeBase64URL(_ value: String) -> Data? {
    var base64 = value
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")

    let remainder = base64.count % 4
    if remainder > 0 {
        base64 += String(repeating: "=", count: 4 - remainder)
    }
    return Data(base64Encoded: base64)
}

func quiverAuthSessionValue(from value: Any) -> HTTP3SessionValue? {
    switch value {
    case let string as String:
        return .string(string)
    case let bool as Bool:
        return .bool(bool)
    case let int as Int:
        return .number(Double(int))
    case let int64 as Int64:
        return .number(Double(int64))
    case let double as Double:
        return .number(double)
    case let float as Float:
        return .number(Double(float))
    case let array as [Any]:
        var mappedValues: [HTTP3SessionValue] = []
        mappedValues.reserveCapacity(array.count)
        for entry in array {
            guard let mappedEntry = quiverAuthSessionValue(from: entry) else { return nil }
            mappedValues.append(mappedEntry)
        }
        return .array(mappedValues)
    case let object as [String: Any]:
        var mappedObject: [String: HTTP3SessionValue] = [:]
        for (key, entry) in object {
            guard let mappedEntry = quiverAuthSessionValue(from: entry) else { return nil }
            mappedObject[key] = mappedEntry
        }
        return .object(mappedObject)
    case _ as NSNull:
        return .null
    default:
        return nil
    }
}

/// Configuration for QuiverAuth's generic server-side application sessions.
public struct AuthSessionConfiguration: Sendable {
    /// Name of the generic auth session cookie.
    public var cookieName: String
    /// Whether the session cookie includes the `Secure` attribute.
    public var cookieSecure: Bool
    /// Whether the session cookie includes the `HttpOnly` attribute.
    public var cookieHTTPOnly: Bool
    /// `SameSite` policy for the session cookie.
    public var cookieSameSite: AuthCookieSameSite
    /// Path attribute for the session cookie.
    public var cookiePath: String
    /// Session cookie lifetime. `nil` creates a browser-session cookie.
    public var cookieMaxAge: Duration?
    /// Store used to persist generic server-side sessions.
    public var store: (any AuthSessionStore)?

    /// The complete cookie configuration used when emitting session headers.
    public var cookie: AuthCookieConfiguration {
        get {
            AuthCookieConfiguration(
                name: cookieName,
                path: cookiePath,
                maxAge: cookieMaxAge,
                secure: cookieSecure,
                httpOnly: cookieHTTPOnly,
                sameSite: cookieSameSite
            )
        }
        set {
            cookieName = newValue.name
            cookiePath = newValue.path
            cookieMaxAge = newValue.maxAge
            cookieSecure = newValue.secure
            cookieHTTPOnly = newValue.httpOnly
            cookieSameSite = newValue.sameSite
        }
    }

    /// Creates configuration for generic QuiverAuth server-side sessions.
    ///
    /// `cookieMaxAge` uses Swift's `Duration`, so call sites can use `.seconds(300)`,
    /// `.minutes(30)`, `.hours(12)`, or `.days(7)`.
    public init(
        cookieName: String = "quiver-auth-session",
        cookieSecure: Bool = true,
        cookieHTTPOnly: Bool = true,
        cookieSameSite: AuthCookieSameSite = .lax,
        cookiePath: String = "/",
        cookieMaxAge: Duration? = .days(7),
        store: (any AuthSessionStore)? = nil
    ) {
        self.cookieName = cookieName
        self.cookieSecure = cookieSecure
        self.cookieHTTPOnly = cookieHTTPOnly
        self.cookieSameSite = cookieSameSite
        self.cookiePath = cookiePath
        self.cookieMaxAge = cookieMaxAge
        self.store = store
    }

}

/// How the client authenticates to the provider's token endpoint.
/// Derived from OAuth 2.0 RFC 6749 client authentication and
/// OpenID Connect Discovery `token_endpoint_auth_methods_supported`.
public enum OIDCTokenEndpointAuthMethod: String, Sendable, Codable {
    /// Send `Authorization: Basic base64(client_id:client_secret)`.
    case clientSecretBasic = "client_secret_basic"
    /// Send `client_secret` as a form body parameter.
    case clientSecretPost = "client_secret_post"
    /// No client authentication (public clients).
    case none = "none"
}

/// Configuration for OIDC/JWT validation and optional browser login flows.
public struct OIDCConfiguration: Sendable {
    /// Expected token issuer (`iss`).
    public var issuer: String?
    /// Expected token audience (`aud`).
    public var audience: String?
    /// Allowed clock skew, in seconds, when validating temporal JWT claims.
    public var clockSkewSeconds: Int
    /// Shared secret used to verify HS256 tokens.
    public var hs256SharedSecret: String?
    /// Allows JWT claims to be accepted even when signature verification fails.
    public var allowUnverifiedSignature: Bool
    /// Explicit JWKS endpoint used for asymmetric JWT verification.
    public var jwksURL: String?
    /// JWKS cache lifetime in seconds.
    public var jwksCacheTTLSeconds: Int
    /// Static JWKs used for asymmetric JWT verification.
    public var staticJWKs: [OIDCJWK]
    /// Optional browser login flow configuration.
    public var login: OIDCLoginConfiguration

    /// Creates OIDC/JWT validation and login configuration.
    public init(
        issuer: String? = nil,
        audience: String? = nil,
        clockSkewSeconds: Int = 60,
        hs256SharedSecret: String? = nil,
        allowUnverifiedSignature: Bool = false,
        jwksURL: String? = nil,
        jwksCacheTTLSeconds: Int = 300,
        staticJWKs: [OIDCJWK] = [],
        login: OIDCLoginConfiguration = OIDCLoginConfiguration()
    ) {
        self.issuer = issuer
        self.audience = audience
        self.clockSkewSeconds = clockSkewSeconds
        self.hs256SharedSecret = hs256SharedSecret
        self.allowUnverifiedSignature = allowUnverifiedSignature
        self.jwksURL = jwksURL
        self.jwksCacheTTLSeconds = jwksCacheTTLSeconds
        self.staticJWKs = staticJWKs
        self.login = login
    }
}

/// Configuration for browser-based OIDC authorization code login.
public struct OIDCLoginConfiguration: Sendable {
    /// Whether browser login redirects and callbacks are enabled.
    public var enabled: Bool
    /// OIDC discovery document URL.
    public var discoveryURL: String?
    /// Explicit authorization endpoint URL.
    public var authorizationEndpoint: String?
    /// Explicit token endpoint URL.
    public var tokenEndpoint: String?
    /// OAuth client identifier.
    public var clientID: String?
    /// OAuth client secret, when using a confidential client.
    public var clientSecret: String?
    /// Absolute redirect URI registered with the provider.
    public var redirectURI: String?
    /// Local callback path used when deriving a redirect URI from the request authority.
    public var redirectPath: String
    /// Path to redirect to after a successful callback.
    public var callbackSuccessPath: String
    /// Optional path to redirect to after a failed callback.
    public var callbackFailurePath: String?
    /// Optional URL shown by HTML error pages as a retry target.
    public var errorRetryURL: String?
    /// Login state lifetime in seconds.
    public var stateTTLSeconds: Int
    /// Authorization request scope.
    public var scope: String
    /// Authorization request response type.
    public var responseType: String
    /// Optional authorization request prompt value.
    public var prompt: String?
    /// Additional authorization request parameters.
    public var extraAuthorizationParameters: [String: String]
    /// Name of the OIDC browser session cookie.
    public var sessionCookieName: String
    /// Whether the OIDC session cookie includes the `Secure` attribute.
    public var sessionCookieSecure: Bool
    /// Whether the OIDC session cookie includes the `HttpOnly` attribute.
    public var sessionCookieHTTPOnly: Bool
    /// `SameSite` policy for the OIDC session cookie.
    public var sessionCookieSameSite: AuthCookieSameSite
    /// Path attribute for the OIDC session cookie.
    public var sessionCookiePath: String
    /// Server-side OIDC session behavior.
    public var serverSession: OIDCServerSessionConfiguration
    /// Whether login redirects should only be built for browser navigation requests.
    public var browserOnly: Bool
    /// How to authenticate to the token endpoint. When `nil`, auto-detected from
    /// OIDC discovery metadata, falling back to `clientSecretBasic` when a secret is set.
    public var tokenEndpointAuthMethod: OIDCTokenEndpointAuthMethod?
    /// Path to redirect to after a successful logout. Defaults to `"/"`.
    public var postLogoutPath: String

    /// Creates browser OIDC login configuration.
    public init(
        enabled: Bool = false,
        discoveryURL: String? = nil,
        authorizationEndpoint: String? = nil,
        tokenEndpoint: String? = nil,
        clientID: String? = nil,
        clientSecret: String? = nil,
        redirectURI: String? = nil,
        redirectPath: String = "/auth/callback",
        callbackSuccessPath: String = "/",
        callbackFailurePath: String? = nil,
        errorRetryURL: String? = "/",
        stateTTLSeconds: Int = 300,
        scope: String = "openid profile email",
        responseType: String = "code",
        prompt: String? = nil,
        extraAuthorizationParameters: [String: String] = [:],
        sessionCookieName: String = "z-token",
        sessionCookieSecure: Bool = true,
        sessionCookieHTTPOnly: Bool = true,
        sessionCookieSameSite: AuthCookieSameSite = .lax,
        sessionCookiePath: String = "/",
        serverSession: OIDCServerSessionConfiguration = OIDCServerSessionConfiguration(),
        browserOnly: Bool = true,
        tokenEndpointAuthMethod: OIDCTokenEndpointAuthMethod? = nil,
        postLogoutPath: String = "/"
    ) {
        self.enabled = enabled
        self.discoveryURL = discoveryURL
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI
        self.redirectPath = redirectPath
        self.callbackSuccessPath = callbackSuccessPath
        self.callbackFailurePath = callbackFailurePath
        self.errorRetryURL = errorRetryURL
        self.stateTTLSeconds = stateTTLSeconds
        self.scope = scope
        self.responseType = responseType
        self.prompt = prompt
        self.extraAuthorizationParameters = extraAuthorizationParameters
        self.sessionCookieName = sessionCookieName
        self.sessionCookieSecure = sessionCookieSecure
        self.sessionCookieHTTPOnly = sessionCookieHTTPOnly
        self.sessionCookieSameSite = sessionCookieSameSite
        self.sessionCookiePath = sessionCookiePath
        self.serverSession = serverSession
        self.browserOnly = browserOnly
        self.tokenEndpointAuthMethod = tokenEndpointAuthMethod
        self.postLogoutPath = postLogoutPath
    }
}

/// Configuration for storing OIDC token sets server-side behind an opaque cookie.
public struct OIDCServerSessionConfiguration: Sendable {
    /// Whether OIDC callbacks store token sets server-side and put only a session id in the cookie.
    public var enabled: Bool
    /// How soon before token expiration refresh should be attempted.
    public var refreshLeewaySeconds: Int
    /// OIDC session cookie lifetime. `nil` creates a browser-session cookie.
    public var cookieMaxAge: Duration?
    /// Whether to fetch live UserInfo claims while hydrating server sessions.
    public var liveUserInfoEnabled: Bool
    /// Explicit UserInfo endpoint URL.
    public var userInfoEndpoint: String?
    /// UserInfo claim cache lifetime in seconds.
    public var userInfoCacheTTLSeconds: Int
    /// Whether stale cached UserInfo claims may be used when live refresh fails.
    public var failOpenOnUserInfoError: Bool

    /// Creates server-side OIDC session configuration.
    public init(
        enabled: Bool = true,
        refreshLeewaySeconds: Int = 60,
        cookieMaxAge: Duration? = .days(7),
        liveUserInfoEnabled: Bool = true,
        userInfoEndpoint: String? = nil,
        userInfoCacheTTLSeconds: Int = 300,
        failOpenOnUserInfoError: Bool = true
    ) {
        self.enabled = enabled
        self.refreshLeewaySeconds = refreshLeewaySeconds
        self.cookieMaxAge = cookieMaxAge
        self.liveUserInfoEnabled = liveUserInfoEnabled
        self.userInfoEndpoint = userInfoEndpoint
        self.userInfoCacheTTLSeconds = userInfoCacheTTLSeconds
        self.failOpenOnUserInfoError = failOpenOnUserInfoError
    }
}

/// Configuration for QuiverAuth-issued application JWTs.
public struct AuthJWTIssuerConfiguration: Sendable, Equatable {
    /// Token issuer (`iss`). When set, validators should use the same value in `OIDCConfiguration.issuer`.
    public var issuer: String?
    /// Token audience (`aud`). When set, validators should use the same value in `OIDCConfiguration.audience`.
    public var audience: String?
    /// Default lifetime for issued tokens.
    public var defaultTTL: Duration
    /// Shared secret used to sign HS256 tokens.
    public var hs256SharedSecret: String
    /// Optional `kid` value placed in the JWT header.
    public var keyID: String?

    /// Creates JWT issuer configuration.
    public init(
        issuer: String? = nil,
        audience: String? = nil,
        defaultTTL: Duration = .seconds(3600),
        hs256SharedSecret: String,
        keyID: String? = nil
    ) {
        self.issuer = issuer
        self.audience = audience
        self.defaultTTL = defaultTTL
        self.hs256SharedSecret = hs256SharedSecret
        self.keyID = keyID
    }
}

/// A JSON Web Key used to verify JWT signatures.
public struct OIDCJWK: Sendable, Equatable, Codable {
    /// JWK key type, such as `RSA` or `EC`.
    public var kty: String
    /// Optional key identifier.
    public var kid: String?
    /// Optional signing algorithm.
    public var alg: String?
    /// Optional public key use, such as `sig`.
    public var use: String?
    /// RSA modulus.
    public var n: String?
    /// RSA exponent.
    public var e: String?
    /// Elliptic curve name.
    public var crv: String?
    /// Elliptic curve x coordinate.
    public var x: String?
    /// Elliptic curve y coordinate.
    public var y: String?

    /// Creates a JSON Web Key used for JWT signature verification.
    public init(
        kty: String,
        kid: String? = nil,
        alg: String? = nil,
        use: String? = nil,
        n: String? = nil,
        e: String? = nil,
        crv: String? = nil,
        x: String? = nil,
        y: String? = nil
    ) {
        self.kty = kty
        self.kid = kid
        self.alg = alg
        self.use = use
        self.n = n
        self.e = e
        self.crv = crv
        self.x = x
        self.y = y
    }
}

/// A JSON Web Key Set used to verify JWT signatures.
public struct OIDCJWKS: Sendable, Equatable, Codable {
    /// Keys in the JWKS document.
    public var keys: [OIDCJWK]

    /// Creates a JWKS document from keys.
    public init(keys: [OIDCJWK]) {
        self.keys = keys
    }
}

/// Top-level QuiverAuth configuration used to create an `AuthPolicy`.
public struct AuthConfiguration: Sendable {
    /// Policy mode controlling accepted authentication sources.
    public var mode: AuthMode
    /// Header names checked for bearer tokens.
    public var bearerHeaderNames: [String]
    /// Header names checked for forwarded identities.
    public var identityHeaderNames: [String]
    /// Header names checked for forwarded email values.
    public var emailHeaderNames: [String]
    /// Cookie names checked for cookie-based auth and JWT cookies.
    public var sessionCookieNames: [String]
    /// Whether forwarded identity and cookie auth require a trusted gateway marker.
    public var requireGatewayMarkerForForwardedIdentity: Bool
    /// Whether configured session cookies may authenticate forwarded requests.
    public var allowCookieSessionAsAuth: Bool
    /// Custom validators evaluated before built-in auth paths.
    public var validators: [AuthValidator]
    /// Generic server-side auth session configuration.
    public var session: AuthSessionConfiguration?
    /// OIDC/JWT validation and login configuration.
    public var oidc: OIDCConfiguration?
    /// Custom JWT issuer configuration used by `AuthPolicy.issueJWT`.
    public var jwtIssuer: AuthJWTIssuerConfiguration?

    /// Creates an auth policy configuration.
    public init(
        mode: AuthMode = .composite,
        bearerHeaderNames: [String] = ["authorization"],
        identityHeaderNames: [String] = [
            "x-authenticated-user",
            "x-auth-request-user",
            "x-forwarded-user",
        ],
        emailHeaderNames: [String] = [
            "x-auth-request-email",
            "x-authenticated-email",
            "x-forwarded-email",
        ],
        sessionCookieNames: [String] = [],
        requireGatewayMarkerForForwardedIdentity: Bool = true,
        allowCookieSessionAsAuth: Bool = false,
        validators: [AuthValidator] = [],
        session: AuthSessionConfiguration? = nil,
        oidc: OIDCConfiguration? = nil,
        jwtIssuer: AuthJWTIssuerConfiguration? = nil
    ) {
        self.mode = mode
        self.bearerHeaderNames = bearerHeaderNames
        self.identityHeaderNames = identityHeaderNames
        self.emailHeaderNames = emailHeaderNames
        self.sessionCookieNames = sessionCookieNames
        self.requireGatewayMarkerForForwardedIdentity = requireGatewayMarkerForForwardedIdentity
        self.allowCookieSessionAsAuth = allowCookieSessionAsAuth
        self.validators = validators
        self.session = session
        self.oidc = oidc
        self.jwtIssuer = jwtIssuer
    }
}

/// Defines which request paths are protected by an `HTTP3AuthGuard`.
public enum ProtectedScope: Sendable, Equatable {
    /// Protect every request.
    case all
    /// Protect every request except paths with one of the given prefixes.
    case except([String])
    /// Protect only paths with one of the given prefixes.
    case only([String])

    /// Returns whether the protected scope applies to a request path.
    public func applies(to path: String) -> Bool {
        switch self {
        case .all:
            return true
        case .except(let publicPrefixes):
            return !publicPrefixes.contains(where: { path.hasPrefix($0) })
        case .only(let protectedPrefixes):
            return protectedPrefixes.contains(where: { path.hasPrefix($0) })
        }
    }
}
