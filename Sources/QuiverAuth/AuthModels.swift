import Foundation
import HTTP3

public struct AuthPrincipal: Sendable, Equatable {
    public let subject: String
    public let email: String?
    public let source: String
    public let claims: [String: HTTP3SessionValue]

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

public struct QuiverAuthSession: Codable, Sendable, Equatable {
    public let subject: String
    public let source: String
    public let email: String?
    public let claims: [String: HTTP3SessionValue]

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

public enum AuthDecision: Sendable, Equatable {
    case allow(AuthPrincipal)
    case deny(status: Int, reason: String)
}

public struct AuthCredentialSnapshot: Sendable {
    public let bearerToken: String?
    public let identityHeaderName: String?
    public let identityHeaderValue: String?
    public let emailHeaderValue: String?
    public let cookies: [(String, String)]

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

    public func cookieValue(named name: String) -> String? {
        cookies.first(where: { $0.0 == name })?.1
    }

    public func hasCookie(named name: String) -> Bool {
        guard let value = cookieValue(named: name) else { return false }
        return !value.isEmpty
    }
}

public enum AuthMode: Sendable {
    case forwardOnly
    case oidcOnly
    case composite

    public init?(rawValue: String) {
        switch rawValue.lowercased() {
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

public struct OIDCConfiguration: Sendable {
    public var issuer: String?
    public var audience: String?
    public var clockSkewSeconds: Int
    public var hs256SharedSecret: String?
    public var allowUnverifiedSignature: Bool
    public var jwksURL: String?
    public var jwksCacheTTLSeconds: Int
    public var staticJWKs: [OIDCJWK]
    public var login: OIDCLoginConfiguration

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

public struct OIDCLoginConfiguration: Sendable {
    public var enabled: Bool
    public var discoveryURL: String?
    public var authorizationEndpoint: String?
    public var tokenEndpoint: String?
    public var clientID: String?
    public var clientSecret: String?
    public var redirectURI: String?
    public var redirectPath: String
    public var callbackSuccessPath: String
    public var callbackFailurePath: String?
    public var errorRetryURL: String?
    public var stateTTLSeconds: Int
    public var scope: String
    public var responseType: String
    public var prompt: String?
    public var extraAuthorizationParameters: [String: String]
    public var sessionCookieName: String
    public var sessionCookieSecure: Bool
    public var sessionCookieHTTPOnly: Bool
    public var sessionCookieSameSite: String
    public var sessionCookiePath: String
    public var serverSession: OIDCServerSessionConfiguration
    public var browserOnly: Bool

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
        sessionCookieSameSite: String = "Lax",
        sessionCookiePath: String = "/",
        serverSession: OIDCServerSessionConfiguration = OIDCServerSessionConfiguration(),
        browserOnly: Bool = true
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
    }
}

public struct OIDCServerSessionConfiguration: Sendable {
    public var enabled: Bool
    public var refreshLeewaySeconds: Int
    public var cookieMaxAgeSeconds: Int?
    public var allowLegacyTokenCookieFallback: Bool
    public var liveUserInfoEnabled: Bool
    public var userInfoEndpoint: String?
    public var userInfoCacheTTLSeconds: Int
    public var failOpenOnUserInfoError: Bool

    public init(
        enabled: Bool = true,
        refreshLeewaySeconds: Int = 60,
        cookieMaxAgeSeconds: Int? = 604800,
        allowLegacyTokenCookieFallback: Bool = true,
        liveUserInfoEnabled: Bool = true,
        userInfoEndpoint: String? = nil,
        userInfoCacheTTLSeconds: Int = 300,
        failOpenOnUserInfoError: Bool = true
    ) {
        self.enabled = enabled
        self.refreshLeewaySeconds = refreshLeewaySeconds
        self.cookieMaxAgeSeconds = cookieMaxAgeSeconds
        self.allowLegacyTokenCookieFallback = allowLegacyTokenCookieFallback
        self.liveUserInfoEnabled = liveUserInfoEnabled
        self.userInfoEndpoint = userInfoEndpoint
        self.userInfoCacheTTLSeconds = userInfoCacheTTLSeconds
        self.failOpenOnUserInfoError = failOpenOnUserInfoError
    }
}

public struct OIDCJWK: Sendable, Equatable, Codable {
    public var kty: String
    public var kid: String?
    public var alg: String?
    public var use: String?
    public var n: String?
    public var e: String?
    public var crv: String?
    public var x: String?
    public var y: String?

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

public struct OIDCJWKS: Sendable, Equatable, Codable {
    public var keys: [OIDCJWK]

    public init(keys: [OIDCJWK]) {
        self.keys = keys
    }
}

public struct AuthConfiguration: Sendable {
    public var mode: AuthMode
    public var bearerHeaderNames: [String]
    public var identityHeaderNames: [String]
    public var emailHeaderNames: [String]
    public var sessionCookieNames: [String]
    public var requireGatewayMarkerForForwardedIdentity: Bool
    public var allowCookieSessionAsAuth: Bool
    public var oidc: OIDCConfiguration?

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
        sessionCookieNames: [String] = [
            "ta_session",
            "tinyauth-session",
            "_oauth2_proxy",
            "pocketid_session",
            "z-token",
        ],
        requireGatewayMarkerForForwardedIdentity: Bool = true,
        allowCookieSessionAsAuth: Bool = true,
        oidc: OIDCConfiguration? = nil
    ) {
        self.mode = mode
        self.bearerHeaderNames = bearerHeaderNames
        self.identityHeaderNames = identityHeaderNames
        self.emailHeaderNames = emailHeaderNames
        self.sessionCookieNames = sessionCookieNames
        self.requireGatewayMarkerForForwardedIdentity = requireGatewayMarkerForForwardedIdentity
        self.allowCookieSessionAsAuth = allowCookieSessionAsAuth
        self.oidc = oidc
    }
}

public enum ProtectedScope: Sendable, Equatable {
    case all
    case except([String])
    case only([String])

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
