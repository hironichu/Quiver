import Foundation
import HTTP3
import QUICCore

public struct AuthPolicy: Sendable {
    private static let logger = QuiverLogging.logger(label: "quiver.auth.policy")

    private let configuration: AuthConfiguration
    private let extractor: AuthExtractor

    public init(configuration: AuthConfiguration, extractor: AuthExtractor = AuthExtractor()) {
        self.configuration = configuration
        self.extractor = extractor
    }

    public func evaluate(_ requestContext: HTTP3RequestContext) async -> AuthDecision {
        await evaluate(request: requestContext.request, isFromGateway: requestContext.isFromAltSvcGateway)
    }

    public func evaluate(_ connectContext: ExtendedConnectContext) async -> AuthDecision {
        let isFromGateway = connectContext.request.headers.contains {
            $0.0.caseInsensitiveCompare("x-quiver-gateway") == .orderedSame
                && $0.1.caseInsensitiveCompare("altsvc") == .orderedSame
        }
        return await evaluate(request: connectContext.request, isFromGateway: isFromGateway)
    }

    public func evaluate(request: HTTP3Request, isFromGateway: Bool) async -> AuthDecision {
        Self.logger.trace(
            "evaluate auth request",
            metadata: [
                "path": "\(request.path)",
                "method": "\(request.method.rawValue)",
                "mode": "\(String(describing: configuration.mode))",
                "isFromGateway": "\(isFromGateway)",
            ]
        )
        let snapshot = extractor.snapshot(request: request, configuration: configuration)
        Self.logger.trace(
            "auth snapshot collected",
            metadata: [
                "path": "\(request.path)",
                "hasBearer": "\(snapshot.bearerToken != nil)",
                "identityHeader": "\(snapshot.identityHeaderName ?? "nil")",
                "hasIdentity": "\(snapshot.identityHeaderValue != nil)",
                "cookieCount": "\(snapshot.cookies.count)",
                "cookieNames": "\(snapshot.cookies.map { $0.0 }.joined(separator: ","))",
            ]
        )

        if configuration.mode != .forwardOnly,
            let token = snapshot.bearerToken ?? oidcTokenFromCookies(snapshot)
        {
            Self.logger.trace(
                "token candidate found",
                metadata: [
                    "path": "\(request.path)",
                    "tokenSource": "\(snapshot.bearerToken != nil ? "bearer" : "cookie")",
                ]
            )
            if let oidcConfig = configuration.oidc {
                let validator = OIDCValidator(configuration: oidcConfig)
                switch await validator.validate(token: token) {
                case .valid(let principal):
                    Self.logger.debug(
                        "oidc token valid",
                        metadata: [
                            "path": "\(request.path)",
                            "subject": "\(principal.subject)",
                        ]
                    )
                    return .allow(
                        AuthPrincipal(
                            subject: principal.subject,
                            email: principal.email,
                            source: "oidc",
                            claims: principal.claims
                        )
                    )
                case .invalid(let reason):
                    Self.logger.debug(
                        "oidc token invalid",
                        metadata: [
                            "path": "\(request.path)",
                            "reason": "\(reason)",
                        ]
                    )
                    if configuration.mode == .oidcOnly {
                        return .deny(status: 401, reason: "invalid bearer token: \(reason)")
                    }
                }
            } else {
                if configuration.mode == .oidcOnly {
                    return .deny(status: 500, reason: "oidc mode enabled but oidc configuration is missing")
                }
                Self.logger.debug(
                    "allowing bearer token in non-oidc mode",
                    metadata: ["path": "\(request.path)"]
                )
                return .allow(
                    AuthPrincipal(
                        subject: "bearer:\(token.prefix(12))",
                        source: "bearer"
                    )
                )
            }
        }

        if configuration.mode != .oidcOnly {
            if let identity = snapshot.identityHeaderValue {
                if configuration.requireGatewayMarkerForForwardedIdentity, !isFromGateway {
                    Self.logger.debug(
                        "deny forwarded identity outside gateway",
                        metadata: ["path": "\(request.path)"]
                    )
                    return .deny(status: 403, reason: "forwarded identity is only trusted from gateway")
                }
                Self.logger.debug(
                    "allow forwarded identity",
                    metadata: [
                        "path": "\(request.path)",
                        "identity": "\(identity)",
                    ]
                )
                return .allow(
                    AuthPrincipal(
                        subject: identity,
                        email: snapshot.emailHeaderValue,
                        source: snapshot.identityHeaderName ?? "forwarded-header",
                        claims: [
                            "identity": .string(identity),
                            "identity_header": .string(snapshot.identityHeaderName ?? "forwarded-header"),
                        ]
                    )
                )
            }

            if configuration.allowCookieSessionAsAuth {
                if let cookieName = configuration.sessionCookieNames.first(where: { snapshot.hasCookie(named: $0) }) {
                    if configuration.requireGatewayMarkerForForwardedIdentity, !isFromGateway {
                        Self.logger.debug(
                            "deny cookie session outside gateway",
                            metadata: [
                                "path": "\(request.path)",
                                "cookieName": "\(cookieName)",
                            ]
                        )
                        return .deny(status: 403, reason: "forwarded cookie session is only trusted from gateway")
                    }
                    Self.logger.debug(
                        "allow cookie session",
                        metadata: [
                            "path": "\(request.path)",
                            "cookieName": "\(cookieName)",
                        ]
                    )
                    return .allow(
                        AuthPrincipal(
                            subject: "cookie:\(cookieName)",
                            source: "cookie",
                            claims: ["cookie_name": .string(cookieName)]
                        )
                    )
                }
            }
        }

        Self.logger.debug(
            "deny due to missing auth signal",
            metadata: ["path": "\(request.path)"]
        )
        return .deny(status: 401, reason: "missing auth signal")
    }

    private func oidcTokenFromCookies(_ snapshot: AuthCredentialSnapshot) -> String? {
        for cookieName in configuration.sessionCookieNames {
            guard let value = snapshot.cookieValue(named: cookieName), !value.isEmpty else { continue }
            if looksLikeJWT(value) {
                return value
            }
        }
        return nil
    }

    private func looksLikeJWT(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 3 && parts.allSatisfy { !$0.isEmpty }
    }

    public func authSnapshot(for request: HTTP3Request) -> AuthCredentialSnapshot {
        extractor.snapshot(request: request, configuration: configuration)
    }

    public func isOIDCCallbackRequest(_ request: HTTP3Request) -> Bool {
        guard let oidc = configuration.oidc else { return false }
        var loginConfiguration = oidc.login

        if !loginConfiguration.enabled,
            let clientID = loginConfiguration.clientID,
            !clientID.isEmpty,
            loginConfiguration.authorizationEndpoint != nil
                || loginConfiguration.discoveryURL != nil
                || oidc.issuer != nil
        {
            loginConfiguration.enabled = true
        }

        guard loginConfiguration.enabled else { return false }

        let callbackPath = oidcCallbackPath(for: loginConfiguration)
        return normalizedRequestPath(request.path) == callbackPath
    }

    public func sessionValues(for principal: AuthPrincipal) -> [String: HTTP3SessionValue] {
        var authClaims = principal.claims
        authClaims["subject"] = .string(principal.subject)
        authClaims["source"] = .string(principal.source)
        if let email = principal.email, !email.isEmpty {
            authClaims["email"] = .string(email)
        }
        return authClaims
    }

    public func defaultSessionPayload(for principal: AuthPrincipal) -> QuiverAuthSession {
        QuiverAuthSession(
            subject: principal.subject,
            source: principal.source,
            email: principal.email,
            claims: sessionValues(for: principal)
        )
    }

    public func session(
        for principal: AuthPrincipal,
        base: HTTP3Session = .empty,
        namespace: String = "auth"
    ) -> HTTP3Session {
        base.setting(namespace: namespace, values: sessionValues(for: principal))
    }

    public func loginRedirectURL(for request: HTTP3Request) async -> URL? {
        guard let oidc = configuration.oidc else { return nil }
        var loginConfiguration = oidc.login

        if !loginConfiguration.enabled,
            let clientID = loginConfiguration.clientID,
            !clientID.isEmpty,
            loginConfiguration.authorizationEndpoint != nil
                || loginConfiguration.discoveryURL != nil
                || oidc.issuer != nil
        {
            loginConfiguration.enabled = true
        }

        let fallbackDiscoveryURL: String?
        if loginConfiguration.discoveryURL == nil, loginConfiguration.authorizationEndpoint == nil,
            let issuer = oidc.issuer
        {
            fallbackDiscoveryURL = oidcDiscoveryURLFromIssuer(issuer)
        } else {
            fallbackDiscoveryURL = nil
        }

        let builder = OIDCLoginRedirectBuilder(
            configuration: loginConfiguration,
            fallbackDiscoveryURL: fallbackDiscoveryURL
        )
        return await builder.buildRedirectURL(for: request)
    }

    func uiRetryURL() -> String? {
        guard let retry = configuration.oidc?.login.errorRetryURL?.trimmingCharacters(in: .whitespacesAndNewlines) else {
            return nil
        }
        return retry.isEmpty ? nil : retry
    }

    func oidcCallbackResponse(for request: HTTP3Request) async -> OIDCLoginCallbackHTTPResponse? {
        guard let oidc = configuration.oidc else { return nil }
        var loginConfiguration = oidc.login

        if !loginConfiguration.enabled,
            let clientID = loginConfiguration.clientID,
            !clientID.isEmpty,
            loginConfiguration.authorizationEndpoint != nil
                || loginConfiguration.discoveryURL != nil
                || oidc.issuer != nil
        {
            loginConfiguration.enabled = true
        }

        let fallbackDiscoveryURL: String?
        if loginConfiguration.discoveryURL == nil, loginConfiguration.authorizationEndpoint == nil,
            let issuer = oidc.issuer
        {
            fallbackDiscoveryURL = oidcDiscoveryURLFromIssuer(issuer)
        } else {
            fallbackDiscoveryURL = nil
        }

        let callbackHandler = OIDCLoginCallbackHandler(
            configuration: loginConfiguration,
            fallbackDiscoveryURL: fallbackDiscoveryURL
        )
        return await callbackHandler.handleIfCallback(request: request)
    }

    private func oidcCallbackPath(for loginConfiguration: OIDCLoginConfiguration) -> String {
        if let explicit = loginConfiguration.redirectURI,
            let components = URLComponents(string: explicit),
            !components.path.isEmpty
        {
            return components.path
        }

        let trimmed = loginConfiguration.redirectPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "/auth/callback" }
        return trimmed.hasPrefix("/") ? trimmed : "/\(trimmed)"
    }

    private func normalizedRequestPath(_ rawPath: String) -> String {
        if let components = URLComponents(string: rawPath), !components.path.isEmpty {
            return components.path
        }

        if let queryStart = rawPath.firstIndex(of: "?") {
            return String(rawPath[..<queryStart])
        }

        return rawPath
    }
}
