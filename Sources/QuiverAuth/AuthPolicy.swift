import Foundation
import HTTP3

public struct AuthPolicy: Sendable {
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
        let snapshot = extractor.snapshot(request: request, configuration: configuration)

        if configuration.mode != .forwardOnly,
            let token = snapshot.bearerToken ?? oidcTokenFromCookies(snapshot)
        {
            if let oidcConfig = configuration.oidc {
                let validator = OIDCValidator(configuration: oidcConfig)
                switch await validator.validate(token: token) {
                case .valid(let principal):
                    return .allow(
                        AuthPrincipal(subject: principal.subject, email: principal.email, source: "oidc")
                    )
                case .invalid(let reason):
                    if configuration.mode == .oidcOnly {
                        return .deny(status: 401, reason: "invalid bearer token: \(reason)")
                    }
                }
            } else {
                if configuration.mode == .oidcOnly {
                    return .deny(status: 500, reason: "oidc mode enabled but oidc configuration is missing")
                }
                return .allow(AuthPrincipal(subject: "bearer:\(token.prefix(12))", source: "bearer"))
            }
        }

        if configuration.mode != .oidcOnly {
            if let identity = snapshot.identityHeaderValue {
                if configuration.requireGatewayMarkerForForwardedIdentity, !isFromGateway {
                    return .deny(status: 403, reason: "forwarded identity is only trusted from gateway")
                }
                return .allow(
                    AuthPrincipal(
                        subject: identity,
                        email: snapshot.emailHeaderValue,
                        source: snapshot.identityHeaderName ?? "forwarded-header"
                    )
                )
            }

            if configuration.allowCookieSessionAsAuth {
                if let cookieName = configuration.sessionCookieNames.first(where: { snapshot.hasCookie(named: $0) }) {
                    if configuration.requireGatewayMarkerForForwardedIdentity, !isFromGateway {
                        return .deny(status: 403, reason: "forwarded cookie session is only trusted from gateway")
                    }
                    return .allow(AuthPrincipal(subject: "cookie:\(cookieName)", source: "cookie"))
                }
            }
        }

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
}
