import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
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
            let oidcConfiguration = configuration.oidc,
            let decision = await evaluateOIDCServerSessionIfConfigured(
                request: request,
                snapshot: snapshot,
                oidcConfiguration: oidcConfiguration
            )
        {
            return decision
        }

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

    private func evaluateOIDCServerSessionIfConfigured(
        request: HTTP3Request,
        snapshot: AuthCredentialSnapshot,
        oidcConfiguration: OIDCConfiguration
    ) async -> AuthDecision? {
        let sessionConfiguration = oidcConfiguration.login.serverSession
        guard sessionConfiguration.enabled else { return nil }

        guard let sessionID = oidcSessionCookieValue(from: snapshot) else { return nil }

        if looksLikeJWT(sessionID) {
            if sessionConfiguration.allowLegacyTokenCookieFallback {
                return nil
            }
            return .deny(status: 401, reason: "legacy token cookies are disabled")
        }

        guard let sessionRecord = await OIDCServerSessionStore.shared.get(sessionID: sessionID) else {
            return .deny(status: 401, reason: "invalid session")
        }

        let hydratedRecord: OIDCServerSessionRecord
        if sessionRecord.tokenSet.shouldRefresh(leewaySeconds: sessionConfiguration.refreshLeewaySeconds) {
            guard let refreshed = await refreshOIDCSessionRecordIfPossible(
                sessionRecord,
                request: request,
                oidcConfiguration: oidcConfiguration
            ) else {
                await OIDCServerSessionStore.shared.delete(sessionID: sessionID)
                return .deny(status: 401, reason: "session refresh failed")
            }
            hydratedRecord = refreshed
        } else {
            hydratedRecord = sessionRecord
        }

        guard let token = hydratedRecord.tokenSet.validationToken() else {
            await OIDCServerSessionStore.shared.delete(sessionID: sessionID)
            return .deny(status: 401, reason: "session token unavailable")
        }

        let validator = OIDCValidator(configuration: oidcConfiguration)
        switch await validator.validate(token: token) {
        case .valid(let principal):
            let enrichedPrincipal = await mergeLiveUserInfoClaimsIfConfigured(
                principal: principal,
                sessionRecord: hydratedRecord,
                oidcConfiguration: oidcConfiguration
            )
            return .allow(
                AuthPrincipal(
                    subject: enrichedPrincipal.subject,
                    email: enrichedPrincipal.email,
                    source: "oidc",
                    claims: enrichedPrincipal.claims
                )
            )
        case .invalid(let reason):
            if reason.contains("token expired") {
                guard let refreshed = await refreshOIDCSessionRecordIfPossible(
                    hydratedRecord,
                    request: request,
                    oidcConfiguration: oidcConfiguration
                ),
                    let refreshedToken = refreshed.tokenSet.validationToken()
                else {
                    await OIDCServerSessionStore.shared.delete(sessionID: sessionID)
                    return .deny(status: 401, reason: "session expired")
                }

                switch await validator.validate(token: refreshedToken) {
                case .valid(let principal):
                    let enrichedPrincipal = await mergeLiveUserInfoClaimsIfConfigured(
                        principal: principal,
                        sessionRecord: refreshed,
                        oidcConfiguration: oidcConfiguration
                    )
                    return .allow(
                        AuthPrincipal(
                            subject: enrichedPrincipal.subject,
                            email: enrichedPrincipal.email,
                            source: "oidc",
                            claims: enrichedPrincipal.claims
                        )
                    )
                case .invalid(let finalReason):
                    await OIDCServerSessionStore.shared.delete(sessionID: sessionID)
                    return .deny(status: 401, reason: "invalid bearer token: \(finalReason)")
                }
            }

            return .deny(status: 401, reason: "invalid bearer token: \(reason)")
        }
    }

    private func mergeLiveUserInfoClaimsIfConfigured(
        principal: OIDCPrincipal,
        sessionRecord: OIDCServerSessionRecord,
        oidcConfiguration: OIDCConfiguration
    ) async -> OIDCPrincipal {
        let sessionConfiguration = oidcConfiguration.login.serverSession
        guard sessionConfiguration.liveUserInfoEnabled else { return principal }

        var mergedClaims = principal.claims
        mergedClaims["_token_claims"] = .object(principal.claims)

        let claimsToMerge = await liveUserInfoClaims(
            from: sessionRecord,
            oidcConfiguration: oidcConfiguration
        )

        guard let claimsToMerge, !claimsToMerge.isEmpty else {
            let mergedSubject = claimsString("sub", in: mergedClaims) ?? principal.subject
            let mergedEmail = claimsString("email", in: mergedClaims) ?? principal.email
            return OIDCPrincipal(subject: mergedSubject, email: mergedEmail, claims: mergedClaims)
        }

        mergedClaims["_userinfo_claims"] = .object(claimsToMerge)
        for (key, value) in claimsToMerge {
            mergedClaims[key] = value
        }

        let mergedSubject = claimsString("sub", in: mergedClaims) ?? principal.subject
        let mergedEmail = claimsString("email", in: mergedClaims) ?? principal.email

        return OIDCPrincipal(subject: mergedSubject, email: mergedEmail, claims: mergedClaims)
    }

    private func liveUserInfoClaims(
        from sessionRecord: OIDCServerSessionRecord,
        oidcConfiguration: OIDCConfiguration
    ) async -> [String: HTTP3SessionValue]? {
        let sessionConfiguration = oidcConfiguration.login.serverSession
        let ttl = max(1, sessionConfiguration.userInfoCacheTTLSeconds)

        if let cachedClaims = sessionRecord.userInfoClaims,
            let fetchedAt = sessionRecord.userInfoFetchedAt,
            fetchedAt.addingTimeInterval(TimeInterval(ttl)) > Date()
        {
            return cachedClaims
        }

        guard let accessToken = sessionRecord.tokenSet.accessToken, !accessToken.isEmpty else {
            return sessionRecord.userInfoClaims
        }

        guard let endpoint = await userInfoEndpoint(for: oidcConfiguration) else {
            return sessionRecord.userInfoClaims
        }

        do {
            let liveClaims = try await fetchUserInfoClaims(
                endpoint: endpoint,
                accessToken: accessToken
            )

            if let updated = await OIDCServerSessionStore.shared.mutate(sessionID: sessionRecord.sessionID, transform: {
                $0.userInfoClaims = liveClaims
                $0.userInfoFetchedAt = Date()
            }) {
                return updated.userInfoClaims
            }

            return liveClaims
        } catch {
            Self.logger.warning(
                "userinfo fetch failed",
                metadata: [
                    "sessionID": "\(sessionRecord.sessionID.prefix(10))",
                    "error": "\(error.localizedDescription)",
                ]
            )

            if sessionConfiguration.failOpenOnUserInfoError {
                return sessionRecord.userInfoClaims
            }

            return nil
        }
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

    private func oidcSessionCookieValue(from snapshot: AuthCredentialSnapshot) -> String? {
        for cookieName in configuration.sessionCookieNames {
            guard let value = snapshot.cookieValue(named: cookieName) else { continue }
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                return trimmed
            }
        }
        return nil
    }

    private func refreshOIDCSessionRecordIfPossible(
        _ sessionRecord: OIDCServerSessionRecord,
        request: HTTP3Request,
        oidcConfiguration: OIDCConfiguration
    ) async -> OIDCServerSessionRecord? {
        guard
            let refreshToken = sessionRecord.tokenSet.refreshToken,
            !refreshToken.isEmpty,
            let clientID = oidcConfiguration.login.clientID,
            !clientID.isEmpty,
            let tokenEndpoint = await oidcTokenEndpoint(for: oidcConfiguration)
        else {
            return sessionRecord
        }

        do {
            let refreshedResponse = try await refreshOIDCTokens(
                tokenEndpoint: tokenEndpoint,
                refreshToken: refreshToken,
                clientID: clientID,
                clientSecret: oidcConfiguration.login.clientSecret
            )

            let refreshedSet = OIDCTokenSet(
                accessToken: refreshedResponse.accessToken ?? sessionRecord.tokenSet.accessToken,
                idToken: refreshedResponse.idToken ?? sessionRecord.tokenSet.idToken,
                refreshToken: refreshedResponse.refreshToken ?? sessionRecord.tokenSet.refreshToken,
                tokenType: refreshedResponse.tokenType ?? sessionRecord.tokenSet.tokenType,
                scope: refreshedResponse.scope ?? sessionRecord.tokenSet.scope,
                expiresAt: refreshedResponse.expiresIn.map {
                    Date().addingTimeInterval(TimeInterval(max(1, $0)))
                } ?? sessionRecord.tokenSet.expiresAt
            )

            return await OIDCServerSessionStore.shared.update(
                sessionID: sessionRecord.sessionID,
                tokenSet: refreshedSet
            )
        } catch {
            Self.logger.warning(
                "oidc refresh failed",
                metadata: [
                    "sessionID": "\(sessionRecord.sessionID.prefix(10))",
                    "error": "\(error.localizedDescription)",
                ]
            )
            return nil
        }
    }

    private func oidcTokenEndpoint(for configuration: OIDCConfiguration) async -> String? {
        if let explicitTokenEndpoint = configuration.login.tokenEndpoint,
            !explicitTokenEndpoint.isEmpty
        {
            return explicitTokenEndpoint
        }

        if let explicitAuthorization = configuration.login.authorizationEndpoint,
            !explicitAuthorization.isEmpty
        {
            return configuration.login.tokenEndpoint
        }

        let fallbackDiscoveryURL: String?
        if configuration.login.discoveryURL == nil,
            configuration.login.authorizationEndpoint == nil,
            let issuer = configuration.issuer
        {
            fallbackDiscoveryURL = oidcDiscoveryURLFromIssuer(issuer)
        } else {
            fallbackDiscoveryURL = nil
        }

        let effectiveDiscoveryURL = configuration.login.discoveryURL ?? fallbackDiscoveryURL
        guard let effectiveDiscoveryURL, let discoveryURL = URL(string: effectiveDiscoveryURL) else {
            return nil
        }

        do {
            let metadata = try await OIDCDiscoveryCache.shared.metadata(discoveryURL: discoveryURL)
            return metadata.tokenEndpoint
        } catch {
            Self.logger.warning(
                "oidc discovery failed for refresh",
                metadata: ["error": "\(error.localizedDescription)"]
            )
            return nil
        }
    }

    private func userInfoEndpoint(for configuration: OIDCConfiguration) async -> String? {
        if let explicit = configuration.login.serverSession.userInfoEndpoint,
            !explicit.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        {
            return explicit
        }

        if let issuer = configuration.issuer {
            let trimmed = issuer.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                let normalized = trimmed.hasSuffix("/") ? String(trimmed.dropLast()) : trimmed
                return normalized + "/api/oidc/userinfo"
            }
        }

        let fallbackDiscoveryURL: String?
        if configuration.login.discoveryURL == nil,
            configuration.login.authorizationEndpoint == nil,
            let issuer = configuration.issuer
        {
            fallbackDiscoveryURL = oidcDiscoveryURLFromIssuer(issuer)
        } else {
            fallbackDiscoveryURL = nil
        }

        let effectiveDiscoveryURL = configuration.login.discoveryURL ?? fallbackDiscoveryURL
        guard let effectiveDiscoveryURL, let discoveryURL = URL(string: effectiveDiscoveryURL) else {
            return nil
        }

        do {
            let metadata = try await OIDCDiscoveryCache.shared.metadata(discoveryURL: discoveryURL)
            return metadata.userInfoEndpoint
        } catch {
            return nil
        }
    }

    private func fetchUserInfoClaims(
        endpoint: String,
        accessToken: String
    ) async throws -> [String: HTTP3SessionValue] {
        guard let url = URL(string: endpoint) else {
            throw NSError(
                domain: "QuiverAuth.AuthPolicy",
                code: 3001,
                userInfo: [NSLocalizedDescriptionKey: "invalid_userinfo_endpoint"]
            )
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "authorization")
        request.setValue("application/json", forHTTPHeaderField: "accept")

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw NSError(
                domain: "QuiverAuth.AuthPolicy",
                code: 3002,
                userInfo: [NSLocalizedDescriptionKey: "invalid_userinfo_response"]
            )
        }

        guard 200..<300 ~= httpResponse.statusCode else {
            let bodySnippet = String(data: data, encoding: .utf8) ?? "<non-utf8-body>"
            throw NSError(
                domain: "QuiverAuth.AuthPolicy",
                code: 3003,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "userinfo_http_\(httpResponse.statusCode):\(bodySnippet.prefix(300))",
                ]
            )
        }

        let payload = try JSONSerialization.jsonObject(with: data)
        guard let object = payload as? [String: Any] else {
            throw NSError(
                domain: "QuiverAuth.AuthPolicy",
                code: 3004,
                userInfo: [NSLocalizedDescriptionKey: "userinfo_payload_not_object"]
            )
        }

        var mapped: [String: HTTP3SessionValue] = [:]
        for (key, value) in object {
            if let mappedValue = mapToSessionValue(value) {
                mapped[key] = mappedValue
            }
        }
        return mapped
    }

    private func refreshOIDCTokens(
        tokenEndpoint: String,
        refreshToken: String,
        clientID: String,
        clientSecret: String?
    ) async throws -> OIDCTokenResponse {
        guard let url = URL(string: tokenEndpoint) else {
            throw NSError(
                domain: "QuiverAuth.AuthPolicy",
                code: 2001,
                userInfo: [NSLocalizedDescriptionKey: "invalid_token_endpoint"]
            )
        }

        var form: [(String, String)] = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refreshToken),
            ("client_id", clientID),
        ]
        if let clientSecret, !clientSecret.isEmpty {
            form.append(("client_secret", clientSecret))
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "content-type")
        request.setValue("application/json", forHTTPHeaderField: "accept")
        request.httpBody = Data(refreshFormURLEncoded(form).utf8)

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw NSError(
                domain: "QuiverAuth.AuthPolicy",
                code: 2002,
                userInfo: [NSLocalizedDescriptionKey: "invalid_refresh_response"]
            )
        }

        guard 200..<300 ~= httpResponse.statusCode else {
            let bodySnippet = String(data: data, encoding: .utf8) ?? "<non-utf8-body>"
            throw NSError(
                domain: "QuiverAuth.AuthPolicy",
                code: 2003,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "refresh_endpoint_http_\(httpResponse.statusCode):\(bodySnippet.prefix(300))",
                ]
            )
        }

        return try JSONDecoder().decode(OIDCTokenResponse.self, from: data)
    }

    private func refreshFormURLEncoded(_ pairs: [(String, String)]) -> String {
        pairs
            .map { "\(refreshURLEncode($0.0))=\(refreshURLEncode($0.1))" }
            .joined(separator: "&")
    }

    private func refreshURLEncode(_ value: String) -> String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: ":#[]@!$&'()*+,;=")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }

    private func claimsString(_ key: String, in claims: [String: HTTP3SessionValue]) -> String? {
        if case .string(let value)? = claims[key] {
            return value
        }
        return nil
    }

    private func mapToSessionValue(_ value: Any) -> HTTP3SessionValue? {
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
                guard let mappedEntry = mapToSessionValue(entry) else { return nil }
                mappedValues.append(mappedEntry)
            }
            return .array(mappedValues)
        case let object as [String: Any]:
            var mappedObject: [String: HTTP3SessionValue] = [:]
            for (key, entry) in object {
                guard let mappedEntry = mapToSessionValue(entry) else { return nil }
                mappedObject[key] = mappedEntry
            }
            return .object(mappedObject)
        case _ as NSNull:
            return .null
        default:
            return nil
        }
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

    func denyResponseHeaders(for request: HTTP3Request, status: Int, reason _: String) -> [(String, String)] {
        guard status == 401 else { return [] }
        guard let oidc = configuration.oidc else { return [] }
        guard oidc.login.serverSession.enabled else { return [] }

        let snapshot = extractor.snapshot(request: request, configuration: configuration)
        guard snapshot.bearerToken == nil else { return [] }
        guard snapshot.cookieValue(named: oidc.login.sessionCookieName) != nil else { return [] }

        return [("set-cookie", clearingSessionCookieHeader(loginConfiguration: oidc.login))]
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

    private func clearingSessionCookieHeader(loginConfiguration: OIDCLoginConfiguration) -> String {
        var parts = ["\(loginConfiguration.sessionCookieName)="]
        parts.append("Path=\(loginConfiguration.sessionCookiePath)")
        parts.append("Max-Age=0")
        if loginConfiguration.sessionCookieSecure { parts.append("Secure") }
        if loginConfiguration.sessionCookieHTTPOnly { parts.append("HttpOnly") }
        parts.append("SameSite=\(loginConfiguration.sessionCookieSameSite)")
        return parts.joined(separator: "; ")
    }
}
