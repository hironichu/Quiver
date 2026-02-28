import Foundation
import Testing
import HTTP3
import Crypto
@testable import QuiverAuth

struct QuiverAuthTests {
    actor ResponseCapture {
        private(set) var status: Int?
        private(set) var headers: [(String, String)] = []

        func set(status: Int, headers: [(String, String)]) {
            self.status = status
            self.headers = headers
        }
    }

    private func requestContext(_ request: HTTP3Request) -> HTTP3RequestContext {
        HTTP3RequestContext(
            request: request,
            streamID: 1,
            respond: { _, _, _, _ in }
        )
    }

    private func base64URL(_ string: String) -> String {
        let data = Data(string.utf8)
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func testJWT(payload: String, alg: String = "RS256") -> String {
        let header = #"{"alg":""# + alg + #"","typ":"JWT"}"#
        return "\(base64URL(header)).\(base64URL(payload)).sig"
    }

    private func queryValue(_ name: String, in url: URL) -> String? {
        URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?
            .first(where: { $0.name == name })?
            .value
    }

    @Test
    func allowsBearerTokenInCompositeMode() async {
        let config = AuthConfiguration(mode: .composite)
        let policy = AuthPolicy(configuration: config)

        let request = HTTP3Request(
            method: .get,
            authority: "example.test",
            path: "/private",
            headers: [("authorization", "Bearer abc.def.ghi")]
        )

        let decision = await policy.evaluate(request: request, isFromGateway: false)
        switch decision {
        case .allow(let principal):
            #expect(principal.source == "bearer")
        case .deny:
            Issue.record("Expected bearer token to authorize")
        }
    }

    @Test
    func deniesForwardedIdentityWithoutGatewayMarkerWhenStrict() async {
        let config = AuthConfiguration(
            mode: .forwardOnly,
            requireGatewayMarkerForForwardedIdentity: true
        )
        let policy = AuthPolicy(configuration: config)

        let request = HTTP3Request(
            method: .get,
            authority: "example.test",
            path: "/private",
            headers: [("x-authenticated-user", "hiro")]
        )

        let decision = await policy.evaluate(request: request, isFromGateway: false)
        switch decision {
        case .allow:
            Issue.record("Expected forwarded identity to be denied when direct")
        case .deny(let status, _):
            #expect(status == 403)
        }
    }

    @Test
    func allowsCookieSessionFromGatewayInForwardMode() async {
        let config = AuthConfiguration(
            mode: .forwardOnly,
            sessionCookieNames: ["ztoken"],
            requireGatewayMarkerForForwardedIdentity: true
        )
        let policy = AuthPolicy(configuration: config)

        let request = HTTP3Request(
            method: .get,
            authority: "example.test",
            path: "/private",
            headers: [("cookie", "ztoken=abc123")]
        )

        let decision = await policy.evaluate(request: request, isFromGateway: true)
        switch decision {
        case .allow(let principal):
            #expect(principal.source == "cookie")
        case .deny:
            Issue.record("Expected gateway cookie session to authorize")
        }
    }

    @Test
    func oidcModeAcceptsValidClaimsWhenUnverifiedAllowed() async {
        let config = AuthConfiguration(
            mode: .oidcOnly,
            oidc: OIDCConfiguration(
                issuer: "https://id.example",
                audience: "quiver-app",
                dangerouslyAllowUnverifiedSignature: true
            )
        )
        let policy = AuthPolicy(configuration: config)

        let exp = Int(Date().timeIntervalSince1970) + 300
        let payload = #"{"sub":"user-1","email":"u@example.com","tenant":"acme","iss":"https://id.example","aud":"quiver-app","exp":"# + String(exp) + #"}"#
        let jwt = testJWT(payload: payload)

        let request = HTTP3Request(
            method: .get,
            authority: "example.test",
            path: "/private",
            headers: [("authorization", "Bearer \(jwt)")]
        )

        let decision = await policy.evaluate(request: request, isFromGateway: false)
        switch decision {
        case .allow(let principal):
            #expect(principal.source == "oidc")
            #expect(principal.subject == "user-1")
            #expect(principal.claims["tenant"] == .string("acme"))
            #expect(principal.claims["email"] == .string("u@example.com"))
        case .deny(let status, let reason):
            Issue.record("Expected OIDC token to pass. status=\(status) reason=\(reason)")
        }
    }

    @Test
    func buildsSessionNamespaceFromPrincipal() {
        let policy = AuthPolicy(configuration: AuthConfiguration(mode: .composite))
        let principal = AuthPrincipal(
            subject: "user-99",
            email: "user99@example.com",
            source: "oidc",
            claims: ["tenant": .string("wuse")]
        )

        let session = policy.session(for: principal)

        #expect(session.get("subject", namespace: "auth") == .string("user-99"))
        #expect(session.get("source", namespace: "auth") == .string("oidc"))
        #expect(session.get("email", namespace: "auth") == .string("user99@example.com"))
        #expect(session.get("tenant", namespace: "auth") == .string("wuse"))
    }

    @Test
    func resolverBuildsDefaultTypedSessionPayload() async {
        let config = AuthConfiguration(
            mode: .forwardOnly,
            requireGatewayMarkerForForwardedIdentity: true
        )
        let policy = AuthPolicy(configuration: config)
        let guardMiddleware: HTTP3AuthGuard<QuiverAuthSession> = HTTP3AuthGuard(policy: policy)

        let request = HTTP3Request(
            method: .get,
            authority: "example.test",
            path: "/private",
            headers: [
                ("x-authenticated-user", "hiro"),
                ("x-auth-request-email", "hiro@example.test"),
                ("x-quiver-gateway", "altsvc"),
            ]
        )

        let resolved = await guardMiddleware.resolver(requestContext(request))
        let typed = resolved.get("auth", as: QuiverAuthSession.self)

        #expect(typed != nil)
        #expect(typed?.subject == "hiro")
        #expect(typed?.email == "hiro@example.test")
        #expect(typed?.source == "x-authenticated-user")
        #expect(resolved.get("subject", namespace: "auth") == .string("hiro"))
    }

    @Test
    func resolverSupportsCustomNamespaceAndPayloadType() async {
        struct CustomSession: Codable, Sendable, Equatable {
            let userID: String
            let provider: String
        }

        let config = AuthConfiguration(
            mode: .forwardOnly,
            requireGatewayMarkerForForwardedIdentity: true
        )
        let policy = AuthPolicy(configuration: config)
        let guardMiddleware = HTTP3AuthGuard(
            policy: policy,
            namespace: "custom-auth",
            into: CustomSession.self,
            payloadBuilder: { principal, _ in
                CustomSession(userID: principal.subject, provider: principal.source)
            }
        )

        let request = HTTP3Request(
            method: .get,
            authority: "example.test",
            path: "/private",
            headers: [
                ("x-authenticated-user", "kira"),
                ("x-quiver-gateway", "altsvc"),
            ]
        )

        let resolved = await guardMiddleware.resolver(requestContext(request))
        let typed = resolved.get("custom-auth", as: CustomSession.self)

        #expect(typed == CustomSession(userID: "kira", provider: "x-authenticated-user"))
        #expect(resolved.get("subject", namespace: "custom-auth") == .string("kira"))
    }

    @Test
    func oidcModeRejectsInvalidIssuer() async {
        let config = AuthConfiguration(
            mode: .oidcOnly,
            oidc: OIDCConfiguration(
                issuer: "https://expected.example",
                audience: "quiver-app",
                dangerouslyAllowUnverifiedSignature: true
            )
        )
        let policy = AuthPolicy(configuration: config)

        let exp = Int(Date().timeIntervalSince1970) + 300
        let payload = #"{"sub":"user-1","iss":"https://wrong.example","aud":"quiver-app","exp":"# + String(exp) + #"}"#
        let jwt = testJWT(payload: payload)

        let request = HTTP3Request(
            method: .get,
            authority: "example.test",
            path: "/private",
            headers: [("authorization", "Bearer \(jwt)")]
        )

        let decision = await policy.evaluate(request: request, isFromGateway: false)
        switch decision {
        case .allow:
            Issue.record("Expected issuer mismatch to be denied")
        case .deny(let status, _):
            #expect(status == 401)
        }
    }

    @Test
    func oidcModeVerifiesES256WithStaticJWK() async throws {
        let privateKey = P256.Signing.PrivateKey()
        let x963 = privateKey.publicKey.x963Representation
        let x = Data(x963[1..<33])
        let y = Data(x963[33..<65])

        let jwk = OIDCJWK(
            kty: "EC",
            kid: "test-es256-kid",
            alg: "ES256",
            use: "sig",
            crv: "P-256",
            x: x.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: ""),
            y: y.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        )

        let config = AuthConfiguration(
            mode: .oidcOnly,
            oidc: OIDCConfiguration(
                issuer: "https://id.example",
                audience: "quiver-app",
                dangerouslyAllowUnverifiedSignature: false,
                staticJWKs: [jwk]
            )
        )
        let policy = AuthPolicy(configuration: config)

        let exp = Int(Date().timeIntervalSince1970) + 300
        let header = #"{"alg":"ES256","typ":"JWT","kid":"test-es256-kid"}"#
        let payload = #"{"sub":"user-es256","iss":"https://id.example","aud":"quiver-app","exp":"# + String(exp) + #"}"#
        let headerPart = base64URL(header)
        let payloadPart = base64URL(payload)
        let signingInput = "\(headerPart).\(payloadPart)"
        let sig = try privateKey.signature(for: Data(signingInput.utf8)).rawRepresentation
        let sigPart = sig.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        let jwt = "\(signingInput).\(sigPart)"

        let request = HTTP3Request(
            method: .get,
            authority: "example.test",
            path: "/private",
            headers: [("authorization", "Bearer \(jwt)")]
        )

        let decision = await policy.evaluate(request: request, isFromGateway: false)
        switch decision {
        case .allow(let principal):
            #expect(principal.source == "oidc")
            #expect(principal.subject == "user-es256")
        case .deny(let status, let reason):
            Issue.record("Expected ES256 verification to pass. status=\(status) reason=\(reason)")
        }
    }

    @Test
    func oidcModeAcceptsJWTFromCookie() async {
        let config = AuthConfiguration(
            mode: .oidcOnly,
            sessionCookieNames: ["z-token"],
            oidc: OIDCConfiguration(
                issuer: "https://id.wuse.io",
                audience: "dbg.wuse.io",
                dangerouslyAllowUnverifiedSignature: true
            )
        )
        let policy = AuthPolicy(configuration: config)

        let exp = Int(Date().timeIntervalSince1970) + 300
        let payload = #"{"sub":"user-cookie","iss":"https://id.wuse.io","aud":"dbg.wuse.io","exp":"# + String(exp) + #"}"#
        let jwt = testJWT(payload: payload)

        let request = HTTP3Request(
            method: .get,
            authority: "example.test",
            path: "/private",
            headers: [("cookie", "z-token=\(jwt)")]
        )

        let decision = await policy.evaluate(request: request, isFromGateway: true)
        switch decision {
        case .allow(let principal):
            #expect(principal.source == "oidc")
            #expect(principal.subject == "user-cookie")
        case .deny(let status, let reason):
            Issue.record("Expected JWT cookie to authorize in oidc mode. status=\(status) reason=\(reason)")
        }
    }

    @Test
    func buildsOIDCLoginRedirectURLForBrowserRequest() async {
        let config = AuthConfiguration(
            mode: .oidcOnly,
            oidc: OIDCConfiguration(
                login: OIDCLoginConfiguration(
                    enabled: true,
                    authorizationEndpoint: "https://id.wuse.io/oauth2/authorize",
                    clientID: "quiver-demo",
                    redirectURI: "https://dbg.wuse.io/auth/callback",
                    scope: "openid profile email"
                )
            )
        )
        let policy = AuthPolicy(configuration: config)

        let request = HTTP3Request(
            method: .get,
            authority: "dbg.wuse.io",
            path: "/private",
            headers: [("accept", "text/html,application/xhtml+xml")]
        )

        guard let redirect = await policy.loginRedirectURL(for: request) else {
            Issue.record("Expected OIDC login redirect URL")
            return
        }

        #expect(redirect.absoluteString.hasPrefix("https://id.wuse.io/oauth2/authorize"))
        #expect(queryValue("client_id", in: redirect) == "quiver-demo")
        #expect(queryValue("redirect_uri", in: redirect) == "https://dbg.wuse.io/auth/callback")
        #expect(queryValue("response_type", in: redirect) == "code")
        #expect(queryValue("scope", in: redirect) == "openid profile email")
        #expect(queryValue("state", in: redirect) != nil)
        #expect(queryValue("nonce", in: redirect) != nil)
    }

    @Test
    func doesNotBuildOIDCLoginRedirectForAPINonBrowserRequestWhenBrowserOnly() async {
        let config = AuthConfiguration(
            mode: .oidcOnly,
            oidc: OIDCConfiguration(
                login: OIDCLoginConfiguration(
                    enabled: true,
                    authorizationEndpoint: "https://id.wuse.io/oauth2/authorize",
                    clientID: "quiver-demo",
                    redirectURI: "https://dbg.wuse.io/auth/callback",
                    browserOnly: true
                )
            )
        )
        let policy = AuthPolicy(configuration: config)

        let request = HTTP3Request(
            method: .get,
            authority: "dbg.wuse.io",
            path: "/private",
            headers: [("accept", "application/json")]
        )

        let redirect = await policy.loginRedirectURL(for: request)
        #expect(redirect == nil)
    }

    @Test
    func derivesOIDCDiscoveryURLFromIssuer() {
        let derived = oidcDiscoveryURLFromIssuer("https://id.wuse.io")
        #expect(derived == "https://id.wuse.io/.well-known/openid-configuration")
    }

    @Test
    func keepsExistingDiscoveryURLWhenAlreadyWellKnown() {
        let raw = "https://id.wuse.io/.well-known/openid-configuration"
        let derived = oidcDiscoveryURLFromIssuer(raw)
        #expect(derived == raw)
    }

    @Test
    func buildsOIDCLoginRedirectWithInferredRedirectURI() async {
        let config = AuthConfiguration(
            mode: .oidcOnly,
            oidc: OIDCConfiguration(
                login: OIDCLoginConfiguration(
                    enabled: true,
                    authorizationEndpoint: "https://id.wuse.io/oauth2/authorize",
                    clientID: "quiver-demo"
                )
            )
        )
        let policy = AuthPolicy(configuration: config)

        let request = HTTP3Request(
            method: .get,
            authority: "dbg.wuse.io",
            path: "/private",
            headers: [
                ("accept", "text/html"),
                ("x-forwarded-proto", "https"),
            ]
        )

        guard let redirect = await policy.loginRedirectURL(for: request) else {
            Issue.record("Expected OIDC login redirect URL")
            return
        }

        #expect(queryValue("redirect_uri", in: redirect) == "https://dbg.wuse.io/auth/callback")
    }

    @Test
    func autoEnablesOIDCLoginRedirectWhenClientIDAndIssuerExist() async {
        let config = AuthConfiguration(
            mode: .oidcOnly,
            oidc: OIDCConfiguration(
                issuer: "https://id.wuse.io",
                login: OIDCLoginConfiguration(
                    enabled: false,
                    authorizationEndpoint: "https://id.wuse.io/oauth2/authorize",
                    clientID: "quiver-demo"
                )
            )
        )
        let policy = AuthPolicy(configuration: config)

        let request = HTTP3Request(
            method: .get,
            authority: "dbg.wuse.io",
            path: "/private",
            headers: [("accept", "text/html")]
        )

        let redirect = await policy.loginRedirectURL(for: request)
        #expect(redirect != nil)
    }

    @Test
    func includesPKCEAndStateInOIDCLoginRedirect() async {
        let config = AuthConfiguration(
            mode: .oidcOnly,
            oidc: OIDCConfiguration(
                login: OIDCLoginConfiguration(
                    enabled: true,
                    authorizationEndpoint: "https://id.wuse.io/oauth2/authorize",
                    clientID: "quiver-demo",
                    redirectURI: "https://dbg.wuse.io/auth/callback"
                )
            )
        )
        let policy = AuthPolicy(configuration: config)

        let request = HTTP3Request(
            method: .get,
            authority: "dbg.wuse.io",
            path: "/private",
            headers: [("accept", "text/html")]
        )

        guard let redirect = await policy.loginRedirectURL(for: request) else {
            Issue.record("Expected OIDC login redirect URL")
            return
        }

        #expect(queryValue("state", in: redirect) != nil)
        #expect(queryValue("nonce", in: redirect) != nil)
        #expect(queryValue("code_challenge", in: redirect) != nil)
        #expect(queryValue("code_challenge_method", in: redirect) == "S256")
    }

    @Test
    func oidcServerSessionCookieAuthenticatesUsingStoredTokenSet() async {
        let config = AuthConfiguration(
            mode: .oidcOnly,
            sessionCookieNames: ["z-token"],
            oidc: OIDCConfiguration(
                issuer: "https://id.wuse.io",
                audience: "dbg.wuse.io",
                dangerouslyAllowUnverifiedSignature: true,
                login: OIDCLoginConfiguration(
                    serverSession: OIDCServerSessionConfiguration(enabled: true)
                )
            )
        )
        let policy = AuthPolicy(configuration: config)

        let exp = Int(Date().timeIntervalSince1970) + 300
        let payload = #"{"sub":"sid-user","iss":"https://id.wuse.io","aud":"dbg.wuse.io","exp":"# + String(exp) + #"}"#
        let jwt = testJWT(payload: payload)
        let record = await OIDCServerSessionStore.shared.create(
            tokenSet: OIDCTokenSet(
                accessToken: nil,
                idToken: jwt,
                refreshToken: nil,
                tokenType: "Bearer",
                scope: "openid",
                expiresAt: Date().addingTimeInterval(300)
            )
        )

        let request = HTTP3Request(
            method: .get,
            authority: "example.test",
            path: "/private",
            headers: [("cookie", "z-token=\(record.sessionID)")]
        )

        let decision = await policy.evaluate(request: request, isFromGateway: true)
        switch decision {
        case .allow(let principal):
            #expect(principal.source == "oidc")
            #expect(principal.subject == "sid-user")
        case .deny(let status, let reason):
            Issue.record("Expected server session cookie to authorize in oidc mode. status=\(status) reason=\(reason)")
        }

        await OIDCServerSessionStore.shared.delete(sessionID: record.sessionID)
    }

    @Test
    func oidcServerSessionRejectsUnknownSessionID() async {
        let config = AuthConfiguration(
            mode: .oidcOnly,
            sessionCookieNames: ["z-token"],
            oidc: OIDCConfiguration(
                dangerouslyAllowUnverifiedSignature: true,
                login: OIDCLoginConfiguration(
                    serverSession: OIDCServerSessionConfiguration(enabled: true)
                )
            )
        )
        let policy = AuthPolicy(configuration: config)

        let request = HTTP3Request(
            method: .get,
            authority: "example.test",
            path: "/private",
            headers: [("cookie", "z-token=missing-session-id")]
        )

        let decision = await policy.evaluate(request: request, isFromGateway: true)
        switch decision {
        case .allow:
            Issue.record("Expected unknown session id to be denied")
        case .deny(let status, let reason):
            #expect(status == 401)
            #expect(reason.contains("invalid session"))
        }
    }

    @Test
    func guardClearsServerSessionCookieOnInvalidSessionDeny() async throws {
        let config = AuthConfiguration(
            mode: .oidcOnly,
            sessionCookieNames: ["z-token"],
            oidc: OIDCConfiguration(
                login: OIDCLoginConfiguration(
                    enabled: false,
                    serverSession: OIDCServerSessionConfiguration(enabled: true)
                )
            )
        )
        let policy = AuthPolicy(configuration: config)
        let guardMiddleware: HTTP3AuthGuard<QuiverAuthSession> = HTTP3AuthGuard(policy: policy)

        let protected = guardMiddleware.protect({ _ in
            Issue.record("Expected request to be denied before protected handler")
        })

        let capture = ResponseCapture()
        let request = HTTP3Request(
            method: .get,
            authority: "example.test",
            path: "/private",
            headers: [
                ("accept", "application/json"),
                ("cookie", "z-token=missing-session-id"),
            ]
        )
        let context = HTTP3RequestContext(
            request: request,
            streamID: 1,
            respond: { status, headers, _, _ in
                await capture.set(status: status, headers: headers)
            }
        )

        try await protected(context)

        let status = await capture.status
        let headers = await capture.headers

        #expect(status == 401)
        let setCookieHeader = headers.first { $0.0.caseInsensitiveCompare("set-cookie") == .orderedSame }?.1
        #expect(setCookieHeader != nil)
        #expect(setCookieHeader?.contains("z-token=") == true)
        #expect(setCookieHeader?.contains("Max-Age=0") == true)
    }

    @Test
    func oidcServerSessionMergesCachedUserInfoClaimsWithPrecedence() async {
        let config = AuthConfiguration(
            mode: .oidcOnly,
            sessionCookieNames: ["z-token"],
            oidc: OIDCConfiguration(
                issuer: "https://id.wuse.io",
                audience: "dbg.wuse.io",
                dangerouslyAllowUnverifiedSignature: true,
                login: OIDCLoginConfiguration(
                    serverSession: OIDCServerSessionConfiguration(
                        enabled: true,
                        liveUserInfoEnabled: true,
                        userInfoCacheTTLSeconds: 600
                    )
                )
            )
        )
        let policy = AuthPolicy(configuration: config)

        let exp = Int(Date().timeIntervalSince1970) + 300
        let payload = #"{"sub":"token-sub","email":"token@example.com","iss":"https://id.wuse.io","aud":"dbg.wuse.io","exp":"# + String(exp) + #"}"#
        let jwt = testJWT(payload: payload)

        let record = await OIDCServerSessionStore.shared.create(
            tokenSet: OIDCTokenSet(
                accessToken: "opaque-access-token",
                idToken: jwt,
                refreshToken: nil,
                tokenType: "Bearer",
                scope: "openid profile email",
                expiresAt: Date().addingTimeInterval(300)
            )
        )

        _ = await OIDCServerSessionStore.shared.mutate(sessionID: record.sessionID) { existing in
            existing.userInfoClaims = [
                "sub": .string("userinfo-sub"),
                "email": .string("userinfo@example.com"),
                "preferred_username": .string("hiro"),
            ]
            existing.userInfoFetchedAt = Date()
        }

        let request = HTTP3Request(
            method: .get,
            authority: "example.test",
            path: "/private",
            headers: [("cookie", "z-token=\(record.sessionID)")]
        )

        let decision = await policy.evaluate(request: request, isFromGateway: true)
        switch decision {
        case .allow(let principal):
            #expect(principal.subject == "userinfo-sub")
            #expect(principal.email == "userinfo@example.com")
            #expect(principal.claims["preferred_username"] == .string("hiro"))
        case .deny(let status, let reason):
            Issue.record("Expected merged cached userinfo claims to authorize. status=\(status) reason=\(reason)")
        }

        await OIDCServerSessionStore.shared.delete(sessionID: record.sessionID)
    }
}
