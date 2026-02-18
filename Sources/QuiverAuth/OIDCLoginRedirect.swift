import Foundation
import Crypto
import HTTP3
import QUICCore
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
private let oidcLogger = QuiverLogging.logger(label: "quiver.auth.oidc")

func oidcDiscoveryURLFromIssuer(_ issuer: String) -> String? {
    let trimmed = issuer.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }

    if trimmed.localizedCaseInsensitiveContains("/.well-known/openid-configuration") {
        return trimmed
    }

    let normalizedIssuer = trimmed.hasSuffix("/") ? String(trimmed.dropLast()) : trimmed
    return normalizedIssuer + "/.well-known/openid-configuration"
}

private struct OIDCDiscoveryDocument: Decodable {
    let authorization_endpoint: String
    let token_endpoint: String?
    let userinfo_endpoint: String?
}

struct OIDCDiscoveryMetadata: Sendable {
    let authorizationEndpoint: String
    let tokenEndpoint: String?
    let userInfoEndpoint: String?
}

actor OIDCDiscoveryCache {
    static let shared = OIDCDiscoveryCache()

    private struct CacheEntry {
        let expiresAt: Date
        let metadata: OIDCDiscoveryMetadata
    }

    private var entries: [String: CacheEntry] = [:]

    func metadata(discoveryURL: URL, ttlSeconds: Int = 300) async throws -> OIDCDiscoveryMetadata {
        let key = discoveryURL.absoluteString
        if let cached = entries[key], cached.expiresAt > Date() {
            return cached.metadata
        }

        let (data, _) = try await URLSession.shared.data(from: discoveryURL)
        let document = try JSONDecoder().decode(OIDCDiscoveryDocument.self, from: data)
        let metadata = OIDCDiscoveryMetadata(
            authorizationEndpoint: document.authorization_endpoint,
            tokenEndpoint: document.token_endpoint,
            userInfoEndpoint: document.userinfo_endpoint
        )
        let expiresAt = Date().addingTimeInterval(TimeInterval(max(1, ttlSeconds)))
        entries[key] = CacheEntry(expiresAt: expiresAt, metadata: metadata)
        return metadata
    }
}

struct PendingOIDCLoginState: Sendable {
    let state: String
    let nonce: String
    let codeVerifier: String
    let codeChallenge: String
    let expiresAt: Date
}

actor OIDCLoginStateStore {
    static let shared = OIDCLoginStateStore()

    private var entries: [String: PendingOIDCLoginState] = [:]

    func create(ttlSeconds: Int) -> PendingOIDCLoginState {
        cleanupExpired()
        let verifier = generateURLSafeToken(length: 48)
        let challenge = pkceS256(verifier)
        let state = generateURLSafeToken()
        let pending = PendingOIDCLoginState(
            state: state,
            nonce: generateURLSafeToken(),
            codeVerifier: verifier,
            codeChallenge: challenge,
            expiresAt: Date().addingTimeInterval(TimeInterval(max(30, ttlSeconds)))
        )
        entries[state] = pending
        return pending
    }

    func consume(state: String) -> PendingOIDCLoginState? {
        cleanupExpired()
        guard let pending = entries.removeValue(forKey: state) else { return nil }
        guard pending.expiresAt > Date() else { return nil }
        return pending
    }

    private func cleanupExpired() {
        let now = Date()
        entries = entries.filter { $0.value.expiresAt > now }
    }
}

struct OIDCLoginCallbackHTTPResponse: Sendable {
    let status: Int
    let headers: [(String, String)]
    let body: Data
}

struct OIDCLoginRedirectBuilder: Sendable {
    let configuration: OIDCLoginConfiguration
    let fallbackDiscoveryURL: String?

    init(configuration: OIDCLoginConfiguration, fallbackDiscoveryURL: String? = nil) {
        self.configuration = configuration
        self.fallbackDiscoveryURL = fallbackDiscoveryURL
    }

    func buildRedirectURL(for request: HTTP3Request) async -> URL? {
        guard configuration.enabled else { return nil }
        if configuration.browserOnly, !isBrowserNavigation(request: request) {
            oidcLogger.trace(
                "skip oidc redirect for non-browser request",
                metadata: ["path": "\(request.path)"]
            )
            return nil
        }

        guard
            let clientID = configuration.clientID, !clientID.isEmpty,
            let redirectURI = resolveRedirectURI(for: request),
            let metadata = await resolveDiscoveryMetadata()
        else {
            oidcLogger.debug(
                "oidc redirect prerequisites missing",
                metadata: [
                    "path": "\(request.path)",
                    "hasClientID": "\(configuration.clientID != nil)",
                    "hasRedirectURI": "\(resolveRedirectURI(for: request) != nil)",
                ]
            )
            return nil
        }

        oidcLogger.debug(
            "building oidc redirect",
            metadata: [
                "path": "\(request.path)",
                "redirectURI": "\(redirectURI)",
                "authorizationEndpoint": "\(metadata.authorizationEndpoint)",
            ]
        )

        let pending = await OIDCLoginStateStore.shared.create(ttlSeconds: configuration.stateTTLSeconds)

        let endpoint = metadata.authorizationEndpoint
        guard var endpointComponents = URLComponents(string: endpoint) else { return nil }

        var queryItems: [URLQueryItem] = [
            URLQueryItem(name: "response_type", value: configuration.responseType),
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "scope", value: configuration.scope),
            URLQueryItem(name: "state", value: pending.state),
            URLQueryItem(name: "nonce", value: pending.nonce),
            URLQueryItem(name: "code_challenge", value: pending.codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ]

        if let prompt = configuration.prompt, !prompt.isEmpty {
            queryItems.append(URLQueryItem(name: "prompt", value: prompt))
        }

        for (name, value) in configuration.extraAuthorizationParameters {
            queryItems.append(URLQueryItem(name: name, value: value))
        }

        if let existing = endpointComponents.queryItems, !existing.isEmpty {
            queryItems = existing + queryItems
        }

        endpointComponents.queryItems = queryItems
        return endpointComponents.url
    }

    private func resolveDiscoveryMetadata() async -> OIDCDiscoveryMetadata? {
        if let explicitAuthorization = configuration.authorizationEndpoint, !explicitAuthorization.isEmpty {
            return OIDCDiscoveryMetadata(
                authorizationEndpoint: explicitAuthorization,
                tokenEndpoint: configuration.tokenEndpoint,
                userInfoEndpoint: nil
            )
        }

        let effectiveDiscoveryURL = configuration.discoveryURL ?? fallbackDiscoveryURL

        guard
            let discoveryRaw = effectiveDiscoveryURL,
            !discoveryRaw.isEmpty,
            let discoveryURL = URL(string: discoveryRaw)
        else {
            return nil
        }

        do {
            return try await OIDCDiscoveryCache.shared.metadata(discoveryURL: discoveryURL)
        } catch {
            return nil
        }
    }

    private func resolveRedirectURI(for request: HTTP3Request) -> String? {
        if let explicit = configuration.redirectURI?.trimmingCharacters(in: .whitespacesAndNewlines),
            !explicit.isEmpty
        {
            return explicit
        }

        let authority = request.authority.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !authority.isEmpty else { return nil }

        let scheme = forwardedProto(request: request) ?? "https"
        let path = normalizedRedirectPath(configuration.redirectPath)
        return "\(scheme)://\(authority)\(path)"
    }

    private func forwardedProto(request: HTTP3Request) -> String? {
        request.headers.first {
            $0.0.caseInsensitiveCompare("x-forwarded-proto") == .orderedSame
        }?.1.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func normalizedRedirectPath(_ path: String) -> String {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "/auth/callback" }
        return trimmed.hasPrefix("/") ? trimmed : "/\(trimmed)"
    }

    private func isBrowserNavigation(request: HTTP3Request) -> Bool {
        let acceptHeader = request.headers.first {
            $0.0.caseInsensitiveCompare("accept") == .orderedSame
        }?.1

        guard let acceptHeader else { return false }
        return acceptHeader.localizedCaseInsensitiveContains("text/html")
    }

    private func randomURLSafeToken(length: Int = 32) -> String {
        generateURLSafeToken(length: length)
    }
}

struct OIDCLoginCallbackHandler: Sendable {
    let configuration: OIDCLoginConfiguration
    let fallbackDiscoveryURL: String?

    func handleIfCallback(request: HTTP3Request) async -> OIDCLoginCallbackHTTPResponse? {
        guard configuration.enabled else { return nil }
        guard let requestURL = requestURL(fromPathAndAuthority: request.path, authority: request.authority) else {
            return nil
        }

        let callbackPath = callbackPathForRequest(request)
        guard requestURL.path == callbackPath else { return nil }

        oidcLogger.debug(
            "oidc callback received",
            metadata: [
                "path": "\(requestURL.path)",
                "authority": "\(request.authority)",
            ]
        )

        let query = URLComponents(url: requestURL, resolvingAgainstBaseURL: false)?.queryItems ?? []
        let errorValue = query.first(where: { $0.name == "error" })?.value
        if let errorValue, !errorValue.isEmpty {
            oidcLogger.debug(
                "oidc callback contains provider error",
                metadata: ["error": "\(errorValue)"]
            )
            return callbackFailureResponse(reason: "oidc_error:\(errorValue)", request: request)
        }

        guard
            let code = query.first(where: { $0.name == "code" })?.value,
            let state = query.first(where: { $0.name == "state" })?.value
        else {
            return callbackFailureResponse(reason: "missing_code_or_state", request: request)
        }

        guard let pending = await OIDCLoginStateStore.shared.consume(state: state) else {
            oidcLogger.debug("oidc callback state invalid or expired")
            return callbackFailureResponse(reason: "invalid_or_expired_state", request: request)
        }

        guard let clientID = configuration.clientID, !clientID.isEmpty else {
            return callbackFailureResponse(reason: "missing_client_id", request: request)
        }
        guard let redirectURI = resolveRedirectURI(for: request) else {
            return callbackFailureResponse(reason: "missing_redirect_uri", request: request)
        }
        guard let metadata = await resolveDiscoveryMetadata() else {
            return callbackFailureResponse(reason: "missing_oidc_discovery", request: request)
        }
        guard let tokenEndpoint = metadata.tokenEndpoint, !tokenEndpoint.isEmpty else {
            oidcLogger.debug("oidc callback missing token endpoint")
            return callbackFailureResponse(reason: "missing_token_endpoint", request: request)
        }

        oidcLogger.debug(
            "exchanging oidc code",
            metadata: [
                "tokenEndpoint": "\(tokenEndpoint)",
                "hasClientSecret": "\(configuration.clientSecret != nil)",
            ]
        )

        do {
            let tokenResponse = try await exchangeCode(
                tokenEndpoint: tokenEndpoint,
                code: code,
                redirectURI: redirectURI,
                clientID: clientID,
                clientSecret: configuration.clientSecret,
                codeVerifier: pending.codeVerifier
            )

            if let idToken = tokenResponse.idToken,
                let nonce = decodeStringClaim("nonce", fromJWT: idToken),
                nonce != pending.nonce
            {
                return callbackFailureResponse(reason: "nonce_mismatch", request: request)
            }

            let cookieValue: String
            if configuration.serverSession.enabled {
                let tokenSet = OIDCTokenSet(
                    accessToken: tokenResponse.accessToken,
                    idToken: tokenResponse.idToken,
                    refreshToken: tokenResponse.refreshToken,
                    tokenType: tokenResponse.tokenType,
                    scope: tokenResponse.scope,
                    expiresAt: tokenResponse.expiresIn.map { Date().addingTimeInterval(TimeInterval(max(1, $0))) }
                )

                guard tokenSet.validationToken() != nil else {
                    oidcLogger.debug("oidc callback missing session token from token response")
                    return callbackFailureResponse(reason: "missing_session_token", request: request)
                }

                let serverSession = await OIDCServerSessionStore.shared.create(tokenSet: tokenSet)
                cookieValue = serverSession.sessionID
            } else {
                guard let sessionToken = tokenResponse.idToken ?? tokenResponse.accessToken, !sessionToken.isEmpty else {
                    oidcLogger.debug("oidc callback missing session token from token response")
                    return callbackFailureResponse(reason: "missing_session_token", request: request)
                }
                cookieValue = sessionToken
            }

            let cookie = sessionCookieHeader(
                token: cookieValue,
                maxAgeSeconds: configuration.serverSession.cookieMaxAgeSeconds
            )
            oidcLogger.debug(
                "oidc callback success, issuing session cookie",
                metadata: [
                    "cookieName": "\(configuration.sessionCookieName)",
                    "successPath": "\(normalizedPath(configuration.callbackSuccessPath))",
                    "serverSession": "\(configuration.serverSession.enabled)",
                ]
            )
            return OIDCLoginCallbackHTTPResponse(
                status: 302,
                headers: [
                    ("set-cookie", cookie),
                    ("location", normalizedPath(configuration.callbackSuccessPath)),
                    ("cache-control", "no-store"),
                ],
                body: Data()
            )
        } catch {
            oidcLogger.warning(
                "oidc callback token exchange failed",
                metadata: ["error": "\(error.localizedDescription)"]
            )
            return callbackFailureResponse(reason: "token_exchange_failed:\(error.localizedDescription)", request: request)
        }
    }

    private func resolveDiscoveryMetadata() async -> OIDCDiscoveryMetadata? {
        if let explicitAuthorization = configuration.authorizationEndpoint, !explicitAuthorization.isEmpty {
            return OIDCDiscoveryMetadata(
                authorizationEndpoint: explicitAuthorization,
                tokenEndpoint: configuration.tokenEndpoint,
                userInfoEndpoint: nil
            )
        }

        let effectiveDiscoveryURL = configuration.discoveryURL ?? fallbackDiscoveryURL
        guard let effectiveDiscoveryURL, let discoveryURL = URL(string: effectiveDiscoveryURL) else {
            return nil
        }

        do {
            return try await OIDCDiscoveryCache.shared.metadata(discoveryURL: discoveryURL)
        } catch {
            return nil
        }
    }

    private func resolveRedirectURI(for request: HTTP3Request) -> String? {
        if let explicit = configuration.redirectURI?.trimmingCharacters(in: .whitespacesAndNewlines),
            !explicit.isEmpty
        {
            return explicit
        }

        let authority = request.authority.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !authority.isEmpty else { return nil }
        let scheme = forwardedProto(request: request) ?? "https"
        return "\(scheme)://\(authority)\(normalizedPath(configuration.redirectPath))"
    }

    private func callbackPathForRequest(_ request: HTTP3Request) -> String {
        if let explicit = configuration.redirectURI, let components = URLComponents(string: explicit), !components.path.isEmpty {
            return components.path
        }
        return normalizedPath(configuration.redirectPath)
    }

    private func callbackFailureResponse(reason: String, request: HTTP3Request) -> OIDCLoginCallbackHTTPResponse {
        if let callbackFailurePath = configuration.callbackFailurePath, !callbackFailurePath.isEmpty {
            return OIDCLoginCallbackHTTPResponse(
                status: 302,
                headers: [
                    ("location", normalizedPath(callbackFailurePath)),
                    ("cache-control", "no-store"),
                ],
                body: Data()
            )
        }

        if shouldReturnHTML(for: request) {
            return OIDCLoginCallbackHTTPResponse(
                status: 401,
                headers: [
                    ("content-type", "text/html; charset=utf-8"),
                    ("cache-control", "no-store"),
                ],
                body: Data(callbackFailureHTML(reason: reason).utf8)
            )
        }

        return OIDCLoginCallbackHTTPResponse(
            status: 401,
            headers: [
                ("content-type", "application/json"),
                ("cache-control", "no-store"),
            ],
            body: Data("{\"error\":\"oidc_callback_failed\",\"reason\":\"\(reason)\"}".utf8)
        )
    }

        private func shouldReturnHTML(for request: HTTP3Request) -> Bool {
                let accept = headerValue("accept", in: request)?.lowercased() ?? ""
                let contentType = headerValue("content-type", in: request)?.lowercased() ?? ""
                let requestedWith = headerValue("x-requested-with", in: request)?.lowercased() ?? ""
                let fetchMode = headerValue("sec-fetch-mode", in: request)?.lowercased() ?? ""

                if accept.contains("application/json") { return false }
                if contentType.contains("application/json") { return false }
                if requestedWith.contains("xmlhttprequest") { return false }
                if !fetchMode.isEmpty && fetchMode != "navigate" { return false }

                return accept.contains("text/html") || fetchMode == "navigate"
        }

        private func headerValue(_ name: String, in request: HTTP3Request) -> String? {
                request.headers.first { $0.0.caseInsensitiveCompare(name) == .orderedSame }?.1
        }

        private func callbackFailureHTML(reason: String) -> String {
                let safeReason = escapeHTML(reason)
            let retryHTML: String
            if let retryURL = configuration.errorRetryURL?.trimmingCharacters(in: .whitespacesAndNewlines), !retryURL.isEmpty {
                retryHTML = "<p><a class=\"btn\" href=\"\(escapeHTML(retryURL))\">Try again</a></p>"
            } else {
                retryHTML = ""
            }

                return """
                <!doctype html>
                <html lang=\"en\">
                    <head>
                        <meta charset=\"utf-8\" />
                        <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
                        <title>Login Failed</title>
                        <style>
                            :root { color-scheme: light dark; }
                            body {
                                margin: 0;
                                font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif;
                                background: #f7f8fa;
                                color: #101828;
                                display: grid;
                                min-height: 100vh;
                                place-items: center;
                                padding: 16px;
                            }
                            .card {
                                width: min(460px, 100%);
                                background: #ffffff;
                                border: 1px solid #e4e7ec;
                                border-radius: 12px;
                                padding: 18px 20px;
                                box-shadow: 0 6px 20px rgba(16, 24, 40, 0.08);
                            }
                            h1 { margin: 0 0 8px 0; font-size: 18px; }
                            p { margin: 0 0 10px 0; color: #475467; font-size: 14px; }
                            code {
                                display: inline-block;
                                margin-top: 4px;
                                padding: 2px 6px;
                                border-radius: 6px;
                                background: #f2f4f7;
                                font-size: 12px;
                                color: #344054;
                            }
                            .btn {
                                display: inline-block;
                                margin-top: 8px;
                                text-decoration: none;
                                background: #175cd3;
                                color: #ffffff;
                                border-radius: 8px;
                                padding: 7px 12px;
                                font-size: 13px;
                            }
                        </style>
                    </head>
                    <body>
                        <main class=\"card\">
                            <h1>Login failed</h1>
                            <p>We could not complete your sign-in flow.</p>
                            <code>\(safeReason)</code>
                            \(retryHTML)
                        </main>
                    </body>
                </html>
                """
        }

        private func escapeHTML(_ value: String) -> String {
                value
                        .replacingOccurrences(of: "&", with: "&amp;")
                        .replacingOccurrences(of: "<", with: "&lt;")
                        .replacingOccurrences(of: ">", with: "&gt;")
                        .replacingOccurrences(of: "\"", with: "&quot;")
                        .replacingOccurrences(of: "'", with: "&#39;")
        }

    private func exchangeCode(
        tokenEndpoint: String,
        code: String,
        redirectURI: String,
        clientID: String,
        clientSecret: String?,
        codeVerifier: String
    ) async throws -> OIDCTokenResponse {
        guard let url = URL(string: tokenEndpoint) else {
            throw NSError(
                domain: "QuiverAuth.OIDCLogin",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid_token_endpoint"]
            )
        }

        var form: [(String, String)] = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirectURI),
            ("client_id", clientID),
            ("code_verifier", codeVerifier),
        ]
        if let clientSecret, !clientSecret.isEmpty {
            form.append(("client_secret", clientSecret))
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "content-type")
        request.setValue("application/json", forHTTPHeaderField: "accept")

        if let clientSecret, !clientSecret.isEmpty {
            let credentials = "\(clientID):\(clientSecret)"
            let encoded = Data(credentials.utf8).base64EncodedString()
            request.setValue("Basic \(encoded)", forHTTPHeaderField: "authorization")
        }

        request.httpBody = Data(formURLEncoded(form).utf8)

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw NSError(
                domain: "QuiverAuth.OIDCLogin",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "token_endpoint_invalid_response"]
            )
        }

        guard 200..<300 ~= httpResponse.statusCode else {
            let bodySnippet = String(data: data, encoding: .utf8) ?? "<non-utf8-body>"
            throw NSError(
                domain: "QuiverAuth.OIDCLogin",
                code: 3,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "token_endpoint_http_\(httpResponse.statusCode):\(bodySnippet.prefix(300))",
                ]
            )
        }

        do {
            return try JSONDecoder().decode(OIDCTokenResponse.self, from: data)
        } catch {
            let bodySnippet = String(data: data, encoding: .utf8) ?? "<non-utf8-body>"
            throw NSError(
                domain: "QuiverAuth.OIDCLogin",
                code: 4,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "token_endpoint_decode_failed:\(error.localizedDescription):\(bodySnippet.prefix(300))",
                ]
            )
        }
    }

    private func sessionCookieHeader(token: String, maxAgeSeconds: Int?) -> String {
        var parts = ["\(configuration.sessionCookieName)=\(token)"]
        parts.append("Path=\(configuration.sessionCookiePath)")
        if let maxAgeSeconds, maxAgeSeconds > 0 {
            parts.append("Max-Age=\(maxAgeSeconds)")
        }
        if configuration.sessionCookieSecure { parts.append("Secure") }
        if configuration.sessionCookieHTTPOnly { parts.append("HttpOnly") }
        parts.append("SameSite=\(configuration.sessionCookieSameSite)")
        return parts.joined(separator: "; ")
    }

    private func normalizedPath(_ path: String) -> String {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return "/" }
        return trimmed.hasPrefix("/") ? trimmed : "/\(trimmed)"
    }

    private func forwardedProto(request: HTTP3Request) -> String? {
        request.headers.first {
            $0.0.caseInsensitiveCompare("x-forwarded-proto") == .orderedSame
        }?.1.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func requestURL(fromPathAndAuthority path: String, authority: String) -> URL? {
        let normalizedPath = path.hasPrefix("/") ? path : "/\(path)"
        return URL(string: "https://\(authority)\(normalizedPath)")
    }

    private func decodeStringClaim(_ name: String, fromJWT token: String) -> String? {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { return nil }
        guard let payloadData = decodeBase64URL(String(parts[1])) else { return nil }
        guard let object = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else { return nil }
        return object[name] as? String
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
}

struct OIDCTokenResponse: Decodable {
    let accessToken: String?
    let idToken: String?
    let refreshToken: String?
    let tokenType: String?
    let scope: String?
    let expiresIn: Int?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case idToken = "id_token"
        case refreshToken = "refresh_token"
        case tokenType = "token_type"
        case scope
        case expiresIn = "expires_in"
    }
}

private func formURLEncoded(_ pairs: [(String, String)]) -> String {
    pairs
        .map { "\(urlEncode($0.0))=\(urlEncode($0.1))" }
        .joined(separator: "&")
}

private func urlEncode(_ value: String) -> String {
    var allowed = CharacterSet.urlQueryAllowed
    allowed.remove(charactersIn: ":#[]@!$&'()*+,;=")
    return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
}

private func generateURLSafeToken(length: Int = 32) -> String {
    var bytes = [UInt8](repeating: 0, count: length)
    for index in bytes.indices {
        bytes[index] = UInt8.random(in: UInt8.min...UInt8.max)
    }
    return Data(bytes)
        .base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func pkceS256(_ verifier: String) -> String {
    let digest = SHA256.hash(data: Data(verifier.utf8))
    return Data(digest)
        .base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}
