import Foundation
import HTTP3
import QuiverAuth

struct Arguments {
    var host: String = "0.0.0.0"
    var h3Port: UInt16 = 4433
    var httpsPort: UInt16? = 8443
    var certPath: String?
    var keyPath: String?

    // OIDC core
    var oidcIssuer: String?
    var oidcAudience: String?
    var oidcJWKSURL: String?
    var oidcDiscoveryURL: String?
    var oidcAuthorizationEndpoint: String?
    var oidcTokenEndpoint: String?

    // OIDC login / browser flow
    var oidcLoginClientID: String?
    var oidcLoginClientSecret: String?
    var oidcRedirectURI: String?
    var oidcScope: String?
    var oidcClaims: String?
    var oidcUserInfoURL: String?
    var oidcTokenAuthMethod: String?
    var oidcCallbackSuccessPath: String?
    var oidcCookieName: String?
    var oidcPostLogoutPath: String?

    // Provider preset ("twitch" is pre-wired for convenience)
    var oidcProvider: String?

    static func parse() -> Arguments {
        var parsed = Arguments()
        let args = CommandLine.arguments

        var index = 1
        while index < args.count {
            switch args[index] {
            case "--host":
                index += 1
                if index < args.count { parsed.host = args[index] }
            case "--h3-port":
                index += 1
                if index < args.count { parsed.h3Port = UInt16(args[index]) ?? parsed.h3Port }
            case "--https-port":
                index += 1
                if index < args.count { parsed.httpsPort = UInt16(args[index]) }
            case "--no-gateway":
                parsed.httpsPort = nil
            case "--cert":
                index += 1
                if index < args.count { parsed.certPath = args[index] }
            case "--key":
                index += 1
                if index < args.count { parsed.keyPath = args[index] }
            case "--oidc-issuer":
                index += 1
                if index < args.count { parsed.oidcIssuer = args[index] }
            case "--oidc-audience":
                index += 1
                if index < args.count { parsed.oidcAudience = args[index] }
            case "--oidc-jwks-url":
                index += 1
                if index < args.count { parsed.oidcJWKSURL = args[index] }
            case "--oidc-discovery-url":
                index += 1
                if index < args.count { parsed.oidcDiscoveryURL = args[index] }
            case "--oidc-authorization-url":
                index += 1
                if index < args.count { parsed.oidcAuthorizationEndpoint = args[index] }
            case "--oidc-token-url":
                index += 1
                if index < args.count { parsed.oidcTokenEndpoint = args[index] }
            case "--oidc-client-id":
                index += 1
                if index < args.count { parsed.oidcLoginClientID = args[index] }
            case "--oidc-client-secret":
                index += 1
                if index < args.count { parsed.oidcLoginClientSecret = args[index] }
            case "--oidc-redirect-uri":
                index += 1
                if index < args.count { parsed.oidcRedirectURI = args[index] }
            case "--oidc-scope":
                index += 1
                if index < args.count { parsed.oidcScope = args[index] }
            case "--oidc-claims":
                index += 1
                if index < args.count { parsed.oidcClaims = args[index] }
            case "--oidc-userinfo-url":
                index += 1
                if index < args.count { parsed.oidcUserInfoURL = args[index] }
            case "--oidc-token-auth-method":
                index += 1
                if index < args.count { parsed.oidcTokenAuthMethod = args[index] }
            case "--oidc-callback-success":
                index += 1
                if index < args.count { parsed.oidcCallbackSuccessPath = args[index] }
            case "--oidc-cookie-name":
                index += 1
                if index < args.count { parsed.oidcCookieName = args[index] }
            case "--oidc-post-logout":
                index += 1
                if index < args.count { parsed.oidcPostLogoutPath = args[index] }
            case "--oidc-provider":
                index += 1
                if index < args.count { parsed.oidcProvider = args[index] }
            case "--help", "-h":
                printUsageAndExit()
            default:
                break
            }
            index += 1
        }

        return parsed
    }

    static func printUsageAndExit() -> Never {
        print(
            """
            HTTP3AuthDemo

            Usage:
              swift run HTTP3AuthDemo --cert <path> --key <path> [options]

            Server options:
              --host <addr>                    Bind host (default: 0.0.0.0)
              --h3-port <port>                 HTTP/3 port (default: 4433)
              --https-port <port>              Alt-Svc HTTPS gateway port (default: 8443)
              --no-gateway                     Disable Alt-Svc gateway
              --cert <path>                    TLS certificate PEM
              --key <path>                     TLS private key PEM

            OIDC core:
              --oidc-issuer <url>              Expected OIDC issuer (e.g. https://id.twitch.tv/oauth2)
              --oidc-audience <aud>            Expected audience (defaults to client_id)
              --oidc-jwks-url <url>            JWKS URL for explicit signature verification
              --oidc-discovery-url <url>       Full discovery document URL (auto-derived from issuer when omitted)
              --oidc-authorization-url <url>   Explicit authorization endpoint when discovery is not used
              --oidc-token-url <url>           Explicit token endpoint when discovery is not used

            OIDC browser login flow:
              --oidc-client-id <id>            OAuth2 client_id (enables browser login redirect)
              --oidc-client-secret <secret>    OAuth2 client_secret (confidential clients)
              --oidc-redirect-uri <uri>        Full redirect URI sent to the provider
              --oidc-scope <scope>             Space-delimited scopes (default: openid profile email)
              --oidc-claims <json>             JSON claims parameter (providers such as Twitch require this)
              --oidc-userinfo-url <url>        Override UserInfo endpoint URL
              --oidc-token-auth-method <m>     client_secret_basic (default) | client_secret_post | none
              --oidc-callback-success <path>   Where to redirect after successful login (default: /me)
              --oidc-cookie-name <name>        Session cookie name (default: z-token)
              --oidc-post-logout <path>        Where to redirect after logout (default: /)

            Provider presets:
              --oidc-provider twitch           Pre-wires issuer, scope, claims, and token auth for Twitch.
                                               Still requires --oidc-client-id / --oidc-client-secret.

            Examples:
              # Generic OIDC (e.g. Keycloak)
              swift run HTTP3AuthDemo \\
                --cert certs/server.crt --key certs/server.key \\
                --oidc-issuer https://keycloak.example.com/realms/myrealm \\
                --oidc-client-id myapp --oidc-client-secret s3cr3t

              # Twitch OIDC
              swift run HTTP3AuthDemo \\
                --cert certs/server.crt --key certs/server.key \\
                --oidc-provider twitch \\
                --oidc-client-id <your_client_id> \\
                --oidc-client-secret <your_client_secret> \\
                --oidc-redirect-uri https://localhost:8443/auth/callback
            """
        )
        exit(0)
    }
}

struct APIResponse: Encodable {
    let ok: Bool
    let message: String
    let data: [String: String]
}

struct APIDebugResponse: Encodable {
    let ok: Bool
    let message: String
    let tokenClaims: [String: HTTP3SessionValue]
    let userInfoClaims: [String: HTTP3SessionValue]
    let mergedClaims: [String: HTTP3SessionValue]
}

struct AuthSession: Codable, Sendable {
    let subject: String?
    let source: String?
    let email: String?
    let sub: String?
    let iss: String?
    let aud: String?
    let preferred_username: String?

    enum CodingKeys: String, CodingKey {
        case subject
        case source
        case email
        case sub
        case iss
        case aud
        case preferred_username
    }

    init(
        subject: String?,
        source: String?,
        email: String?,
        sub: String?,
        iss: String?,
        aud: String?,
        preferred_username: String? = nil
    ) {
        self.subject = subject
        self.source = source
        self.email = email
        self.sub = sub
        self.iss = iss
        self.aud = aud
        self.preferred_username = preferred_username
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        subject = try container.decodeIfPresent(String.self, forKey: .subject)
        source = try container.decodeIfPresent(String.self, forKey: .source)
        email = try container.decodeIfPresent(String.self, forKey: .email)
        sub = try container.decodeIfPresent(String.self, forKey: .sub)
        iss = try container.decodeIfPresent(String.self, forKey: .iss)
        preferred_username = try container.decodeIfPresent(String.self, forKey: .preferred_username)
        if let singleAud = try? container.decode(String.self, forKey: .aud) {
            aud = singleAud
        } else if let audArray = try? container.decode([String].self, forKey: .aud) {
            aud = audArray.joined(separator: ",")
        } else {
            aud = nil
        }
    }
}

@main
struct HTTP3AuthDemo {
    static func main() async {
        let args = Arguments.parse()

        guard let cert = args.certPath, let key = args.keyPath else {
            print("Missing --cert and --key")
            Arguments.printUsageAndExit()
        }

        let options = HTTP3ServerOptions(
            host: args.host,
            port: args.h3Port,
            certificatePath: cert,
            privateKeyPath: key,
            verifyPeer: false,
            gatewayHTTPPort: nil,
            gatewayHTTPSPort: args.httpsPort,
            advertiseAltSvc: true,
            gatewayHTTPSBehavior: .serveApplication
        )

        let server = HTTP3Server(options: options)

        let authConfig = buildAuthConfiguration(args: args)
        let policy = AuthPolicy(configuration: authConfig)
        let guardMiddleware = HTTP3AuthGuard(
            policy: policy,
            namespace: "auth",
            into: AuthSession.self
        )

        await server.onRequestSession(guardMiddleware.resolver)

        let router = HTTP3Router()

        let loginConfigured = args.oidcLoginClientID != nil

        router.get("/") { context, _ in
            let body: String
            if loginConfigured {
                body = """
                    <!doctype html>
                    <html lang="en">
                    <head><meta charset="utf-8"><title>HTTP3AuthDemo</title></head>
                    <body>
                      <h1>HTTP3AuthDemo</h1>
                      <p>You are not logged in.</p>
                      <a href="/login"><button>Login</button></a>
                    </body>
                    </html>
                    """
            } else {
                body = """
                    <!doctype html>
                    <html lang="en">
                    <head><meta charset="utf-8"><title>HTTP3AuthDemo</title></head>
                    <body>
                      <h1>HTTP3AuthDemo</h1>
                      <p>OIDC login is not configured. Pass --oidc-client-id to enable it.</p>
                      <ul>
                        <li><a href="/health">GET /health</a> - public health check</li>
                        <li><a href="/private">GET /private</a> - protected route</li>
                        <li><a href="/me">GET /me</a> - session claims</li>
                        <li><a href="/me-debug">GET /me-debug</a> - debug claims</li>
                      </ul>
                    </body>
                    </html>
                    """
            }
            try await context.respond(
                status: 200,
                headers: [("content-type", "text/html; charset=utf-8"), ("cache-control", "no-store")],
                Data(body.utf8)
            )
        }

        router.get("/login") { context, _ in
            guard let loginURL = await policy.loginRedirectURL(for: context.request) else {
                try await context.respond(
                    status: 503,
                    headers: [("content-type", "text/plain")],
                    Data("OIDC login is not configured.".utf8)
                )
                return
            }
            try await context.respond(
                status: 302,
                headers: [("location", loginURL.absoluteString), ("cache-control", "no-store")],
                Data()
            )
        }

        router.get("/logout") { context, _ in
            if let (status, headers, body) = await policy.logoutResponse(for: context.request) {
                try await context.respond(status: status, headers: headers, body)
            } else {
                try await context.respond(
                    status: 302,
                    headers: [("location", "/"), ("cache-control", "no-store")],
                    Data()
                )
            }
        }

        router.get("/health") { context, _ in
            try await context.respondJSON(
                status: 200,
                APIResponse(ok: true, message: "public", data: ["path": context.request.path])
            )
        }

        router.get("/private") { context, _ in
            let subject = context.session.get("auth", as: AuthSession.self)?.subject ?? "unknown"
            try await context.respondJSON(
                status: 200,
                APIResponse(ok: true, message: "authorized", data: ["subject": subject])
            )
        }

        router.get("/me") { context, _ in
            guard let session = context.session.get("auth", as: AuthSession.self) else {
                try await context.respondJSON(
                    status: 500,
                    APIResponse(ok: false, message: "auth session not available", data: [:])
                )
                return
            }

            let claims: [String: String] = [
                "subject": session.subject ?? "",
                "source": session.source ?? "",
                "email": session.email ?? "",
                "sub": session.sub ?? "",
                "iss": session.iss ?? "",
                "aud": session.aud ?? "",
                "preferred_username": session.preferred_username ?? "",
            ]

            try await context.respondJSON(
                status: 200,
                APIResponse(ok: true, message: "auth session", data: claims.filter { !$0.value.isEmpty })
            )
        }

        router.get("/me-debug") { context, _ in
            guard let authNamespace = context.session.get("auth") else {
                try await context.respondJSON(
                    status: 500,
                    APIDebugResponse(
                        ok: false,
                        message: "auth session not available",
                        tokenClaims: [:],
                        userInfoClaims: [:],
                        mergedClaims: [:]
                    )
                )
                return
            }

            let tokenClaims: [String: HTTP3SessionValue]
            if case .object(let value)? = authNamespace["_token_claims"] {
                tokenClaims = value
            } else {
                tokenClaims = [:]
            }

            let userInfoClaims: [String: HTTP3SessionValue]
            if case .object(let value)? = authNamespace["_userinfo_claims"] {
                userInfoClaims = value
            } else {
                userInfoClaims = [:]
            }

            let mergedClaims = authNamespace.filter {
                $0.key != "_token_claims" && $0.key != "_userinfo_claims"
            }

            try await context.respondJSON(
                status: 200,
                APIDebugResponse(
                    ok: true,
                    message: "auth debug",
                    tokenClaims: tokenClaims,
                    userInfoClaims: userInfoClaims,
                    mergedClaims: mergedClaims
                )
            )
        }

        let publicRoutes = ["/", "/login", "/logout", "/health"]
        let guarded = guardMiddleware.protect(router.handler, scope: .except(publicRoutes))

        await server.onRequest { context in
            try await guarded(context)
        }

        printBanner(args: args)

        do {
            if args.httpsPort != nil {
                try await server.listenAll()
            } else {
                try await server.listen()
            }
        } catch {
            print("Server error: \(error)")
        }

        await server.stop(gracePeriod: .seconds(2))
    }

    // MARK: - Auth configuration

    private static func buildAuthConfiguration(args: Arguments) -> AuthConfiguration {
        let provider = args.oidcProvider?.lowercased()

        let issuer = args.oidcIssuer ?? (provider == "twitch" ? "https://id.twitch.tv/oauth2" : nil)
        let scope = args.oidcScope ?? (provider == "twitch" ? "openid user:read:email" : nil)
        let tokenAuthMethod: OIDCTokenEndpointAuthMethod? = {
            if let raw = args.oidcTokenAuthMethod {
                return OIDCTokenEndpointAuthMethod(rawValue: raw)
            }
            if provider == "twitch" {
                return .clientSecretPost
            }
            return nil
        }()

        var extraParams: [String: String] = [:]
        if let claims = args.oidcClaims {
            extraParams["claims"] = claims
        } else if provider == "twitch" {
            extraParams["claims"] =
                "{\"id_token\":{\"preferred_username\":null,\"email\":null}}"
        }

        let hasOIDC = issuer != nil || args.oidcLoginClientID != nil

        let oidcConfig: OIDCConfiguration?
        if hasOIDC {
            let serverSessionConfig = OIDCServerSessionConfiguration(
                enabled: true,
                userInfoEndpoint: args.oidcUserInfoURL
            )

            let loginConfig = OIDCLoginConfiguration(
                enabled: args.oidcLoginClientID != nil,
                discoveryURL: args.oidcDiscoveryURL,
                authorizationEndpoint: args.oidcAuthorizationEndpoint,
                tokenEndpoint: args.oidcTokenEndpoint,
                clientID: args.oidcLoginClientID,
                clientSecret: args.oidcLoginClientSecret,
                redirectURI: args.oidcRedirectURI,
                callbackSuccessPath: args.oidcCallbackSuccessPath ?? "/me",
                scope: scope ?? "openid profile email",
                extraAuthorizationParameters: extraParams,
                sessionCookieName: args.oidcCookieName ?? "z-token",
                serverSession: serverSessionConfig,
                tokenEndpointAuthMethod: tokenAuthMethod,
                postLogoutPath: args.oidcPostLogoutPath ?? "/"
            )

            oidcConfig = OIDCConfiguration(
                issuer: issuer,
                audience: args.oidcAudience,
                jwksURL: args.oidcJWKSURL,
                login: loginConfig
            )
        } else {
            oidcConfig = nil
        }

        return AuthConfiguration(
            mode: hasOIDC ? .oidcOnly : .forwardOnly,
            oidc: oidcConfig
        )
    }

    // MARK: - Banner

    private static func printBanner(args: Arguments) {
        print("HTTP3AuthDemo listening")
        print("  H3:            \(args.host):\(args.h3Port)")
        print("  Gateway HTTPS: \(args.httpsPort.map(String.init) ?? "disabled")")
        print("")
        print("  Routes (public):    GET /  GET /login  GET /logout  GET /health")
        print("  Routes (protected): GET /private  GET /me  GET /me-debug")
        if let issuer = args.oidcIssuer ?? (args.oidcProvider == "twitch" ? "https://id.twitch.tv/oauth2" : nil) {
            print("")
            print("  OIDC issuer:  \(issuer)")
            print("  OIDC login:   \(args.oidcLoginClientID != nil ? "enabled (client_id=\(args.oidcLoginClientID!))" : "disabled")")
            if let provider = args.oidcProvider {
                print("  Provider:     \(provider) preset active")
            }
        } else {
            print("")
            print("  OIDC: not configured (pass --oidc-client-id to enable browser login)")
        }
    }
}

private extension HTTP3RequestContext {
    func respondJSON<T: Encodable>(status: Int, _ value: T) async throws {
        let data = try JSONEncoder().encode(value)
        try await respond(
            status: status,
            headers: [
                ("content-type", "application/json"),
                ("cache-control", "no-store"),
            ],
            data
        )
    }
}
