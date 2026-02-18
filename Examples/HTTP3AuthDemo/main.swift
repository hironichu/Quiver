// =============================================================================
// HTTP/3 Auth Demo (Small)
// =============================================================================
//
// Minimal server showing:
//   1) Centralized auth check for regular HTTP/3 requests
//   2) Same auth check for Extended CONNECT (e.g. WebTransport)
//   3) Alt-Svc gateway enabled with Alt-Svc advertisement enabled
//
// Run:
//   swift run HTTP3AuthDemo --cert certs/localhost.pem --key certs/localhost-key.pem
//
// Optional:
//   --host 0.0.0.0 --h3-port 4433 --https-port 443 --http-port 80
//
// Minimal OIDC login redirect setup (browser):
//   --oidc-issuer https://id.wuse.io --oidc-login-client-id <client_id>
//
// Try:
//   curl --http3 -k https://127.0.0.1:4433/public/health
//   curl --http3 -k https://127.0.0.1:4433/private -H 'authorization: Bearer demo-token'
//
// =============================================================================

import Foundation
import HTTP3
import Logging
import QuiverAuth

struct Arguments {
    var host: String = "0.0.0.0"
    var h3Port: UInt16 = 4433
    var httpsPort: UInt16? = 443
    var httpPort: UInt16? = nil
    var certPath: String?
    var keyPath: String?
    var authDebug: Bool = false
    var authMode: AuthMode = .composite
    var oidcIssuer: String?
    var oidcAudience: String?
    var oidcHS256Secret: String?
    var oidcAllowUnverifiedSignature: Bool = false
    var oidcJWKSURL: String?
    var oidcLoginEnabled: Bool = false
    var oidcLoginDiscoveryURL: String?
    var oidcLoginAuthorizationEndpoint: String?
    var oidcLoginClientID: String?
    var oidcLoginClientSecret: String?
    var oidcLoginRedirectURI: String?
    var oidcLoginErrorRetryURL: String? = "/"
    var oidcLoginScope: String = "openid profile email"
    var oidcLoginPrompt: String?
    var oidcLoginBrowserOnly: Bool = true

    static func parse() -> Arguments {
        var parsed = Arguments()
        let args = CommandLine.arguments

        var idx = 1
        while idx < args.count {
            switch args[idx] {
            case "--host":
                idx += 1
                if idx < args.count { parsed.host = args[idx] }
            case "--h3-port":
                idx += 1
                if idx < args.count { parsed.h3Port = UInt16(args[idx]) ?? parsed.h3Port }
            case "--https-port":
                idx += 1
                if idx < args.count { parsed.httpsPort = UInt16(args[idx]) }
            case "--http-port":
                idx += 1
                if idx < args.count { parsed.httpPort = UInt16(args[idx]) }
            case "--cert":
                idx += 1
                if idx < args.count { parsed.certPath = args[idx] }
            case "--key":
                idx += 1
                if idx < args.count { parsed.keyPath = args[idx] }
            case "--no-gateway":
                parsed.httpsPort = nil
                parsed.httpPort = nil
            case "--auth-debug":
                parsed.authDebug = true
            case "--auth-mode":
                idx += 1
                if idx < args.count, let parsedMode = AuthMode(rawValue: args[idx]) {
                    parsed.authMode = parsedMode
                }
            case "--oidc-issuer":
                idx += 1
                if idx < args.count { parsed.oidcIssuer = args[idx] }
            case "--oidc-audience":
                idx += 1
                if idx < args.count { parsed.oidcAudience = args[idx] }
            case "--oidc-hs256-secret":
                idx += 1
                if idx < args.count { parsed.oidcHS256Secret = args[idx] }
            case "--oidc-allow-unverified-signature":
                parsed.oidcAllowUnverifiedSignature = true
            case "--oidc-jwks-url":
                idx += 1
                if idx < args.count { parsed.oidcJWKSURL = args[idx] }
            case "--oidc-login-enabled":
                parsed.oidcLoginEnabled = true
            case "--oidc-login-discovery-url":
                idx += 1
                if idx < args.count { parsed.oidcLoginDiscoveryURL = args[idx] }
            case "--oidc-login-authorization-endpoint":
                idx += 1
                if idx < args.count { parsed.oidcLoginAuthorizationEndpoint = args[idx] }
            case "--oidc-login-client-id":
                idx += 1
                if idx < args.count { parsed.oidcLoginClientID = args[idx] }
            case "--oidc-login-client-secret":
                idx += 1
                if idx < args.count { parsed.oidcLoginClientSecret = args[idx] }
            case "--oidc-login-redirect-uri":
                idx += 1
                if idx < args.count { parsed.oidcLoginRedirectURI = args[idx] }
            case "--oidc-login-error-retry-url":
                idx += 1
                if idx < args.count { parsed.oidcLoginErrorRetryURL = args[idx] }
            case "--oidc-login-scope":
                idx += 1
                if idx < args.count { parsed.oidcLoginScope = args[idx] }
            case "--oidc-login-prompt":
                idx += 1
                if idx < args.count { parsed.oidcLoginPrompt = args[idx] }
            case "--oidc-login-allow-api":
                parsed.oidcLoginBrowserOnly = false
            case "--help", "-h":
                printUsageAndExit()
            default:
                break
            }
            idx += 1
        }

        return parsed
    }

    static func printUsageAndExit() -> Never {
        print(
            """
            HTTP3AuthDemo (small)

            Usage:
              swift run HTTP3AuthDemo --cert <path> --key <path> [options]

            Required (when gateway is enabled):
              --cert <path>            TLS certificate PEM for gateway HTTPS listener
              --key <path>             TLS private key PEM for gateway HTTPS listener

            Options:
              --host <addr>            Bind host (default: 0.0.0.0)
              --h3-port <port>         QUIC HTTP/3 port (default: 4433)
              --https-port <port>      Gateway HTTPS port (default: 443)
              --http-port <port>       Optional HTTP redirect port
              --no-gateway             Disable gateway completely
              --auth-debug             Print auth-relevant headers/cookies per request
                            --auth-mode <mode>       forward | oidc | composite (default: composite)
                            --oidc-issuer <iss>      Expected issuer claim for bearer token
                            --oidc-audience <aud>    Expected audience claim for bearer token
                            --oidc-hs256-secret <s>  HS256 secret for JWT signature verification
                              --oidc-jwks-url <url>    JWKS endpoint for RS256/ES256/EdDSA verification
                            --oidc-allow-unverified-signature
                                                                             Allow claim-only validation for non-HS256 JWTs (dev only)
                            --oidc-login-enabled          Enable 302 login redirect on 401
                            --oidc-login-client-id <id>   OIDC client_id for authorization redirect
                            --oidc-login-client-secret <s>
                                                                             OIDC client_secret for token exchange (confidential clients)
                            --oidc-login-redirect-uri <u> OIDC redirect_uri for authorization redirect
                            --oidc-login-error-retry-url <u>
                                                                             Retry URL shown on HTML auth error pages (default: /)
                            --oidc-login-discovery-url <u>
                                                                                     Optional explicit OIDC discovery URL
                            --oidc-login-authorization-endpoint <u>
                                                                                     Optional explicit authorization endpoint override
                            --oidc-login-scope <scope>    Authorization scope (default: openid profile email)
                            --oidc-login-prompt <prompt>  Optional prompt parameter
                            --oidc-login-allow-api        Allow redirects for non-browser Accept headers
              --help, -h               Show help
            """
        )
        exit(0)
    }
}

func masked(_ value: String, visiblePrefix: Int = 8) -> String {
    guard value.count > visiblePrefix else { return value }
    let prefix = value.prefix(visiblePrefix)
    return "\(prefix)…"
}

func debugAuthSnapshot(
    _ request: HTTP3Request,
    snapshot: AuthCredentialSnapshot,
    decision: AuthDecision
) {
    let interestingHeaders = [
        "host",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-for",
        "x-quiver-gateway",
        "authorization",
        "x-authenticated-user",
        "x-auth-request-user",
        "x-forwarded-user",
        "x-auth-request-email",
    ]
    var visible: [String] = []
    func header(_ name: String, in request: HTTP3Request) -> String? {
        request.headers.first(where: { $0.0.caseInsensitiveCompare(name) == .orderedSame })?.1
    }
    for name in interestingHeaders {
        if let value = header(name, in: request), !value.isEmpty {
            if name == "authorization" {
                visible.append("authorization=present")
            } else {
                visible.append("\(name)=\(value)")
            }
        }
    }

    let cookies = snapshot.cookies
    let cookieNames = cookies.map { $0.0 }.joined(separator: ",")
    let cookieDump = cookies
        .map { "\($0.0)=\(masked($0.1))" }
        .joined(separator: "; ")

    let decisionText: String
    switch decision {
    case .allow(let principal):
        decisionText = "ALLOW source=\(principal.source) subject=\(principal.subject)"
    case .deny(let status, let reason):
        decisionText = "DENY status=\(status) reason=\(reason)"
    }

    print(
        "[AUTH] \(decisionText) \(request.method.rawValue) \(request.path) authz{\(visible.joined(separator: "; "))} cookieCount=\(cookies.count) cookieNames{\(cookieNames)} cookieDump{\(cookieDump)}"
    )
}

@main
struct HTTP3AuthDemo {
    static func main() async {
        let args = Arguments.parse()

        let options: HTTP3ServerOptions
        if let cert = args.certPath, let key = args.keyPath {
            options = HTTP3ServerOptions(
                host: args.host,
                port: args.h3Port,
                certificatePath: cert,
                privateKeyPath: key,
                verifyPeer: false,
                enableDatagrams: true,
                enableConnectProtocol: true,
                enableH3Datagram: true,
                gatewayHTTPPort: args.httpPort,
                gatewayHTTPSPort: args.httpsPort,
                altSvcMaxAge: 86400,
                advertiseAltSvc: true,
                gatewayHTTPSBehavior: .serveApplication
            )

        } else {
            print("Missing --cert/--key. This demo requires PEM files so gateway HTTPS can start.")
            print("Hint: use your existing cert files from certs/. Run with --help for options.")
            return
        }

        let server = HTTP3Server(options: options)

        let oidcConfig: OIDCConfiguration?
        if args.oidcIssuer != nil || args.oidcAudience != nil || args.oidcHS256Secret != nil
            || args.oidcAllowUnverifiedSignature || args.oidcJWKSURL != nil
            || args.oidcLoginEnabled
            || args.oidcLoginDiscoveryURL != nil
            || args.oidcLoginAuthorizationEndpoint != nil
            || args.oidcLoginClientID != nil
            || args.oidcLoginClientSecret != nil
            || args.oidcLoginRedirectURI != nil
        {
            oidcConfig = OIDCConfiguration(
                issuer: args.oidcIssuer,
                audience: args.oidcAudience,
                hs256SharedSecret: args.oidcHS256Secret,
                allowUnverifiedSignature: args.oidcAllowUnverifiedSignature,
                jwksURL: args.oidcJWKSURL,
                login: OIDCLoginConfiguration(
                    enabled: args.oidcLoginEnabled || args.oidcLoginClientID != nil,
                    discoveryURL: args.oidcLoginDiscoveryURL,
                    authorizationEndpoint: args.oidcLoginAuthorizationEndpoint,
                    clientID: args.oidcLoginClientID,
                    clientSecret: args.oidcLoginClientSecret,
                    redirectURI: args.oidcLoginRedirectURI,
                    errorRetryURL: args.oidcLoginErrorRetryURL,
                    scope: args.oidcLoginScope,
                    prompt: args.oidcLoginPrompt,
                    browserOnly: args.oidcLoginBrowserOnly
                )
            )
        } else {
            oidcConfig = nil
        }

        let authConfig = AuthConfiguration(
            mode: args.authMode,
            sessionCookieNames: [
                "ta_session",
                "tinyauth-session",
                "_oauth2_proxy",
                "pocketid_session",
                "z-token",
            ],
            oidc: oidcConfig
        )
        let authPolicy = AuthPolicy(configuration: authConfig)
        let authGuard = HTTP3AuthGuard(policy: authPolicy)

        let appHandler: HTTP3Server.RequestHandler = { context in
            let path = context.request.path

            if path == "/public/health" {
                try await context.respond(
                    status: 200,
                    headers: [("content-type", "application/json")],
                    Data("{\"ok\":true,\"auth\":\"public\"}".utf8)
                )
                return
            }

            if path == "/private" {
                try await context.respond(
                    status: 200,
                    headers: [("content-type", "application/json")],
                    Data("{\"ok\":true,\"auth\":\"granted\",\"path\":\"/private\"}".utf8)
                )
                return
            }

            try await context.respond(
                status: 200,
                headers: [("content-type", "application/json")],
                Data("{\"ok\":true,\"auth\":\"granted\",\"path\":\"\(path)\"}".utf8)
            )
        }

        let guardedHandler = authGuard.protect(appHandler, scope: .except(["/public/health"]))

        await server.onRequest { context in
            if args.authDebug {
                let snapshot = authPolicy.authSnapshot(for: context.request)
                let decision = await authPolicy.evaluate(context)
                debugAuthSnapshot(context.request, snapshot: snapshot, decision: decision)
            }
            try await guardedHandler(context)
        }

        let connectHandler: HTTP3Server.ExtendedConnectHandler = { context in
            try await context.accept()
            try await context.stream.closeWrite()
        }
        let guardedConnectHandler = authGuard.protectExtendedConnect(
            connectHandler,
            allowedProtocols: ["webtransport"]
        )

        await server.onExtendedConnect { context in
            if args.authDebug {
                let snapshot = authPolicy.authSnapshot(for: context.request)
                let decision = await authPolicy.evaluate(context)
                debugAuthSnapshot(context.request, snapshot: snapshot, decision: decision)
            }
            try await guardedConnectHandler(context)
        }

        print("HTTP3AuthDemo listening")
        print("- H3: \(args.host):\(args.h3Port)")
        print("- Gateway HTTPS: \(args.httpsPort.map(String.init) ?? "disabled")")
        print("- Gateway HTTP: \(args.httpPort.map(String.init) ?? "disabled")")
        print("- Alt-Svc advertise: enabled")
        print("- Public route: /public/health")
        print("- Protected route: /private")
        print("- Auth debug: \(args.authDebug ? "enabled" : "disabled")")
        print("- Auth mode: \(String(describing: args.authMode))")
        if let oidcConfig {
            print("- OIDC issuer: \(oidcConfig.issuer ?? "not-set")")
            print("- OIDC audience: \(oidcConfig.audience ?? "not-set")")
            print("- OIDC JWKS URL: \(oidcConfig.jwksURL ?? "not-set")")
            print("- OIDC login redirect: \(oidcConfig.login.enabled ? "enabled" : "disabled")")
            print("- OIDC login client_id: \(oidcConfig.login.clientID ?? "not-set")")
            print("- OIDC login client_secret: \(oidcConfig.login.clientSecret == nil ? "not-set" : "set")")
            print("- OIDC login redirect_uri: \(oidcConfig.login.redirectURI ?? "not-set")")
            print("- OIDC login error retry URL: \(oidcConfig.login.errorRetryURL ?? "not-set")")
            print("- OIDC login discovery URL: \(oidcConfig.login.discoveryURL ?? "issuer fallback")")
            if oidcConfig.login.enabled, oidcConfig.login.clientID != nil, oidcConfig.login.redirectURI == nil {
                print("- OIDC login redirect_uri mode: inferred from request authority")
            }
            print(
                "- OIDC signature mode: \(oidcConfig.allowUnverifiedSignature ? "claims-only (unverified)" : "verified for HS256 only")"
            )
        }

        do {
            if args.httpsPort != nil || args.httpPort != nil {
                try await server.listenAll()
            } else {
                try await server.listen()
            }
        } catch {
            print("Server error: \(error)")
        }

        await server.stop(gracePeriod: .seconds(2))
    }
}
