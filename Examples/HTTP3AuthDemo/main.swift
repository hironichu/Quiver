import Foundation
import HTTP3
import QuiverAuth

struct Arguments {
    var host: String = "0.0.0.0"
    var h3Port: UInt16 = 4433
    var httpsPort: UInt16? = 8443
    var certPath: String?
    var keyPath: String?

    var oidcIssuer: String?
    var oidcAudience: String?
    var oidcJWKSURL: String?
    var oidcLoginClientID: String?
    var oidcLoginClientSecret: String?

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
            case "--oidc-client-id":
                index += 1
                if index < args.count { parsed.oidcLoginClientID = args[index] }
            case "--oidc-client-secret":
                index += 1
                if index < args.count { parsed.oidcLoginClientSecret = args[index] }
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
            HTTP3AuthDemo (minimal)

            Usage:
              swift run HTTP3AuthDemo --cert <path> --key <path> [options]

            Options:
              --host <addr>             Bind host (default: 0.0.0.0)
              --h3-port <port>          HTTP/3 port (default: 4433)
              --https-port <port>       Alt-Svc HTTPS gateway port (default: 8443)
              --no-gateway              Disable Alt-Svc gateway
              --cert <path>             TLS certificate PEM
              --key <path>              TLS private key PEM

              --oidc-issuer <url>       Expected OIDC issuer
              --oidc-audience <aud>     Expected audience
              --oidc-jwks-url <url>     JWKS URL for signature verification
              --oidc-client-id <id>     Browser login client_id (enables redirect)
              --oidc-client-secret <s>  Browser login client_secret (confidential clients)
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

struct AuthSession: Codable, Sendable {
    let subject: String?
    let source: String?
    let email: String?
    let sub: String?
    let iss: String?
    let aud: String?

    enum CodingKeys: String, CodingKey {
        case subject
        case source
        case email
        case sub
        case iss
        case aud
    }

    init(
        subject: String?,
        source: String?,
        email: String?,
        sub: String?,
        iss: String?,
        aud: String?
    ) {
        self.subject = subject
        self.source = source
        self.email = email
        self.sub = sub
        self.iss = iss
        self.aud = aud
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        subject = try container.decodeIfPresent(String.self, forKey: .subject)
        source = try container.decodeIfPresent(String.self, forKey: .source)
        email = try container.decodeIfPresent(String.self, forKey: .email)
        sub = try container.decodeIfPresent(String.self, forKey: .sub)
        iss = try container.decodeIfPresent(String.self, forKey: .iss)

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

        let policy = AuthPolicy(configuration: buildAuthConfiguration(args: args))
        let guardMiddleware = HTTP3AuthGuard(
            policy: policy,
            namespace: "auth",
            into: AuthSession.self
        )

        await server.onRequestSession(guardMiddleware.resolver)

        let router = HTTP3Router()

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
                print("No auth session available for /me")
                try await context.respondJSON(
                    status: 500,
                    APIResponse(ok: false, message: "auth session not available", data: [:])
                )
                return
            }
           if let auth = context.session.get("auth"),
            let value = auth["mom"] {
                switch value {
                case .string(let v): print(v)
                case .array(let a): print(a)
                case .object(let o): print(o)
                default: break
                }
            }
            let claims: [String: String] = [
                "subject": session.subject ?? "",
                "source": session.source ?? "",
                "email": session.email ?? "",
                "sub": session.sub ?? "",
                "iss": session.iss ?? "",
                "aud": session.aud ?? "",
            ]

            try await context.respondJSON(
                status: 200,
                APIResponse(ok: true, message: "auth session", data: claims.filter { !$0.value.isEmpty })
            )
        }

        let guarded = guardMiddleware.protect(router.handler, scope: .except(["/health"]))

        await server.onRequest { context in
            try await guarded(context)
        }

        print("HTTP3AuthDemo listening")
        print("- H3: \(args.host):\(args.h3Port)")
        print("- Gateway HTTPS: \(args.httpsPort.map(String.init) ?? "disabled")")
        print("- Routes: GET /health (public), GET /private (protected), GET /me (protected)")

        if let issuer = args.oidcIssuer {
            print("- OIDC issuer: \(issuer)")
            print("- OIDC login: \(args.oidcLoginClientID == nil ? "disabled" : "enabled")")
        } else {
            print("- OIDC issuer: not configured")
        }

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

    private static func buildAuthConfiguration(args: Arguments) -> AuthConfiguration {
        let hasOIDC = args.oidcIssuer != nil || args.oidcLoginClientID != nil

        let oidcConfig: OIDCConfiguration?
        if hasOIDC {
            oidcConfig = OIDCConfiguration(
                issuer: args.oidcIssuer,
                audience: args.oidcAudience,
                jwksURL: args.oidcJWKSURL,
                login: OIDCLoginConfiguration(
                    enabled: args.oidcLoginClientID != nil,
                    clientID: args.oidcLoginClientID,
                    clientSecret: args.oidcLoginClientSecret
                )
            )
        } else {
            oidcConfig = nil
        }

        return AuthConfiguration(
            mode: hasOIDC ? .oidcOnly : .forwardOnly,
            oidc: oidcConfig
        )
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
