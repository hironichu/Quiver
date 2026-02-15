// =============================================================================
// Alt-Svc Gateway Demo
// =============================================================================
//
// HTTP/3 server with an Alt-Svc TCP gateway that advertises HTTP/3
// to browsers via the Alt-Svc header (RFC 7838 / RFC 9114 Section 3).
//
// The gateway listens on TCP (HTTP + HTTPS) and responds with
// `Alt-Svc: h3=":PORT"` so browsers discover and upgrade to HTTP/3.
// The QUIC HTTP/3 server serves the actual content.
//
// ## Running
//
//   swift run AltSvcDemo \
//       --certpath /path/to/cert.pem \
//       --keypath /path/to/key.pem \
//       --httpsPort 443
//
//   # With optional HTTP redirect port
//   swift run AltSvcDemo \
//       --certpath cert.pem \
//       --keypath key.pem \
//       --httpsPort 443 \
//       --httpPort 80
//
// =============================================================================

import Foundation
import HTTP3
import Logging
import QUIC
import QUICCore
import QUICCrypto

// MARK: - Constants

let defaultH3Port: UInt16 = 4433
let defaultGatewayHTTPSPort: UInt16 = 443

// MARK: - Argument Parsing

struct Arguments {
    let host: String
    let certPath: String
    let keyPath: String
    let httpsPort: UInt16
    let httpPort: UInt16?
    let h3Port: UInt16
    let logLevel: Logger.Level

    static func parse() -> Arguments? {
        let args = CommandLine.arguments

        if args.contains("--help") || args.contains("-h") {
            printUsage()
            return nil
        }

        let host = value(for: "--host", in: args) ?? "0.0.0.0"

        guard let certPath = value(for: "--certpath", in: args) else {
            printError("--certpath is required")
            printUsage()
            return nil
        }

        guard let keyPath = value(for: "--keypath", in: args) else {
            printError("--keypath is required")
            printUsage()
            return nil
        }

        guard let httpsPortStr = value(for: "--httpsPort", in: args),
            let httpsPort = UInt16(httpsPortStr)
        else {
            printError("--httpsPort is required (valid port number)")
            printUsage()
            return nil
        }

        var httpPort: UInt16? = nil
        if let httpPortStr = value(for: "--httpPort", in: args) {
            guard let parsed = UInt16(httpPortStr) else {
                printError("--httpPort must be a valid port number")
                return nil
            }
            httpPort = parsed
        }

        let h3Port: UInt16
        if let h3Str = value(for: "--h3Port", in: args), let parsed = UInt16(h3Str) {
            h3Port = parsed
        } else {
            h3Port = defaultH3Port
        }

        let logLevel: Logger.Level
        if let levelStr = value(for: "--log-level", in: args) ?? value(for: "-l", in: args) {
            let levels: [String: Logger.Level] = [
                "trace": .trace, "debug": .debug, "info": .info,
                "notice": .notice, "warning": .warning,
                "error": .error, "critical": .critical,
            ]
            logLevel = levels[levelStr.lowercased()] ?? .info
        } else {
            logLevel = .info
        }

        return Arguments(
            host: host,
            certPath: certPath,
            keyPath: keyPath,
            httpsPort: httpsPort,
            httpPort: httpPort,
            h3Port: h3Port,
            logLevel: logLevel
        )
    }

    private static func value(for key: String, in args: [String]) -> String? {
        guard let idx = args.firstIndex(of: key), idx + 1 < args.count else {
            return nil
        }
        return args[idx + 1]
    }
}

// MARK: - Logging

func log(_ tag: String, _ message: String) {
    let ts = ISO8601DateFormatter().string(from: Date())
    print("[\(ts)] [\(tag)] \(message)")
}

func printError(_ message: String) {
    print("ERROR: \(message)")
}

func printUsage() {
    print(
        """
        Alt-Svc Gateway Demo

        USAGE:
            swift run AltSvcDemo --certpath <path> --keypath <path> --httpsPort <port> [options]

        REQUIRED:
            --certpath <path>       PEM certificate file path
            --keypath <path>        PEM private key file path
            --httpsPort <port>      HTTPS gateway port (e.g. 443)

        OPTIONAL:
            --host <address>        Host to bind (default: 0.0.0.0)
            --httpPort <port>       HTTP redirect port (e.g. 80). Omit to disable.
            --h3Port <port>         QUIC HTTP/3 port (default: \(defaultH3Port))
            --log-level, -l <level> Log level: trace|debug|info|notice|warning|error|critical
                                    (default: info)
            --help, -h              Show this help

        DESCRIPTION:
            Starts an HTTP/3 server on the QUIC port and an Alt-Svc TCP gateway
            on the HTTPS port. The gateway advertises HTTP/3 via the Alt-Svc
            header so browsers discover and upgrade automatically.

            If --httpPort is specified, an additional TCP listener redirects
            all plain HTTP requests to HTTPS with 301 Moved Permanently.

        EXAMPLES:
            swift run AltSvcDemo \\
                --certpath server.pem --keypath server-key.pem --httpsPort 443

            swift run AltSvcDemo \\
                --certpath server.pem --keypath server-key.pem \\
                --httpsPort 8443 --httpPort 8080 --h3Port 4433
        """)
}

// MARK: - HTML Page

func helloWorldPage(h3Port: UInt16, httpsPort: UInt16, httpPort: UInt16?) -> String {
    let httpInfo: String
    if let p = httpPort {
        httpInfo = """
                            <tr>
                                <td>HTTP Redirect</td>
                                <td>TCP :\(p) &rarr; HTTPS :\(httpsPort)</td>
                                <td><span class="badge badge-redirect">301</span></td>
                            </tr>
            """
    } else {
        httpInfo = ""
    }

    return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Quiver HTTP/3</title>
            <style>
                :root {
                    --bg: #0a0e17;
                    --surface: #121a2b;
                    --border: #1e2d47;
                    --text: #e0e6f0;
                    --muted: #7a8ba8;
                    --accent: #38bdf8;
                    --accent-dim: #1d4e7e;
                    --green: #34d399;
                    --orange: #fb923c;
                }

                * { margin: 0; padding: 0; box-sizing: border-box; }

                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                                 "Helvetica Neue", Arial, sans-serif;
                    background: var(--bg);
                    color: var(--text);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }

                .container {
                    max-width: 620px;
                    width: 90%;
                    padding: 2.5rem;
                }

                .logo {
                    font-size: 0.85rem;
                    font-weight: 600;
                    letter-spacing: 0.15em;
                    text-transform: uppercase;
                    color: var(--accent);
                    margin-bottom: 0.75rem;
                }

                h1 {
                    font-size: 2.25rem;
                    font-weight: 700;
                    line-height: 1.2;
                    margin-bottom: 0.5rem;
                }

                .subtitle {
                    color: var(--muted);
                    font-size: 1.05rem;
                    margin-bottom: 2rem;
                }

                .card {
                    background: var(--surface);
                    border: 1px solid var(--border);
                    border-radius: 10px;
                    padding: 1.5rem;
                    margin-bottom: 1.5rem;
                }

                .card h2 {
                    font-size: 0.8rem;
                    font-weight: 600;
                    letter-spacing: 0.1em;
                    text-transform: uppercase;
                    color: var(--muted);
                    margin-bottom: 1rem;
                }

                table {
                    width: 100%;
                    border-collapse: collapse;
                }

                td {
                    padding: 0.5rem 0;
                    font-size: 0.9rem;
                    vertical-align: middle;
                }

                td:first-child {
                    color: var(--muted);
                    width: 140px;
                }

                td:last-child {
                    text-align: right;
                }

                tr + tr {
                    border-top: 1px solid var(--border);
                }

                .badge {
                    display: inline-block;
                    padding: 0.15rem 0.55rem;
                    border-radius: 4px;
                    font-size: 0.75rem;
                    font-weight: 600;
                    letter-spacing: 0.03em;
                }

                .badge-h3 {
                    background: var(--accent-dim);
                    color: var(--accent);
                }

                .badge-tls {
                    background: #1a3a2a;
                    color: var(--green);
                }

                .badge-redirect {
                    background: #3a2a1a;
                    color: var(--orange);
                }

                .status-line {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                    margin-top: 1.5rem;
                    font-size: 0.85rem;
                    color: var(--muted);
                }

                .status-dot {
                    width: 8px;
                    height: 8px;
                    border-radius: 50%;
                    background: var(--green);
                    flex-shrink: 0;
                }

                code {
                    font-family: "SF Mono", "Fira Code", "Cascadia Code", monospace;
                    background: var(--bg);
                    padding: 0.1rem 0.4rem;
                    border-radius: 4px;
                    font-size: 0.82rem;
                }

                .alt-svc-value {
                    font-family: "SF Mono", "Fira Code", "Cascadia Code", monospace;
                    font-size: 0.82rem;
                    color: var(--accent);
                    word-break: break-all;
                }

                .footer {
                    margin-top: 1.5rem;
                    font-size: 0.78rem;
                    color: var(--muted);
                    text-align: center;
                }

                .footer a {
                    color: var(--accent);
                    text-decoration: none;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">Quiver</div>
                <h1>You're seeing this from<br>Quiver HTTP/3</h1>
                <p class="subtitle">
                    Served over QUIC with Alt-Svc gateway advertisement.
                </p>

                <div class="card">
                    <h2>Listeners</h2>
                    <table>
                        <tr>
                            <td>HTTP/3 (QUIC)</td>
                            <td>UDP :\(h3Port)</td>
                            <td><span class="badge badge-h3">H3</span></td>
                        </tr>
                        <tr>
                            <td>HTTPS Gateway</td>
                            <td>TCP :\(httpsPort)</td>
                            <td><span class="badge badge-tls">TLS</span></td>
                        </tr>
        \(httpInfo)
                    </table>
                </div>

                <div class="card">
                    <h2>Alt-Svc Header</h2>
                    <p class="alt-svc-value">h3=":\(h3Port)"; ma=86400</p>
                </div>

                <div class="status-line">
                    <span class="status-dot"></span>
                    <span>Server running &mdash; protocol negotiation active</span>
                </div>

                <div class="footer">
                    RFC 9114 (HTTP/3) &middot; RFC 9000 (QUIC) &middot; RFC 7838 (Alt-Svc)
                </div>
            </div>
        </body>
        </html>
        """
}

// MARK: - Server

func runServer(args: Arguments) async throws {
    log("AltSvc", "Alt-Svc Gateway Demo")
    log("AltSvc", "  Certificate : \(args.certPath)")
    log("AltSvc", "  Private Key : \(args.keyPath)")
    log("AltSvc", "  HTTPS Port  : \(args.httpsPort)")
    log("AltSvc", "  HTTP Port   : \(args.httpPort.map(String.init) ?? "disabled")")
    log("AltSvc", "  H3 Port     : \(args.h3Port)")

    let options = HTTP3ServerOptions(
        host: args.host,
        port: args.h3Port,
        certificatePath: args.certPath,
        privateKeyPath: args.keyPath,
        alpn: ["h3"],
        maxConnections: 100,
        maxIdleTimeout: .seconds(60),
        gatewayHTTPPort: args.httpPort,
        gatewayHTTPSPort: args.httpsPort,
        altSvcMaxAge: 86400
    )

    let server = HTTP3Server(options: options)

    // Build the HTML payload once
    let html = helloWorldPage(
        h3Port: args.h3Port,
        httpsPort: args.httpsPort,
        httpPort: args.httpPort
    )
    let htmlData = Data(html.utf8)

    await server.onRequest { context in
        log(
            "Request",
            "\(context.request.method) \(context.request.path) "
                + "[stream:\(context.streamID)]")

        try await context.respond(
            status: 200,
            headers: [
                ("content-type", "text/html; charset=utf-8"),
                ("server", "quiver-altsvc-demo"),
            ],
            htmlData
        )
    }

    log("AltSvc", "")
    log("AltSvc", "Starting listeners...")
    log("AltSvc", "  QUIC H3  -> udp://0.0.0.0:\(args.h3Port)")
    log("AltSvc", "  HTTPS GW -> tcp://0.0.0.0:\(args.httpsPort)")
    if let httpPort = args.httpPort {
        log("AltSvc", "  HTTP  GW -> tcp://0.0.0.0:\(httpPort) (redirect)")
    }
    log("AltSvc", "")
    log("AltSvc", "Listening... (Ctrl+C to stop)")

    do {
        try await server.listenAll()
    } catch {
        log("AltSvc", "Server error: \(error)")
    }

    await server.stop(gracePeriod: .seconds(5))
    log("AltSvc", "Server stopped.")
}

// MARK: - Entry Point

guard let args = Arguments.parse() else {
    let isHelp = CommandLine.arguments.contains(where: { $0 == "--help" || $0 == "-h" })
    exit(isHelp ? 0 : 1)
}

LoggingSystem.bootstrap { label in
    var handler = StreamLogHandler.standardOutput(label: label)
    handler.logLevel = args.logLevel
    return handler
}

do {
    try await runServer(args: args)
} catch {
    printError("\(error)")
    exit(1)
}
