// =============================================================================
// HTTP/3 Server & Client Demo
// =============================================================================
//
// Demonstrates the HTTP/3 API built on QUIC:
//   - Server: HTTP3ServerOptions + HTTP3Server + HTTP3Router
//   - Client: Manual QUIC connection + HTTP3Connection
//
// ## Running
//
//   swift run HTTP3Demo server
//   swift run HTTP3Demo client
//
//   # With real certificates
//   swift run HTTP3Demo server --cert server.pem --key server-key.pem
//   swift run HTTP3Demo client --ca-cert ca.pem
//
//   # Custom host/port
//   swift run HTTP3Demo server --host 0.0.0.0 --port 8443
//   swift run HTTP3Demo client --host 127.0.0.1 --port 8443
//
// =============================================================================

import Foundation
import Logging
import QUIC
import QUICCore
import QUICCrypto
import HTTP3

// MARK: - Configuration

let defaultHost = "127.0.0.1"
let defaultPort: UInt16 = 4443
let h3ALPN = "h3"

// MARK: - Argument Parsing

struct DemoArguments {
    enum Mode: String {
        case server, client, help
    }

    let mode: Mode
    let host: String
    let port: UInt16
    let logLevel: Logger.Level
    let certPath: String?
    let keyPath: String?
    let caCertPath: String?

    static func parse() -> DemoArguments {
        let args = CommandLine.arguments

        var mode: Mode = .help
        var host = defaultHost
        var port = defaultPort
        var logLevel: Logger.Level = .info
        var certPath: String? = nil
        var keyPath: String? = nil
        var caCertPath: String? = nil

        var i = 1
        while i < args.count {
            switch args[i] {
            case "server": mode = .server
            case "client": mode = .client
            case "help", "--help", "-h": mode = .help
            case "--host":
                i += 1; if i < args.count { host = args[i] }
            case "--port", "-p":
                i += 1; if i < args.count { port = UInt16(args[i]) ?? defaultPort }
            case "--log-level", "-l":
                i += 1
                if i < args.count {
                    let levels: [String: Logger.Level] = [
                        "trace": .trace, "debug": .debug, "info": .info,
                        "notice": .notice, "warning": .warning,
                        "error": .error, "critical": .critical,
                    ]
                    logLevel = levels[args[i].lowercased()] ?? .info
                }
            case "--cert":
                i += 1; if i < args.count { certPath = args[i] }
            case "--key":
                i += 1; if i < args.count { keyPath = args[i] }
            case "--ca-cert":
                i += 1; if i < args.count { caCertPath = args[i] }
            default: break
            }
            i += 1
        }

        return DemoArguments(
            mode: mode, host: host, port: port, logLevel: logLevel,
            certPath: certPath, keyPath: keyPath, caCertPath: caCertPath
        )
    }
}

// MARK: - Logging

func log(_ tag: String, _ message: String) {
    let timestamp = ISO8601DateFormatter().string(from: Date())
    print("[\(timestamp)] [\(tag)] \(message)")
}

// MARK: - HTTP/3 Server

func runServer(host: String, port: UInt16, certPath: String?, keyPath: String?) async throws {
    log("HTTP3", "HTTP/3 Demo Server")
    log("HTTP3", "  Address: \(host):\(port)")

    // Build server options — handles TLS + QUIC + HTTP/3 settings internally
    let options: HTTP3ServerOptions

    if let certPath = certPath, let keyPath = keyPath {
        log("HTTP3", "  TLS: Production (cert: \(certPath), key: \(keyPath))")
        options = HTTP3ServerOptions(
            host: host,
            port: port,
            certificatePath: certPath,
            privateKeyPath: keyPath,
            alpn: [h3ALPN],
            maxConnections: 100,
            maxIdleTimeout: .seconds(60)
        )
    } else {
        log("HTTP3", "  TLS: Development (self-signed P-256)")
        let signingKey = SigningKey.generateP256()
        let mockCert = Data([0x30, 0x82, 0x01, 0x00])
        options = HTTP3ServerOptions(
            host: host,
            port: port,
            signingKey: signingKey,
            certificateChain: [mockCert],
            alpn: [h3ALPN],
            maxConnections: 100,
            maxIdleTimeout: .seconds(60),
            developmentMode: true
        )
    }

    let server = HTTP3Server(options: options)

    // Set up routing
    let router = buildRouter()
    await server.onRequest(router.handler)

    log("HTTP3", "")
    log("HTTP3", "Routes:")
    log("HTTP3", "  GET  /            Welcome page")
    log("HTTP3", "  GET  /health      Health check")
    log("HTTP3", "  GET  /info        Server info")
    log("HTTP3", "  POST /echo        Echo body")
    log("HTTP3", "  POST /api/json    JSON echo")
    log("HTTP3", "  GET  /headers     Reflect headers")
    log("HTTP3", "  GET  /stream-info Stream metadata")
    log("HTTP3", "  ANY  /api/method  Method echo")
    log("HTTP3", "")
    log("HTTP3", "Listening... (Ctrl+C to stop)")

    do {
        try await server.listen()
    } catch {
        log("HTTP3", "Server error: \(error)")
    }

    await server.stop(gracePeriod: .seconds(5))
    log("HTTP3", "Server stopped.")
}

// MARK: - Router

func buildRouter() -> HTTP3Router {
    let router = HTTP3Router()
    let startTime = Date()

    // GET /
    router.get("/") { context in
        log("Handler", "\(context.request.method) / [stream:\(context.streamID)]")

        let html = """
        <!DOCTYPE html>
        <html>
        <head><title>Quiver HTTP/3</title></head>
        <body>
            <h1>Quiver HTTP/3 Demo</h1>
            <p>HTTP/3 (RFC 9114) over QUIC (RFC 9000)</p>
            <ul>
                <li><code>GET /health</code></li>
                <li><code>GET /info</code></li>
                <li><code>POST /echo</code></li>
                <li><code>POST /api/json</code></li>
                <li><code>GET /headers</code></li>
                <li><code>GET /stream-info</code></li>
                <li><code>ANY /api/method</code></li>
            </ul>
        </body>
        </html>
        """

        try await context.respond(
            status: 200,
            headers: [
                ("content-type", "text/html; charset=utf-8"),
                ("server", "quiver-http3-demo"),
            ],
            Data(html.utf8)
        )
    }

    // GET /health
    router.get("/health") { context in
        log("Handler", "\(context.request.method) /health [stream:\(context.streamID)]")

        let json = """
        {"status":"healthy","protocol":"h3","timestamp":"\(ISO8601DateFormatter().string(from: Date()))"}
        """
        try await context.respond(
            status: 200,
            headers: [("content-type", "application/json"), ("cache-control", "no-cache")],
            Data(json.utf8)
        )
    }

    // GET /info
    router.get("/info") { context in
        log("Handler", "\(context.request.method) /info [stream:\(context.streamID)]")

        let uptime = Date().timeIntervalSince(startTime)
        let json = """
        {"server":"Quiver HTTP/3 Demo","uptime_seconds":\(String(format: "%.1f", uptime)),"platform":"\(platformDescription())"}
        """
        try await context.respond(
            status: 200,
            headers: [("content-type", "application/json")],
            Data(json.utf8)
        )
    }

    // POST /echo
    router.post("/echo") { context in
        log("Handler", "\(context.request.method) /echo [stream:\(context.streamID)]")

        let body = try await context.body.data()
        let contentType = context.request.headers.first(where: { $0.0.lowercased() == "content-type" })?.1
            ?? "application/octet-stream"

        try await context.respond(
            status: 200,
            headers: [
                ("content-type", contentType),
                ("x-echo-size", "\(body.count)"),
            ],
            body
        )
    }

    // POST /api/json
    router.post("/api/json") { context in
        log("Handler", "\(context.request.method) /api/json [stream:\(context.streamID)]")

        let body = try await context.body.data()
        let contentType = context.request.headers.first(where: { $0.0.lowercased() == "content-type" })?.1 ?? ""

        if !contentType.contains("json") && !body.isEmpty {
            try await context.respond(
                status: 415,
                headers: [("content-type", "application/json")],
                Data(#"{"error":"unsupported_content_type","hint":"Use Content-Type: application/json"}"#.utf8)
            )
            return
        }

        let bodyString = String(data: body, encoding: .utf8) ?? "null"
        let json = """
        {"received":true,"size":\(body.count),"stream_id":\(context.streamID),"payload":\(bodyString.isEmpty ? "null" : bodyString)}
        """
        try await context.respond(
            status: 200,
            headers: [("content-type", "application/json")],
            Data(json.utf8)
        )
    }

    // GET /headers
    router.get("/headers") { context in
        log("Handler", "\(context.request.method) /headers [stream:\(context.streamID)]")

        var entries: [String] = []
        for (name, value) in context.request.headers {
            let n = name.replacingOccurrences(of: "\"", with: "\\\"")
            let v = value.replacingOccurrences(of: "\"", with: "\\\"")
            entries.append("\"\(n)\":\"\(v)\"")
        }

        let json = """
        {"pseudo_headers":{":method":"\(context.request.method)",":path":"\(context.request.path)"},"headers":{\(entries.joined(separator: ","))},"count":\(context.request.headers.count)}
        """
        try await context.respond(
            status: 200,
            headers: [("content-type", "application/json")],
            Data(json.utf8)
        )
    }

    // GET /stream-info
    router.get("/stream-info") { context in
        log("Handler", "\(context.request.method) /stream-info [stream:\(context.streamID)]")

        let id = context.streamID
        let types = ["client-bidi", "server-bidi", "client-uni", "server-uni"]
        let streamType = types[Int(id & 0x03)]

        let json = """
        {"stream_id":\(id),"type":"\(streamType)","sequence":\(id / 4)}
        """
        try await context.respond(
            status: 200,
            headers: [("content-type", "application/json")],
            Data(json.utf8)
        )
    }

    // ANY /api/method
    router.route("/api/method") { context in
        log("Handler", "\(context.request.method) /api/method [stream:\(context.streamID)]")

        let json = """
        {"method":"\(context.request.method)","path":"\(context.request.path)"}
        """
        try await context.respond(
            status: 200,
            headers: [("content-type", "application/json")],
            Data(json.utf8)
        )
    }

    // 404
    router.setNotFound { context in
        log("Handler", "\(context.request.method) \(context.request.path) [stream:\(context.streamID)] -> 404")

        let json = """
        {"error":"not_found","path":"\(context.request.path)"}
        """
        try await context.respond(
            status: 404,
            headers: [("content-type", "application/json")],
            Data(json.utf8)
        )
    }

    return router
}

// MARK: - HTTP/3 Client

func runClient(host: String, port: UInt16, caCertPath: String?) async throws {
    log("HTTP3", "HTTP/3 Demo Client")
    log("HTTP3", "  Target: \(host):\(port)")

    // Client still uses manual TLS + QUIC config (no HTTP3ClientOptions yet)
    let tlsConfig: TLSConfiguration
    if let caCertPath = caCertPath {
        log("HTTP3", "  TLS: Production (CA: \(caCertPath))")
        var config = TLSConfiguration.client(serverName: "localhost", alpnProtocols: [h3ALPN])
        try config.loadTrustedCAs(fromPEMFile: caCertPath)
        config.verifyPeer = true
        config.allowSelfSigned = false
        tlsConfig = config
    } else {
        log("HTTP3", "  TLS: Development (self-signed allowed)")
        var config = TLSConfiguration.client(serverName: "localhost", alpnProtocols: [h3ALPN])
        config.verifyPeer = false
        config.allowSelfSigned = true
        tlsConfig = config
    }

    let isProduction = (caCertPath != nil)
    var quicConfig: QUICConfiguration
    if isProduction {
        quicConfig = QUICConfiguration.production {
            TLS13Handler(configuration: tlsConfig)
        }
    } else {
        quicConfig = QUICConfiguration.development {
            TLS13Handler(configuration: tlsConfig)
        }
    }
    quicConfig.alpn = [h3ALPN]
    quicConfig.maxIdleTimeout = .seconds(60)
    quicConfig.initialMaxStreamsBidi = 100
    quicConfig.initialMaxStreamsUni = 100

    // Connect
    let endpoint = QUICEndpoint(configuration: quicConfig)
    let serverAddress = QUIC.SocketAddress(ipAddress: host, port: port)

    let quicConnection: any QUICConnectionProtocol
    do {
        quicConnection = try await endpoint.dial(address: serverAddress, timeout: .seconds(10))
    } catch {
        log("Client", "Connection failed: \(error)")
        log("Client", "Is the server running? swift run HTTP3Demo server --host \(host) --port \(port)")
        throw error
    }

    log("Client", "QUIC connected to \(quicConnection.remoteAddress)")

    // HTTP/3 layer
    let h3 = HTTP3Connection(
        quicConnection: quicConnection,
        role: .client,
        settings: HTTP3Settings.literalOnly
    )
    try await h3.initialize()
    try await h3.waitForReady(timeout: .seconds(5))
    log("Client", "HTTP/3 ready")
    log("Client", "")

    let authority = "\(host):\(port)"

    // Request 1: GET /
    log("Client", "--- GET / ---")
    let r1 = try await h3.sendRequest(HTTP3Request(method: .get, scheme: "https", authority: authority, path: "/"))
    try await printResponse(r1)

    // Request 2: GET /health
    log("Client", "--- GET /health ---")
    let r2 = try await h3.sendRequest(HTTP3Request(method: .get, scheme: "https", authority: authority, path: "/health"))
    try await printResponse(r2)

    // Request 3: POST /echo
    log("Client", "--- POST /echo ---")
    let r3 = try await h3.sendRequest(HTTP3Request(
        method: .post, scheme: "https", authority: authority, path: "/echo",
        headers: [("content-type", "text/plain")],
        body: Data("Hello from HTTP/3 client!".utf8)
    ))
    try await printResponse(r3)

    // Request 4: POST /api/json
    log("Client", "--- POST /api/json ---")
    let r4 = try await h3.sendRequest(HTTP3Request(
        method: .post, scheme: "https", authority: authority, path: "/api/json",
        headers: [("content-type", "application/json")],
        body: Data(#"{"name":"quiver","features":["http3","qpack"]}"#.utf8)
    ))
    try await printResponse(r4)

    // Request 5: GET /headers
    log("Client", "--- GET /headers ---")
    let r5 = try await h3.sendRequest(HTTP3Request(
        method: .get, scheme: "https", authority: authority, path: "/headers",
        headers: [("user-agent", "quiver-demo/0.1"), ("accept", "application/json")]
    ))
    try await printResponse(r5)

    // Request 6: GET /stream-info
    log("Client", "--- GET /stream-info ---")
    let r6 = try await h3.sendRequest(HTTP3Request(method: .get, scheme: "https", authority: authority, path: "/stream-info"))
    try await printResponse(r6)

    // Request 7: GET /nonexistent (404)
    log("Client", "--- GET /nonexistent (expect 404) ---")
    let r7 = try await h3.sendRequest(HTTP3Request(method: .get, scheme: "https", authority: authority, path: "/nonexistent"))
    try await printResponse(r7)

    // Cleanup
    log("Client", "All requests complete.")
    await h3.close()
    await quicConnection.close(error: nil)
    await endpoint.stop()
    log("Client", "Done.")
}

func printResponse(_ response: consuming HTTP3Response) async throws {
    log("Client", "  Status: \(response.status) \(response.statusText)")
    for (name, value) in response.headers {
        log("Client", "  \(name): \(value)")
    }
    let body = try await response.body().data()
    if !body.isEmpty {
        let text = String(data: body, encoding: .utf8) ?? "<binary \(body.count) bytes>"
        let display = text.count > 300 ? String(text.prefix(300)) + "..." : text
        log("Client", "  Body: \(display)")
    }
    log("Client", "")
}

// MARK: - Utility

func platformDescription() -> String {
    #if os(Linux)
    return "Linux"
    #elseif os(macOS)
    return "macOS"
    #elseif os(Windows)
    return "Windows"
    #else
    return "Unknown"
    #endif
}

func printHelp() {
    print("""
    HTTP/3 Demo Server & Client

    USAGE:
        swift run HTTP3Demo <mode> [options]

    MODES:
        server      Start the HTTP/3 server
        client      Connect and make HTTP/3 requests
        help        Show this help

    OPTIONS:
        --host <addr>       Host address (default: \(defaultHost))
        --port, -p <port>   Port number (default: \(defaultPort))
        --log-level, -l     Log level: trace|debug|info|notice|warning|error|critical

    SERVER:
        --cert <path>       PEM certificate file
        --key <path>        PEM private key file

        Without --cert/--key, uses a self-signed P-256 key (development mode).

    CLIENT:
        --ca-cert <path>    PEM CA certificate for server verification

        Without --ca-cert, accepts self-signed certificates (development mode).

    EXAMPLES:
        swift run HTTP3Demo server
        swift run HTTP3Demo client
        swift run HTTP3Demo server --cert server.pem --key server-key.pem
        swift run HTTP3Demo client --ca-cert ca.pem
    """)
}

// MARK: - Entry Point

let arguments = DemoArguments.parse()

LoggingSystem.bootstrap { label in
    var handler = StreamLogHandler.standardOutput(label: label)
    handler.logLevel = arguments.logLevel
    return handler
}

switch arguments.mode {
case .server:
    do {
        try await runServer(
            host: arguments.host,
            port: arguments.port,
            certPath: arguments.certPath,
            keyPath: arguments.keyPath
        )
    } catch {
        log("HTTP3", "Fatal: \(error)")
        exit(1)
    }

case .client:
    do {
        try await runClient(
            host: arguments.host,
            port: arguments.port,
            caCertPath: arguments.caCertPath
        )
    } catch {
        log("HTTP3", "Fatal: \(error)")
        exit(1)
    }

case .help:
    printHelp()
}