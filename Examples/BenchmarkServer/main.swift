// =============================================================================
// Quiver Benchmark Server
// =============================================================================
//
// High-throughput benchmark server exercising all protocol layers:
//   - QUIC raw stream echo on port 4501 (bulk throughput)
//   - HTTP/3 variable payloads on port 4500 (HTML, big headers, large body)
//   - WebTransport bidi/uni stream echo on port 4500 (reliability)
//   - WebTransport datagram echo on port 4500 (throughput + loss measurement)
//
// Usage:
//   swift run BenchmarkServer [cert.pem key.pem]
//
// If no arguments, runs in development mode (self-signed TLS).
// =============================================================================

import Foundation
import Logging
import QUIC
import QUICCore
import QUICCrypto
import QUICTransport
import NIOUDPTransport
import HTTP3
import QPACK

// =============================================================================
// MARK: - Configuration (edit these directly)
// =============================================================================

let benchHost = "127.0.0.1"

/// Port for HTTP/3 + WebTransport (Phases 2, 3, 4)
let h3Port: UInt16 = 4500

/// Port for raw QUIC stream echo (Phase 1)
let quicPort: UInt16 = 4501

let h3ALPN = "h3"
let quicBenchALPN = "quic-bench"

/// Large HTML page (~64 KB) served at /bench/html
let largeHTMLSize = 64 * 1024
/// Number of headers served at /bench/headers
let bigHeaderCount = 200
/// Large body size served at /bench/large-body (~4 MB)
let largeBodySize = 4 * 1024 * 1024

/// QUIC transport limits (tuned for throughput)
let maxStreamsBidi: UInt64 = 1024
let maxStreamsUni: UInt64 = 1024
let maxData: UInt64 = 100_000_000           // 100 MB connection-level
let maxStreamData: UInt64 = 16_000_000      // 16 MB per stream
let idleTimeout: Duration = .seconds(120)

// =============================================================================
// MARK: - Logging
// =============================================================================

func log(_ tag: String, _ message: String) {
    let ts = ISO8601DateFormatter().string(from: Date())
    print("[\(ts)] [\(tag)] \(message)")
}

// =============================================================================
// MARK: - Pre-built Response Payloads
// =============================================================================

/// Pre-generate static payloads once at startup to avoid allocation during serving.
let prebuiltLargeHTML: Data = {
    var html = "<!DOCTYPE html><html><head><title>Quiver Bench</title></head><body>"
    html += "<h1>Quiver HTTP/3 Benchmark Payload</h1>"
    html += "<p>This page is approximately \(largeHTMLSize / 1024) KB of HTML.</p>"
    html += "<div>"
    let paragraph = "<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.</p>\n"
    while html.utf8.count < largeHTMLSize - 100 {
        html += paragraph
    }
    html += "</div></body></html>"
    return Data(html.utf8)
}()

let prebuiltLargeBody: Data = {
    // Deterministic repeating pattern for integrity checks
    var body = Data(count: largeBodySize)
    for i in 0..<largeBodySize {
        body[i] = UInt8(i & 0xFF)
    }
    return body
}()

let prebuiltBigHeaders: [(String, String)] = {
    var headers: [(String, String)] = [
        ("content-type", "application/json"),
        ("server", "quiver-bench"),
    ]
    for i in 0..<bigHeaderCount {
        headers.append(("x-bench-header-\(i)", "value-\(i)-\(String(repeating: "x", count: 64))"))
    }
    return headers
}()

// =============================================================================
// MARK: - TLS Configuration
// =============================================================================

/// Shared signing key for development mode so both listeners use the same identity.
let sharedDevSigningKey = SigningKey.generateP256()
let sharedDevMockCert = Data([0x30, 0x82, 0x01, 0x00])

func makeServerTLSConfig(certPath: String?, keyPath: String?, alpn: String) throws -> TLSConfiguration {
    if let certPath = certPath, let keyPath = keyPath {
        var tlsConfig = try TLSConfiguration.server(
            certificatePath: certPath,
            privateKeyPath: keyPath,
            alpnProtocols: [alpn]
        )
        tlsConfig.verifyPeer = false
        return tlsConfig
    } else {
        var tlsConfig = TLSConfiguration.server(
            signingKey: sharedDevSigningKey,
            certificateChain: [sharedDevMockCert],
            alpnProtocols: [alpn]
        )
        tlsConfig.verifyPeer = false
        return tlsConfig
    }
}

/// Build a QUICConfiguration for the HTTP/3 + WebTransport listener (port 4500)
func makeH3Config(certPath: String?, keyPath: String?) throws -> QUICConfiguration {
    let tlsConfig = try makeServerTLSConfig(certPath: certPath, keyPath: keyPath, alpn: h3ALPN)
    let isProduction = (certPath != nil && keyPath != nil)

    var config: QUICConfiguration
    if isProduction {
        config = QUICConfiguration.production {
            TLS13Handler(configuration: tlsConfig)
        }
    } else {
        config = QUICConfiguration.development {
            TLS13Handler(configuration: tlsConfig)
        }
    }

    config.alpn = [h3ALPN]
    config.maxUDPPayloadSize = 1452
    config.maxIdleTimeout = idleTimeout
    config.initialMaxStreamsBidi = maxStreamsBidi
    config.initialMaxStreamsUni = maxStreamsUni
    config.initialMaxData = maxData
    config.initialMaxStreamDataBidiLocal = maxStreamData
    config.initialMaxStreamDataBidiRemote = maxStreamData
    config.initialMaxStreamDataUni = maxStreamData
    config.enableDatagrams = true
    config.maxDatagramFrameSize = 65535
    return config
}

/// Build a QUICConfiguration for the raw QUIC echo listener (port 4501)
func makeRawQUICConfig(certPath: String?, keyPath: String?) throws -> QUICConfiguration {
    let tlsConfig = try makeServerTLSConfig(certPath: certPath, keyPath: keyPath, alpn: quicBenchALPN)
    let isProduction = (certPath != nil && keyPath != nil)

    var config: QUICConfiguration
    if isProduction {
        config = QUICConfiguration.production {
            TLS13Handler(configuration: tlsConfig)
        }
    } else {
        config = QUICConfiguration.development {
            TLS13Handler(configuration: tlsConfig)
        }
    }

    config.alpn = [quicBenchALPN]
    config.maxUDPPayloadSize = 1452
    config.maxIdleTimeout = idleTimeout
    config.initialMaxStreamsBidi = maxStreamsBidi
    config.initialMaxStreamsUni = maxStreamsUni
    config.initialMaxData = maxData
    config.initialMaxStreamDataBidiLocal = maxStreamData
    config.initialMaxStreamDataBidiRemote = maxStreamData
    config.initialMaxStreamDataUni = maxStreamData
    config.enableDatagrams = false
    return config
}

// =============================================================================
// MARK: - Stats Tracker
// =============================================================================

final class ServerStats: @unchecked Sendable {
    private let lock = NSLock()

    var quicBytesEchoed: UInt64 = 0
    var quicStreamsHandled: UInt64 = 0
    var h3RequestsServed: UInt64 = 0
    var h3BytesSent: UInt64 = 0
    var wtBidiStreams: UInt64 = 0
    var wtUniStreams: UInt64 = 0
    var wtDatagramsEchoed: UInt64 = 0
    var wtDatagramsFailed: UInt64 = 0
    var wtBytesEchoed: UInt64 = 0

    func add(quicBytes: UInt64) { lock.lock(); quicBytesEchoed += quicBytes; lock.unlock() }
    func incQuicStreams() { lock.lock(); quicStreamsHandled += 1; lock.unlock() }
    func incH3Requests() { lock.lock(); h3RequestsServed += 1; lock.unlock() }
    func add(h3Bytes: UInt64) { lock.lock(); h3BytesSent += h3Bytes; lock.unlock() }
    func incWtBidi() { lock.lock(); wtBidiStreams += 1; lock.unlock() }
    func incWtUni() { lock.lock(); wtUniStreams += 1; lock.unlock() }
    func incWtDatagram() { lock.lock(); wtDatagramsEchoed += 1; lock.unlock() }
    func incWtDatagramFail() { lock.lock(); wtDatagramsFailed += 1; lock.unlock() }
    func add(wtBytes: UInt64) { lock.lock(); wtBytesEchoed += wtBytes; lock.unlock() }

    func snapshot() -> String {
        lock.lock()
        defer { lock.unlock() }
        return """
        +-------------------------------------------------------------+
        |                   SERVER STATS SNAPSHOT                     |
        +-------------------------------------------------------------+
        |  QUIC Raw Echo (port \(quicPort))                                |
        |    Streams handled .......... \(pad(quicStreamsHandled))|
        |    Bytes echoed ............. \(pad(quicBytesEchoed, unit: true))|
        +-------------------------------------------------------------+
        |  HTTP/3 (port \(h3Port))                                         |
        |    Requests served .......... \(pad(h3RequestsServed))|
        |    Bytes sent ............... \(pad(h3BytesSent, unit: true))|
        +-------------------------------------------------------------+
        |  WebTransport (port \(h3Port))                                   |
        |    Bidi streams echoed ...... \(pad(wtBidiStreams))|
        |    Uni streams echoed ....... \(pad(wtUniStreams))|
        |    Datagrams echoed ......... \(pad(wtDatagramsEchoed))|
        |    Datagrams failed ......... \(pad(wtDatagramsFailed))|
        |    Total bytes echoed ....... \(pad(wtBytesEchoed, unit: true))|
        +-------------------------------------------------------------+
        """
    }

    private func pad(_ v: UInt64, unit: Bool = false) -> String {
        let s: String
        if unit {
            s = formatBytes(v)
        } else {
            s = "\(v)"
        }
        let needed = 30 - s.count
        return s + String(repeating: " ", count: max(1, needed))
    }
}

func formatBytes(_ bytes: UInt64) -> String {
    let b = Double(bytes)
    if b >= 1_073_741_824 { return String(format: "%.2f GB", b / 1_073_741_824) }
    if b >= 1_048_576 { return String(format: "%.2f MB", b / 1_048_576) }
    if b >= 1024 { return String(format: "%.2f KB", b / 1024) }
    return "\(bytes) B"
}

let stats = ServerStats()

// =============================================================================
// MARK: - Raw QUIC Echo Handler (port 4501)
// =============================================================================

/// Handles a single raw QUIC connection by echoing all incoming streams.
func handleRawQUICConnection(_ connection: any QUICConnectionProtocol, id: UInt64) async {
    let tag = "QUIC#\(id)"
    log(tag, "Connection from \(connection.remoteAddress)")

    var streamCount: UInt64 = 0
    for await stream in connection.incomingStreams {
        streamCount += 1
        stats.incQuicStreams()
        let num = streamCount
        Task {
            await handleRawEchoStream(stream, tag: "\(tag)/s\(num)")
        }
    }

    log(tag, "Connection closed (\(streamCount) streams)")
}

/// Echoes data on a raw QUIC stream (bidi: read->write, uni: read->discard).
func handleRawEchoStream(_ stream: any QUICStreamProtocol, tag: String) async {
    do {
        while true {
            let data = try await stream.read()
            if data.isEmpty { break }
            stats.add(quicBytes: UInt64(data.count))

            // Echo back only on bidi streams
            if stream.isBidirectional {
                try await stream.write(data)
            }
        }
        if stream.isBidirectional {
            try await stream.closeWrite()
        }
    } catch {
        // Stream reset or closed -- expected during benchmarks
    }
}

/// Starts the raw QUIC echo listener on quicPort.
/// Returns (endpoint, runTask, acceptTask) for lifecycle management.
func startRawQUICListener(certPath: String?, keyPath: String?) async throws -> (QUICEndpoint, Task<Void, Error>, Task<Void, Never>) {
    let config = try makeRawQUICConfig(certPath: certPath, keyPath: keyPath)

    let (endpoint, runTask) = try await QUICEndpoint.serve(
        host: benchHost,
        port: quicPort,
        configuration: config
    )

    log("QUIC", "Raw QUIC echo listening on \(benchHost):\(quicPort) (ALPN: \(quicBenchALPN))")

    let connectionStream = await endpoint.incomingConnections

    let acceptTask = Task<Void, Never> {
        var connCount: UInt64 = 0
        for await connection in connectionStream {
            connCount += 1
            let id = connCount
            Task {
                await handleRawQUICConnection(connection, id: id)
            }
        }
    }

    return (endpoint, runTask, acceptTask)
}

// =============================================================================
// MARK: - HTTP/3 Router
// =============================================================================

func buildBenchRouter() -> HTTP3Router {
    let router = HTTP3Router()

    // GET / - health
    router.get("/") { context in
        stats.incH3Requests()
        let body = Data("{\"status\":\"ok\",\"server\":\"quiver-bench\"}".utf8)
        stats.add(h3Bytes: UInt64(body.count))
        try await context.respond(HTTP3Response(
            status: 200,
            headers: [("content-type", "application/json")],
            body: body
        ))
    }

    // GET /bench/html - large HTML page (~64KB)
    router.get("/bench/html") { context in
        stats.incH3Requests()
        stats.add(h3Bytes: UInt64(prebuiltLargeHTML.count))
        try await context.respond(HTTP3Response(
            status: 200,
            headers: [
                ("content-type", "text/html; charset=utf-8"),
                ("content-length", "\(prebuiltLargeHTML.count)"),
            ],
            body: prebuiltLargeHTML
        ))
    }

    // GET /bench/headers - response with many headers
    router.get("/bench/headers") { context in
        stats.incH3Requests()
        let body = Data("{\"header_count\":\(prebuiltBigHeaders.count)}".utf8)
        stats.add(h3Bytes: UInt64(body.count))
        try await context.respond(HTTP3Response(
            status: 200,
            headers: prebuiltBigHeaders,
            body: body
        ))
    }

    // GET /bench/large-body - large binary body (~4MB)
    router.get("/bench/large-body") { context in
        stats.incH3Requests()
        stats.add(h3Bytes: UInt64(prebuiltLargeBody.count))
        try await context.respond(HTTP3Response(
            status: 200,
            headers: [
                ("content-type", "application/octet-stream"),
                ("content-length", "\(prebuiltLargeBody.count)"),
            ],
            body: prebuiltLargeBody
        ))
    }

    // POST /bench/echo - echo request body
    router.post("/bench/echo") { context in
        stats.incH3Requests()
        let body = context.request.body ?? Data()
        stats.add(h3Bytes: UInt64(body.count))
        try await context.respond(HTTP3Response(
            status: 200,
            headers: [
                ("content-type", "application/octet-stream"),
                ("content-length", "\(body.count)"),
                ("x-echo", "true"),
            ],
            body: body
        ))
    }

    // POST /bench/sink - accept data, return 204 (test upload throughput)
    router.post("/bench/sink") { context in
        stats.incH3Requests()
        let body = context.request.body ?? Data()
        stats.add(h3Bytes: UInt64(body.count))
        try await context.respond(HTTP3Response(
            status: 204,
            headers: [("x-received-bytes", "\(body.count)")]
        ))
    }

    router.setNotFound { context in
        stats.incH3Requests()
        let body = Data("{\"error\":\"not_found\"}".utf8)
        try await context.respond(HTTP3Response(
            status: 404,
            headers: [("content-type", "application/json")],
            body: body
        ))
    }

    return router
}

// =============================================================================
// MARK: - WebTransport Session Handler
// =============================================================================

func handleBenchSession(_ session: WebTransportSession, num: UInt64) async {
    let tag = "WT#\(num)"
    log(tag, "Session started")

    await withTaskGroup(of: Void.self) { group in

        // Bidi echo: read -> write back
        group.addTask {
            var count: UInt64 = 0
            for await stream in await session.incomingBidirectionalStreams {
                count += 1
                stats.incWtBidi()
                let streamNum = count
                Task {
                    await echoBidiStream(stream, tag: "\(tag)/bidi#\(streamNum)")
                }
            }
        }

        // Uni echo: read incoming uni -> send back on new uni
        group.addTask {
            var count: UInt64 = 0
            for await stream in await session.incomingUnidirectionalStreams {
                count += 1
                stats.incWtUni()
                let streamNum = count
                Task {
                    await echoUniStream(session: session, incoming: stream, tag: "\(tag)/uni#\(streamNum)")
                }
            }
        }

        // Datagram echo
        group.addTask {
            for await datagram in await session.incomingDatagrams {
                stats.add(wtBytes: UInt64(datagram.count))
                do {
                    try await session.sendDatagram(datagram)
                    stats.incWtDatagram()
                } catch {
                    stats.incWtDatagramFail()
                }
            }
        }
    }

    log(tag, "Session ended")
}

func echoBidiStream(_ stream: WebTransportStream, tag: String) async {
    do {
        while true {
            let data = try await stream.read()
            if data.isEmpty { break }
            stats.add(wtBytes: UInt64(data.count))
            try await stream.write(data)
        }
        try await stream.closeWrite()
    } catch {
        // Stream reset or closed -- expected during benchmarks
    }
}

func echoUniStream(session: WebTransportSession, incoming: WebTransportStream, tag: String) async {
    do {
        // Read all data from the incoming uni stream
        var accumulated = Data()
        while true {
            let chunk = try await incoming.read()
            if chunk.isEmpty { break }
            accumulated.append(chunk)
        }
        stats.add(wtBytes: UInt64(accumulated.count))

        // Send back on a new outgoing uni stream
        let outgoing = try await session.openUnidirectionalStream()
        try await outgoing.write(accumulated)
        try await outgoing.closeWrite()
    } catch {
        // Stream reset or closed -- expected during benchmarks
    }
}

// =============================================================================
// MARK: - Stats Printer
// =============================================================================

func startStatsPrinter() -> Task<Void, Never> {
    return Task {
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(10))
            log("Stats", "\n\(stats.snapshot())")
        }
    }
}

// =============================================================================
// MARK: - Entrypoint
// =============================================================================

// Parse positional args: [cert.pem key.pem]
var certPath: String? = nil
var keyPath: String? = nil

let args = CommandLine.arguments.dropFirst() // skip binary name
let positional = Array(args)

if positional.count >= 2 {
    certPath = positional[0]
    keyPath = positional[1]
}

log("Server", "=================================================================")
log("Server", "  Quiver Benchmark Server")
log("Server", "=================================================================")
log("Server", "")
log("Server", "  Listeners:")
log("Server", "    QUIC raw echo .... \(benchHost):\(quicPort)  (ALPN: \(quicBenchALPN))")
log("Server", "    HTTP/3 + WT ...... \(benchHost):\(h3Port)  (ALPN: \(h3ALPN))")
log("Server", "")
if let c = certPath, let k = keyPath {
    log("Server", "  TLS:           Production (cert: \(c), key: \(k))")
} else {
    log("Server", "  TLS:           Development (self-signed)")
}
log("Server", "  Max streams:   bidi=\(maxStreamsBidi) uni=\(maxStreamsUni)")
log("Server", "  Max data:      conn=\(formatBytes(maxData)) stream=\(formatBytes(maxStreamData))")
log("Server", "  Datagrams:     enabled on H3 port (max frame=65535)")
log("Server", "")
log("Server", "  Protocols:")
log("Server", "    [:\(quicPort)] QUIC raw  - Stream echo (bidi echo, uni sink)")
log("Server", "    [:\(h3Port)] HTTP/3    - GET /bench/html       (~\(largeHTMLSize/1024) KB HTML)")
log("Server", "              - GET /bench/headers     (\(bigHeaderCount) headers)")
log("Server", "              - GET /bench/large-body  (~\(largeBodySize/1024/1024) MB)")
log("Server", "              - POST /bench/echo       (echo body)")
log("Server", "              - POST /bench/sink       (accept body, 204)")
log("Server", "    [:\(h3Port)] WebTransport:")
log("Server", "              - Bidi stream echo")
log("Server", "              - Uni stream echo")
log("Server", "              - Datagram echo")
log("Server", "")
log("Server", "  Stats printed every 10 seconds.")
log("Server", "  Press Ctrl+C to stop.")
log("Server", "=================================================================")
log("Server", "")

do {
    // =========================================================================
    // Listener 1: Raw QUIC echo on quicPort
    // =========================================================================
    let (quicEndpoint, quicRunTask, quicAcceptTask) = try await startRawQUICListener(
        certPath: certPath, keyPath: keyPath
    )

    // =========================================================================
    // Listener 2: HTTP/3 + WebTransport on h3Port
    // =========================================================================
    let h3Config = try makeH3Config(certPath: certPath, keyPath: keyPath)

    let wtServer = WebTransportServer(
        configuration: WebTransportServer.Configuration(
            maxSessionsPerConnection: 16,
            maxConnections: 0, // unlimited
            allowedPaths: ["/bench"]
        )
    )

    // Register HTTP/3 request handler
    let router = buildBenchRouter()
    await wtServer.onRequest(router.handler)

    // Start session handler
    let sessionTask = Task {
        var sessionCount: UInt64 = 0
        for await session in await wtServer.incomingSessions {
            sessionCount += 1
            let num = sessionCount
            log("Server", "WebTransport session #\(num) established")
            Task {
                await handleBenchSession(session, num: num)
            }
        }
    }

    // Start stats printer
    let statsTask = startStatsPrinter()

    log("Server", "Both listeners active. Waiting for connections...")
    log("Server", "")

    // =========================================================================
    // Block on the HTTP/3 listener (it runs until stop() is called)
    // =========================================================================
    do {
        try await wtServer.listen(
            host: benchHost,
            port: h3Port,
            quicConfiguration: h3Config
        )
    } catch {
        log("Server", "H3 listener error: \(error)")
    }

    // Cleanup
    sessionTask.cancel()
    statsTask.cancel()
    quicAcceptTask.cancel()
    await wtServer.stop(gracePeriod: .seconds(5))
    await quicEndpoint.stop()
    quicRunTask.cancel()
    log("Server", "Server stopped.")

} catch {
    log("Server", "FATAL: \(error)")
    exit(1)
}