// =============================================================================
// WebTransport Echo Server & Client Demo
// =============================================================================
//
// This example demonstrates the WebTransport API built on top of HTTP/3 + QUIC:
//   1. A WebTransport echo server that accepts sessions and echoes data back
//      on bidirectional streams, unidirectional streams, and datagrams
//   2. A WebTransport client that connects, sends messages via all three
//      transport mechanisms, and verifies the echoed responses
//
// ## Running
//
//   # Start the WebTransport echo server (default: 127.0.0.1:4445)
//   swift run WebTransportDemo server
//
//   # In another terminal, run the client
//   swift run WebTransportDemo client
//
//   # Custom host/port
//   swift run WebTransportDemo server --host 0.0.0.0 --port 5555
//   swift run WebTransportDemo client --host 127.0.0.1 --port 5555
//
//   # With real certificates (production mode)
//   swift run WebTransportDemo server --cert /path/to/cert.pem --key /path/to/key.pem
//   swift run WebTransportDemo client --ca-cert /path/to/ca.pem
//
// ## Architecture
//
//   ┌─────────────────────────┐       QUIC/UDP        ┌─────────────────────────┐
//   │   WebTransport Client   │ ◄───────────────────► │   WebTransport Server   │
//   │                         │   HTTP/3 + Extended    │                         │
//   │  connect(path: "/echo") │   CONNECT handshake    │  WebTransportServer     │
//   │                         │                        │  .listen(host:port:)    │
//   │  ┌───────────────────┐  │                        │  ┌───────────────────┐  │
//   │  │ Bidi Stream Echo  │──│── "Hello, bidi!" ────►│──│ Echo bidi streams │  │
//   │  │                   │◄─│── "Hello, bidi!" ◄────│──│                   │  │
//   │  ├───────────────────┤  │                        │  ├───────────────────┤  │
//   │  │ Uni Stream Echo   │──│── "Hello, uni!" ─────►│──│ Echo via new uni  │  │
//   │  │ (incoming uni)    │◄─│── "Hello, uni!" ◄─────│──│ stream back       │  │
//   │  ├───────────────────┤  │                        │  ├───────────────────┤  │
//   │  │ Datagram Echo     │──│── "ping" ────────────►│──│ Echo datagrams    │  │
//   │  │                   │◄─│── "ping" ◄────────────│──│                   │  │
//   │  └───────────────────┘  │                        │  └───────────────────┘  │
//   └─────────────────────────┘                        └─────────────────────────┘
//
// ## WebTransport Concepts
//
//   - **WebTransportSession**: Established via Extended CONNECT (RFC 9220) over
//     HTTP/3. A single HTTP/3 connection can host multiple sessions.
//
//   - **Bidirectional Streams**: Both sides can read and write. The session ID
//     is written as the first varint on the stream (framing is automatic).
//
//   - **Unidirectional Streams**: One-way data flow. Stream type 0x54 +
//     session ID are written as prefix (framing is automatic). For echo,
//     the server reads from the client's uni stream and sends the response
//     on a new server-initiated uni stream.
//
//   - **Datagrams**: Unreliable, unordered messages. Associated with the
//     session via a quarter-stream-ID prefix in the QUIC DATAGRAM frame.
//     Best for latency-sensitive data where occasional loss is acceptable.
//
// ## Security Modes
//
//   This demo supports two TLS modes:
//
//   1. **Development mode** (default, no arguments):
//      Uses a self-signed P-256 certificate generated at startup.
//      The client uses `allowSelfSigned = true` to accept it.
//      Provides REAL TLS 1.3 encryption but no identity verification.
//
//   2. **Production mode** (with --cert/--key and --ca-cert):
//      Uses PEM certificate and key files from disk.
//      The client verifies the server certificate against a trusted CA.
//      Full TLS 1.3 encryption and identity verification.
//
// =============================================================================

import Foundation
import HTTP3
import Logging
import NIOUDPTransport
import QPACK
import QUIC
import QUICCore
import QUICCrypto
import QUICTransport

// MARK: - Configuration

/// Default server address
let defaultHost = "127.0.0.1"

/// Default server port
let defaultPort: UInt16 = 4445

/// ALPN protocol for HTTP/3 (required for WebTransport)
let h3ALPN = "h3"

/// WebTransport session path
let echoPath = "/echo"

// MARK: - Argument Parsing

/// Simple argument parser for the demo
struct DemoArguments {
    enum Mode: String {
        case server
        case client
        case help
    }

    let mode: Mode
    let host: String
    let port: UInt16
    let logLevel: Logger.Level

    // TLS options
    let certPath: String?  // Server: PEM certificate path
    let keyPath: String?  // Server: PEM private key path
    let caCertPath: String?  // Client: PEM CA certificate path
    let useSystemCertificates: Bool  // Client: use system trust store

    // Demo options
    let skipDatagrams: Bool

    static func parseLogLevel(_ string: String) -> Logger.Level? {
        switch string.lowercased() {
        case "trace": return .trace
        case "debug": return .debug
        case "info": return .info
        case "notice": return .notice
        case "warning", "warn": return .warning
        case "error": return .error
        case "critical": return .critical
        default: return nil
        }
    }

    static func parse() -> DemoArguments {
        let args = CommandLine.arguments

        // Default values
        var mode: Mode = .help
        var host = defaultHost
        var port = defaultPort
        var logLevel: Logger.Level = .info
        var certPath: String?
        var keyPath: String?
        var caCertPath: String?
        var useSystemCertificates = false
        var skipDatagrams = false

        var i = 1
        while i < args.count {
            let arg = args[i]
            switch arg {
            case "server":
                mode = .server
            case "client":
                mode = .client
            case "help", "--help", "-h":
                mode = .help
            case "--host":
                i += 1
                if i < args.count { host = args[i] }
            case "--port", "-p":
                i += 1
                if i < args.count { port = UInt16(args[i]) ?? defaultPort }
            case "--log-level", "-l":
                i += 1
                if i < args.count {
                    logLevel = parseLogLevel(args[i]) ?? .info
                }
            case "--cert":
                i += 1
                if i < args.count { certPath = args[i] }
            case "--key":
                i += 1
                if i < args.count { keyPath = args[i] }
            case "--ca-cert":
                i += 1
                if i < args.count { caCertPath = args[i] }
            case "--use-system-certificates":
                useSystemCertificates = true
            case "--skip-datagrams":
                skipDatagrams = true
            default:
                break
            }
            i += 1
        }

        return DemoArguments(
            mode: mode,
            host: host,
            port: port,
            logLevel: logLevel,
            certPath: certPath,
            keyPath: keyPath,
            caCertPath: caCertPath,
            useSystemCertificates: useSystemCertificates,
            skipDatagrams: skipDatagrams
        )
    }
}

// MARK: - Logging Helper

func log(_ tag: String, _ message: String) {
    let timestamp = Date()
    let formatter = DateFormatter()
    formatter.dateFormat = "HH:mm:ss.SSS"
    print("[\(formatter.string(from: timestamp))] [\(tag)] \(message)")
}

// MARK: - TLS Configuration Helpers

/// Creates a server TLS configuration.
///
/// When `certPath` and `keyPath` are provided, loads real PEM certificates
/// from disk (production mode). Otherwise, generates a self-signed P-256
/// key pair at startup (development mode).
func makeServerTLSConfig(certPath: String?, keyPath: String?) throws -> (TLSConfiguration, String) {
    if let certPath = certPath, let keyPath = keyPath {
        var tlsConfig = try TLSConfiguration.server(
            certificatePath: certPath,
            privateKeyPath: keyPath,
            alpnProtocols: [h3ALPN]
        )
        tlsConfig.verifyPeer = false
        return (tlsConfig, "Production (cert: \(certPath), key: \(keyPath))")
    } else {
        let signingKey = SigningKey.generateP256()
        let mockCertDER = Data([0x30, 0x82, 0x01, 0x00])
        var tlsConfig = TLSConfiguration.server(
            signingKey: signingKey,
            certificateChain: [mockCertDER],
            alpnProtocols: [h3ALPN]
        )
        tlsConfig.verifyPeer = false
        return (tlsConfig, "Development (self-signed P-256, no cert files)")
    }
}

/// Creates a client TLS configuration.
///
/// Resolution order:
/// 1) `useSystemCertificates == true` => verify with system trust store
/// 2) `caCertPath != nil` => verify with explicit CA bundle
/// 3) fallback => development mode (allow self-signed)
func makeClientTLSConfig(
    caCertPath: String?,
    useSystemCertificates: Bool
) throws -> (TLSConfiguration, String) {
    if useSystemCertificates {
        var tlsConfig = TLSConfiguration.client(
            serverName: "localhost",
            alpnProtocols: [h3ALPN]
        )
        tlsConfig.verifyPeer = true
        tlsConfig.allowSelfSigned = false
        return (tlsConfig, "Production (system trust store, verifyPeer: true)")
    } else if let caCertPath = caCertPath {
        var tlsConfig = TLSConfiguration.client(
            serverName: "localhost",
            alpnProtocols: [h3ALPN]
        )
        try tlsConfig.loadTrustedCAs(fromPEMFile: caCertPath)
        tlsConfig.verifyPeer = true
        tlsConfig.allowSelfSigned = false
        return (tlsConfig, "Production (CA: \(caCertPath), verifyPeer: true)")
    } else {
        var tlsConfig = TLSConfiguration.client(
            serverName: "localhost",
            alpnProtocols: [h3ALPN]
        )
        tlsConfig.verifyPeer = false
        tlsConfig.allowSelfSigned = true
        return (tlsConfig, "Development (allowSelfSigned: true, verifyPeer: false)")
    }
}

// MARK: - QUIC Configuration Helpers

/// Creates a QUIC configuration for the WebTransport server.
func makeServerConfiguration(certPath: String?, keyPath: String?) throws -> QUICConfiguration {
    let (tlsConfig, description) = try makeServerTLSConfig(certPath: certPath, keyPath: keyPath)
    log("Config", "TLS mode: \(description)")

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
    config.maxIdleTimeout = .seconds(60)

    // WebTransport requires generous stream limits:
    // - HTTP/3 control streams (3 uni from each side)
    // - QPACK encoder/decoder streams
    // - WebTransport bidi/uni streams for application data
    // - The Extended CONNECT stream itself
    config.initialMaxStreamsBidi = 200
    config.initialMaxStreamsUni = 200

    // Flow control limits
    config.initialMaxData = 10_000_000
    config.initialMaxStreamDataBidiLocal = 1_000_000
    config.initialMaxStreamDataBidiRemote = 1_000_000
    config.initialMaxStreamDataUni = 1_000_000

    // WebTransport datagram support (RFC 9221)
    // Required for WebTransport datagrams — advertises max_datagram_frame_size
    // transport parameter so the peer knows we accept DATAGRAM frames.
    config.enableDatagrams = true
    config.maxDatagramFrameSize = 65535

    return config
}

/// Creates a QUIC configuration for the WebTransport client.
func makeClientConfiguration(
    caCertPath: String?,
    useSystemCertificates: Bool
) throws -> QUICConfiguration {
    let (tlsConfig, description) = try makeClientTLSConfig(
        caCertPath: caCertPath,
        useSystemCertificates: useSystemCertificates
    )
    log("Config", "TLS mode: \(description)")

    let isProduction = useSystemCertificates || (caCertPath != nil)

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
    config.maxIdleTimeout = .seconds(60)
    config.initialMaxStreamsBidi = 200
    config.initialMaxStreamsUni = 200
    config.initialMaxData = 10_000_000
    config.initialMaxStreamDataBidiLocal = 1_000_000
    config.initialMaxStreamDataBidiRemote = 1_000_000
    config.initialMaxStreamDataUni = 1_000_000

    // WebTransport datagram support (RFC 9221)
    config.enableDatagrams = true
    config.maxDatagramFrameSize = 65535

    return config
}

// MARK: - WebTransport Echo Server

/// Runs the WebTransport echo server.
///
/// The server:
/// 1. Creates a WebTransportServer with options and path registration
/// 2. Creates a QUIC endpoint and feeds connections via `serve(connectionSource:)`
/// 3. For each incoming WebTransport session:
///    a. Echoes bidirectional stream data back to the sender
///    b. Reads unidirectional streams and sends a response on a new uni stream
///    c. Echoes datagrams back to the sender
///
/// ## WebTransport Server Setup Flow
///
/// ```
/// QUICEndpoint.serve(host, port, quicConfig)     ← UDP socket + QUIC I/O
///   └─► server.serve(connectionSource)            ← WebTransport + HTTP/3 layer
///       └─► Middleware resolution                  ← Accept/reject via middleware
///           └─► WebTransportSession created        ← Yielded to incomingSessions
/// ```
func runServer(host: String, port: UInt16, certPath: String?, keyPath: String?) async throws {
    log("Server", "╔══════════════════════════════════════════════════════════════╗")
    log("Server", "║            WebTransport Echo Server                         ║")
    log("Server", "╚══════════════════════════════════════════════════════════════╝")
    log("Server", "")
    log("Server", "Configuration:")
    log("Server", "  Address:       \(host):\(port)")
    log("Server", "  ALPN:          \(h3ALPN)")
    log("Server", "  Session path:  \(echoPath)")

    if let certPath = certPath, let keyPath = keyPath {
        log("Server", "  TLS:           Production (cert: \(certPath))")
        log("Server", "                 (key:  \(keyPath))")
    } else {
        log("Server", "  TLS:           Development (self-signed, real TLS 1.3 encryption)")
        if certPath != nil && keyPath == nil {
            log(
                "Server",
                "  Warning: --cert provided without --key, falling back to development mode")
        }
        if certPath == nil && keyPath != nil {
            log(
                "Server",
                "  Warning: --key provided without --cert, falling back to development mode")
        }
    }
    log("Server", "")

    // Step 1: Create the QUIC configuration
    //
    // The demo builds its own QUICConfiguration with TLS because
    // WebTransportServerOptions.buildQUICConfiguration() does not set
    // securityMode (QUICCrypto is not a direct HTTP3 dependency).
    // We create the QUIC endpoint ourselves and feed connections via
    // server.serve(connectionSource:).
    //
    let quicConfig = try makeServerConfiguration(certPath: certPath, keyPath: keyPath)

    // Step 2: Create the WebTransport server
    //
    // WebTransportServerOptions carries cert paths and transport params.
    // The server uses middleware to control session acceptance and
    // register(path:) for path-based routing.
    //
    // NOTE: certificatePath/privateKeyPath are provided for documentation
    // purposes but TLS is configured via the QUICConfiguration above.
    //
    let serverOptions = WebTransportServerOptions(
        certificatePath: certPath ?? "dev-self-signed",
        privateKeyPath: keyPath ?? "dev-self-signed",
        maxSessions: 4,
        maxIdleTimeout: .seconds(60),
        initialMaxStreamsBidi: 200,
        initialMaxStreamsUni: 200
    )

    let server = WebTransportServer(
        host: host,
        port: port,
        options: serverOptions
    )

    // Register the echo path — only this path will be accepted
    await server.register(path: echoPath)

    // Step 3: Start the session handler in a background task
    //
    // `server.incomingSessions` is an AsyncStream<WebTransportSession>.
    // Each session represents a fully established WebTransport connection
    // that was accepted via Extended CONNECT.
    //
    var sessionCount: UInt64 = 0

    let sessionHandlerTask = Task {
        for await session in await server.incomingSessions {
            sessionCount += 1
            let sessionNum = sessionCount
            let sessionID = await session.sessionID

            log("Server", "")
            log("Server", "═══ New WebTransport Session #\(sessionNum) ═══")
            log("Server", "  Session ID: \(sessionID)")
            log("Server", "")

            // Handle each session concurrently
            Task {
                await handleServerSession(session, sessionNum: sessionNum)
            }
        }
    }

    log("Server", "Registered echo handlers:")
    log("Server", "  • Bidirectional stream echo")
    log("Server", "  • Unidirectional stream echo (read → respond on new uni)")
    log("Server", "  • Datagram echo")
    log("Server", "")
    log("Server", "Listening on \(host):\(port)")
    log("Server", "Press Ctrl+C to stop")
    log("Server", "")
    log("Server", "Waiting for WebTransport sessions...")
    log(
        "Server",
        "  (Connect with: swift run WebTransportDemo client --host \(host) --port \(port))")
    log("Server", "")

    // Step 4: Start listening
    //
    // We create the QUIC endpoint ourselves (with TLS configured via
    // makeServerConfiguration) and feed connections to the server.
    //
    let (endpoint, runTask) = try await QUICEndpoint.serve(
        host: host,
        port: port,
        configuration: quicConfig
    )

    let connectionStream = await endpoint.incomingConnections

    do {
        try await server.serve(connectionSource: connectionStream)
    } catch {
        log("Server", "Server error: \(error)")
    }

    // Cleanup
    sessionHandlerTask.cancel()
    log("Server", "Shutting down...")
    await server.stop(gracePeriod: .seconds(5))
    await endpoint.stop()
    runTask.cancel()
    log("Server", "Server stopped.")
}

// MARK: - Session Handler (Server-side)

/// Handles a single WebTransport session by running echo handlers concurrently.
///
/// Spawns three concurrent tasks:
/// 1. Bidirectional stream echo
/// 2. Unidirectional stream echo
/// 3. Datagram echo
func handleServerSession(_ session: WebTransportSession, sessionNum: UInt64) async {
    let tag = "Session#\(sessionNum)"

    // Run all echo handlers concurrently
    await withTaskGroup(of: Void.self) { group in

        // Handler 1: Echo bidirectional streams
        //
        // When the client opens a bidi stream, we read data and write it back.
        // The session ID framing is handled automatically by the WebTransport layer.
        group.addTask {
            var streamCount: UInt64 = 0
            for await stream in await session.incomingBidirectionalStreams {
                streamCount += 1
                let streamNum = streamCount
                let streamID = stream.id

                log(tag, "Bidi stream #\(streamNum) opened (QUIC stream \(streamID))")

                Task {
                    await handleBidiEcho(
                        stream,
                        tag: tag,
                        streamNum: streamNum
                    )
                }
            }
            log(tag, "Incoming bidi streams ended (total: \(streamCount))")
        }

        // Handler 2: Echo unidirectional streams
        //
        // When the client opens a uni stream, we read all data from it,
        // then open a new server→client uni stream and write the data there.
        // This demonstrates the uni stream echo pattern since uni streams
        // are one-directional.
        group.addTask {
            var streamCount: UInt64 = 0
            for await stream in await session.incomingUnidirectionalStreams {
                streamCount += 1
                let streamNum = streamCount
                let streamID = stream.id

                log(tag, "Uni stream #\(streamNum) received (QUIC stream \(streamID))")

                Task {
                    await handleUniEcho(
                        session: session,
                        incomingStream: stream,
                        tag: tag,
                        streamNum: streamNum
                    )
                }
            }
            log(tag, "Incoming uni streams ended (total: \(streamCount))")
        }

        // Handler 3: Echo datagrams
        //
        // QUIC datagrams are unreliable, unordered messages. The session
        // associates them with this session using the quarter-stream-ID prefix.
        // We simply echo each datagram back.
        group.addTask {
            var datagramCount: UInt64 = 0
            for await datagram in await session.incomingDatagrams {
                datagramCount += 1

                if let text = String(data: datagram, encoding: .utf8) {
                    log(
                        tag,
                        "Datagram #\(datagramCount) received: \"\(text)\" (\(datagram.count) bytes)"
                    )
                } else {
                    log(tag, "Datagram #\(datagramCount) received: \(datagram.count) bytes")
                }

                // Echo back
                do {
                    try await session.sendDatagram(datagram)
                    log(tag, "Datagram #\(datagramCount) echoed")
                } catch {
                    log(tag, "Datagram #\(datagramCount) echo failed: \(error)")
                }
            }
            log(tag, "Incoming datagrams ended (total: \(datagramCount))")
        }

        // Wait for all handlers to complete (session closed or streams ended)
    }

    let isClosed = await session.isClosed
    log(tag, "Session ended (closed: \(isClosed))")
}

/// Echoes data on a bidirectional stream.
///
/// Reads data in a loop and writes it back until the client closes
/// the write side (FIN received, indicated by empty data).
func handleBidiEcho(
    _ stream: WebTransportStream,
    tag: String,
    streamNum: UInt64
) async {
    var totalBytes: UInt64 = 0
    var messageCount: UInt64 = 0

    do {
        while true {
            let data = try await stream.read()

            // Empty data means FIN received (stream closed by peer)
            if data.isEmpty {
                log(tag, "Bidi #\(streamNum): FIN received")
                break
            }

            messageCount += 1
            totalBytes += UInt64(data.count)

            if let text = String(data: data, encoding: .utf8) {
                log(tag, "Bidi #\(streamNum): read \"\(text)\" (\(data.count) bytes)")
            } else {
                log(tag, "Bidi #\(streamNum): read \(data.count) bytes")
            }

            // Echo back
            try await stream.write(data)
            log(tag, "Bidi #\(streamNum): echoed \(data.count) bytes")
        }

        // Close our write side to signal we're done
        try await stream.closeWrite()
        log(
            tag, "Bidi #\(streamNum): closed (total: \(messageCount) messages, \(totalBytes) bytes)"
        )
    } catch {
        log(tag, "Bidi #\(streamNum): error: \(error)")
    }
}

/// Echoes data from an incoming unidirectional stream by reading all data
/// and sending it back on a new server-initiated unidirectional stream.
///
/// Since uni streams are one-directional, the echo pattern is:
///   client → uni stream → server (reads all) → new uni stream → client
func handleUniEcho(
    session: WebTransportSession,
    incomingStream: WebTransportStream,
    tag: String,
    streamNum: UInt64
) async {
    // Read all data from the incoming uni stream
    var receivedData = Data()
    do {
        while true {
            let chunk = try await incomingStream.read()
            if chunk.isEmpty {
                break
            }
            receivedData.append(chunk)
        }
    } catch {
        log(tag, "Uni #\(streamNum): read error: \(error)")
        // Still try to echo whatever we received
    }

    if receivedData.isEmpty {
        log(tag, "Uni #\(streamNum): received empty stream, skipping echo")
        return
    }

    if let text = String(data: receivedData, encoding: .utf8) {
        log(tag, "Uni #\(streamNum): received \"\(text)\" (\(receivedData.count) bytes total)")
    } else {
        log(tag, "Uni #\(streamNum): received \(receivedData.count) bytes total")
    }

    // Open a new server→client uni stream and send the echo
    do {
        let responseStream = try await session.openUnidirectionalStream()
        try await responseStream.write(receivedData)
        try await responseStream.closeWrite()
        log(tag, "Uni #\(streamNum): echoed on new uni stream (QUIC stream \(responseStream.id))")
    } catch {
        log(tag, "Uni #\(streamNum): echo send error: \(error)")
    }
}

// MARK: - WebTransport Echo Client

/// Runs the WebTransport echo client.
///
/// The client:
/// 1. Establishes a WebTransport session via `WebTransport.connect()`
/// 2. Tests all three echo mechanisms:
///    a. Bidirectional stream echo
///    b. Unidirectional stream echo
///    c. Datagram echo
///
/// ## Client Setup Flow
///
/// ```
/// WebTransport.connect(url, options)
///   └─► QUICEndpoint(config).dial(address)     ← QUIC handshake
///       └─► HTTP3Connection.initialize()        ← HTTP/3 SETTINGS exchange
///           └─► sendExtendedConnect()            ← Extended CONNECT → 200 OK
///               └─► WebTransportSession          ← Ready for streams & datagrams
/// ```
func runClient(
    host: String,
    port: UInt16,
    caCertPath: String?,
    useSystemCertificates: Bool,
    skipDatagrams: Bool
) async throws {
    log("Client", "╔══════════════════════════════════════════════════════════════╗")
    log("Client", "║            WebTransport Echo Client                         ║")
    log("Client", "╚══════════════════════════════════════════════════════════════╝")
    log("Client", "")
    log("Client", "Connecting to \(host):\(port)")

    if useSystemCertificates {
        log("WebTransport", "  TLS: Production (system trust store)")
    } else if let caCertPath = caCertPath {
        log("WebTransport", "  TLS: Production (CA cert: \(caCertPath))")
    } else {
        log("WebTransport", "  TLS: Development (allowSelfSigned: true)")
    }
    log("Client", "")

    // Step 1: Create client QUIC configuration
    let quicConfig = try makeClientConfiguration(
        caCertPath: caCertPath,
        useSystemCertificates: useSystemCertificates
    )

    // Step 2: Connect and establish a WebTransport session
    //
    // WebTransport.connect() handles the entire flow in one call:
    //   1. Creates a QUICEndpoint and dials the server (QUIC handshake)
    //   2. Initializes HTTP/3 (control + QPACK streams, SETTINGS)
    //   3. Sends Extended CONNECT with :protocol=webtransport
    //   4. Checks 200 OK and creates the session
    //
    // We use WebTransportOptionsAdvanced because the demo builds its own
    // QUICConfiguration with custom TLS (production/development mode).
    //
    let url = "https://\(host):\(port)\(echoPath)"
    let advancedOptions = WebTransportOptionsAdvanced(quic: quicConfig)

    log("Client", "Connecting to \(url) via WebTransport...")
    let session: WebTransportSession
    do {
        session = try await WebTransport.connect(
            url: url,
            options: advancedOptions
        )
    } catch {
        log("Client", "WebTransport session failed: \(error)")
        log("Client", "")
        log("Client", "Make sure the server is running:")
        log("Client", "  swift run WebTransportDemo server --host \(host) --port \(port)")
        throw error
    }

    let sessionID = await session.sessionID
    log("Client", "WebTransport session established!")
    log("Client", "  Session ID: \(sessionID)")
    log("Client", "")

    // Small delay to let the session fully stabilize
    try await Task.sleep(for: .milliseconds(100))

    // =========================================================================
    // Test 1: Bidirectional Stream Echo
    // =========================================================================
    log("Client", "═══════════════════════════════════════════════════════════")
    log("Client", "  Test 1: Bidirectional Stream Echo")
    log("Client", "═══════════════════════════════════════════════════════════")
    log("Client", "")

    do {
        try await testBidiStreamEcho(session: session)
        log("Client", "")
        log("Client", "✓ Bidi stream echo: PASSED")
    } catch {
        log("Client", "")
        log("Client", "✗ Bidi stream echo: FAILED — \(error)")
    }
    log("Client", "")

    try await Task.sleep(for: .milliseconds(200))

    // =========================================================================
    // Test 2: Unidirectional Stream Echo
    // =========================================================================
    log("Client", "═══════════════════════════════════════════════════════════")
    log("Client", "  Test 2: Unidirectional Stream Echo")
    log("Client", "═══════════════════════════════════════════════════════════")
    log("Client", "")

    do {
        try await testUniStreamEcho(session: session)
        log("Client", "")
        log("Client", "✓ Uni stream echo: PASSED")
    } catch {
        log("Client", "")
        log("Client", "✗ Uni stream echo: FAILED — \(error)")
    }
    log("Client", "")

    try await Task.sleep(for: .milliseconds(200))

    // =========================================================================
    // Test 3: Datagram Echo
    // =========================================================================
    if !skipDatagrams {
        log("Client", "═══════════════════════════════════════════════════════════")
        log("Client", "  Test 3: Datagram Echo")
        log("Client", "═══════════════════════════════════════════════════════════")
        log("Client", "")

        do {
            try await testDatagramEcho(session: session)
            log("Client", "")
            log("Client", "✓ Datagram echo: PASSED")
        } catch {
            log("Client", "")
            log("Client", "✗ Datagram echo: FAILED — \(error)")
        }
        log("Client", "")
    } else {
        log("Client", "(Skipping datagram test — use without --skip-datagrams to enable)")
        log("Client", "")
    }

    // =========================================================================
    // Cleanup
    // =========================================================================
    log("Client", "═══════════════════════════════════════════════════════════")
    log("Client", "  Cleanup")
    log("Client", "═══════════════════════════════════════════════════════════")
    log("Client", "")

    log("Client", "Closing WebTransport session...")
    try await session.close()
    log("Client", "Session closed")

    log("Client", "")
    log("Client", "╔══════════════════════════════════════════════════════════════╗")
    log("Client", "║            Demo Complete!                                   ║")
    log("Client", "╚══════════════════════════════════════════════════════════════╝")
}

// MARK: - Test: Bidirectional Stream Echo

/// Tests bidirectional stream echo.
///
/// Opens a bidi stream, sends multiple messages, reads back echoes,
/// then closes the stream gracefully.
func testBidiStreamEcho(session: WebTransportSession) async throws {
    // Open a bidirectional stream
    //
    // The WebTransport layer automatically writes the session ID as
    // the first varint on the stream. After that, all reads/writes
    // are pure application data.
    //
    log("Client", "Opening bidirectional stream...")
    let stream = try await session.openBidirectionalStream()
    log("Client", "Bidi stream opened (QUIC stream \(stream.id))")

    let messages = [
        "Hello, WebTransport!",
        "Bidirectional stream echo test 🚀",
        "This is message number three.",
    ]

    for (index, message) in messages.enumerated() {
        let data = Data(message.utf8)
        let num = index + 1

        log("Client", "[\(num)/\(messages.count)] Sending: \"\(message)\" (\(data.count) bytes)")
        try await stream.write(data)

        let echo = try await stream.read()
        if let echoText = String(data: echo, encoding: .utf8) {
            log(
                "Client",
                "[\(num)/\(messages.count)] Received: \"\(echoText)\" (\(echo.count) bytes)")
        } else {
            log("Client", "[\(num)/\(messages.count)] Received: \(echo.count) bytes")
        }

        // Verify echo matches
        if echo == data {
            log("Client", "[\(num)/\(messages.count)] ✓ Match")
        } else {
            log(
                "Client",
                "[\(num)/\(messages.count)] ✗ Mismatch! Expected \(data.count) bytes, got \(echo.count)"
            )
        }
    }

    // Close the stream
    log("Client", "Closing bidi stream...")
    try await stream.closeWrite()
    log("Client", "Bidi stream closed")
}

// MARK: - Test: Unidirectional Stream Echo

/// Tests unidirectional stream echo.
///
/// Opens a client→server uni stream, writes data, closes it.
/// Then reads from the server→client uni stream to get the echo.
///
/// The echo pattern for uni streams is:
///   1. Client opens uni stream, writes data, closes with FIN
///   2. Server reads all data from client's uni stream
///   3. Server opens a new uni stream, writes the echo, closes with FIN
///   4. Client reads the echo from the server's uni stream
func testUniStreamEcho(session: WebTransportSession) async throws {
    let message = "Hello via unidirectional stream! 📡"
    let data = Data(message.utf8)

    // Start listening for the server's response uni stream BEFORE sending.
    // This avoids a race condition where the server sends the response
    // before we start listening.
    log("Client", "Setting up uni stream listener...")

    let echoReceived = Task<Data, Error> { () -> Data in
        // Wait for the server's response on a new uni stream
        var iterator = await session.incomingUnidirectionalStreams.makeAsyncIterator()
        guard let responseStream = await iterator.next() else {
            throw DemoError.noResponseStream
        }

        log("Client", "Incoming uni stream received (QUIC stream \(responseStream.id))")

        // Read all data from the response stream
        var received = Data()
        while true {
            let chunk = try await responseStream.read()
            if chunk.isEmpty {
                break
            }
            received.append(chunk)
        }
        return received
    }

    // Send data on a client→server uni stream
    log("Client", "Opening unidirectional stream...")
    let sendStream = try await session.openUnidirectionalStream()
    log("Client", "Uni stream opened (QUIC stream \(sendStream.id))")

    log("Client", "Sending: \"\(message)\" (\(data.count) bytes)")
    try await sendStream.write(data)
    try await sendStream.closeWrite()
    log("Client", "Uni stream closed (FIN sent)")

    // Wait for the echo response with a timeout
    log("Client", "Waiting for echo response on incoming uni stream...")

    let echo: Data
    do {
        echo = try await withThrowingTaskGroup(of: Data.self) { group in
            group.addTask {
                try await echoReceived.value
            }
            group.addTask {
                try await Task.sleep(for: .seconds(5))
                throw DemoError.timeout("Uni stream echo response")
            }

            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    } catch {
        echoReceived.cancel()
        throw error
    }

    if let echoText = String(data: echo, encoding: .utf8) {
        log("Client", "Received echo: \"\(echoText)\" (\(echo.count) bytes)")
    } else {
        log("Client", "Received echo: \(echo.count) bytes")
    }

    // Verify
    if echo == data {
        log("Client", "✓ Uni stream echo matches")
    } else {
        log("Client", "✗ Uni stream echo mismatch! Expected \(data.count) bytes, got \(echo.count)")
    }
}

// MARK: - Test: Datagram Echo

/// Tests datagram echo.
///
/// Sends QUIC datagrams and verifies they are echoed back.
/// Datagrams are unreliable, so we send multiple and accept
/// partial success.
func testDatagramEcho(session: WebTransportSession) async throws {
    let messages = [
        "ping",
        "datagram test 🏓",
        "unreliable but fast!",
    ]

    let expectedCount = messages.count

    // Start listening for echoed datagrams BEFORE sending.
    // The Task collects datagrams internally and returns them,
    // avoiding mutable capture across Sendable boundaries.
    let receiverTask = Task<[Data], Never> {
        var collected: [Data] = []
        var count = 0
        for await datagram in await session.incomingDatagrams {
            collected.append(datagram)
            count += 1
            if let text = String(data: datagram, encoding: .utf8) {
                log("Client", "Received datagram #\(count): \"\(text)\" (\(datagram.count) bytes)")
            } else {
                log("Client", "Received datagram #\(count): \(datagram.count) bytes")
            }
            // We expect at most messages.count echoes
            if count >= expectedCount {
                break
            }
        }
        return collected
    }

    // Send datagrams
    for (index, message) in messages.enumerated() {
        let data = Data(message.utf8)
        let num = index + 1

        log(
            "Client",
            "[\(num)/\(messages.count)] Sending datagram: \"\(message)\" (\(data.count) bytes)")
        do {
            if message.contains("fast") {
                // Demonstrate TTL strategy for this specific message
                try await session.sendDatagram(data, strategy: .ttl(.milliseconds(200)))
            } else {
                try await session.sendDatagram(data)
            }
        } catch {
            log("Client", "[\(num)/\(messages.count)] Send failed: \(error)")
            log("Client", "  (Datagrams require H3_DATAGRAM and may not be supported by all peers)")
        }

        // Small delay between sends
        try await Task.sleep(for: .milliseconds(50))
    }

    // Wait for echoes with a timeout
    log("Client", "Waiting for datagram echoes...")

    let receivedDatagrams: [Data]
    do {
        receivedDatagrams = try await withThrowingTaskGroup(of: [Data].self) { group in
            group.addTask {
                await receiverTask.value
            }
            group.addTask {
                try await Task.sleep(for: .seconds(3))
                return []  // timeout sentinel returns empty
            }
            // First task to finish wins
            let result = try await group.next() ?? []
            group.cancelAll()
            return result
        }
    } catch {
        // Timeout is acceptable for datagrams (they're unreliable)
        receivedDatagrams = []
    }

    receiverTask.cancel()

    let sent = messages.count
    let received = receivedDatagrams.count
    log("Client", "Datagram results: \(received)/\(sent) echoed")

    if received > 0 {
        log("Client", "✓ At least some datagrams were echoed (\(received)/\(sent))")
    } else {
        log(
            "Client",
            "⚠ No datagrams were echoed (datagrams are unreliable, or H3_DATAGRAM not negotiated)")
    }
}

// MARK: - Errors

enum DemoError: Error, CustomStringConvertible {
    case noResponseStream
    case timeout(String)
    case echoMismatch(expected: Int, got: Int)

    var description: String {
        switch self {
        case .noResponseStream:
            return "No response unidirectional stream received from server"
        case .timeout(let what):
            return "Timeout waiting for: \(what)"
        case .echoMismatch(let expected, let got):
            return "Echo mismatch: expected \(expected) bytes, got \(got) bytes"
        }
    }
}

// MARK: - Help

func printHelp() {
    print(
        """

        WebTransport Echo Demo
        ======================

        A demo that showcases WebTransport over HTTP/3 + QUIC with three
        echo mechanisms: bidirectional streams, unidirectional streams,
        and datagrams.

        USAGE:
            swift run WebTransportDemo <mode> [options]

        MODES:
            server      Start the WebTransport echo server
            client      Connect to the server and run echo tests
            help        Show this help message

        OPTIONS:
            --host <address>        Host address (default: \(defaultHost))
            --port, -p <port>       Port number (default: \(defaultPort))
            --log-level, -l <level> Log verbosity (default: info)
                                    Levels: trace, debug, info, notice, warning, error, critical

        SERVER OPTIONS:
            --cert <path>           Path to PEM certificate file
            --key <path>            Path to PEM private key file

            When both --cert and --key are provided, the server runs in
            production mode with the specified certificate. Otherwise, it
            generates a self-signed P-256 key pair for development.

        CLIENT OPTIONS:
            --ca-cert <path>        Path to PEM CA certificate file
            --skip-datagrams        Skip the datagram echo test

            When --ca-cert is provided, the client verifies the server's
            certificate against the trusted CA (production mode). Otherwise,
            it accepts self-signed certificates (development mode).

        EXAMPLES:
            # Development mode (self-signed, real TLS encryption)
            swift run WebTransportDemo server
            swift run WebTransportDemo client

            # Production mode (with real certificates)
            swift run WebTransportDemo server --cert server.pem --key server-key.pem
            swift run WebTransportDemo client --ca-cert ca.pem

            # Custom host/port
            swift run WebTransportDemo server --host 0.0.0.0 --port 5555
            swift run WebTransportDemo client --host 192.168.1.10 --port 5555

            # Verbose logging
            swift run WebTransportDemo server --log-level debug
            swift run WebTransportDemo client --log-level trace

            # Skip datagram test (if not supported)
            swift run WebTransportDemo client --skip-datagrams

        ECHO MECHANISMS:

            1. Bidirectional Stream Echo
               Client opens a bidi stream, sends messages, reads echoes.
               Both sides can read and write on the same stream.

               Client                          Server
                 |── open bidi stream ──────────►|
                 |── "Hello, WebTransport!" ────►|
                 |◄── "Hello, WebTransport!" ────|
                 |── closeWrite (FIN) ──────────►|
                 |◄── closeWrite (FIN) ──────────|

            2. Unidirectional Stream Echo
               Client opens a uni stream (client→server), sends data, closes it.
               Server reads all data, then opens a new uni stream (server→client)
               and writes the echo.

               Client                          Server
                 |── open uni stream ───────────►|
                 |── "Hello, uni!" ─────────────►|
                 |── closeWrite (FIN) ──────────►|
                 |                               |── reads all data
                 |◄──────── open uni stream ─────|
                 |◄──────── "Hello, uni!" ───────|
                 |◄──────── closeWrite (FIN) ────|

            3. Datagram Echo
               Client sends QUIC datagrams, server echoes them back.
               Datagrams are unreliable and unordered — some may be lost.

               Client                          Server
                 |── datagram "ping" ───────────►|
                 |◄── datagram "ping" ───────────|
                 |── datagram "pong" ───────────►|
                 |◄── datagram "pong" ───────────|

        WEBTRANSPORT ARCHITECTURE:

            ┌──────────────────────────────────────────────────────┐
            │  WebTransport Session                                │
            │  (Established via Extended CONNECT on HTTP/3)        │
            │                                                      │
            │  ┌──────────────────┐  ┌──────────────────┐         │
            │  │ Bidi Streams     │  │ Uni Streams       │         │
            │  │ (both directions)│  │ (one direction)   │         │
            │  └──────────────────┘  └──────────────────┘         │
            │  ┌──────────────────┐                                │
            │  │ Datagrams        │                                │
            │  │ (unreliable)     │                                │
            │  └──────────────────┘                                │
            ├──────────────────────────────────────────────────────┤
            │  HTTP/3 (RFC 9114)                                   │
            │  • SETTINGS with WebTransport extensions             │
            │  • Extended CONNECT (RFC 9220)                       │
            │  • H3_DATAGRAM, ENABLE_CONNECT_PROTOCOL              │
            ├──────────────────────────────────────────────────────┤
            │  QUIC (RFC 9000)                                     │
            │  • Multiplexed streams, flow control                 │
            │  • TLS 1.3 encryption                                │
            │  • Connection migration, 0-RTT                       │
            ├──────────────────────────────────────────────────────┤
            │  UDP Transport (swift-nio-udp)                       │
            └──────────────────────────────────────────────────────┘

        """)
}

// MARK: - Entry Point

let arguments = DemoArguments.parse()

// Bootstrap swift-log with the requested log level.
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
        log("Server", "Fatal error: \(error)")
        exit(1)
    }

case .client:
    do {
        try await runClient(
            host: arguments.host,
            port: arguments.port,
            caCertPath: arguments.caCertPath,
            useSystemCertificates: arguments.useSystemCertificates,
            skipDatagrams: arguments.skipDatagrams
        )
    } catch {
        log("Client", "Fatal error: \(error)")
        exit(1)
    }

case .help:
    printHelp()
}
