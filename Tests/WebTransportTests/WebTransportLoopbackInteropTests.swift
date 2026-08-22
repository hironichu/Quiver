/// WebTransport Loopback Interop Tests
///
/// End-to-end HTTP/3 + WebTransport over a REAL QUIC connection (real UDP
/// sockets, real TLS 1.3 handshake) between a Quiver client and a Quiver
/// server on localhost. No mocks.
///
/// This closes a gap: the existing WebTransport tests exercise session logic
/// over `MockIntegrationConnection`, and the loopback interop tests exercise
/// real QUIC but stop at the raw-stream layer (no H3/WT). The critical-stream
/// lifecycle bug observed on-device (WT CONNECT returns 200, then the session
/// aborts with H3_CLOSED_CRITICAL_STREAM right after) lives precisely in the
/// H3/WT-over-real-QUIC layer that had no in-suite coverage.
///
/// The load-bearing assertion is not "CONNECT returns 200" — it is that the
/// session STAYS ALIVE and remains usable for a beat after establishment
/// (open a bidi stream, round-trip a payload). That is what the user feels as
/// "the app works."

import Testing
import Foundation
@testable import QUIC
@testable import QUICCore
@testable import QUICCrypto
import QUICStream
import HTTP3

// MARK: - Loopback rig (H3/WT flavor)

/// Self-contained server/client QUIC configuration for H3/WebTransport over
/// loopback. Uses development-mode TLS (self-signed P-256, no validation) and
/// the standard "h3" ALPN so both ends agree.
private enum WTLoopback {

    static let alpn = "h3"

    static func makeServerConfiguration() -> QUICConfiguration {
        let signingKey = SigningKey.generateP256()
        let mockCertDER = Data([0x30, 0x82, 0x01, 0x00])

        var config = QUICConfiguration.development {
            let tlsConfig = TLSConfiguration.server(
                signingKey: signingKey,
                certificateChain: [mockCertDER],
                alpnProtocols: [alpn]
            )
            return TLS13Handler(configuration: tlsConfig)
        }
        config.alpn = [alpn]
        config.maxIdleTimeout = .seconds(30)
        config.initialMaxStreamsBidi = 100
        config.initialMaxStreamsUni = 100
        config.initialMaxData = 10_000_000
        config.initialMaxStreamDataBidiLocal = 1_000_000
        config.initialMaxStreamDataBidiRemote = 1_000_000
        config.initialMaxStreamDataUni = 1_000_000
        return config
    }

    static func makeClientConfiguration() -> QUICConfiguration {
        var config = QUICConfiguration.development {
            var tlsConfig = TLSConfiguration.client(
                serverName: "localhost",
                alpnProtocols: [alpn]
            )
            tlsConfig.verifyPeer = false
            tlsConfig.allowSelfSigned = true
            return TLS13Handler(configuration: tlsConfig)
        }
        config.alpn = [alpn]
        config.maxIdleTimeout = .seconds(30)
        config.initialMaxStreamsBidi = 100
        config.initialMaxStreamsUni = 100
        config.initialMaxData = 10_000_000
        config.initialMaxStreamDataBidiLocal = 1_000_000
        config.initialMaxStreamDataBidiRemote = 1_000_000
        config.initialMaxStreamDataUni = 1_000_000
        return config
    }

    /// Starts a real QUIC endpoint and a WebTransport server on top of it.
    /// Returns the bound port and the running pieces for teardown.
    ///
    /// Each accepted session has an echo handler attached: it reads every
    /// incoming bidirectional stream and writes the bytes straight back. This
    /// lets a client prove the session is genuinely usable (not just 200-OK'd).
    static func startServer() async throws -> (
        endpoint: QUICEndpoint,
        runTask: Task<Void, Error>,
        wtServer: WebTransportServer,
        serveTask: Task<Void, Never>,
        acceptTask: Task<Void, Never>,
        port: UInt16
    ) {
        let serverConfig = makeServerConfiguration()
        let (endpoint, runTask) = try await QUICEndpoint.serve(
            host: "127.0.0.1",
            port: 0,
            configuration: serverConfig
        )

        var boundPort: UInt16?
        for _ in 0..<50 {
            if let addr = await endpoint.localAddress, addr.port != 0 {
                boundPort = addr.port
                break
            }
            try await Task.sleep(for: .milliseconds(20))
        }
        guard let port = boundPort else {
            await endpoint.stop()
            runTask.cancel()
            throw WTLoopbackError.serverDidNotBind
        }

        var wtConfig = WebTransportConfiguration(quic: serverConfig, maxSessions: 4)
        wtConfig.maxSessions = 4
        let wtServer = WebTransportServer(configuration: wtConfig)

        // Feed real incoming QUIC connections into the WT server.
        let connectionStream = await endpoint.incomingConnections
        let serveTask = Task<Void, Never> {
            do {
                try await wtServer.serve(connectionSource: connectionStream)
            } catch {
                // Server stopped or errored — teardown path.
            }
        }

        // Accept sessions and attach an echo handler to each.
        let acceptTask = Task<Void, Never> {
            for await session in await wtServer.incomingSessions {
                Task {
                    for await stream in await session.incomingBidirectionalStreams {
                        Task { await echoWTStream(stream) }
                    }
                }
            }
        }

        return (endpoint, runTask, wtServer, serveTask, acceptTask, port)
    }
}

private enum WTLoopbackError: Error, CustomStringConvertible {
    case serverDidNotBind
    case timeout(String)

    var description: String {
        switch self {
        case .serverDidNotBind: return "Server did not bind to a local address"
        case .timeout(let what): return "Timed out: \(what)"
        }
    }
}

/// Echo handler for a WebTransport bidirectional stream: read until FIN,
/// writing each chunk straight back, then close the write side.
private func echoWTStream(_ stream: WebTransportStream) async {
    do {
        while true {
            let chunk = try await stream.read()
            if chunk.isEmpty { break }
            try await stream.write(chunk)
        }
        try await stream.closeWrite()
    } catch {
        // Stream/connection torn down — nothing to do.
    }
}

/// Read all bytes from a WebTransport stream until FIN (empty read) or timeout.
private func readAllWT(
    _ stream: WebTransportStream,
    timeout: Duration
) async throws -> Data {
    return try await withThrowingTaskGroup(of: Data.self) { group in
        group.addTask {
            var result = Data()
            while true {
                let chunk = try await stream.read()
                if chunk.isEmpty { break }
                result.append(chunk)
            }
            return result
        }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw WTLoopbackError.timeout("readAllWT")
        }
        guard let data = try await group.next() else {
            throw WTLoopbackError.timeout("readAllWT (no result)")
        }
        group.cancelAll()
        return data
    }
}

// MARK: - Tests

@Suite("WebTransport Loopback Interop")
struct WebTransportLoopbackInteropTests {

    /// The keystone test: establish a real WebTransport session over real QUIC,
    /// then prove it survives and stays usable. This is the in-suite analogue of
    /// the on-device failure where CONNECT returns 200 and the session aborts
    /// with H3_CLOSED_CRITICAL_STREAM immediately after.
    @Test("WT session survives and round-trips after CONNECT", .timeLimit(.minutes(1)))
    func sessionSurvivesAndRoundTrips() async throws {
        let (endpoint, runTask, wtServer, serveTask, acceptTask, port) =
            try await WTLoopback.startServer()
        defer {
            Task {
                await wtServer.stop()
                await endpoint.stop()
                runTask.cancel()
                serveTask.cancel()
                acceptTask.cancel()
            }
        }

        // Client: dial a real QUIC connection, then establish WebTransport over it.
        let clientConfig = WTLoopback.makeClientConfiguration()
        let clientEndpoint = QUICEndpoint(configuration: clientConfig)
        let address = QUIC.SocketAddress(ipAddress: "127.0.0.1", port: port)
        let quicConnection = try await clientEndpoint.dial(address: address, timeout: .seconds(10))
        defer {
            Task {
                await quicConnection.close(error: nil)
                await clientEndpoint.stop()
            }
        }

        #expect(quicConnection.isEstablished, "QUIC connection should be established after dial()")

        var wtConfig = WebTransportConfiguration(quic: clientConfig, maxSessions: 4)
        wtConfig.maxSessions = 4
        let session = try await WebTransportClient.connect(
            authority: "127.0.0.1:\(port)",
            path: "/wt",
            over: quicConnection,
            configuration: wtConfig
        )

        let established = await session.isEstablished
        #expect(established, "WebTransport session should be established after CONNECT 200")

        // The bug reproduction window: on-device, the connection is torn down
        // (H3_CLOSED_CRITICAL_STREAM) within this beat. Hold, then verify the
        // connection is still alive.
        try await Task.sleep(for: .milliseconds(1500))

        #expect(
            quicConnection.isEstablished,
            "QUIC connection must STILL be established ~1.5s after CONNECT (no critical-stream close)"
        )
        let stillEstablished = await session.isEstablished
        #expect(stillEstablished, "WebTransport session must still be established after the hold")

        // Prove the session is genuinely usable: open a bidi stream and
        // round-trip a payload through the server echo handler.
        let stream = try await session.openBidirectionalStream()
        let payload = Data("ping-after-connect".utf8)
        try await stream.write(payload)
        try await stream.closeWrite()

        let echo = try await readAllWT(stream, timeout: .seconds(10))
        #expect(echo == payload, "Server should echo the payload back over the live WT session")
    }

    /// Tighter variant: round-trip immediately after CONNECT (no hold), to catch
    /// the race where the first client bidi stream arrives in the same flight as
    /// the 200 and gets misrouted/reset.
    @Test("WT bidi round-trip immediately after CONNECT", .timeLimit(.minutes(1)))
    func bidiRoundTripImmediatelyAfterConnect() async throws {
        let (endpoint, runTask, wtServer, serveTask, acceptTask, port) =
            try await WTLoopback.startServer()
        defer {
            Task {
                await wtServer.stop()
                await endpoint.stop()
                runTask.cancel()
                serveTask.cancel()
                acceptTask.cancel()
            }
        }

        let clientConfig = WTLoopback.makeClientConfiguration()
        let clientEndpoint = QUICEndpoint(configuration: clientConfig)
        let address = QUIC.SocketAddress(ipAddress: "127.0.0.1", port: port)
        let quicConnection = try await clientEndpoint.dial(address: address, timeout: .seconds(10))
        defer {
            Task {
                await quicConnection.close(error: nil)
                await clientEndpoint.stop()
            }
        }

        var wtConfig = WebTransportConfiguration(quic: clientConfig, maxSessions: 4)
        wtConfig.maxSessions = 4
        let session = try await WebTransportClient.connect(
            authority: "127.0.0.1:\(port)",
            path: "/wt",
            over: quicConnection,
            configuration: wtConfig
        )

        let established = await session.isEstablished
        #expect(established, "WebTransport session should be established after CONNECT 200")

        let stream = try await session.openBidirectionalStream()
        let payload = Data("immediate".utf8)
        try await stream.write(payload)
        try await stream.closeWrite()

        let echo = try await readAllWT(stream, timeout: .seconds(10))
        #expect(echo == payload, "Server should echo immediately after CONNECT")
    }
}
