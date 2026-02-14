/// Alt-Svc Gateway (RFC 7838 / RFC 9114 Section 3)
///
/// A lightweight NIO-based HTTP/1.1 + HTTP/2 TCP server that runs
/// alongside the HTTP/3 QUIC server. Its sole purpose is to advertise
/// HTTP/3 availability via the `Alt-Svc` response header and redirect
/// plain HTTP traffic to HTTPS.
///
/// ## Ports
///
/// - **HTTP port** (default 80): Returns `301 Moved Permanently` to
///   the HTTPS equivalent URL.
/// - **HTTPS port** (default 443): Terminates TLS (via NIOSSL),
///   negotiates HTTP/2 or HTTP/1.1 via ALPN, and responds with
///   `Alt-Svc: h3=":PORT"; ma=MAX_AGE` plus a minimal HTML body
///   instructing the browser to upgrade.
///
/// ## References
///
/// - [RFC 7838: HTTP Alternative Services](https://www.rfc-editor.org/rfc/rfc7838.html)
/// - [RFC 9114 Section 3: Connection Setup](https://www.rfc-editor.org/rfc/rfc9114.html#section-3)

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Logging
import NIOCore
import NIOPosix
import NIOHTTP1

import NIOSSL
import QUICCore

// MARK: - Configuration

/// Configuration for the Alt-Svc gateway.
public struct AltSvcGatewayConfiguration: Sendable {

    /// Host address to bind both HTTP and HTTPS listeners.
    public var host: String

    /// Plain HTTP port (redirect to HTTPS). `nil` disables the redirect listener.
    public var httpPort: UInt16?

    /// HTTPS port (serves Alt-Svc header). `nil` disables the HTTPS listener.
    public var httpsPort: UInt16?

    /// The HTTP/3 (QUIC) port that Alt-Svc points browsers to.
    public var h3Port: UInt16

    /// `ma=` value in the Alt-Svc header (seconds). Default: 86400 (24h).
    public var altSvcMaxAge: UInt32

    /// Path to the TLS certificate file (PEM).
    public var certificatePath: String?

    /// Path to the TLS private key file (PEM).
    public var privateKeyPath: String?

    public init(
        host: String = "0.0.0.0",
        httpPort: UInt16? = 80,
        httpsPort: UInt16? = 443,
        h3Port: UInt16 = 4433,
        altSvcMaxAge: UInt32 = 86400,
        certificatePath: String? = nil,
        privateKeyPath: String? = nil
    ) {
        self.host = host
        self.httpPort = httpPort
        self.httpsPort = httpsPort
        self.h3Port = h3Port
        self.altSvcMaxAge = altSvcMaxAge
        self.certificatePath = certificatePath
        self.privateKeyPath = privateKeyPath
    }
}

// MARK: - Errors

/// Errors specific to the Alt-Svc gateway.
public enum AltSvcGatewayError: Error, Sendable, CustomStringConvertible {
    /// HTTPS listener requested but no certificate path provided.
    case missingCertificate
    /// HTTPS listener requested but no private key path provided.
    case missingPrivateKey
    /// Failed to create the NIOSSL context.
    case tlsConfigurationFailed(String)
    /// The gateway is already running.
    case alreadyRunning
    /// The gateway failed to bind.
    case bindFailed(String)

    public var description: String {
        switch self {
        case .missingCertificate:
            return "AltSvcGateway: HTTPS enabled but no certificatePath provided"
        case .missingPrivateKey:
            return "AltSvcGateway: HTTPS enabled but no privateKeyPath provided"
        case .tlsConfigurationFailed(let reason):
            return "AltSvcGateway: TLS configuration failed: \(reason)"
        case .alreadyRunning:
            return "AltSvcGateway: gateway is already running"
        case .bindFailed(let reason):
            return "AltSvcGateway: failed to bind: \(reason)"
        }
    }
}

// MARK: - Gateway Actor

/// The Alt-Svc gateway manages plain HTTP redirect and HTTPS Alt-Svc
/// signaling listeners on behalf of the HTTP/3 server.
///
/// Implemented as an actor to provide safe mutable access to the
/// bound channel references without resorting to unsafe annotations.
public actor AltSvcGateway {

    private static let logger = QuiverLogging.logger(label: "http3.altsvc-gateway")

    /// Configuration snapshot (immutable after init).
    private let configuration: AltSvcGatewayConfiguration

    /// NIO event loop group for TCP listeners.
    private let group: MultiThreadedEventLoopGroup

    /// Bound HTTP channel (port 80). Protected by actor isolation.
    private var httpChannel: Channel?

    /// Bound HTTPS channel (port 443). Protected by actor isolation.
    private var httpsChannel: Channel?

    /// Whether the gateway owns the event loop group and should shut it down.
    private let ownsEventLoopGroup: Bool

    public init(
        configuration: AltSvcGatewayConfiguration,
        eventLoopGroup: MultiThreadedEventLoopGroup? = nil
    ) {
        self.configuration = configuration
        if let elg = eventLoopGroup {
            self.group = elg
            self.ownsEventLoopGroup = false
        } else {
            self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
            self.ownsEventLoopGroup = true
        }
    }

    // MARK: - Lifecycle

    /// Starts the gateway listeners.
    ///
    /// - Throws: `AltSvcGatewayError` on misconfiguration or bind failure.
    public func start() async throws {
        guard httpChannel == nil && httpsChannel == nil else {
            throw AltSvcGatewayError.alreadyRunning
        }

        // Start HTTP redirect listener
        if let httpPort = configuration.httpPort {
            let channel = try await bootstrapHTTP(port: httpPort)
            self.httpChannel = channel
            Self.logger.info(
                "Alt-Svc gateway HTTP redirect listening",
                metadata: [
                    "host": "\(configuration.host)",
                    "port": "\(httpPort)",
                ]
            )
        }

        // Start HTTPS Alt-Svc listener
        if let httpsPort = configuration.httpsPort {
            guard configuration.certificatePath != nil else {
                throw AltSvcGatewayError.missingCertificate
            }
            guard configuration.privateKeyPath != nil else {
                throw AltSvcGatewayError.missingPrivateKey
            }
            let channel = try await bootstrapHTTPS(port: httpsPort)
            self.httpsChannel = channel
            Self.logger.info(
                "Alt-Svc gateway HTTPS listening",
                metadata: [
                    "host": "\(configuration.host)",
                    "port": "\(httpsPort)",
                    "h3Port": "\(configuration.h3Port)",
                    "altSvcMaxAge": "\(configuration.altSvcMaxAge)",
                ]
            )
        }
    }

    /// Stops both listeners and shuts down the event loop group.
    public func stop() async {
        do {
            try await httpChannel?.close()
        } catch {
            Self.logger.debug("HTTP channel close: \(error)")
        }
        httpChannel = nil

        do {
            try await httpsChannel?.close()
        } catch {
            Self.logger.debug("HTTPS channel close: \(error)")
        }
        httpsChannel = nil

        if ownsEventLoopGroup {
            try? await group.shutdownGracefully()
        }

        Self.logger.info("Alt-Svc gateway stopped")
    }

    // MARK: - Bootstrap: HTTP (port 80)

    private func bootstrapHTTP(port: UInt16) async throws -> Channel {
        let httpsPort = configuration.httpsPort ?? 443
        let host = configuration.host

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 64)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                // Use syncOperations to avoid Sendable requirements on
                // handler values crossing isolation boundaries. The
                // childChannelInitializer runs on the channel's event
                // loop, so synchronous pipeline mutation is safe.
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.configureHTTPServerPipeline()
                    try channel.pipeline.syncOperations.addHandler(
                        HTTPRedirectHandler(host: host, httpsPort: httpsPort)
                    )
                }
            }

        do {
            return try await bootstrap.bind(host: host, port: Int(port)).get()
        } catch {
            throw AltSvcGatewayError.bindFailed("HTTP \(host):\(port) — \(error)")
        }
    }

    // MARK: - Bootstrap: HTTPS (port 443)

    private func bootstrapHTTPS(port: UInt16) async throws -> Channel {
        let certPath = configuration.certificatePath!
        let keyPath = configuration.privateKeyPath!

        let sslContext: NIOSSLContext
        do {
            let cert = try NIOSSLCertificate.fromPEMFile(certPath)
            let key = try NIOSSLPrivateKey(file: keyPath, format: .pem)

            var tlsConfig = TLSConfiguration.makeServerConfiguration(
                certificateChain: cert.map { .certificate($0) },
                privateKey: .privateKey(key)
            )
            tlsConfig.applicationProtocols = ["http/1.1"]

            sslContext = try NIOSSLContext(configuration: tlsConfig)
        } catch {
            throw AltSvcGatewayError.tlsConfigurationFailed("\(error)")
        }

        let h3Port = configuration.h3Port
        let altSvcMaxAge = configuration.altSvcMaxAge

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 64)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                // Use syncOperations to perform all pipeline mutations
                // synchronously on the event loop. This avoids the
                // NIOSSLHandler Sendable conformance warning (upstream
                // NIOSSL marks it @available(*, unavailable)) by never
                // passing the handler across an isolation boundary.
                channel.eventLoop.makeCompletedFuture {
                    let sslHandler = NIOSSLServerHandler(context: sslContext)
                    try channel.pipeline.syncOperations.addHandler(sslHandler)
                    try channel.pipeline.syncOperations.configureHTTPServerPipeline()
                    try channel.pipeline.syncOperations.addHandler(
                        AltSvcResponseHandler(
                            h3Port: h3Port,
                            altSvcMaxAge: altSvcMaxAge
                        )
                    )
                }
            }

        do {
            return try await bootstrap.bind(host: configuration.host, port: Int(port)).get()
        } catch {
            throw AltSvcGatewayError.bindFailed("HTTPS \(configuration.host):\(port) — \(error)")
        }
    }
}

// MARK: - HTTP Redirect Handler (port 80)

/// Handles every inbound HTTP/1.1 request on the plain HTTP port by
/// responding with `301 Moved Permanently` to the HTTPS equivalent.
///
/// All stored properties are immutable (`let`) and of `Sendable` types
/// (`String`, `UInt16`), making this class genuinely `Sendable` without
/// requiring `@unchecked`.
private final class HTTPRedirectHandler: ChannelInboundHandler, RemovableChannelHandler, Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let host: String
    private let httpsPort: UInt16

    init(host: String, httpsPort: UInt16) {
        self.host = host
        self.httpsPort = httpsPort
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)

        guard case .head(let request) = part else {
            // Ignore .body and .end
            return
        }

        // Build the redirect location
        let requestHost = request.headers["host"].first ?? host
        // Strip port from host if present
        let bareHost = requestHost.split(separator: ":").first.map(String.init) ?? requestHost
        let portSuffix = httpsPort == 443 ? "" : ":\(httpsPort)"
        let location = "https://\(bareHost)\(portSuffix)\(request.uri)"

        var headers = HTTPHeaders()
        headers.add(name: "location", value: location)
        headers.add(name: "content-length", value: "0")
        headers.add(name: "connection", value: "close")

        let head = HTTPResponseHead(
            version: request.version,
            status: .movedPermanently,
            headers: headers
        )

        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        context.close(promise: nil)
    }
}

// MARK: - Alt-Svc Response Handler (port 443)

/// Handles every inbound request on the HTTPS port by responding
/// with the `Alt-Svc` header pointing to the HTTP/3 endpoint.
///
/// The response is a `200 OK` (so the browser processes Alt-Svc)
/// with a minimal HTML body explaining that HTTP/3 is required.
/// Browsers that support H3 will upgrade on the next navigation.
///
/// All stored properties are immutable (`let`) and of `Sendable` types
/// (`UInt16`, `UInt32`, `String`, `Data`), making this class genuinely
/// `Sendable` without requiring `@unchecked`.
private final class AltSvcResponseHandler: ChannelInboundHandler, RemovableChannelHandler, Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let h3Port: UInt16
    private let altSvcMaxAge: UInt32
    private let altSvcHeaderValue: String
    private let responseBody: Data

    init(h3Port: UInt16, altSvcMaxAge: UInt32) {
        self.h3Port = h3Port
        self.altSvcMaxAge = altSvcMaxAge
        self.altSvcHeaderValue = "h3=\":\(h3Port)\"; ma=\(altSvcMaxAge)"
        self.responseBody = Data("""
        <!DOCTYPE html>
        <html>
        <head><title>HTTP/3 Required</title></head>
        <body>
        <h1>HTTP/3 Required</h1>
        <p>This server requires HTTP/3 (QUIC). Your browser should upgrade
        automatically on the next request via the <code>Alt-Svc</code> header.</p>
        <p>If you continue to see this page, your browser may not support HTTP/3
        or the QUIC port <strong>\(h3Port)</strong> may be blocked by your network.</p>
        <p><small>Alt-Svc: \(String(format: "h3=\":%d\"; ma=%d", h3Port, altSvcMaxAge))</small></p>
        </body>
        </html>
        """.utf8)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)

        guard case .head(let request) = part else {
            return
        }

        var headers = HTTPHeaders()
        headers.add(name: "alt-svc", value: altSvcHeaderValue)
        headers.add(name: "content-type", value: "text/html; charset=utf-8")
        headers.add(name: "content-length", value: "\(responseBody.count)")
        headers.add(name: "cache-control", value: "no-cache")
        headers.add(name: "connection", value: "close")

        let head = HTTPResponseHead(
            version: request.version,
            status: .ok,
            headers: headers
        )

        context.write(wrapOutboundOut(.head(head)), promise: nil)

        var buffer = context.channel.allocator.buffer(capacity: responseBody.count)
        buffer.writeBytes(responseBody)
        context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)

        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        context.close(promise: nil)
    }
}
