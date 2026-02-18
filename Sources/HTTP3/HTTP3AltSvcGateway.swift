/// Alt-Svc Gateway (RFC 7838 / RFC 9114 Section 3)
///
/// A lightweight NIO-based HTTP/1.1 + HTTP/2 TCP server that runs
/// alongside the HTTP/3 QUIC server. It advertises HTTP/3 availability
/// via the `Alt-Svc` response header and redirects plain HTTP traffic
/// to HTTPS.
///
/// ## Ports
///
/// - **HTTP port** (default 80): Returns `301 Moved Permanently` to
///   the HTTPS equivalent URL.
/// - **HTTPS port** (default 443): Terminates TLS (via NIOSSL),
///   negotiates HTTP/1.1 via ALPN, and responds with
///   `Alt-Svc: h3=":PORT"; ma=MAX_AGE`. In shared mode it dispatches
///   to the application handler; in lock mode it serves an
///   `HTTP/3 Required` informational page.
///
/// ## References
///
/// - [RFC 7838: HTTP Alternative Services](https://www.rfc-editor.org/rfc/rfc7838.html)
/// - [RFC 9114 Section 3: Connection Setup](https://www.rfc-editor.org/rfc/rfc9114.html#section-3)


import Foundation
import Logging
import NIOCore
import NIOPosix
import NIOHTTP1

import NIOSSL
import QUICCore

// MARK: - Configuration

/// Configuration for the Alt-Svc gateway.
public struct AltSvcGatewayConfiguration: Sendable {

    /// HTTPS gateway behavior.
    public enum HTTPSBehavior: String, Sendable, Hashable {
        /// Serve application resources by dispatching requests to the
        /// same handler used by the HTTP/3 server.
        case serveApplication

        /// Return a static informational page requiring HTTP/3.
        case requireHTTP3
    }

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

    /// Whether HTTPS responses should advertise `Alt-Svc: h3=...`.
    ///
    /// When `false`, the gateway still serves HTTP/1.1 over TLS but does
    /// not emit Alt-Svc headers, preventing new browser-side HTTP/3 discovery
    /// through Alt-Svc caching.
    ///
    /// - Default: `true`
    public var advertiseAltSvc: Bool

    /// Behavior for HTTPS gateway responses.
    public var httpsBehavior: HTTPSBehavior

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
        advertiseAltSvc: Bool = true,
        httpsBehavior: HTTPSBehavior = .serveApplication,
        certificatePath: String? = nil,
        privateKeyPath: String? = nil
    ) {
        self.host = host
        self.httpPort = httpPort
        self.httpsPort = httpsPort
        self.h3Port = h3Port
        self.altSvcMaxAge = altSvcMaxAge
        self.advertiseAltSvc = advertiseAltSvc
        self.httpsBehavior = httpsBehavior
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

    /// HTTPS shared-application mode requested but no request handler was provided.
    case missingRequestHandler

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
        case .missingRequestHandler:
            return "AltSvcGateway: HTTPS behavior serveApplication requires a request handler"
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

    /// Shared application request handler used in HTTPS serve-application mode.
    private let requestHandler: HTTP3Server.RequestHandler?

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
        requestHandler: HTTP3Server.RequestHandler? = nil,
        eventLoopGroup: MultiThreadedEventLoopGroup? = nil
    ) {
        self.configuration = configuration
        self.requestHandler = requestHandler
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
            if configuration.httpsBehavior == .serveApplication && requestHandler == nil {
                throw AltSvcGatewayError.missingRequestHandler
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
                    "httpsBehavior": "\(configuration.httpsBehavior.rawValue)",
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
        let advertiseAltSvc = configuration.advertiseAltSvc
        let httpsBehavior = configuration.httpsBehavior
        let requestHandler = self.requestHandler
        let host = configuration.host

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
                    switch httpsBehavior {
                    case .serveApplication:
                        guard let requestHandler else {
                            throw AltSvcGatewayError.missingRequestHandler
                        }
                        try channel.pipeline.syncOperations.addHandler(
                            AltSvcApplicationProxyHandler(
                                h3Port: h3Port,
                                altSvcMaxAge: altSvcMaxAge,
                                advertiseAltSvc: advertiseAltSvc,
                                fallbackAuthority: host,
                                requestHandler: requestHandler
                            )
                        )
                    case .requireHTTP3:
                        try channel.pipeline.syncOperations.addHandler(
                            AltSvcRequiredResponseHandler(
                                h3Port: h3Port,
                                altSvcMaxAge: altSvcMaxAge,
                                advertiseAltSvc: advertiseAltSvc
                            )
                        )
                    }
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
private final class AltSvcRequiredResponseHandler: ChannelInboundHandler, RemovableChannelHandler, Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let h3Port: UInt16
    private let altSvcMaxAge: UInt32
    private let altSvcHeaderValue: String?
    private let responseBody: Data

    init(h3Port: UInt16, altSvcMaxAge: UInt32, advertiseAltSvc: Bool) {
        self.h3Port = h3Port
        self.altSvcMaxAge = altSvcMaxAge
        self.altSvcHeaderValue = advertiseAltSvc ? "h3=\":\(h3Port)\"; ma=\(altSvcMaxAge)" : nil
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
        if let altSvcHeaderValue {
            headers.add(name: "alt-svc", value: altSvcHeaderValue)
        }
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

// MARK: - Alt-Svc Application Proxy Handler (port 443)

/// Dispatches HTTPS gateway requests into the shared HTTP/3 request
/// handler so HTTP/1.1 can serve the same resources as HTTP/3.
private final class AltSvcApplicationProxyHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let requestHandler: HTTP3Server.RequestHandler
    private let fallbackAuthority: String
    private let altSvcHeaderValue: String?

    private var requestHead: HTTPRequestHead?
    private var bodyContinuation: AsyncStream<Data>.Continuation?
    private var dispatchTask: Task<Void, Never>?

    init(
        h3Port: UInt16,
        altSvcMaxAge: UInt32,
        advertiseAltSvc: Bool,
        fallbackAuthority: String,
        requestHandler: @escaping HTTP3Server.RequestHandler
    ) {
        self.requestHandler = requestHandler
        self.fallbackAuthority = fallbackAuthority
        self.altSvcHeaderValue = advertiseAltSvc ? "h3=\":\(h3Port)\"; ma=\(altSvcMaxAge)" : nil
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)

        switch part {
        case .head(let request):
            guard requestHead == nil else {
                context.close(promise: nil)
                return
            }

            requestHead = request

            guard let method = HTTPMethod(rawValue: request.method.rawValue) else {
                var headers = HTTPHeaders()
                if let altSvcHeaderValue {
                    headers.add(name: "alt-svc", value: altSvcHeaderValue)
                }
                headers.add(name: "content-type", value: "text/plain; charset=utf-8")
                headers.add(name: "content-length", value: "22")
                headers.add(name: "connection", value: "close")

                let head = HTTPResponseHead(
                    version: request.version,
                    status: HTTPResponseStatus(statusCode: 501),
                    headers: headers
                )

                context.write(wrapOutboundOut(.head(head)), promise: nil)
                var buffer = ByteBufferAllocator().buffer(capacity: 22)
                buffer.writeString("Method Not Implemented")
                context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
                context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
                context.close(promise: nil)
                return
            }

            var bodyContinuation: AsyncStream<Data>.Continuation?
            let bodyStream = AsyncStream<Data> { continuation in
                bodyContinuation = continuation
            }
            self.bodyContinuation = bodyContinuation

            let responder = HTTP1GatewayResponder(
                context: context,
                requestVersion: request.version,
                altSvcHeaderValue: altSvcHeaderValue
            )

            let http3Request = Self.buildRequest(
                from: request,
                mappedMethod: method,
                fallbackAuthority: fallbackAuthority
            )

            let requestContext = HTTP3RequestContext(
                request: http3Request,
                streamID: 0,
                bodyStream: bodyStream,
                respond: { status, headers, body, trailers in
                    try await responder.sendBuffered(
                        status: status,
                        headers: headers,
                        body: body,
                        trailers: trailers
                    )
                },
                respondStreaming: { status, headers, trailers, writer in
                    try await responder.startStreaming(
                        status: status,
                        headers: headers,
                        trailers: trailers
                    )

                    let bodyWriter = HTTP3BodyWriter(_write: { data in
                        try await responder.sendStreamingChunk(data)
                    })

                    try await writer(bodyWriter)
                    try await responder.finishStreaming()
                }
            )

            let requestHandler = self.requestHandler
            dispatchTask = Task {
                do {
                    try await requestHandler(requestContext)
                } catch {
                    await responder.sendInternalServerErrorIfNeeded()
                }
            }

        case .body(var buffer):
            if let bytes = buffer.readBytes(length: buffer.readableBytes), !bytes.isEmpty {
                bodyContinuation?.yield(Data(bytes))
            }

        case .end:
            bodyContinuation?.finish()
            bodyContinuation = nil
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        bodyContinuation?.finish()
        bodyContinuation = nil
        dispatchTask?.cancel()
        dispatchTask = nil
        requestHead = nil
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        bodyContinuation?.finish()
        bodyContinuation = nil
        dispatchTask?.cancel()
        dispatchTask = nil
        requestHead = nil
        context.close(promise: nil)
    }

    private static func buildRequest(
        from request: HTTPRequestHead,
        mappedMethod: HTTPMethod,
        fallbackAuthority: String
    ) -> HTTP3Request {
        let authority = (request.headers.first(name: "host")?.isEmpty == false)
            ? request.headers.first(name: "host")!
            : fallbackAuthority

        let path = request.uri.isEmpty ? "/" : request.uri

        var headers: [(String, String)] = []
        headers.reserveCapacity(request.headers.count)
        for header in request.headers {
            let name = header.name.lowercased()
            if name == "host" || name == "connection" || name == "keep-alive"
                || name == "proxy-connection" || name == "transfer-encoding" || name == "upgrade"
            {
                continue
            }
            headers.append((name, header.value))
        }

        if !headers.contains(where: { $0.0 == "x-forwarded-proto" }) {
            headers.append(("x-forwarded-proto", "https"))
        }
        if !headers.contains(where: { $0.0 == "x-forwarded-host" }) {
            headers.append(("x-forwarded-host", authority))
        }
        headers.append(("x-quiver-gateway", "altsvc"))

        return HTTP3Request(
            method: mappedMethod,
            scheme: "https",
            authority: authority,
            path: path,
            headers: headers,
            body: nil
        )
    }
}

// MARK: - HTTP/1.1 Response Bridge

private final class HTTP1GatewayResponder: @unchecked Sendable {
    private let context: ChannelHandlerContext
    private let requestVersion: HTTPVersion
    private let altSvcHeaderValue: String?
    private let lock = NSLock()

    private var hasSentHead = false
    private var hasFinished = false

    init(
        context: ChannelHandlerContext,
        requestVersion: HTTPVersion,
        altSvcHeaderValue: String?
    ) {
        self.context = context
        self.requestVersion = requestVersion
        self.altSvcHeaderValue = altSvcHeaderValue
    }

    func sendBuffered(
        status: Int,
        headers: [(String, String)],
        body: Data,
        trailers: [(String, String)]?
    ) async throws {
        guard withLock({ !hasFinished }) else { return }

        let responseHeaders = makeHeaders(
            from: headers,
            contentLength: body.count,
            trailers: trailers,
            streaming: false
        )
        let responseHead = HTTPResponseHead(
            version: requestVersion,
            status: HTTPResponseStatus(statusCode: status),
            headers: responseHeaders
        )

        try await writeOnEventLoop(.head(responseHead), flush: false)

        if !body.isEmpty {
            try await writeBodyOnEventLoop(body, flush: false)
        }

        try await writeOnEventLoop(.end(nil), flush: true)
        withLock {
            hasSentHead = true
            hasFinished = true
        }
        _ = try? await context.eventLoop.submit { self.context.close(promise: nil) }.get()
    }

    func startStreaming(
        status: Int,
        headers: [(String, String)],
        trailers: [(String, String)]?
    ) async throws {
        guard withLock({ !hasSentHead }) else { return }

        let responseHeaders = makeHeaders(
            from: headers,
            contentLength: nil,
            trailers: trailers,
            streaming: true
        )
        let responseHead = HTTPResponseHead(
            version: requestVersion,
            status: HTTPResponseStatus(statusCode: status),
            headers: responseHeaders
        )

        try await writeOnEventLoop(.head(responseHead), flush: true)
        withLock { hasSentHead = true }
    }

    func sendStreamingChunk(_ data: Data) async throws {
        guard withLock({ hasSentHead && !hasFinished }) else { return }
        guard !data.isEmpty else { return }

        try await writeBodyOnEventLoop(data, flush: true)
    }

    func finishStreaming() async throws {
        guard withLock({ !hasFinished }) else { return }
        if withLock({ !hasSentHead }) {
            try await startStreaming(status: 200, headers: [], trailers: nil)
        }
        try await writeOnEventLoop(.end(nil), flush: true)
        withLock { hasFinished = true }
        _ = try? await context.eventLoop.submit { self.context.close(promise: nil) }.get()
    }

    func sendInternalServerErrorIfNeeded() async {
        guard withLock({ !hasFinished }) else { return }
        try? await sendBuffered(
            status: 500,
            headers: [("content-type", "text/plain; charset=utf-8")],
            body: Data("Internal Server Error".utf8),
            trailers: nil
        )
    }

    private func makeHeaders(
        from headers: [(String, String)],
        contentLength: Int?,
        trailers: [(String, String)]?,
        streaming: Bool
    ) -> HTTPHeaders {
        var httpHeaders = HTTPHeaders()

        for (name, value) in headers {
            httpHeaders.add(name: name, value: value)
        }

        if let altSvcHeaderValue, httpHeaders.first(name: "alt-svc") == nil {
            httpHeaders.add(name: "alt-svc", value: altSvcHeaderValue)
        }

        if let contentLength {
            if httpHeaders.first(name: "content-length") == nil {
                httpHeaders.add(name: "content-length", value: "\(contentLength)")
            }
        } else if streaming {
            if httpHeaders.first(name: "transfer-encoding") == nil {
                httpHeaders.add(name: "transfer-encoding", value: "chunked")
            }
        }

        if let trailers, !trailers.isEmpty {
            let trailerNames = trailers.map { $0.0.lowercased() }.joined(separator: ", ")
            if !trailerNames.isEmpty {
                httpHeaders.add(name: "trailer", value: trailerNames)
            }
        }

        httpHeaders.replaceOrAdd(name: "connection", value: "close")
        return httpHeaders
    }

    private func writeOnEventLoop(_ part: HTTPServerResponsePart, flush: Bool) async throws {
        if flush {
            try await context.eventLoop.submit {
                self.context.writeAndFlush(NIOAny(part), promise: nil)
            }.get()
        } else {
            try await context.eventLoop.submit {
                self.context.write(NIOAny(part), promise: nil)
            }.get()
        }
    }

    private func writeBodyOnEventLoop(_ body: Data, flush: Bool) async throws {
        if flush {
            try await context.eventLoop.submit {
                var buffer = ByteBufferAllocator().buffer(capacity: body.count)
                buffer.writeBytes(body)
                self.context.writeAndFlush(NIOAny(HTTPServerResponsePart.body(.byteBuffer(buffer))), promise: nil)
            }.get()
        } else {
            try await context.eventLoop.submit {
                var buffer = ByteBufferAllocator().buffer(capacity: body.count)
                buffer.writeBytes(body)
                self.context.write(NIOAny(HTTPServerResponsePart.body(.byteBuffer(buffer))), promise: nil)
            }.get()
        }
    }

    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}
