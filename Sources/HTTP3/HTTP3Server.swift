/// HTTP/3 Server (RFC 9114)
///
/// A server that listens for incoming QUIC connections and handles
/// HTTP/3 requests. The server manages multiple concurrent HTTP/3
/// connections and dispatches incoming requests to a user-provided
/// request handler.
///
/// ## Architecture
///
/// The server operates in layers:
/// 1. **QUIC Listener** — Accepts incoming QUIC connections
/// 2. **HTTP/3 Connection** — Manages HTTP/3 state per QUIC connection
/// 3. **Request Handler** — User-provided closure for processing requests
///
/// ## Usage
///
/// ```swift
/// let server = HTTP3Server(settings: HTTP3Settings())
///
/// // Register a request handler
/// server.onRequest { context in
///     let response = HTTP3Response(
///         status: 200,
///         headers: [("content-type", "text/plain")],
///         body: Data("Hello, HTTP/3!".utf8)
///     )
///     try await context.respond(response)
/// }
///
/// // Start listening
/// try await server.listen(
///     quicConnection: quicListener,
///     address: SocketAddress(ipAddress: "0.0.0.0", port: 443)
/// )
///
/// // Later, stop the server
/// await server.stop()
/// ```
///
/// ## Thread Safety
///
/// `HTTP3Server` is an `actor`, ensuring all mutable state is
/// accessed serially. Incoming connections and requests are handled
/// concurrently via structured `Task`s.

import Foundation
import Logging
import QPACK
import QUIC
import QUICCore
import QUICCrypto

// MARK: - HTTP/3 Server

/// HTTP/3 server for handling incoming requests over QUIC
///
/// Accepts QUIC connections, establishes HTTP/3 sessions, and
/// dispatches incoming requests to a registered handler.
///
/// ## Extended CONNECT / WebTransport Support (RFC 9220)
///
/// The server can handle Extended CONNECT requests separately from
/// regular HTTP requests. Register a handler via `onExtendedConnect()`
/// to receive WebTransport (or other tunneled protocol) session requests.
///
/// ```swift
/// let server = HTTP3Server(settings: .webTransport())
///
/// server.onRequest { context in
///     try await context.respond(status: 200, Data("Hello".utf8))
/// }
///
/// server.onExtendedConnect { context in
///     if context.request.isWebTransportConnect {
///         try await context.accept()
///         // context.stream is now open for WebTransport session use
///     } else {
///         try await context.reject(status: 501)
///     }
/// }
///
/// try await server.serve(connectionSource: listener.incomingConnections)
/// ```
/// Options for enabling WebTransport on an `HTTP3Server`.
///
/// Pass an instance to `HTTP3Server.enableWebTransport(_:)` to configure
/// how WebTransport sessions are accepted.
///
/// - Note: Named `HTTP3WebTransportOptions` to avoid collision with the
///   client-facing `WebTransportOptions` in the WebTransport module.
///
/// ## Usage
///
/// ```swift
/// let server = HTTP3Server()
/// let sessions = await server.enableWebTransport(
///     HTTP3WebTransportOptions(maxSessionsPerConnection: 4)
/// )
/// ```
public struct HTTP3WebTransportOptions: Sendable {
    /// Maximum number of concurrent WebTransport sessions per HTTP/3 connection.
    ///
    /// This value is advertised via `SETTINGS_WEBTRANSPORT_MAX_SESSIONS`.
    /// Browsers require this to be > 0 to establish WebTransport connections.
    ///
    /// - Default: 1
    public var maxSessionsPerConnection: UInt64

    /// Allowed WebTransport request paths.
    ///
    /// If non-empty, only Extended CONNECT requests whose `:path`
    /// matches one of these values will be accepted. All others are
    /// rejected with 404.
    ///
    /// If empty (default), all paths are accepted.
    public var allowedPaths: [String]

    /// Creates WebTransport options.
    ///
    /// - Parameters:
    ///   - maxSessionsPerConnection: Max concurrent WT sessions per connection (default: 1)
    ///   - allowedPaths: Paths to accept, empty = all (default: [])
    public init(
        maxSessionsPerConnection: UInt64 = 1,
        allowedPaths: [String] = []
    ) {
        self.maxSessionsPerConnection = maxSessionsPerConnection
        self.allowedPaths = allowedPaths
    }
}

public actor HTTP3Server {
    private static let logger = QuiverLogging.logger(label: "http3.server")

    // MARK: - Types

    /// Request handler closure type
    ///
    /// Called for each incoming HTTP/3 request. The handler receives
    /// an `HTTP3RequestContext` that includes the request and a method
    /// to send back a response.
    public typealias RequestHandler = @Sendable (HTTP3RequestContext) async throws -> Void

    /// Optional request-session resolver closure type.
    ///
    /// Called before each request handler invocation to produce
    /// an immutable `HTTP3Session` snapshot attached to the context.
    public typealias RequestSessionResolver = @Sendable (HTTP3RequestContext) async -> HTTP3Session

    /// Extended CONNECT handler closure type (RFC 9220)
    ///
    /// Called for each incoming Extended CONNECT request. The handler
    /// receives an `ExtendedConnectContext` that allows accepting or
    /// rejecting the request. When accepted, the CONNECT stream remains
    /// open for session use (e.g., WebTransport).
    public typealias ExtendedConnectHandler =
        @Sendable (ExtendedConnectContext) async throws -> Void

    /// Optional Extended CONNECT session resolver closure type.
    ///
    /// Called before each Extended CONNECT handler invocation to produce
    /// an immutable `HTTP3Session` snapshot attached to the context.
    public typealias ExtendedConnectSessionResolver =
        @Sendable (ExtendedConnectContext) async -> HTTP3Session

    /// Server state
    public enum State: Sendable, Hashable, CustomStringConvertible {
        /// Server created but not listening
        case idle

        /// Server is listening for connections
        case listening

        /// Server is shutting down (draining connections)
        case stopping

        /// Server has stopped
        case stopped

        public var description: String {
            switch self {
            case .idle: return "idle"
            case .listening: return "listening"
            case .stopping: return "stopping"
            case .stopped: return "stopped"
            }
        }
    }

    // MARK: - Properties

    /// Local HTTP/3 settings to use for all connections.
    ///
    /// This property may be mutated by `enableWebTransport(_:)` to merge
    /// the WebTransport-required settings before the server starts.
    public private(set) var settings: HTTP3Settings

    /// Current server state
    public private(set) var state: State = .idle

    /// The registered request handler
    private var handler: RequestHandler?

    /// The registered Extended CONNECT handler (RFC 9220)
    private var extendedConnectHandler: ExtendedConnectHandler?

    /// Optional resolver for filling request session snapshots.
    private var requestSessionResolver: RequestSessionResolver?

    /// Optional resolver for filling Extended CONNECT session snapshots.
    private var extendedConnectSessionResolver: ExtendedConnectSessionResolver?

    /// Active HTTP/3 connections managed by this server
    private var connections: [ObjectIdentifier: HTTP3Connection] = [:]

    /// Counter for tracking total connections accepted
    private var totalConnectionsAccepted: UInt64 = 0

    /// Counter for tracking total requests handled
    private var totalRequestsHandled: UInt64 = 0

    /// Maximum concurrent connections (0 = unlimited)
    private let maxConnections: Int

    /// Task for the listener loop
    private var listenerTask: Task<Void, Never>?

    /// The QUIC endpoint created by `listen(host:port:quicConfiguration:)`.
    ///
    /// Stored so that `stop()` can shut it down.
    private var quicEndpoint: QUICEndpoint?

    /// The I/O loop task created by `listen(host:port:quicConfiguration:)`.
    ///
    /// Stored so that `stop()` can cancel it.
    private var quicRunTask: Task<Void, Error>?

    /// Server options for the simple `init(options:)` + `listen()` path.
    ///
    /// `nil` when the server is created with the advanced
    /// `init(_:maxConnections:)` initializer.
    private let serverOptions: HTTP3ServerOptions?

    /// Alt-Svc gateway (HTTP/1.1 + HTTP/2 over TCP) that advertises
    /// HTTP/3 via the `Alt-Svc` header. Created by `listenAll()`.
    /// Protected by `HTTP3Server` actor isolation.
    private var gateway: AltSvcGateway?

    // MARK: - Initialization

    /// Creates an HTTP/3 server with options.
    ///
    /// This is the recommended initializer for most use cases. It
    /// encapsulates certificate material, TLS policy, transport
    /// parameters, and HTTP/3 settings in a single options struct.
    /// Call `listen()` (no arguments) to start the server.
    ///
    /// - Parameter options: Server options (certificates, TLS, transport, HTTP/3)
    ///
    /// ## Example
    ///
    /// ```swift
    /// let options = HTTP3ServerOptions(
    ///     certificatePath: "/path/to/cert.pem",
    ///     privateKeyPath: "/path/to/key.pem"
    /// )
    /// let server = HTTP3Server(options: options)
    ///
    /// await server.onRequest { context in
    ///     try await context.respond(status: 200, Data("Hello!".utf8))
    /// }
    ///
    /// try await server.listen()
    /// ```
    public init(options: HTTP3ServerOptions) {
        self.serverOptions = options
        self.settings = options.buildHTTP3Settings()
        self.maxConnections = options.maxConnections
    }

    /// Creates an HTTP/3 server (advanced).
    ///
    /// Use this initializer when you need full control over
    /// `QUICConfiguration` and `TLSConfiguration`. You must pass
    /// a fully configured `QUICConfiguration` to
    /// `listen(host:port:quicConfiguration:)`.
    ///
    /// - Parameters:
    ///   - settings: HTTP/3 settings for all connections (default: literal-only QPACK)
    ///   - maxConnections: Maximum concurrent connections, 0 for unlimited (default: 0)
    public init(
        settings: HTTP3Settings = HTTP3Settings(),
        maxConnections: Int = 0
    ) {
        self.serverOptions = nil
        self.settings = settings
        self.maxConnections = maxConnections
    }

    // MARK: - Configuration

    /// Registers a request handler.
    ///
    /// The handler is called for each incoming HTTP/3 request across
    /// all connections. Only one handler can be registered at a time;
    /// calling this again replaces the previous handler.
    ///
    /// - Parameter handler: The closure to handle incoming requests
    ///
    /// ## Example
    ///
    /// ```swift
    /// server.onRequest { context in
    ///     switch context.request.path {
    ///     case "/":
    ///         try await context.respond(
    ///             status: 200,
    ///             headers: [("content-type", "text/html")],
    ///             body: Data("<h1>Home</h1>".utf8)
    ///         )
    ///     case "/api/health":
    ///         try await context.respond(
    ///             status: 200,
    ///             headers: [("content-type", "application/json")],
    ///             body: Data("{\"status\":\"ok\"}".utf8)
    ///         )
    ///     default:
    ///         try await context.respond(status: 404)
    ///     }
    /// }
    /// ```
    public func onRequest(_ handler: @escaping RequestHandler) {
        self.handler = handler
    }

    /// Registers a request-session resolver.
    ///
    /// If registered, the resolver is called before each request handler.
    /// The returned session snapshot is attached to `context.session`.
    /// Calling this again replaces the previous resolver.
    ///
    /// - Parameter resolver: Closure that returns a session snapshot for each request
    public func onRequestSession(_ resolver: @escaping RequestSessionResolver) {
        self.requestSessionResolver = resolver
    }

    /// Registers an Extended CONNECT handler (RFC 9220).
    ///
    /// The handler is called for each incoming Extended CONNECT request
    /// (requests with a `:protocol` pseudo-header). This includes
    /// WebTransport session establishment requests.
    ///
    /// If no Extended CONNECT handler is registered, Extended CONNECT
    /// requests receive a `501 Not Implemented` response automatically.
    ///
    /// - Parameter handler: The closure to handle incoming Extended CONNECT requests
    ///
    /// ## Example
    ///
    /// ```swift
    /// server.onExtendedConnect { context in
    ///     guard context.request.isWebTransportConnect else {
    ///         try await context.reject(status: 501)
    ///         return
    ///     }
    ///     try await context.accept()
    ///     // Use context.stream for WebTransport session
    /// }
    /// ```
    public func onExtendedConnect(_ handler: @escaping ExtendedConnectHandler) {
        self.extendedConnectHandler = handler
    }

    /// Registers an Extended CONNECT session resolver.
    ///
    /// If registered, the resolver is called before each Extended CONNECT
    /// handler. The returned session snapshot is attached to `context.session`.
    /// Calling this again replaces the previous resolver.
    ///
    /// - Parameter resolver: Closure that returns a session snapshot for each CONNECT request
    public func onExtendedConnectSession(_ resolver: @escaping ExtendedConnectSessionResolver) {
        self.extendedConnectSessionResolver = resolver
    }

    // MARK: - Server Lifecycle

    /// Starts accepting HTTP/3 connections from a QUIC connection source.
    ///
    /// This method accepts incoming QUIC connections from the provided
    /// async stream and initializes HTTP/3 sessions for each one.
    /// It runs until `stop()` is called or the connection source ends.
    ///
    /// - Parameter connectionSource: An async stream of incoming QUIC connections
    /// - Throws: `HTTP3Error` if the server cannot start
    ///
    /// ## Example
    ///
    /// ```swift
    /// // Using with a QUIC listener's incoming connections
    /// try await server.serve(connectionSource: listener.incomingConnections)
    /// ```
    public func serve(
        connectionSource: AsyncStream<any QUICConnectionProtocol>
    ) async throws {
        guard state == .idle else {
            throw HTTP3Error(
                code: .internalError,
                reason: "Server already started (state: \(state))"
            )
        }

        guard handler != nil else {
            throw HTTP3Error(
                code: .internalError,
                reason: "No request handler registered. Call onRequest() first."
            )
        }

        state = .listening

        for await quicConnection in connectionSource {
            if state == .stopping || state == .stopped {
                break
            }

            if maxConnections > 0 && connections.count >= maxConnections {
                await quicConnection.close(
                    applicationError: HTTP3ErrorCode.excessiveLoad.rawValue,
                    reason: "Server connection limit reached"
                )
                continue
            }

            totalConnectionsAccepted += 1

            Task { [weak self] in
                await self?.handleConnection(quicConnection)
            }
        }
        if state == .listening {
            state = .stopped
        }
    }

    /// Starts accepting connections using a single QUIC connection.
    ///
    /// This is a convenience method for testing or single-connection
    /// scenarios where you already have a QUIC connection established.
    ///
    /// - Parameter quicConnection: The QUIC connection to serve HTTP/3 on
    /// - Throws: `HTTP3Error` if initialization fails
    public func serveConnection(_ quicConnection: any QUICConnectionProtocol) async throws {
        guard handler != nil else {
            throw HTTP3Error(
                code: .internalError,
                reason: "No request handler registered. Call onRequest() first."
            )
        }

        state = .listening
        await handleConnection(quicConnection)
    }

    /// Stops the server gracefully.
    ///
    /// Sends GOAWAY to all active connections and waits for them
    /// to drain before closing. If the server was started via
    /// `listen(host:port:quicConfiguration:)`, the underlying QUIC
    /// endpoint and I/O loop are also shut down.
    ///
    /// - Parameter gracePeriod: Maximum time to wait for connections to drain
    ///   (default: 5 seconds)
    public func stop(gracePeriod: Duration = .seconds(5)) async {
        guard state == .listening else { return }

        state = .stopping

        // Stop the Alt-Svc gateway first (TCP listeners)
        if let gw = gateway {
            await gw.stop()
            gateway = nil
            Self.logger.info("Alt-Svc gateway shut down")
        }

        // Cancel the listener task if running
        listenerTask?.cancel()
        listenerTask = nil

        // Send GOAWAY to all active connections
        for (_, connection) in connections {
            await connection.close(error: .noError)
        }

        // Wait briefly for connections to drain
        let deadline = ContinuousClock.now + gracePeriod
        while !connections.isEmpty && ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(100))
        }

        // Force-close any remaining connections
        for (_, connection) in connections {
            await connection.close(error: .noError)
        }

        connections.removeAll()

        // Tear down the QUIC endpoint if we own it (created by listen())
        if let endpoint = quicEndpoint {
            await endpoint.stop()
            quicEndpoint = nil
        }
        quicRunTask?.cancel()
        quicRunTask = nil

        state = .stopped
    }

    // MARK: - Connection Handling

    /// Handles a single QUIC connection's HTTP/3 lifecycle.
    ///
    /// Creates an HTTP/3 connection, initializes it (control streams,
    /// SETTINGS exchange), and processes incoming requests.
    ///
    /// - Parameter quicConnection: The QUIC connection to handle
    private func handleConnection(_ quicConnection: any QUICConnectionProtocol) async {
        let h3Connection = HTTP3Connection(
            quicConnection: quicConnection,
            role: .server,
            settings: settings
        )

        // Track the connection
        let connectionID = ObjectIdentifier(quicConnection as AnyObject)
        connections[connectionID] = h3Connection

        defer {
            // Clean up when the connection ends
            Task { [weak self] in
                await self?.removeConnection(connectionID)
            }
        }

        do {
            // Initialize HTTP/3 (open control + QPACK streams, send SETTINGS)
            try await h3Connection.initialize()

            // Start Extended CONNECT handler loop in a separate task
            let extConnectTask = Task { [weak self] in
                await self?.handleExtendedConnectStream(h3Connection)
            }

            defer { extConnectTask.cancel() }

            // Process incoming regular requests
            for await context in await h3Connection.incomingRequests {
                // Check server state
                if state == .stopping || state == .stopped {
                    break
                }

                totalRequestsHandled += 1

                // Dispatch to handler in a separate task for concurrency
                if let handler = self.handler {
                    let resolvedContext: HTTP3RequestContext
                    if let requestSessionResolver = self.requestSessionResolver {
                        resolvedContext = context.withSession(await requestSessionResolver(context))
                    } else {
                        resolvedContext = context
                    }

                    let capturedHandler = handler
                    Task {
                        do {
                            try await capturedHandler(resolvedContext)
                        } catch {
                            // Handler threw an error — send 500 if possible
                            try? await resolvedContext.respond(
                                status: 500,
                                headers: [("content-type", "text/plain")],
                                Data("Internal Server Error".utf8)
                            )
                        }
                    }
                }
            }
        } catch {
            // Connection initialization or processing failed
            // Log the actual error so operators can diagnose the root cause
            // (e.g. streamLimitReached if QUIC handshake wasn't complete)
            Self.logger.warning("Connection error for \(quicConnection.remoteAddress): \(error)")
            // Close the connection with an appropriate error
            await h3Connection.close(error: .internalError)
        }
    }

    /// Handles the incoming Extended CONNECT stream for a connection.
    ///
    /// Consumes `incomingExtendedConnect` from the HTTP/3 connection
    /// and dispatches each request to the registered Extended CONNECT handler.
    /// If no handler is registered, Extended CONNECT requests are automatically
    /// rejected with 501 Not Implemented.
    private func handleExtendedConnectStream(_ h3Connection: HTTP3Connection) async {
        for await context in await h3Connection.incomingExtendedConnect {
            // Check server state
            if state == .stopping || state == .stopped {
                break
            }

            totalRequestsHandled += 1

            if let extHandler = self.extendedConnectHandler {
                let resolvedContext: ExtendedConnectContext
                if let extendedConnectSessionResolver = self.extendedConnectSessionResolver {
                    resolvedContext = context.withSession(await extendedConnectSessionResolver(context))
                } else {
                    resolvedContext = context
                }

                let capturedHandler = extHandler
                Task {
                    do {
                        try await capturedHandler(resolvedContext)
                    } catch {
                        // Handler threw an error — reject with 500 if possible
                        try? await resolvedContext.reject(
                            status: 500,
                            headers: [("content-type", "text/plain")],
                            // body: Data("Internal Server Error".utf8)
                        )
                    }
                }
            } else {
                // No Extended CONNECT handler registered — reject with 501
                Task {
                    try? await context.reject(
                        status: 501,
                        headers: [("content-type", "text/plain")],
                        // body: Data("Extended CONNECT not supported".utf8)
                    )
                }
            }
        }
    }

    /// Removes a connection from the active connections set.
    ///
    /// - Parameter id: The connection's object identifier
    private func removeConnection(_ id: ObjectIdentifier) {
        connections.removeValue(forKey: id)
    }

    // MARK: - Server Info

    /// The number of currently active connections
    public var activeConnectionCount: Int {
        connections.count
    }

    /// Total number of connections accepted since the server started
    public var totalConnections: UInt64 {
        totalConnectionsAccepted
    }

    /// Total number of requests handled since the server started
    public var totalRequests: UInt64 {
        totalRequestsHandled
    }

    /// Whether the server is currently listening
    public var isListening: Bool {
        state == .listening
    }

    /// Whether the server has been stopped
    public var isStopped: Bool {
        state == .stopped
    }

    /// A summary of the server's current state
    /// Whether an Extended CONNECT handler has been registered
    public var hasExtendedConnectHandler: Bool {
        extendedConnectHandler != nil
    }

    public var debugDescription: String {
        var parts = [String]()
        parts.append("state=\(state)")
        parts.append("connections=\(connections.count)")
        parts.append("totalAccepted=\(totalConnectionsAccepted)")
        parts.append("totalRequests=\(totalRequestsHandled)")
        parts.append("settings=\(settings)")
        if extendedConnectHandler != nil {
            parts.append("extendedConnect=enabled")
        }
        return "HTTP3Server(\(parts.joined(separator: ", ")))"
    }

    // MARK: - Convenience: listen

    /// Starts the server on the specified host and port.
    ///
    /// This is a convenience method that creates the full QUIC stack
    /// internally (UDP socket → QUIC endpoint → connection stream) and
    /// feeds incoming connections to the HTTP/3 server.
    ///
    /// The method blocks until `stop()` is called or the connection
    /// Starts the HTTP/3 server using the stored `HTTP3ServerOptions`.
    ///
    /// Validates the options, builds `TLSConfiguration` and
    /// `QUICConfiguration` internally, then binds and listens.
    /// Blocks until `stop()` is called.
    ///
    /// Only usable when the server was created with `init(options:)`.
    ///
    /// - Throws: `HTTP3ServerOptions.ValidationError` if options are invalid,
    ///   or any TLS/QUIC/socket error if the server cannot start
    ///
    /// ## Usage
    ///
    /// ```swift
    /// let server = HTTP3Server(options: HTTP3ServerOptions(
    ///     certificatePath: "cert.pem",
    ///     privateKeyPath: "key.pem"
    /// ))
    ///
    /// await server.onRequest { context in
    ///     try await context.respond(status: 200, Data("OK".utf8))
    /// }
    ///
    /// try await server.listen()
    /// ```
    public func listen() async throws {
        guard let options = serverOptions else {
            throw HTTP3Error(
                code: .internalError,
                reason: "listen() requires HTTP3ServerOptions. "
                    + "Use init(options:) or call listen(host:port:quicConfiguration:) instead."
            )
        }

        try options.validate()

        let tlsConfig = try options.buildTLSConfiguration()
        let quicConfig = options.buildQUICConfiguration(tlsConfiguration: tlsConfig)

        try await listen(
            host: options.host,
            port: options.port,
            quicConfiguration: quicConfig
        )
    }

    /// Starts both the Alt-Svc gateway (TCP) and the HTTP/3 server (QUIC).
    ///
    /// 1. Validates options.
    /// 2. If `gatewayHTTPPort` or `gatewayHTTPSPort` is set, starts the
    ///    `AltSvcGateway` on those TCP ports.
    /// 3. Starts the QUIC HTTP/3 server via `listen()`.
    ///
    /// The gateway advertises `Alt-Svc: h3=":PORT"` on the HTTPS
    /// listener so browsers discover HTTP/3 automatically.
    ///
    /// Only usable when the server was created with `init(options:)`.
    ///
    /// - Throws: `HTTP3ServerOptions.ValidationError`, `AltSvcGatewayError`,
    ///   or any TLS/QUIC/socket error
    ///
    /// ## Usage
    ///
    /// ```swift
    /// let options = HTTP3ServerOptions(
    ///     certificatePath: "cert.pem",
    ///     privateKeyPath: "key.pem",
    ///     gatewayHTTPPort: 80,
    ///     gatewayHTTPSPort: 443
    /// )
    /// let server = HTTP3Server(options: options)
    ///
    /// await server.onRequest { context in
    ///     try await context.respond(status: 200, Data("OK".utf8))
    /// }
    ///
    /// try await server.listenAll()
    /// ```
    public func listenAll() async throws {
        guard let options = serverOptions else {
            throw HTTP3Error(
                code: .internalError,
                reason: "listenAll() requires HTTP3ServerOptions. "
                    + "Use init(options:) or call listen(host:port:quicConfiguration:) instead."
            )
        }

        try options.validate()

        // Start the Alt-Svc gateway if configured
        if let gatewayConfig = options.buildGatewayConfiguration() {
            let currentHandler = self.handler
            let currentRequestSessionResolver = self.requestSessionResolver
            if gatewayConfig.httpsBehavior == .serveApplication, currentHandler == nil {
                throw HTTP3Error(
                    code: .internalError,
                    reason: "listenAll() in serveApplication mode requires a request handler. "
                        + "Call onRequest() before listenAll()."
                )
            }

            let gatewayRequestHandler: RequestHandler?
            if let currentHandler {
                gatewayRequestHandler = { context in
                    if let currentRequestSessionResolver {
                        let resolvedContext = context.withSession(await currentRequestSessionResolver(context))
                        try await currentHandler(resolvedContext)
                    } else {
                        try await currentHandler(context)
                    }
                }
            } else {
                gatewayRequestHandler = nil
            }

            let gw = AltSvcGateway(
                configuration: gatewayConfig,
                requestHandler: gatewayRequestHandler
            )
            try await gw.start()
            self.gateway = gw
            Self.logger.info(
                "Proxy Gateway started",
                metadata: [
                    "httpPort": "\(gatewayConfig.httpPort.map(String.init) ?? "disabled")",
                    "httpsPort": "\(gatewayConfig.httpsPort.map(String.init) ?? "disabled")",
                    "h3Port": "\(gatewayConfig.h3Port)",
                    "httpsBehavior": "\(gatewayConfig.httpsBehavior.rawValue)",
                ]
            )
        }

        // Start the QUIC HTTP/3 server (blocks until stop())
        do {
            try await listen()
        } catch {
            // Tear down gateway on QUIC startup failure
            if let gw = gateway {
                await gw.stop()
                gateway = nil
            }
            throw error
        }
    }

    /// Starts the HTTP/3 server (advanced).
    ///
    /// Binds a QUIC endpoint and begins accepting connections. The
    /// source ends. Call `stop()` from another task to shut down.
    ///
    /// - Parameters:
    ///   - host: The host address to bind to (e.g., `"0.0.0.0"` or `"127.0.0.1"`)
    ///   - port: The port number to listen on
    ///   - quicConfiguration: QUIC transport configuration (TLS, flow control, etc.)
    /// - Throws: `HTTP3Error` if the server cannot start, or QUIC/socket errors
    ///
    /// ## Usage
    ///
    /// ```swift
    /// let tlsConfig = try TLSConfiguration.server(
    ///     certificatePath: "cert.pem",
    ///     privateKeyPath: "key.pem"
    /// )
    /// var quicConfig = QUICConfiguration()
    /// quicConfig.securityMode = .production {
    ///     TLS13Handler(configuration: tlsConfig)
    /// }
    ///
    /// let server = HTTP3Server()
    /// try await server.listen(
    ///     host: "0.0.0.0",
    ///     port: 4433,
    ///     quicConfiguration: quicConfig
    /// )
    /// ```
    public func listen(
        host: String,
        port: UInt16,
        quicConfiguration: QUICConfiguration
    ) async throws {
        let (endpoint, runTask) = try await QUICEndpoint.serve(
            host: host,
            port: port,
            configuration: quicConfiguration
        )

        self.quicEndpoint = endpoint
        self.quicRunTask = runTask

        Self.logger.info(
            "HTTP/3 server listening",
            metadata: [
                "host": "\(host)",
                "port": "\(port)",
            ]
        )

        let connectionStream = await endpoint.incomingConnections

        // serve() blocks until the connection source ends or stop() is called.
        // On return (or throw), the QUIC resources are cleaned up by stop().
        do {
            try await serve(connectionSource: connectionStream)
        } catch {
            // Ensure QUIC resources are cleaned up on error
            await endpoint.stop()
            runTask.cancel()
            self.quicEndpoint = nil
            self.quicRunTask = nil
            throw error
        }
    }

    // MARK: - Convenience: enableWebTransport

    /// Enables WebTransport session handling on this server.
    ///
    /// Call this **before** `listen()` or `serve()`. It:
    /// 1. Merges the required HTTP/3 settings (`enableConnectProtocol`,
    ///    `enableH3Datagram`, `webtransportMaxSessions`)
    /// 2. Registers an internal Extended CONNECT handler that accepts
    ///    WebTransport sessions
    /// 3. Returns an `AsyncStream` that delivers each established
    ///    `WebTransportSession`
    ///
    /// - Parameter options: WebTransport configuration (default: 1 session, all paths)
    /// - Returns: An `AsyncStream<WebTransportSession>` of incoming sessions
    ///
    /// ## Usage
    ///
    /// ```swift
    /// let server = HTTP3Server()
    ///
    /// await server.onRequest { context in
    ///     try await context.respond(status: 200, Data("OK".utf8))
    /// }
    ///
    /// let sessions = await server.enableWebTransport(
    ///     HTTP3WebTransportOptions(maxSessionsPerConnection: 4)
    /// )
    ///
    /// Task {
    ///     for await session in sessions {
    ///         Task { await handleSession(session) }
    ///     }
    /// }
    ///
    /// try await server.listen(host: "0.0.0.0", port: 443, quicConfiguration: config)
    /// ```
    public func enableWebTransport(
        _ options: HTTP3WebTransportOptions = HTTP3WebTransportOptions()
    ) -> AsyncStream<WebTransportSession> {
        // Merge WebTransport-required settings
        settings.enableConnectProtocol = true
        settings.enableH3Datagram = true
        settings.webtransportMaxSessions = options.maxSessionsPerConnection

        // Create the session delivery stream
        var continuation: AsyncStream<WebTransportSession>.Continuation!
        let stream = AsyncStream<WebTransportSession> { cont in
            continuation = cont
        }
        let sessionContinuation = continuation!

        let allowedPaths = options.allowedPaths
        let maxSessions = options.maxSessionsPerConnection

        // Register the Extended CONNECT handler
        self.onExtendedConnect { context in
            // Only accept WebTransport Extended CONNECT requests
            guard context.request.isWebTransportConnect else {
                try await context.reject(
                    status: 501,
                    headers: [("content-type", "text/plain")],
                    // body: Data("Only WebTransport is supported via Extended CONNECT".utf8)
                )
                return
            }

            // Check allowed paths
            if !allowedPaths.isEmpty {
                guard allowedPaths.contains(context.request.path) else {
                    try await context.reject(
                        status: 404,
                        headers: [("content-type", "text/plain")],
                        // body: Data("WebTransport path not found".utf8)
                    )
                    return
                }
            }

            // Enforce per-connection session quota
            let h3Connection = context.connection
            let activeCount = await h3Connection.activeWebTransportSessionCount
            if maxSessions > 0 && activeCount >= Int(maxSessions) {
                Self.logger.warning(
                    "WebTransport session limit reached",
                    metadata: [
                        "active": "\(activeCount)",
                        "limit": "\(maxSessions)",
                        "streamID": "\(context.streamID)",
                    ]
                )
                try await context.reject(
                    status: 429,
                    headers: [("content-type", "text/plain")],
                    // body: Data("Too many WebTransport sessions".utf8)
                )
                return
            }

            // Accept and create the WebTransport session
            do {
                try await context.accept()

                let session = try await h3Connection.createWebTransportSession(
                    from: context,
                    role: .server
                )

                Self.logger.info(
                    "WebTransport session accepted",
                    metadata: [
                        "sessionID": "\(session.sessionID)",
                        "streamID": "\(context.streamID)",
                        "path": "\(context.request.path)",
                        "authority": "\(context.request.authority)",
                    ]
                )

                sessionContinuation.yield(session)
            } catch {
                Self.logger.warning(
                    "Failed to create WebTransport session: \(error)",
                    metadata: ["streamID": "\(context.streamID)"]
                )
                try? await context.reject(status: 500)
            }
        }

        return stream
    }

    //Unsafe operation, expose the QUIC endpoint for advanced use cases (e.g. custom WebTransport handling, manual QUiC streams stat tracking, etc.)
    public var endpoint: QUICEndpoint? {
        return quicEndpoint
    }
}

// MARK: - Simple Router

/// A simple path-based router for HTTP/3 servers.
///
/// Provides a convenient way to register handlers for specific
/// path patterns without a full routing framework.
///
/// ## Usage
///
/// ```swift
/// let router = HTTP3Router()
/// router.get("/") { context, _ in
///     try await context.respond(
///         status: 200,
///         Data("Home".utf8)
///     )
/// }
/// router.post("/api/data") { context, _ in
///     // handle POST
/// }
///
/// server.onRequest(router.handler)
/// ```
public final class HTTP3Router: Sendable {

    public typealias RouteParams = [String: String]
    public typealias RouteHandler = @Sendable (HTTP3RequestContext, RouteParams) async throws -> Void

    private enum RouteSegment: Sendable {
        case literal(String)
        case parameter(name: String, constraint: ParameterConstraint)
    }

    private enum ParameterConstraint: Sendable {
        case any
        case uuid
        case exactLength(Int)
        case lengthRange(Int, Int)
        case regex(String)
    }

    /// Route entry
    private struct Route: Sendable {
        let method: HTTPMethod?  // nil = any method
        let path: String
        let segments: [RouteSegment]
        let handler: RouteHandler
    }

    /// Registered routes
    private let routes: LockedBox<[Route]>

    /// Handler for unmatched routes (default: 404)
    private let notFoundHandler: LockedBox<RouteHandler>

    /// Creates a new HTTP/3 router.
    public init() {
        self.routes = LockedBox([])
        self.notFoundHandler = LockedBox({ context, _ in
            try await context.respond(
                status: 404,
                headers: [("content-type", "text/plain")],
                Data("Not Found".utf8)
            )
        })
    }

    /// Registers a route for any HTTP method.
    ///
    /// - Parameters:
    ///   - path: The URL path to match
    ///   - handler: The request handler `(context, params)`
    public func route(_ path: String, handler: @escaping RouteHandler) {
        let route = Route(
            method: nil,
            path: path,
            segments: Self.parseRouteSegments(path),
            handler: handler
        )
        routes.withLock { $0.append(route) }
    }

    /// Registers a GET route.
    public func get(_ path: String, handler: @escaping RouteHandler) {
        let route = Route(
            method: .get,
            path: path,
            segments: Self.parseRouteSegments(path),
            handler: handler
        )
        routes.withLock { $0.append(route) }
    }

    /// Registers a POST route.
    public func post(_ path: String, handler: @escaping RouteHandler) {
        let route = Route(
            method: .post,
            path: path,
            segments: Self.parseRouteSegments(path),
            handler: handler
        )
        routes.withLock { $0.append(route) }
    }

    /// Registers a PUT route.
    public func put(_ path: String, handler: @escaping RouteHandler) {
        let route = Route(
            method: .put,
            path: path,
            segments: Self.parseRouteSegments(path),
            handler: handler
        )
        routes.withLock { $0.append(route) }
    }

    /// Registers a DELETE route.
    public func delete(_ path: String, handler: @escaping RouteHandler) {
        let route = Route(
            method: .delete,
            path: path,
            segments: Self.parseRouteSegments(path),
            handler: handler
        )
        routes.withLock { $0.append(route) }
    }

    /// Registers a PATCH route.
    public func patch(_ path: String, handler: @escaping RouteHandler) {
        let route = Route(
            method: .patch,
            path: path,
            segments: Self.parseRouteSegments(path),
            handler: handler
        )
        routes.withLock { $0.append(route) }
    }

    /// Sets the handler for unmatched routes.
    ///
    /// - Parameter handler: The fallback handler (default returns 404)
    public func setNotFound(_ handler: @escaping RouteHandler) {
        notFoundHandler.withLock { $0 = handler }
    }

    /// The combined request handler suitable for `HTTP3Server.onRequest()`.
    ///
    /// This handler matches incoming requests against registered routes
    /// and dispatches to the appropriate handler. Unmatched requests are
    /// forwarded to the not-found handler.
    public var handler: HTTP3Server.RequestHandler {
        return { [self] context in
            let pathSegments = Self.parsePathSegments(context.request.path)

            let matchingRoute = self.routes.withLock {
                routes -> (route: Route, parameters: [String: String])?
            in
                for route in routes {
                    // Check method (nil matches any)
                    if let method = route.method, method != context.request.method {
                        continue
                    }

                    if let parameters = Self.match(
                        routeSegments: route.segments,
                        requestSegments: pathSegments
                    ) {
                        return (route, parameters)
                    }
                }
                return nil
            }

            if let matchingRoute {
                try await matchingRoute.route.handler(context, matchingRoute.parameters)
            } else {
                let fallback = self.notFoundHandler.withLock { $0 }
                try await fallback(context, [:])
            }
        }
    }

    private static func parseRouteSegments(_ path: String) -> [RouteSegment] {
        parsePathSegments(path).map(parseRouteSegment)
    }

    private static func parsePathSegments(_ path: String) -> [String] {
        var normalized = path
        if let queryIndex = normalized.firstIndex(of: "?") {
            normalized = String(normalized[..<queryIndex])
        }
        if let fragmentIndex = normalized.firstIndex(of: "#") {
            normalized = String(normalized[..<fragmentIndex])
        }

        let trimmed = normalized.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard !trimmed.isEmpty else { return [] }
        return trimmed.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
    }

    private static func parseRouteSegment(_ segment: String) -> RouteSegment {
        guard segment.hasPrefix("{"), segment.hasSuffix("}") else {
            return .literal(segment)
        }

        let inner = String(segment.dropFirst().dropLast())
        guard !inner.isEmpty else {
            return .literal(segment)
        }

        let pieces = inner.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        let name = String(pieces[0])
        guard !name.isEmpty else {
            return .literal(segment)
        }

        let constraint: ParameterConstraint
        if pieces.count == 1 {
            constraint = .any
        } else {
            constraint = parseConstraint(String(pieces[1]))
        }

        return .parameter(name: name, constraint: constraint)
    }

    private static func parseConstraint(_ rawConstraint: String) -> ParameterConstraint {
        let constraint = rawConstraint.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = constraint.lowercased()

        if lower == "uuid" {
            return .uuid
        }

        if let exact = Int(constraint), exact >= 0 {
            return .exactLength(exact)
        }

        if lower.hasPrefix("("), lower.hasSuffix(")") {
            let rangeBody = String(lower.dropFirst().dropLast())
            let parts = rangeBody.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: true)
            if parts.count == 2,
                let min = Int(parts[0]),
                let max = Int(parts[1]),
                min >= 0,
                max >= min
            {
                return .lengthRange(min, max)
            }
        }

        return .regex(constraint)
    }

    private static func match(
        routeSegments: [RouteSegment],
        requestSegments: [String]
    ) -> [String: String]? {
        guard routeSegments.count == requestSegments.count else {
            return nil
        }

        var parameters: [String: String] = [:]
        parameters.reserveCapacity(routeSegments.count)

        for (routeSegment, requestSegment) in zip(routeSegments, requestSegments) {
            switch routeSegment {
            case .literal(let literal):
                guard literal == requestSegment else {
                    return nil
                }
            case .parameter(let name, let constraint):
                guard matchesConstraint(constraint, value: requestSegment) else {
                    return nil
                }
                parameters[name] = requestSegment
            }
        }

        return parameters
    }

    private static func matchesConstraint(_ constraint: ParameterConstraint, value: String) -> Bool {
        switch constraint {
        case .any:
            return true
        case .uuid:
            return UUID(uuidString: value) != nil
        case .exactLength(let expected):
            return value.count == expected
        case .lengthRange(let min, let max):
            let length = value.count
            return length >= min && length <= max
        case .regex(let pattern):
            do {
                let expression = try NSRegularExpression(pattern: "^\(pattern)$")
                let range = NSRange(location: 0, length: value.utf16.count)
                return expression.firstMatch(in: value, options: [], range: range) != nil
            } catch {
                return false
            }
        }
    }
}

// MARK: - LockedBox (Thread-safe container)

/// A simple thread-safe container for mutable values.
///
/// Uses `NSLock` for synchronization. This is a minimal utility
/// for the router's route table.
internal final class LockedBox<Value>: @unchecked Sendable {
    private var _value: Value
    private let lock = NSLock()

    init(_ value: Value) {
        self._value = value
    }

    func withLock<Result>(_ body: (inout Value) -> Result) -> Result {
        lock.lock()
        defer { lock.unlock() }
        return body(&_value)
    }
}
