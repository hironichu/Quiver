/// WebTransport Server (draft-ietf-webtrans-http3)
///
/// A server that accepts incoming WebTransport sessions over HTTP/3.
/// Uses `WebTransportServerOptions` for configuration and supports
/// middleware-based request acceptance via `WebTransportMiddleware`.
///
/// ## Middleware Resolution
///
/// The server resolves incoming Extended CONNECT requests through a
/// layered middleware system:
///
/// | Routes registered? | Path matches route? | Route has middleware? | Global middleware? | Result |
/// |----|----|----|----|----|
/// | Yes | Yes | Yes | — | Run route middleware |
/// | Yes | Yes | No | Yes | Run global middleware |
/// | Yes | Yes | No | No | Accept |
/// | Yes | No | — | — | Reject 404 |
/// | No | — | — | Yes | Run global middleware |
/// | No | — | — | No | Accept (open server) |
///
/// ## Usage
///
/// ### Open server (accept all)
///
/// ```swift
/// let server = WebTransportServer(
///     host: "0.0.0.0", port: 4433, options: serverOptions
/// )
/// try await server.listen()
///
/// for await session in server.incomingSessions {
///     Task { await handleSession(session) }
/// }
/// ```
///
/// ### Path-based routing with middleware
///
/// ```swift
/// let server = WebTransportServer(
///     host: "0.0.0.0", port: 4433, options: serverOptions,
///     middleware: { context in
///         // Global fallback: require auth header
///         guard context.headers.contains(where: { $0.0 == "authorization" }) else {
///             return .reject(reason: "Missing auth")
///         }
///         return .accept
///     }
/// )
/// await server.register(path: "/echo")
/// await server.register(path: "/chat") { context in
///     guard context.origin == "https://example.com" else {
///         return .reject(reason: "Invalid origin")
///     }
///     return .accept
/// }
/// try await server.listen()
/// ```
///
/// ## References
///
/// - [draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)
/// - [RFC 9220: Bootstrapping WebSockets with HTTP/3](https://www.rfc-editor.org/rfc/rfc9220.html)

import Foundation
import Logging
import QUIC
import QUICCore

// MARK: - WebTransport Server

/// A WebTransport server that manages session establishment and lifecycle.
///
/// Delegates to `HTTP3Server` for connection management and HTTP/3 protocol
/// handling. Middleware closures control session acceptance/rejection.
public actor WebTransportServer {
    private static let logger = QuiverLogging.logger(label: "webtransport.server")

    // MARK: - Types

    /// Server state.
    public enum State: Sendable, Hashable, CustomStringConvertible {
        /// Server created but not listening
        case idle
        /// Server is listening for connections
        case listening
        /// Server is shutting down
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

    /// The bind host address.
    public let host: String

    /// The bind port.
    public let port: UInt16

    /// Server options (certificates, transport params, session limits).
    public let options: WebTransportServerOptions

    /// Global middleware applied when no route-specific middleware matches.
    private let globalMiddleware: WebTransportMiddleware?

    /// Registered routes: path -> optional middleware.
    /// When a path is registered with `nil` middleware, the global
    /// middleware (if any) is used; otherwise the request is accepted.
    private var routes: [String: WebTransportMiddleware?] = [:]

    /// The underlying HTTP/3 server.
    public let httpServer: HTTP3Server

    /// Current server state.
    public private(set) var state: State = .idle

    /// Stream of incoming WebTransport sessions.
    ///
    /// Each element is an established `WebTransportSession` ready for
    /// stream and datagram operations.
    public private(set) var incomingSessions: AsyncStream<WebTransportSession>

    /// Continuation for the incoming sessions stream.
    private var incomingSessionsContinuation: AsyncStream<WebTransportSession>.Continuation?

    /// The QUIC endpoint created by `listen()`.
    private var quicEndpoint: QUICEndpoint?

    /// The I/O loop task created by `listen()`.
    private var quicRunTask: Task<Void, Error>?

    /// Whether WebTransport has been enabled on the underlying HTTP3Server.
    private var webTransportEnabled = false

    // MARK: - Initialization (host: String)

    /// Creates a WebTransport server bound to a host and port.
    ///
    /// - Parameters:
    ///   - host: The host address to bind to (e.g. `"0.0.0.0"`)
    ///   - port: The port number to listen on
    ///   - options: Server options (certificates, transport params, etc.)
    ///   - middleware: Global middleware for session acceptance (default: nil = accept all)
    public init(
        host: String,
        port: UInt16,
        options: WebTransportServerOptions,
        middleware: WebTransportMiddleware? = nil
    ) {
        self.host = host
        self.port = port
        self.options = options
        self.globalMiddleware = middleware

        // Create the underlying HTTP/3 server with WT-required settings
        self.httpServer = HTTP3Server(
            settings: options.buildHTTP3Settings(),
            maxConnections: options.maxConnections
        )

        // Create the incoming sessions stream
        var continuation: AsyncStream<WebTransportSession>.Continuation!
        self.incomingSessions = AsyncStream { cont in
            continuation = cont
        }
        self.incomingSessionsContinuation = continuation
    }

    // MARK: - Initialization (SocketAddress)

    /// Creates a WebTransport server bound to a socket address.
    ///
    /// - Parameters:
    ///   - host: The socket address to bind to
    ///   - port: The port number
    ///   - options: Server options (certificates, transport params, etc.)
    ///   - middleware: Global middleware for session acceptance (default: nil = accept all)
    public init(
        host: SocketAddress,
        port: UInt16,
        options: WebTransportServerOptions,
        middleware: WebTransportMiddleware? = nil
    ) {
        self.init(
            host: host.ipAddress,
            port: port,
            options: options,
            middleware: middleware
        )
    }

    // MARK: - Route Registration

    /// Registers a path for WebTransport session acceptance.
    ///
    /// When routes are registered, only requests matching a registered
    /// path are considered. Unmatched paths receive a 404 rejection.
    ///
    /// - Parameters:
    ///   - path: The request path to accept (e.g. `"/echo"`, `"/chat"`)
    ///   - middleware: Optional per-route middleware. When `nil`, the global
    ///     middleware is used; if no global middleware exists, the request
    ///     is accepted unconditionally.
    public func register(
        path: String,
        middleware: WebTransportMiddleware? = nil
    ) {
        routes[path] = middleware
    }

    // MARK: - Server Lifecycle

    /// Starts the WebTransport server.
    ///
    /// Creates the QUIC endpoint, binds to the configured host/port,
    /// enables WebTransport on the underlying HTTP/3 server, and begins
    /// accepting connections. Blocks until `stop()` is called.
    ///
    /// - Throws: `WebTransportServerOptions.ValidationError` if options are invalid,
    ///   or any QUIC/HTTP3 error if the server cannot start
    public func listen() async throws {
        try options.validate()

        guard state == .idle else {
            throw HTTP3Error(
                code: .internalError,
                reason: "WebTransport server already started (state: \(state))"
            )
        }

        // Enable WebTransport on the HTTP3Server
        await enableWebTransportIfNeeded()

        // Build QUIC config from options (securityMode must be set by caller
        // or added here when QUICCrypto dependency is available)
        let quicConfig = options.buildQUICConfiguration()

        let (endpoint, runTask) = try await QUICEndpoint.serve(
            host: host,
            port: port,
            configuration: quicConfig
        )

        self.quicEndpoint = endpoint
        self.quicRunTask = runTask

        Self.logger.info(
            "WebTransport server listening",
            metadata: [
                "host": "\(host)",
                "port": "\(port)",
                "maxSessions": "\(options.maxSessions)",
                "routes": "\(routes.keys.sorted())",
            ]
        )

        state = .listening

        let connectionStream = await endpoint.incomingConnections

        // Install a default 404 handler for regular HTTP/3 requests
        await httpServer.onRequest { context in
            try await context.respond(
                status: 404,
                headers: [("content-type", "text/plain")],
                Data("Not Found".utf8)
            )
        }

        do {
            try await httpServer.serve(connectionSource: connectionStream)
        } catch {
            state = .stopped
            await endpoint.stop()
            runTask.cancel()
            self.quicEndpoint = nil
            self.quicRunTask = nil
            throw error
        }

        state = .stopped
    }

    /// Starts accepting WebTransport connections from an external QUIC
    /// connection source.
    ///
    /// Use this when you manage the QUIC endpoint yourself.
    ///
    /// - Parameter connectionSource: An async stream of incoming QUIC connections
    /// - Throws: `HTTP3Error` if the server cannot start
    public func serve(
        connectionSource: AsyncStream<any QUICConnectionProtocol>
    ) async throws {
        try options.validate()

        guard state == .idle else {
            throw HTTP3Error(
                code: .internalError,
                reason: "WebTransport server already started (state: \(state))"
            )
        }

        state = .listening

        await enableWebTransportIfNeeded()

        // Install a default 404 handler for regular HTTP/3 requests
        await httpServer.onRequest { context in
            try await context.respond(
                status: 404,
                headers: [("content-type", "text/plain")],
                Data("Not Found".utf8)
            )
        }

        do {
            try await httpServer.serve(connectionSource: connectionSource)
        } catch {
            state = .stopped
            throw error
        }

        state = .stopped
    }

    /// Stops the server gracefully.
    ///
    /// Sends GOAWAY to active connections, waits for the grace period,
    /// then tears down the QUIC endpoint.
    ///
    /// - Parameter gracePeriod: Maximum time to wait for sessions to drain
    public func stop(gracePeriod: Duration = .seconds(5)) async {
        guard state == .listening else { return }

        state = .stopping

        await httpServer.stop(gracePeriod: gracePeriod)

        // Finish the sessions stream
        incomingSessionsContinuation?.finish()
        incomingSessionsContinuation = nil

        // Tear down the QUIC endpoint if we own it
        if let endpoint = quicEndpoint {
            await endpoint.stop()
            quicEndpoint = nil
        }
        quicRunTask?.cancel()
        quicRunTask = nil

        state = .stopped
    }

    // MARK: - Middleware Resolution

    /// Resolves the middleware for an incoming request.
    ///
    /// Resolution logic:
    /// 1. If routes are registered and path matches a route with middleware -> that middleware
    /// 2. If routes are registered and path matches a route without middleware -> global middleware (if any)
    /// 3. If routes are registered and path matches NO route -> reject 404
    /// 4. If no routes registered and global middleware exists -> global middleware
    /// 5. If no routes registered and no global middleware -> accept (open server)
    ///
    /// - Parameter path: The `:path` from the Extended CONNECT request
    /// - Returns: A `WebTransportReply` or a middleware to evaluate
    private func resolveMiddleware(
        for path: String
    ) -> MiddlewareResolution {
        if routes.isEmpty {
            // No routes registered
            if let global = globalMiddleware {
                return .runMiddleware(global)
            } else {
                return .accept
            }
        }

        // Routes are registered — path must match
        guard let routeEntry = routes[path] else {
            return .reject(reason: "No route registered for path: \(path)")
        }

        // Route exists — check for route-specific middleware
        if let routeMiddleware = routeEntry {
            return .runMiddleware(routeMiddleware)
        }

        // Route exists but no route-specific middleware — try global
        if let global = globalMiddleware {
            return .runMiddleware(global)
        }

        // Route exists, no middleware anywhere — accept
        return .accept
    }

    /// Internal resolution result.
    private enum MiddlewareResolution {
        case accept
        case reject(reason: String)
        case runMiddleware(WebTransportMiddleware)
    }

    // MARK: - Internal: Enable WebTransport

    /// Enables WebTransport on the underlying HTTP3Server (idempotent).
    ///
    /// Registers the Extended CONNECT handler that integrates with the
    /// middleware resolution system.
    private func enableWebTransportIfNeeded() async {
        guard !webTransportEnabled else { return }
        webTransportEnabled = true

        // Capture self's route/middleware state via the actor — the handler
        // closure calls back into the actor for resolution.
        let server = self

        // Build a snapshot of options for the H3-level enableWebTransport call
        let h3Options = HTTP3WebTransportOptions(
            maxSessionsPerConnection: options.maxSessions,
            allowedPaths: []  // Path filtering is handled by our middleware, not H3
        )

        // Enable WT on the HTTP3Server to get settings merged + session stream
        let h3Sessions = await httpServer.enableWebTransport(h3Options)

        // We do NOT use the h3Sessions stream directly because we need
        // middleware control. Instead, we install our own Extended CONNECT
        // handler that runs middleware before accepting.

        // Override the Extended CONNECT handler with middleware integration
        await httpServer.onExtendedConnect { context in
            guard context.request.isWebTransportConnect else {
                try await context.reject(
                    status: 501,
                    headers: [("content-type", "text/plain")]
                )
                return
            }

            // Build the middleware request context
            let requestContext = WebTransportRequestContext(
                path: context.request.path,
                authority: context.request.authority,
                headers: context.request.headers,
                origin: context.request.headers.first(where: { $0.0.lowercased() == "origin" })?.1
            )

            // Resolve middleware via the actor
            let resolution = await server.resolveMiddleware(for: context.request.path)

            let reply: WebTransportReply
            switch resolution {
            case .accept:
                reply = .accept

            case .reject(let reason):
                reply = .reject(reason: reason)

            case .runMiddleware(let middleware):
                reply = await middleware(requestContext)
            }

            // Apply the reply
            switch reply {
            case .accept:
                do {
                    try await context.accept()

                    let h3Connection = context.connection
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

                    await server.yieldSession(session)
                } catch {
                    Self.logger.warning(
                        "Failed to create WebTransport session: \(error)",
                        metadata: ["streamID": "\(context.streamID)"]
                    )
                    try? await context.reject(status: 500)
                }

            case .reject(let reason):
                Self.logger.info(
                    "WebTransport session rejected by middleware",
                    metadata: [
                        "path": "\(context.request.path)",
                        "reason": "\(reason)",
                        "streamID": "\(context.streamID)",
                    ]
                )

                try await context.reject(
                    status: 403,
                    headers: [
                        ("content-type", "text/plain"),
                        ("x-wt-reject", reason),
                    ]
                )
            }
        }

        // Drain the h3Sessions stream in the background so it doesn't
        // block the HTTP3Server's internal continuation. Sessions are
        // delivered through our Extended CONNECT handler above, not here.
        Task {
            for await _ in h3Sessions {
                // Consumed and discarded — we yield sessions through
                // our own handler above instead.
            }
        }
    }

    /// Yields a session to the `incomingSessions` stream.
    private func yieldSession(_ session: WebTransportSession) {
        incomingSessionsContinuation?.yield(session)
    }

    // MARK: - Server Info

    /// Whether the server is currently listening.
    public var isListening: Bool {
        state == .listening
    }

    /// Whether the server has stopped.
    public var isStopped: Bool {
        state == .stopped
    }

    /// The number of active HTTP/3 connections.
    public var activeConnectionCount: Int {
        get async { await httpServer.activeConnectionCount }
    }

    /// The number of registered routes.
    public var registeredRouteCount: Int {
        routes.count
    }

    /// A debug description of the server.
    public var debugDescription: String {
        var parts = [String]()
        parts.append("state=\(state)")
        parts.append("host=\(host):\(port)")
        parts.append("maxSessions=\(options.maxSessions)")
        parts.append("routes=\(routes.keys.sorted())")
        parts.append("globalMiddleware=\(globalMiddleware != nil)")
        return "WebTransportServer(\(parts.joined(separator: ", ")))"
    }
}