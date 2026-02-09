/// WebTransport Server (draft-ietf-webtrans-http3)
///
/// A convenience wrapper around `HTTP3Server` that automatically handles
/// WebTransport session establishment via Extended CONNECT (RFC 9220).
///
/// ## Overview
///
/// `WebTransportServer` simplifies the server-side WebTransport workflow:
/// 1. Configures HTTP/3 settings for WebTransport (Extended CONNECT, datagrams, max sessions)
/// 2. Registers an Extended CONNECT handler that accepts WebTransport sessions
/// 3. Creates and manages `WebTransportSession` instances
/// 4. Exposes an `incomingSessions` async stream for the application
///
/// ## Usage
///
/// ```swift
/// let server = WebTransportServer(maxSessions: 10)
///
/// // Optionally handle regular HTTP/3 requests alongside WebTransport
/// server.onRequest { context in
///     try await context.respond(HTTP3Response(status: 200, body: Data("OK".utf8)))
/// }
///
/// // Accept WebTransport sessions
/// Task {
///     for await session in server.incomingSessions {
///         Task {
///             // Echo bidirectional streams
///             for await stream in await session.incomingBidirectionalStreams {
///                 let data = try await stream.read()
///                 try await stream.write(data)
///                 try await stream.closeWrite()
///             }
///         }
///     }
/// }
///
/// // Start serving
/// try await server.serve(connectionSource: listener.incomingConnections)
/// ```
///
/// ## Thread Safety
///
/// `WebTransportServer` is an `actor`, ensuring all mutable state is
/// accessed serially. This is consistent with Swift 6 concurrency
/// requirements and the project's design principles.
///
/// ## References
///
/// - [draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)
/// - [RFC 9220: Bootstrapping WebSockets with HTTP/3](https://www.rfc-editor.org/rfc/rfc9220.html)
/// - [RFC 9297: HTTP Datagrams and the Capsule Protocol](https://www.rfc-editor.org/rfc/rfc9297.html)

import Foundation
import QUIC
import QUICCore
import Logging

// MARK: - WebTransport Server

/// A WebTransport server that manages session establishment and lifecycle.
///
/// Wraps `HTTP3Server` with automatic WebTransport session handling.
/// The server configures the required HTTP/3 settings, handles Extended
/// CONNECT negotiation, and delivers established sessions to the application.
public actor WebTransportServer {
    private static let logger = Logger(label: "webtransport.server")

    // MARK: - Types

    /// Server state
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

    /// Configuration for the WebTransport server.
    public struct Configuration: Sendable {
        /// Maximum number of concurrent WebTransport sessions per connection.
        ///
        /// This value is advertised via `SETTINGS_WEBTRANSPORT_MAX_SESSIONS`.
        /// Browsers require this to be > 0 to establish WebTransport connections.
        ///
        /// - Default: 1
        public var maxSessionsPerConnection: UInt64

        /// Maximum number of concurrent HTTP/3 connections.
        ///
        /// 0 means unlimited.
        ///
        /// - Default: 0 (unlimited)
        public var maxConnections: Int

        /// Additional HTTP/3 settings to merge with WebTransport defaults.
        ///
        /// The WebTransport-required settings (`enableConnectProtocol`,
        /// `enableH3Datagram`, `webtransportMaxSessions`) are always set.
        /// This allows overriding QPACK and other settings.
        public var additionalSettings: HTTP3Settings

        /// Allowed WebTransport paths.
        ///
        /// If non-empty, only Extended CONNECT requests with a `:path`
        /// matching one of these values will be accepted. All others are
        /// rejected with 404.
        ///
        /// If empty (default), all paths are accepted.
        public var allowedPaths: [String]

        /// Creates a WebTransport server configuration.
        ///
        /// - Parameters:
        ///   - maxSessionsPerConnection: Max concurrent WT sessions per connection (default: 1)
        ///   - maxConnections: Max concurrent HTTP/3 connections, 0 = unlimited (default: 0)
        ///   - additionalSettings: Additional HTTP/3 settings (default: literal-only QPACK)
        ///   - allowedPaths: Paths to accept, empty = all (default: [])
        public init(
            maxSessionsPerConnection: UInt64 = 1,
            maxConnections: Int = 0,
            additionalSettings: HTTP3Settings = HTTP3Settings(),
            allowedPaths: [String] = []
        ) {
            self.maxSessionsPerConnection = maxSessionsPerConnection
            self.maxConnections = maxConnections
            self.additionalSettings = additionalSettings
            self.allowedPaths = allowedPaths
        }

        /// Default configuration.
        public static let `default` = Configuration()
    }

    // MARK: - Properties

    /// Server configuration.
    public let configuration: Configuration

    /// The underlying HTTP/3 server.
    private let httpServer: HTTP3Server

    /// Current server state.
    public private(set) var state: State = .idle

    /// Continuation for delivering new WebTransport sessions.
    private var incomingSessionsContinuation: AsyncStream<WebTransportSession>.Continuation?

    /// Stream of incoming WebTransport sessions.
    ///
    /// Each element is an established `WebTransportSession` ready for
    /// stream and datagram operations.
    ///
    /// ## Usage
    ///
    /// ```swift
    /// for await session in server.incomingSessions {
    ///     Task { await handleSession(session) }
    /// }
    /// ```
    public private(set) var incomingSessions: AsyncStream<WebTransportSession>

    /// The QUIC endpoint created by `listen(host:port:quicConfiguration:)`.
    ///
    /// Stored so that `stop()` can shut it down.
    private var quicEndpoint: QUICEndpoint?

    /// The I/O loop task created by `listen(host:port:quicConfiguration:)`.
    ///
    /// Stored so that `stop()` can cancel it.
    private var quicRunTask: Task<Void, Error>?

    /// Active HTTP/3 connections (needed to create sessions from).
    private var activeConnections: [ObjectIdentifier: HTTP3Connection] = [:]

    /// Total sessions accepted across all connections.
    private var totalSessionsAccepted: UInt64 = 0

    /// Registered request handler for non-WebTransport HTTP/3 requests.
    private var requestHandler: HTTP3Server.RequestHandler?

    // MARK: - Initialization

    /// Creates a WebTransport server.
    ///
    /// - Parameter configuration: Server configuration (default: `.default`)
    public init(configuration: Configuration = .default) {
        self.configuration = configuration

        // Build HTTP/3 settings with WebTransport requirements
        var settings = configuration.additionalSettings
        settings.enableConnectProtocol = true
        settings.enableH3Datagram = true
        settings.webtransportMaxSessions = configuration.maxSessionsPerConnection

        self.httpServer = HTTP3Server(
            settings: settings,
            maxConnections: configuration.maxConnections
        )

        // Create the incoming sessions stream
        var continuation: AsyncStream<WebTransportSession>.Continuation!
        self.incomingSessions = AsyncStream { cont in
            continuation = cont
        }
        self.incomingSessionsContinuation = continuation
    }

    /// Creates a WebTransport server with simple parameters.
    ///
    /// - Parameters:
    ///   - maxSessions: Maximum concurrent sessions per connection (default: 1)
    ///   - maxConnections: Maximum concurrent connections (default: 0 = unlimited)
    public init(maxSessions: UInt64 = 1, maxConnections: Int = 0) {
        self.init(configuration: Configuration(
            maxSessionsPerConnection: maxSessions,
            maxConnections: maxConnections
        ))
    }

    // MARK: - Configuration

    /// Registers a handler for regular (non-WebTransport) HTTP/3 requests.
    ///
    /// This allows serving both WebTransport sessions and regular HTTP/3
    /// requests on the same server.
    ///
    /// - Parameter handler: The closure to handle incoming requests
    public func onRequest(_ handler: @escaping HTTP3Server.RequestHandler) {
        self.requestHandler = handler
    }

    // MARK: - Server Lifecycle

    /// Starts accepting WebTransport connections from a QUIC connection source.
    ///
    /// This method:
    /// 1. Registers an Extended CONNECT handler for WebTransport
    /// 2. Registers the optional HTTP/3 request handler
    /// 3. Starts the underlying HTTP/3 server
    ///
    /// - Parameter connectionSource: An async stream of incoming QUIC connections
    /// - Throws: `HTTP3Error` if the server cannot start
    public func serve(
        connectionSource: AsyncStream<any QUICConnectionProtocol>
    ) async throws {
        guard state == .idle else {
            throw HTTP3Error(
                code: .internalError,
                reason: "WebTransport server already started (state: \(state))"
            )
        }

        state = .listening

        // Register the request handler (or a default 404 handler)
        let userRequestHandler = self.requestHandler
        await httpServer.onRequest { context in
            if let handler = userRequestHandler {
                try await handler(context)
            } else {
                // Default: return 404 for non-WebTransport requests
                try await context.respond(HTTP3Response(
                    status: 404,
                    headers: [("content-type", "text/plain")],
                    body: Data("Not Found".utf8)
                ))
            }
        }

        // Register the Extended CONNECT handler for WebTransport
        let allowedPaths = self.configuration.allowedPaths
        let maxSessions = self.configuration.maxSessionsPerConnection
        let sessionsContinuation = self.incomingSessionsContinuation

        await httpServer.onExtendedConnect { [weak self] context in
            // Only accept WebTransport Extended CONNECT requests
            guard context.request.isWebTransportConnect else {
                try await context.reject(
                    status: 501,
                    headers: [("content-type", "text/plain")],
                    body: Data("Only WebTransport is supported".utf8)
                )
                return
            }

            // Check allowed paths
            if !allowedPaths.isEmpty {
                guard allowedPaths.contains(context.request.path) else {
                    try await context.reject(
                        status: 404,
                        headers: [("content-type", "text/plain")],
                        body: Data("WebTransport path not found".utf8)
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
                    body: Data("Too many WebTransport sessions".utf8)
                )
                return
            }

            // Accept and create the WebTransport session using the
            // connection reference carried on the context — no lookup needed.
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

                sessionsContinuation?.yield(session)

                if let self = self {
                    await self.incrementSessionCount()
                }
            } catch {
                Self.logger.warning(
                    "Failed to create WebTransport session: \(error)",
                    metadata: ["streamID": "\(context.streamID)"]
                )
                try? await context.reject(status: 500)
            }
        }

        // Start the HTTP/3 server
        do {
            try await httpServer.serve(connectionSource: connectionSource)
        } catch {
            state = .stopped
            throw error
        }

        state = .stopped
    }

    /// Serves a single QUIC connection for WebTransport.
    ///
    /// This is a convenience method for testing or single-connection scenarios.
    /// It establishes the HTTP/3 connection, handles WebTransport negotiation,
    /// and delivers sessions via `incomingSessions`.
    ///
    /// - Parameter quicConnection: The QUIC connection to serve
    /// - Throws: `HTTP3Error` if initialization fails
    public func serveConnection(_ quicConnection: any QUICConnectionProtocol) async throws {
        guard state == .idle || state == .listening else {
            throw HTTP3Error(
                code: .internalError,
                reason: "WebTransport server not in valid state (state: \(state))"
            )
        }

        state = .listening

        // Build HTTP/3 settings
        var settings = configuration.additionalSettings
        settings.enableConnectProtocol = true
        settings.enableH3Datagram = true
        settings.webtransportMaxSessions = configuration.maxSessionsPerConnection

        // Create and initialize the HTTP/3 connection
        let h3Connection = HTTP3Connection(
            quicConnection: quicConnection,
            role: .server,
            settings: settings
        )

        let connectionID = ObjectIdentifier(quicConnection as AnyObject)
        activeConnections[connectionID] = h3Connection

        defer {
            activeConnections.removeValue(forKey: connectionID)
        }

        try await h3Connection.initialize()

        // Process Extended CONNECT requests for WebTransport
        let allowedPaths = configuration.allowedPaths
        let maxSessions = configuration.maxSessionsPerConnection
        let sessionsContinuation = incomingSessionsContinuation

        // Handle Extended CONNECT in a background task
        let extConnectTask = Task { [weak self] in
            for await context in await h3Connection.incomingExtendedConnect {
                guard context.request.isWebTransportConnect else {
                    try? await context.reject(status: 501)
                    continue
                }

                if !allowedPaths.isEmpty && !allowedPaths.contains(context.request.path) {
                    try? await context.reject(status: 404)
                    continue
                }

                // Enforce per-connection session quota
                let activeCount = await h3Connection.activeWebTransportSessionCount
                if maxSessions > 0 && activeCount >= Int(maxSessions) {
                    Self.logger.warning(
                        "WebTransport session limit reached on connection",
                        metadata: [
                            "active": "\(activeCount)",
                            "limit": "\(maxSessions)",
                        ]
                    )
                    try? await context.reject(
                        status: 429,
                        headers: [("content-type", "text/plain")],
                        body: Data("Too many WebTransport sessions".utf8)
                    )
                    continue
                }

                // Accept the session
                do {
                    try await context.accept()

                    let session = try await h3Connection.createWebTransportSession(
                        from: context,
                        role: .server
                    )

                    sessionsContinuation?.yield(session)

                    if let self = self {
                        await self.incrementSessionCount()
                    }

                    Self.logger.info(
                        "WebTransport session created",
                        metadata: [
                            "sessionID": "\(session.sessionID)",
                            "path": "\(context.request.path)",
                        ]
                    )
                } catch {
                    Self.logger.warning("Failed to create WebTransport session: \(error)")
                    try? await context.reject(status: 500)
                }
            }
        }

        defer { extConnectTask.cancel() }

        // Process regular HTTP/3 requests if a handler is registered
        if let handler = requestHandler {
            for await context in await h3Connection.incomingRequests {
                let capturedHandler = handler
                Task {
                    do {
                        try await capturedHandler(context)
                    } catch {
                        try? await context.respond(HTTP3Response(
                            status: 500,
                            body: Data("Internal Server Error".utf8)
                        ))
                    }
                }
            }
        } else {
            // Keep alive — wait for incoming requests to end (connection close)
            for await _ in await h3Connection.incomingRequests {
                // Discard non-WT requests with 404
            }
        }
    }

    /// Stops the server gracefully.
    ///
    /// If the server was started via `listen(host:port:quicConfiguration:)`,
    /// the underlying QUIC endpoint and I/O loop are also shut down.
    ///
    /// - Parameter gracePeriod: Maximum time to wait for sessions to drain
    public func stop(gracePeriod: Duration = .seconds(5)) async {
        guard state == .listening else { return }

        state = .stopping

        await httpServer.stop(gracePeriod: gracePeriod)

        // Finish the sessions stream
        incomingSessionsContinuation?.finish()
        incomingSessionsContinuation = nil

        activeConnections.removeAll()

        // Tear down the QUIC endpoint if we own it (created by listen())
        if let endpoint = quicEndpoint {
            await endpoint.stop()
            quicEndpoint = nil
        }
        quicRunTask?.cancel()
        quicRunTask = nil

        state = .stopped
    }

    // MARK: - Internal Helpers

    /// Increments the total session counter.
    private func incrementSessionCount() {
        totalSessionsAccepted += 1
    }

    // MARK: - Server Info

    /// The total number of WebTransport sessions accepted.
    public var totalSessions: UInt64 {
        totalSessionsAccepted
    }

    /// Whether the server is currently listening.
    public var isListening: Bool {
        state == .listening
    }

    /// Whether the server has stopped.
    public var isStopped: Bool {
        state == .stopped
    }

    /// A debug description of the server.
    public var debugDescription: String {
        var parts = [String]()
        parts.append("state=\(state)")
        parts.append("maxSessions=\(configuration.maxSessionsPerConnection)")
        parts.append("totalSessions=\(totalSessionsAccepted)")
        parts.append("activeConnections=\(activeConnections.count)")
        return "WebTransportServer(\(parts.joined(separator: ", ")))"
    }

    // MARK: - Convenience: listen

    /// Starts the WebTransport server on the specified host and port.
    ///
    /// This is a convenience method that creates the full QUIC stack
    /// internally (UDP socket → QUIC endpoint → connection stream) and
    /// feeds incoming connections to the WebTransport server.
    ///
    /// The method blocks until `stop()` is called or the connection
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
    /// let server = WebTransportServer(maxSessions: 4)
    ///
    /// Task {
    ///     for await session in await server.incomingSessions {
    ///         Task { await handleSession(session) }
    ///     }
    /// }
    ///
    /// // Blocks until stop() is called
    /// try await server.listen(
    ///     host: "0.0.0.0",
    ///     port: 443,
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
            "WebTransport server listening",
            metadata: [
                "host": "\(host)",
                "port": "\(port)",
                "maxSessions": "\(configuration.maxSessionsPerConnection)",
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
}