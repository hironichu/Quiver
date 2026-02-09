/// QUIC Endpoint
///
/// Main entry point for QUIC connections.
/// Provides both client and server APIs.

import Foundation
import Synchronization
import Logging
import QUICCore
import QUICCrypto
import QUICConnection
@_exported import QUICTransport
import NIOUDPTransport

// MARK: - QUIC Endpoint

/// A QUIC endpoint that can act as client or server
///
/// Provides a unified API for:
/// - Client connections: `dial(address:)` / `connect(to:)`
/// - Server listening: `serve(host:port:configuration:)`
/// - Packet I/O and routing
/// - Timer management
///
/// ## Usage
///
/// ### Client
/// ```swift
/// let endpoint = QUICEndpoint(configuration: config)
/// let connection = try await endpoint.dial(address: serverAddress)
/// let stream = try await connection.openStream()
/// try await stream.write(data)
/// ```
///
/// ### Server
/// ```swift
/// let (endpoint, runTask) = try await QUICEndpoint.serve(
///     host: "0.0.0.0",
///     port: 4433,
///     configuration: config
/// )
/// for await connection in await endpoint.incomingConnections {
///     // Handle connection
/// }
/// await endpoint.stop()
/// runTask.cancel()
/// ```
public actor QUICEndpoint {
    // MARK: - Properties

    /// Configuration
    private let configuration: QUICConfiguration

    /// Connection router
    private let router: ConnectionRouter

    /// Timer manager
    private let timerManager: TimerManager

    /// Whether this endpoint is a server
    private let isServer: Bool

    /// Incoming connections (server mode)
    private var incomingConnectionContinuation: AsyncStream<any QUICConnectionProtocol>.Continuation?

    /// Connections that have been created but not yet yielded to incomingConnections.
    /// These are waiting for their QUIC handshake to complete so that peer transport
    /// parameters (stream limits, flow control) are available before higher layers
    /// (e.g. HTTP/3) attempt to open streams.
    private var pendingConnections: Set<ObjectIdentifier> = []

    /// Send callback (for testing without real socket)
    private var sendCallback: (@Sendable (Data, SocketAddress) async throws -> Void)?

    /// The UDP socket (for real I/O)
    private var socket: (any QUICSocket)?

    /// Task running the main I/O loop
    private var ioTask: Task<Void, Never>?

    /// Local address
    private var _localAddress: SocketAddress?

    /// Whether the endpoint is running
    private var isRunning: Bool = false

    /// Stop signal for the I/O loop
    private var shouldStop: Bool = false

    /// Logger for endpoint events
    private let logger = Logger(label: "quic.endpoint")

    // MARK: - Initialization

    /// Creates a client endpoint
    /// - Parameter configuration: QUIC configuration
    public init(configuration: QUICConfiguration) {
        self.configuration = configuration
        self.router = ConnectionRouter(isServer: false, dcidLength: 8)
        self.timerManager = TimerManager(idleTimeout: configuration.maxIdleTimeout)
        self.isServer = false
    }

    /// Creates a server endpoint (internal)
    private init(configuration: QUICConfiguration, isServer: Bool) {
        self.configuration = configuration
        self.router = ConnectionRouter(isServer: isServer, dcidLength: 8)
        self.timerManager = TimerManager(idleTimeout: configuration.maxIdleTimeout)
        self.isServer = isServer
    }

    // MARK: - TLS Provider Creation

    /// Creates a TLS provider based on the security mode configuration.
    ///
    /// This method enforces the security mode hierarchy:
    /// 1. If `securityMode` is set, use it
    /// 2. Otherwise, if `tlsProviderFactory` is set (legacy), use it
    /// 3. Otherwise, throw `QUICSecurityError.tlsProviderNotConfigured`
    ///
    /// - Parameter isClient: Whether this is for a client connection
    /// - Returns: A configured TLS provider
    /// - Throws: `QUICSecurityError.tlsProviderNotConfigured` if no TLS provider is configured
    private func createTLSProvider(isClient: Bool) throws -> any TLS13Provider {
        // Priority 1: Check securityMode (new API)
        if let securityMode = configuration.securityMode {
            switch securityMode {
            case .production(let factory):
                return factory()
            case .development(let factory):
                return factory()
            case .testing:
                #if DEBUG
                logger.warning(
                    "Using MockTLSProvider in testing mode - NOT FOR PRODUCTION USE",
                    metadata: ["isClient": "\(isClient)"]
                )
                return MockTLSProvider(configuration: TLSConfiguration())
                #else
                fatalError("Testing mode is not available in release builds. Configure a real TLS provider using QUICConfiguration.production() or QUICConfiguration.development().")
                #endif
            }
        }

        // Priority 2: Check legacy tlsProviderFactory
        if let factory = configuration.tlsProviderFactory {
            return factory(isClient)
        }

        // No TLS provider configured - fail safely
        logger.error(
            "TLS provider not configured. Set securityMode or tlsProviderFactory before connecting.",
            metadata: ["isClient": "\(isClient)"]
        )
        throw QUICSecurityError.tlsProviderNotConfigured
    }

    /// Creates a TLS provider with session resumption configuration.
    ///
    /// - Parameters:
    ///   - isClient: Whether this is for a client connection
    ///   - sessionTicket: Optional session ticket for resumption
    ///   - maxEarlyDataSize: Maximum early data size for 0-RTT
    /// - Returns: A configured TLS provider
    /// - Throws: `QUICSecurityError.tlsProviderNotConfigured` if no TLS provider is configured
    private func createTLSProvider(
        isClient: Bool,
        sessionTicket: Data?,
        maxEarlyDataSize: UInt32?
    ) throws -> any TLS13Provider {
        // Priority 1: Check securityMode (new API)
        if let securityMode = configuration.securityMode {
            switch securityMode {
            case .production(let factory):
                return factory()
            case .development(let factory):
                return factory()
            case .testing:
                #if DEBUG
                logger.warning(
                    "Using MockTLSProvider in testing mode - NOT FOR PRODUCTION USE",
                    metadata: ["isClient": "\(isClient)"]
                )
                var tlsConfig = TLSConfiguration()
                tlsConfig.sessionTicket = sessionTicket
                if let maxSize = maxEarlyDataSize {
                    tlsConfig.maxEarlyDataSize = maxSize
                }
                return MockTLSProvider(configuration: tlsConfig)
                #else
                fatalError("Testing mode is not available in release builds. Configure a real TLS provider using QUICConfiguration.production() or QUICConfiguration.development().")
                #endif
            }
        }

        // Priority 2: Check legacy tlsProviderFactory
        if let factory = configuration.tlsProviderFactory {
            return factory(isClient)
        }

        // No TLS provider configured - fail safely
        logger.error(
            "TLS provider not configured. Set securityMode or tlsProviderFactory before connecting.",
            metadata: ["isClient": "\(isClient)"]
        )
        throw QUICSecurityError.tlsProviderNotConfigured
    }

    // MARK: - Server API

    /// Creates a server endpoint listening on the specified address
    /// - Parameters:
    ///   - address: The address to bind to
    ///   - configuration: QUIC configuration
    /// - Returns: A listening endpoint
    public static func listen(
        address: SocketAddress,
        configuration: QUICConfiguration
    ) async throws -> QUICEndpoint {
        let endpoint = QUICEndpoint(configuration: configuration, isServer: true)
        await endpoint.setLocalAddress(address)
        return endpoint
    }

    /// Creates a server endpoint with a UDP socket and starts it
    /// - Parameters:
    ///   - socket: The UDP socket to use
    ///   - configuration: QUIC configuration
    /// - Returns: A tuple of (endpoint, runTask) - the task runs the I/O loop
    public static func serve(
        socket: any QUICSocket,
        configuration: QUICConfiguration
    ) async throws -> (endpoint: QUICEndpoint, runTask: Task<Void, Error>) {
        let endpoint = QUICEndpoint(configuration: configuration, isServer: true)

        // Start the I/O loop in a separate task
        let runTask = Task {
            try await endpoint.run(socket: socket)
        }

        // Wait briefly for the socket to start and get the address
        try await Task.sleep(for: .milliseconds(10))
        if let nioAddr = await socket.localAddress,
           let addr = SocketAddress(nioAddr) {
            await endpoint.setLocalAddress(addr)
        }

        return (endpoint, runTask)
    }

    /// Creates a server endpoint bound to the specified host and port, and starts the I/O loop.
    ///
    /// This convenience method creates a `NIOQUICSocket` internally, binds it
    /// to the specified address, and starts the packet processing loop.
    ///
    /// - Parameters:
    ///   - host: The host address to bind to (e.g., `"0.0.0.0"` or `"127.0.0.1"`)
    ///   - port: The port number to bind to
    ///   - configuration: QUIC configuration
    /// - Returns: A tuple of (endpoint, runTask) — the task drives the I/O loop until cancelled
    ///
    /// ## Usage
    ///
    /// ```swift
    /// let (endpoint, runTask) = try await QUICEndpoint.serve(
    ///     host: "0.0.0.0",
    ///     port: 4433,
    ///     configuration: quicConfig
    /// )
    ///
    /// for await connection in endpoint.incomingConnections {
    ///     Task { await handleConnection(connection) }
    /// }
    ///
    /// // Cleanup
    /// await endpoint.stop()
    /// runTask.cancel()
    /// ```
    public static func serve(
        host: String,
        port: UInt16,
        configuration: QUICConfiguration
    ) async throws -> (endpoint: QUICEndpoint, runTask: Task<Void, Error>) {
        let udpConfig = UDPConfiguration(
            bindAddress: .specific(host: host, port: Int(port)),
            reuseAddress: false,
            receiveBufferSize: 65536,
            sendBufferSize: 65536,
            maxDatagramSize: 65507
        )
        let socket = NIOQUICSocket(configuration: udpConfig)
        return try await serve(socket: socket, configuration: configuration)
    }

    /// Sets the local address (internal)
    private func setLocalAddress(_ address: SocketAddress) {
        _localAddress = address
    }

    /// The local address this endpoint is bound to
    public var localAddress: SocketAddress? {
        _localAddress
    }

    /// Stream of incoming connections (server mode)
    public var incomingConnections: AsyncStream<any QUICConnectionProtocol> {
        AsyncStream { continuation in
            self.incomingConnectionContinuation = continuation
        }
    }

    // MARK: - Client API

    /// Dials a remote QUIC server and waits for handshake completion
    ///
    /// This method creates a socket, starts the packet I/O loop, connects to
    /// the server, and waits for the TLS handshake to complete before returning.
    ///
    /// - Parameters:
    ///   - address: The server address
    ///   - timeout: Maximum time to wait for handshake (default 30 seconds)
    /// - Returns: The established connection (handshake complete)
    /// - Throws: QUICEndpointError if connection or handshake fails
    ///
    /// ## Usage
    /// ```swift
    /// let endpoint = QUICEndpoint(configuration: config)
    /// let connection = try await endpoint.dial(address: serverAddress)
    /// // Connection is now established and ready to use
    /// let stream = try await connection.openStream()
    /// ```
    public func dial(
        address: SocketAddress,
        timeout: Duration = .seconds(30)
    ) async throws -> any QUICConnectionProtocol {
        guard !isServer else {
            throw QUICEndpointError.serverCannotConnect
        }

        // Create socket with a random local port
        let socket = NIOQUICSocket(configuration: .unicast(port: 0))
        try await socket.start()

        // Set socket directly before running to avoid race condition
        // (run() also sets this but we need it immediately for send())
        self.socket = socket
        self.isRunning = true

        // Start I/O loop in background task
        let runTask = Task { [self] in
            try await runPacketLoop(socket: socket)
        }

        // connect() is the low-level API that returns immediately after
        // sending the Initial packet. We then await handshake completion
        // and race it against a timeout using a task group.
        let connection = try await connect(to: address)

        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                // Task 1: wait for handshake completion
                group.addTask {
                    try await connection.waitForHandshake()
                }

                // Task 2: timeout sentinel
                group.addTask {
                    try await Task.sleep(for: timeout)
                    throw QUICEndpointError.handshakeTimeout
                }

                // First task to finish wins; cancel the other
                try await group.next()
                group.cancelAll()
            }
            return connection
        } catch {
            // On failure (timeout or connect error), tear down the I/O loop
            runTask.cancel()
            await socket.stop()
            throw error
        }
    }

    /// Connects to a remote QUIC server
    /// - Parameter address: The server address
    /// - Returns: The established connection
    public func connect(to address: SocketAddress) async throws -> any QUICConnectionProtocol {
        guard !isServer else {
            throw QUICEndpointError.serverCannotConnect
        }

        // Generate connection IDs
        // Note: length 8 is always valid (0-20 allowed), so random() will never return nil
        guard let sourceConnectionID = ConnectionID.random(length: 8),
              let destinationConnectionID = ConnectionID.random(length: 8) else {
            throw QUICError.internalError("Failed to generate connection IDs")
        }

        // Create TLS provider (fails if not configured)
        let tlsProvider = try createTLSProvider(isClient: true)

        // Create transport parameters from configuration
        let transportParameters = TransportParameters(from: configuration, sourceConnectionID: sourceConnectionID)

        // Create connection
        let connection = ManagedConnection(
            role: .client,
            version: configuration.version,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: destinationConnectionID,
            transportParameters: transportParameters,
            tlsProvider: tlsProvider,
            localAddress: _localAddress,
            remoteAddress: address
        )

        // Set callback for NEW_CONNECTION_ID frames
        connection.setNewConnectionIDCallback { [weak router, weak connection] cid in
            guard let router = router, let connection = connection else { return }
            router.register(connection, for: [cid])
        }

        // Register connection
        router.register(connection)
        timerManager.register(connection)

        // Initialize sendSignal stream before starting the loop
        // This ensures the continuation is set up before any writes can occur
        let sendSignal = connection.sendSignal

        // Start outbound send loop for this connection
        // This runs in the background and monitors sendSignal to send packets
        // when stream data is written
        if let socket = self.socket {
            Task { [weak self] in
                guard let self = self else { return }
                await self.outboundSendLoop(connection: connection, sendSignal: sendSignal, socket: socket)
            }
        }

        // Start handshake
        let initialPackets = try await connection.start()

        // Send initial packets
        for packet in initialPackets {
            try await send(packet, to: address)
        }

        // Low-level API: return immediately after sending Initial packets.
        // The caller is responsible for driving the packet loop and, if
        // desired, calling connection.waitForHandshake() explicitly.
        // The high-level dial() API handles this automatically.

        return connection
    }

    // MARK: - 0-RTT Client API

    /// Connects to a remote QUIC server with 0-RTT early data
    ///
    /// Attempts to use a cached session for 0-RTT early data. If a valid session
    /// is found, the client will send Initial + 0-RTT packets in the first flight.
    ///
    /// - Parameters:
    ///   - address: The server address
    ///   - earlyData: Data to send as 0-RTT (optional, can send later via stream)
    ///   - sessionCache: Client session cache for retrieving stored sessions
    /// - Returns: Tuple of (connection, earlyDataAccepted)
    /// - Throws: QUICEndpointError or connection errors
    ///
    /// ## Usage
    /// ```swift
    /// let sessionCache = ClientSessionCache()
    /// // ... store sessions from previous connections ...
    ///
    /// let (connection, accepted) = try await endpoint.connectWith0RTT(
    ///     to: serverAddress,
    ///     earlyData: requestData,
    ///     sessionCache: sessionCache
    /// )
    ///
    /// if !accepted {
    ///     // 0-RTT was rejected, resend data on 1-RTT
    ///     try await stream.write(requestData)
    /// }
    /// ```
    public func connectWith0RTT(
        to address: SocketAddress,
        earlyData: Data? = nil,
        sessionCache: ClientSessionCache
    ) async throws -> (connection: any QUICConnectionProtocol, earlyDataAccepted: Bool) {
        guard !isServer else {
            throw QUICEndpointError.serverCannotConnect
        }

        // Try to retrieve a session that supports early data
        let serverIdentity = "\(address.ipAddress):\(address.port)"
        let cachedSession = sessionCache.retrieveForEarlyData(for: serverIdentity)

        if let session = cachedSession, session.supportsEarlyData {
            // Connect with 0-RTT using cached session
            return try await connectWithSession(
                to: address,
                session: session,
                earlyData: earlyData,
                sessionCache: sessionCache
            )
        } else {
            // No valid session for 0-RTT, fall back to regular connection
            let connection = try await connect(to: address)
            try await connection.waitForHandshake()
            return (connection, false)
        }
    }

    /// Connects using a cached session (internal implementation)
    private func connectWithSession(
        to address: SocketAddress,
        session: ClientSessionCache.CachedSession,
        earlyData: Data?,
        sessionCache: ClientSessionCache
    ) async throws -> (connection: any QUICConnectionProtocol, earlyDataAccepted: Bool) {
        // Generate connection IDs
        // Note: length 8 is always valid (0-20 allowed), so random() will never return nil
        guard let sourceConnectionID = ConnectionID.random(length: 8),
              let destinationConnectionID = ConnectionID.random(length: 8) else {
            throw QUICError.internalError("Failed to generate connection IDs")
        }

        // Create TLS provider with session ticket for resumption (fails if not configured)
        let tlsProvider = try createTLSProvider(
            isClient: true,
            sessionTicket: session.ticket.ticket,
            maxEarlyDataSize: session.maxEarlyDataSize
        )

        // Create transport parameters from configuration
        let transportParameters = TransportParameters(from: configuration, sourceConnectionID: sourceConnectionID)

        // Create connection with 0-RTT support
        let connection = ManagedConnection(
            role: .client,
            version: configuration.version,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: destinationConnectionID,
            transportParameters: transportParameters,
            tlsProvider: tlsProvider,
            localAddress: _localAddress,
            remoteAddress: address
        )

        // Register connection
        router.register(connection)
        timerManager.register(connection)

        // Initialize sendSignal stream before starting the loop
        let sendSignal = connection.sendSignal

        // Start outbound send loop for this connection
        if let socket = self.socket {
            Task { [weak self] in
                guard let self = self else { return }
                await self.outboundSendLoop(connection: connection, sendSignal: sendSignal, socket: socket)
            }
        }

        // Start handshake with 0-RTT
        let (initialPackets, zeroRTTPackets) = try await connection.startWith0RTT(
            session: session,
            earlyData: earlyData
        )

        // Send initial packets
        for packet in initialPackets {
            try await send(packet, to: address)
        }

        // Send 0-RTT packets
        for packet in zeroRTTPackets {
            try await send(packet, to: address)
        }

        // Await handshake completion, then report actual 0-RTT acceptance
        // from the TLS provider (set after EncryptedExtensions is processed).
        try await connection.waitForHandshake()
        return (connection, connection.is0RTTAccepted)
    }

    // MARK: - Packet Processing

    /// Processes an incoming packet
    /// - Parameters:
    ///   - data: The packet data
    ///   - remoteAddress: Where the packet came from
    /// - Returns: Outbound packets to send
    public func processIncomingPacket(_ data: Data, from remoteAddress: SocketAddress) async throws -> [Data] {
        // Check for Version Negotiation packet first (version == 0 in long header)
        // RFC 9000 Section 6: Version Negotiation packets are special and must be
        // handled before normal routing
        if VersionNegotiator.isVersionNegotiationPacket(data) {
            try await handleVersionNegotiationPacket(data, from: remoteAddress)
            return []  // VN packets don't generate responses
        }

        // Route the packet
        switch router.route(data: data, from: remoteAddress) {
        case .routed(let connection):
            // Process packet through the connection
            timerManager.recordActivity(for: connection)
            let responses = try await connection.processDatagram(data)

            // Send responses
            for response in responses {
                try await send(response, to: remoteAddress)
            }

            // Check if this connection was pending handshake completion.
            // Multi-round-trip handshakes (e.g. TLS 1.3 with HRR) may
            // require several packets before isEstablished becomes true.
            let connID = ObjectIdentifier(connection)
            if pendingConnections.contains(connID) && connection.isEstablished {
                pendingConnections.remove(connID)
                incomingConnectionContinuation?.yield(connection)
            }

            return responses

        case .newConnection(let info):
            // Server: Create new connection for Initial packet
            guard isServer else {
                throw QUICEndpointError.unexpectedPacket
            }

            let connection = try await handleNewConnection(info: info)
            let responses = try await connection.processDatagram(data)

            // Send responses
            for response in responses {
                try await send(response, to: remoteAddress)
            }

            // Yield to incomingConnections AFTER processDatagram completes.
            // processDatagram processes the client's Initial CRYPTO frame,
            // runs TLS, and (for most handshakes) completes the server-side
            // handshake — which installs peer transport parameters and sets
            // stream limits.  Yielding before this point causes higher layers
            // (e.g. HTTP/3) to race and fail with streamLimitReached because
            // peer limits are still 0.
            if connection.isEstablished {
                incomingConnectionContinuation?.yield(connection)
            } else {
                // Multi-round-trip handshake (rare with MockTLS, possible with
                // real TLS 1.3 + HRR).  Track as pending — it will be yielded
                // in the .routed branch once the handshake completes on a
                // subsequent packet.
                pendingConnections.insert(ObjectIdentifier(connection))
            }

            return responses

        case .notFound(let dcid):
            throw QUICEndpointError.connectionNotFound(dcid)

        case .invalid(let error):
            throw error
        }
    }

    /// Handles a new incoming connection (server mode)
    private func handleNewConnection(info: ConnectionRouter.IncomingConnectionInfo) async throws -> ManagedConnection {
        // Generate our source connection ID
        // Note: length 8 is always valid (0-20 allowed), so random() will never return nil
        guard let sourceConnectionID = ConnectionID.random(length: 8) else {
            throw QUICError.internalError("Failed to generate connection ID")
        }

        // Create TLS provider (fails if not configured)
        let tlsProvider = try createTLSProvider(isClient: false)

        // Create transport parameters from configuration
        // For servers, we MUST include original_destination_connection_id (RFC 9000 Section 18.2)
        let transportParameters = TransportParameters(
            from: configuration,
            sourceConnectionID: sourceConnectionID,
            originalDestinationConnectionID: info.destinationConnectionID
        )

        // Create connection
        // For servers:
        // - sourceConnectionID: Our randomly chosen SCID
        // - destinationConnectionID: Client's SCID (for future packets to the client)
        // - originalConnectionID: DCID from client's Initial (for Initial key derivation)
        let connection = ManagedConnection(
            role: .server,
            version: configuration.version,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: info.sourceConnectionID,
            originalConnectionID: info.destinationConnectionID,
            transportParameters: transportParameters,
            tlsProvider: tlsProvider,
            localAddress: _localAddress,
            remoteAddress: info.remoteAddress
        )

        // Register with both our SCID and the client's DCID
        router.register(connection, for: [
            sourceConnectionID,
            info.destinationConnectionID
        ])
        timerManager.register(connection)

        // Initialize sendSignal stream before starting the loop
        // This ensures the continuation is set up before any writes can occur
        let sendSignal = connection.sendSignal

        // Start outbound send loop for this connection
        // This runs in the background and monitors sendSignal to send packets
        // when stream data is written
        if let socket = self.socket {
            Task { [weak self] in
                guard let self = self else { return }
                await self.outboundSendLoop(connection: connection, sendSignal: sendSignal, socket: socket)
            }
        }

        // Start handshake (server doesn't send first)
        _ = try await connection.start()

        // NOTE: Do NOT yield to incomingConnectionContinuation here.
        // The handshake is not yet complete — peer transport parameters
        // have not been received, so stream limits are all 0.
        // If we yield now, higher layers (e.g. HTTP/3) will race to open
        // streams and fail with streamLimitReached.
        //
        // Instead, the caller (processIncomingPacket) will yield the
        // connection AFTER processDatagram() completes the handshake.

        return connection
    }

    // MARK: - Version Negotiation

    /// Handles a Version Negotiation packet
    ///
    /// RFC 9000 Section 6.2: When a client receives a Version Negotiation packet,
    /// it must validate the packet and may retry with a different version.
    ///
    /// - Parameters:
    ///   - data: The Version Negotiation packet data
    ///   - remoteAddress: Where the packet came from
    private func handleVersionNegotiationPacket(_ data: Data, from remoteAddress: SocketAddress) async throws {
        // Only clients process Version Negotiation packets
        guard !isServer else {
            // Servers ignore VN packets (RFC 9000 Section 6)
            return
        }

        // Find the connection that might be waiting for a response from this address
        // VN packets have DCID = our SCID and SCID = our DCID
        guard data.count >= 7 else { return }

        // Extract DCID from VN packet (which should be our SCID)
        let dcidLength = Int(data[5])
        guard dcidLength <= ConnectionID.maxLength else { return }
        guard data.count >= 6 + dcidLength else { return }
        let dcidBytes = data[6..<(6 + dcidLength)]
        let vnDCID = try ConnectionID(bytes: dcidBytes)  // Slice is already Data

        // Try to find a connection with this SCID
        guard let connection = router.connection(for: vnDCID) else {
            // No connection found - possibly spoofed packet
            return
        }

        // RFC 9000 Section 6.2: A client MUST discard any Version Negotiation packet
        // if it has received and successfully processed any other packet
        // (This check should be done in the connection)
        if await connection.hasReceivedValidPacket {
            return  // Discard late VN packets
        }

        // Validate and parse the packet
        let offeredVersions: [QUICVersion]
        do {
            offeredVersions = try VersionNegotiator.validateAndParseVersionNegotiation(
                data,
                originalDCID: connection.destinationConnectionID,
                originalSCID: connection.sourceConnectionID
            )
        } catch {
            // Invalid VN packet, discard
            return
        }

        // Try to select a common version
        if let newVersion = VersionNegotiator.selectVersion(
            offered: offeredVersions,
            supported: QUICVersion.supportedVersions
        ) {
            // We can retry with the new version
            try await connection.retryWithVersion(newVersion)
        } else {
            // No common version - close connection gracefully
            // RFC 9000: This isn't a protocol error, just an incompatibility
            await connection.close(error: nil)
            logger.debug("UNREGISTER from handleVersionNegotiationPacket for SCID=\(connection.sourceConnectionID)")
            router.unregister(connection)
            timerManager.markClosed(connection)
        }
    }

    // MARK: - Timer Processing

    /// Processes expired timers
    /// - Returns: Any packets that need to be sent
    public func processTimers() async throws -> [(Data, SocketAddress)] {
        var outbound: [(Data, SocketAddress)] = []

        let events = timerManager.processTimers()
        for event in events {
            switch event {
            case .sendAck(let connection), .lossDetection(let connection), .probe(let connection):
                let packets = try connection.onTimerExpired()
                for packet in packets {
                    outbound.append((packet, connection.remoteAddress))
                }

            case .idleTimeout(let connection):
                // Close connection due to idle timeout
                await connection.close(error: nil)
                logger.info("Idle timeout: UNREGISTER for SCID=\(connection.sourceConnectionID)")
                router.unregister(connection)
                timerManager.markClosed(connection)
            }
        }

        return outbound
    }

    /// Gets the next timer deadline
    public func nextTimerDeadline() -> ContinuousClock.Instant? {
        timerManager.nextDeadline()
    }

    // MARK: - Event Loop

    /// Runs the main event loop (for testing)
    /// Call this with incoming packets and it will process them
    public func runOnce(
        incoming: [(data: Data, address: SocketAddress)]
    ) async throws -> [(data: Data, address: SocketAddress)] {
        var outgoing: [(data: Data, address: SocketAddress)] = []

        // Process incoming packets
        for (data, address) in incoming {
            do {
                let responses = try await processIncomingPacket(data, from: address)
                for response in responses {
                    outgoing.append((response, address))
                }
            } catch {
                // Log error but continue processing
                logger.warning("Error processing packet: \(error)")
            }
        }

        // Process timers
        let timerPackets = try await processTimers()
        outgoing.append(contentsOf: timerPackets)

        return outgoing
    }

    // MARK: - UDP I/O Loop

    /// Runs the main I/O loop with a real UDP socket
    ///
    /// This method starts the event loop that:
    /// - Receives UDP datagrams from the socket
    /// - Processes them through the QUIC state machine
    /// - Sends response packets
    /// - Handles timer events
    ///
    /// The loop runs until `stop()` is called.
    ///
    /// - Parameter socket: The UDP socket to use for I/O
    /// - Throws: QUICEndpointError.alreadyRunning if already running
    public func run(socket: any QUICSocket) async throws {
        guard !isRunning else {
            throw QUICEndpointError.alreadyRunning
        }

        self.socket = socket
        self.isRunning = true
        self.shouldStop = false

        // Start the socket
        try await socket.start()

        // Update local address
        if let nioAddr = await socket.localAddress,
           let addr = SocketAddress(nioAddr) {
            _localAddress = addr
        }

        // Start the I/O loop with cancellation handling
        await withTaskCancellationHandler {
            await withTaskGroup(of: Void.self) { group in
                // Packet receiving task
                group.addTask {
                    await self.packetReceiveLoop(socket: socket)
                }

                // Timer processing task
                group.addTask {
                    await self.timerProcessingLoop(socket: socket)
                }

                // Wait for both tasks to complete
                await group.waitForAll()
            }
        } onCancel: {
            // When the task is cancelled, stop the socket to unblock the I/O loops
            Task { [socket] in
                await socket.stop()
            }
        }

        // Cleanup
        if !shouldStop {
            // Only stop socket if not already stopped by stop()
            await socket.stop()
        }
        self.socket = nil
        self.isRunning = false
    }

    /// Internal method to run packet loop without setup (for use by dial())
    ///
    /// - Parameter socket: The already-started socket
    private func runPacketLoop(socket: any QUICSocket) async throws {
        self.shouldStop = false

        // Update local address
        if let nioAddr = await socket.localAddress,
           let addr = SocketAddress(nioAddr) {
            _localAddress = addr
        }

        // Start the I/O loop with cancellation handling
        await withTaskCancellationHandler {
            await withTaskGroup(of: Void.self) { group in
                // Packet receiving task
                group.addTask {
                    await self.packetReceiveLoop(socket: socket)
                }

                // Timer processing task
                group.addTask {
                    await self.timerProcessingLoop(socket: socket)
                }

                // Wait for both tasks to complete
                await group.waitForAll()
            }
        } onCancel: {
            // When the task is cancelled, stop the socket to unblock the I/O loops
            Task { [socket] in
                await socket.stop()
            }
        }

        // Cleanup
        if !shouldStop {
            await socket.stop()
        }
        self.socket = nil
        self.isRunning = false
    }

    /// Stops the I/O loop
    ///
    /// This method signals the I/O tasks to stop and finishes the socket's
    /// incoming stream, allowing the packet receive loop to exit gracefully.
    public func stop() async {
        guard isRunning else { return }
        shouldStop = true

        // Finish the incoming connections stream
        incomingConnectionContinuation?.finish()
        incomingConnectionContinuation = nil

        // Stop the socket to finish its AsyncStream
        // This will cause the packetReceiveLoop's for-await to exit
        if let socket = socket {
            await socket.stop()
        }
    }

    /// The packet receive loop
    private func packetReceiveLoop(socket: any QUICSocket) async {
        for await packet in socket.incomingPackets {
            guard !shouldStop else { break }

            // Convert NIO address to QUIC address
            guard let remoteAddress = SocketAddress(packet.remoteAddress) else {
                continue
            }

            do {
                let responses = try await processIncomingPacket(packet.data, from: remoteAddress)
                for response in responses {
                    try await socket.send(response, to: packet.remoteAddress)
                }
            } catch {
                logger.warning("Error processing packet from \(remoteAddress): \(error)")
            }
        }
    }

    /// The outbound send loop for a connection
    ///
    /// Monitors the connection's sendSignal and sends packets when data is available.
    /// This enables immediate packet transmission when stream data is written,
    /// rather than waiting for incoming packets or timer events.
    ///
    /// The loop exits when:
    /// - The connection is shut down (sendSignal finishes)
    /// - The endpoint stops (shouldStop becomes true)
    ///
    /// - Parameters:
    ///   - connection: The connection to monitor
    ///   - sendSignal: The pre-initialized send signal stream
    ///   - socket: The socket to send packets through
    private func outboundSendLoop(
        connection: ManagedConnection,
        sendSignal: AsyncStream<Void>,
        socket: any QUICSocket
    ) async {
        logger.debug("outboundSendLoop STARTED for connection SCID=\(connection.sourceConnectionID)")
        var iterationCount = 0
        for await _ in sendSignal {
            iterationCount += 1
            logger.trace("outboundSendLoop signal #\(iterationCount) for SCID=\(connection.sourceConnectionID), shouldStop=\(shouldStop)")
            guard !shouldStop else { logger.debug("outboundSendLoop breaking due to shouldStop"); break }

            do {
                // Generate packets from pending stream data
                let packets = try connection.generateOutboundPackets()
                if !packets.isEmpty {
                    logger.trace("Sending \(packets.count) packets (total \(packets.map(\.count).reduce(0, +)) bytes)")
                }

                // Send each packet
                for packet in packets {
                    let nioAddress = try connection.remoteAddress.toNIOAddress()
                    try await socket.send(packet, to: nioAddress)
                    logger.trace("Sent packet: \(packet.count) bytes")
                }
            } catch {
                // Log error but continue - don't break the loop for transient errors
                logger.warning(
                    "Failed to send outbound packets",
                    metadata: [
                        "error": "\(error)",
                        "remoteAddress": "\(connection.remoteAddress)"
                    ]
                )
            }
        }

        // Loop ended: sendSignal was finished (connection closing or endpoint stopping).
        // Flush any final queued packets — in particular the CONNECTION_CLOSE frame
        // that handler.close() queued just before shutdown() finished the signal.
        // Without this flush the peer never learns the connection was closed and
        // keeps sending packets to a DCID that we are about to unregister.
        do {
            let finalPackets = try connection.generateOutboundPackets()
            if !finalPackets.isEmpty {
                logger.debug("outboundSendLoop flushing \(finalPackets.count) final packets for SCID=\(connection.sourceConnectionID)")
                for packet in finalPackets {
                    let nioAddress = try connection.remoteAddress.toNIOAddress()
                    try await socket.send(packet, to: nioAddress)
                }
            }
        } catch {
            // Best-effort — if we can't send the final packets, just log and proceed
            logger.warning(
                "Failed to flush final packets on connection close",
                metadata: [
                    "error": "\(error)",
                    "remoteAddress": "\(connection.remoteAddress)"
                ]
            )
        }

        logger.debug("outboundSendLoop EXITED for connection SCID=\(connection.sourceConnectionID) after \(iterationCount) iterations, shouldStop=\(shouldStop)")
        router.unregister(connection)
        timerManager.markClosed(connection)
    }

    /// The timer processing loop
    private func timerProcessingLoop(socket: any QUICSocket) async {
        while !shouldStop {
            // Calculate time until next timer
            let nextDeadline = timerManager.nextDeadline()
            let waitDuration: Duration

            if let deadline = nextDeadline {
                let now = ContinuousClock.now
                if deadline <= now {
                    waitDuration = .zero
                } else {
                    waitDuration = deadline - now
                }
            } else {
                // No active timers, wait for a reasonable interval
                waitDuration = .milliseconds(100)
            }

            // Wait until next timer or timeout
            do {
                try await Task.sleep(for: waitDuration)
            } catch {
                // Task was cancelled
                break
            }

            // Process timer events
            do {
                let packets = try await processTimers()
                for (data, address) in packets {
                    let nioAddress = try address.toNIOAddress()
                    try await socket.send(data, to: nioAddress)
                }
            } catch {
                // Log error but continue
            }
        }
    }

    // MARK: - Send Callback

    /// Sets a callback for sending packets (for testing)
    public func setSendCallback(_ callback: @escaping @Sendable (Data, SocketAddress) async throws -> Void) {
        sendCallback = callback
    }

    /// Sends a packet
    private func send(_ data: Data, to address: SocketAddress) async throws {
        if let socket = socket {
            // Use the real socket - convert to NIO address
            let nioAddress = try address.toNIOAddress()
            try await socket.send(data, to: nioAddress)
        } else if let callback = sendCallback {
            // Use the callback (for testing)
            try await callback(data, address)
        }
        // If neither, packets are silently dropped (useful for unit testing)
    }

    // MARK: - Connection Management

    /// Closes all connections
    ///
    /// Note: Actual cleanup (router unregister, timer manager) happens
    /// when each connection's outboundSendLoop ends after shutdown.
    public func closeAll() async {
        for connection in router.allConnections {
            await connection.close(error: nil)
        }
    }

    /// Number of active connections
    public var connectionCount: Int {
        router.connectionCount
    }

    /// Gets a connection by its ID
    public func connection(for connectionID: ConnectionID) -> ManagedConnection? {
        router.connection(for: connectionID)
    }
}

// MARK: - Errors

/// Errors from QUICEndpoint
public enum QUICEndpointError: Error, Sendable {
    /// Server endpoint cannot initiate connections
    case serverCannotConnect

    /// Connection not found for the given DCID
    case connectionNotFound(ConnectionID)

    /// Unexpected packet received
    case unexpectedPacket

    /// Endpoint is already running
    case alreadyRunning

    /// Endpoint is not running
    case notRunning

    /// Handshake timed out
    case handshakeTimeout
}
