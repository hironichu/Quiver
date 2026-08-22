/// QUICEndpoint — Client Operations
///
/// Extension containing client-side connection logic:
/// - `dial` — connects and waits for handshake completion
/// - `connect` — low-level connect (returns before handshake completes)
/// - `connectWith0RTT` — connects with 0-RTT early data
/// - `connectWithSession` — connects using a cached TLS session

import Foundation
import QUICCore
import QUICCrypto
import QUICConnection
@_exported import QUICTransport
import NIOUDPTransport
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Learn the route-correct local source address for `targetIP` the way a
/// connected socket (TCP / URLSession) does: open a throwaway connected UDP
/// socket, let the kernel run route + source-address selection, read it back
/// with `getsockname()`, and discard the socket. No packets are sent.
///
/// Why: an unconnected, wildcard-bound (`::` / `0.0.0.0`) UDP socket defers
/// source selection to per-packet send time. On a multi-homed host — notably
/// the iOS Simulator, which bridges `en0` while a destination's route may be
/// scoped to another interface (`en7`) — that selection picks the wrong source
/// and the QUIC Initials never get a reply (handshakeTimeout). Binding the real
/// socket to the source a *connected* probe resolves makes the unconnected
/// socket egress correctly. Returns nil if the probe fails, so the caller falls
/// back to the wildcard and single-homed hosts see identical behavior.
func routeCorrectSourceAddress(targetIP: String, targetPort: UInt16, isIPv6: Bool) -> String? {
    let fd = socket(isIPv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0)
    guard fd >= 0 else { return nil }
    defer { close(fd) }
    let port = targetPort.bigEndian

    if isIPv6 {
        var dst = sockaddr_in6()
        dst.sin6_family = sa_family_t(AF_INET6)
        dst.sin6_port = port
        guard inet_pton(AF_INET6, targetIP, &dst.sin6_addr) == 1 else { return nil }
        let connected = withUnsafePointer(to: &dst) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard connected == 0 else { return nil }
        var src = sockaddr_in6()
        var len = socklen_t(MemoryLayout<sockaddr_in6>.size)
        let named = withUnsafeMutablePointer(to: &src) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        guard named == 0 else { return nil }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &src.sin6_addr, &buf, socklen_t(buf.count)) != nil else { return nil }
        return String(cString: buf)
    } else {
        var dst = sockaddr_in()
        dst.sin_family = sa_family_t(AF_INET)
        dst.sin_port = port
        guard inet_pton(AF_INET, targetIP, &dst.sin_addr) == 1 else { return nil }
        let connected = withUnsafePointer(to: &dst) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else { return nil }
        var src = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &src) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        guard named == 0 else { return nil }
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &src.sin_addr, &buf, socklen_t(buf.count)) != nil else { return nil }
        return String(cString: buf)
    }
}

// MARK: - Client API

extension QUICEndpoint {

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

        // Validate configuration consistency before creating the socket
        try configuration.validate()

        // Create socket with a random local port, using configured buffer sizes
        let socketConfig = configuration.socketConfiguration
        let isV6 = address.ipAddress.contains(":")
        // Bind to the route-correct source the kernel would pick for a *connected*
        // socket (see routeCorrectSourceAddress). On single-homed hosts this equals
        // the address an unconnected wildcard socket would have used, so behavior is
        // unchanged; on multi-homed hosts / the iOS Simulator it fixes the source
        // selection that otherwise drops the QUIC Initials (handshakeTimeout). Falls
        // back to the wildcard in the target family if the probe fails.
        let bindHost = routeCorrectSourceAddress(targetIP: address.ipAddress, targetPort: address.port, isIPv6: isV6)
            ?? (isV6 ? "::" : "0.0.0.0")
        let udpConfig = UDPConfiguration(
            bindAddress: .specific(host: bindHost, port: 0),  // bind in the target family (IPv6-only servers)
            reuseAddress: false,
            receiveBufferSize: socketConfig.receiveBufferSize ?? 65536,
            sendBufferSize: socketConfig.sendBufferSize ?? 65536,
            maxDatagramSize: socketConfig.maxDatagramSize,
            enableECN: socketConfig.enableECN
        )

        // Determine address family from the target address for platform options
        let addrFamily: PlatformSocketOptions.AddressFamily =
            address.ipAddress.contains(":") ? .ipv6 : .ipv4
        let platformOpts = PlatformSocketOptions.forQUIC(
            addressFamily: addrFamily,
            enableECN: socketConfig.enableECN,
            enableDF: socketConfig.enableDF
        )
        let socket = NIOQUICSocket(configuration: udpConfig, platformOptions: platformOpts)
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
            // On failure (timeout or connect error), shut down the connection
            // first so its sendSignal stream finishes and the outboundSendLoop
            // can exit cleanly *before* we tear down the socket.
            if let managed = connection as? ManagedConnection {
                managed.shutdown()
            }
            runTask.cancel()
            await socket.stop()
            throw error
        }
    }

    /// Connects to a remote QUIC server
    ///
    /// - Parameter address: The server address
    /// - Returns: The established connection
    ///
    /// ## Concurrency Safety
    ///
    /// The `connect` → `register` → `start` → `send Initial` sequence is safe
    /// against incoming packets arriving for the new connection's DCID before
    /// the handshake begins. Because `QUICEndpoint` is an `actor`, both this
    /// method and the packet-receive path (`processIncomingPacket`) are
    /// actor-isolated and therefore cannot interleave. The router registration
    /// happens *before* the first Initial packet is sent, so by the time any
    /// response packet could arrive and be routed, the connection is fully
    /// registered and initialized.
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
            congestionControllerFactory: configuration.congestionControllerFactory,
            localAddress: _localAddress,
            remoteAddress: address,
            maxDatagramSize: configuration.maxUDPPayloadSize
        )

        // Enable ECN if the socket was created with ECN support
        if let nioSocket = self.socket as? NIOQUICSocket,
           nioSocket.platformOptions?.ecnEnabled == true {
            connection.enableECN()
        }

        // Enable DPLPMTUD if the socket has the DF bit set
        if let nioSocket = self.socket as? NIOQUICSocket,
           nioSocket.platformOptions?.dfEnabled == true {
            connection.enablePMTUD()
        }

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
    func connectWithSession(
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
            congestionControllerFactory: configuration.congestionControllerFactory,
            localAddress: _localAddress,
            remoteAddress: address,
            maxDatagramSize: configuration.maxUDPPayloadSize
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
}