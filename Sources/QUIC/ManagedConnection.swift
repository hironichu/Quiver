/// Managed Connection
///
/// High-level connection wrapper that orchestrates handshake, packet processing,
/// and stream management. Implements QUICConnectionProtocol for public API.

import Foundation
import Logging
import Synchronization
import QUICCore
import QUICCrypto
import QUICConnection
import QUICStream
import QUICRecovery

// MARK: - Handshake State

/// Connection handshake state
public enum HandshakeState: Sendable, Equatable {
    /// Connection not yet started
    case idle

    /// Client: Initial packet sent, waiting for server response
    /// Server: Not applicable
    case connecting

    /// Server: Initial received, handshake in progress
    /// Client: Handshake packets being exchanged
    case handshakeInProgress

    /// Handshake complete, connection established
    case established

    /// Connection is closing
    case closing

    /// Connection is closed
    case closed
}

// MARK: - Managed Connection

/// High-level managed connection for QUIC
///
/// Wraps QUICConnectionHandler and provides:
/// - Handshake state machine
/// - Packet encryption/decryption via PacketProcessor
/// - TLS 1.3 integration
/// - Stream management via QUICConnectionProtocol
/// - Anti-amplification limit enforcement (RFC 9000 Section 8.1)
public final class ManagedConnection: Sendable {
    private static let logger = Logger(label: "quic.connection.managed")

    // MARK: - Properties

    /// Connection handler (low-level orchestration)
    private let handler: QUICConnectionHandler

    /// Packet processor (encryption/decryption)
    private let packetProcessor: PacketProcessor

    /// TLS provider
    private let tlsProvider: any TLS13Provider

    /// Anti-amplification limiter (RFC 9000 Section 8.1)
    /// Servers must not send more than 3x bytes received until address is validated
    private let amplificationLimiter: AntiAmplificationLimiter

    /// Path validation manager for connection migration (RFC 9000 Section 9.3)
    private let pathValidationManager: PathValidationManager

    /// Connection ID manager for connection migration (RFC 9000 Section 9.5)
    private let connectionIDManager: ConnectionIDManager

    /// Internal state
    private let state: Mutex<ManagedConnectionState>

    /// State for stream read continuations
    private struct StreamContinuationsState: Sendable {
        var continuations: [UInt64: CheckedContinuation<Data, any Error>] = [:]
        /// Buffer for stream data received before read() is called
        var pendingData: [UInt64: [Data]] = [:]
        var isShutdown: Bool = false
        /// Streams whose receive side is complete (FIN received, all data read).
        /// Reads on these streams return empty `Data` to signal end-of-stream.
        var finishedStreams: Set<UInt64> = []
    }

    /// Stream continuations for async stream API
    private let streamContinuationsState: Mutex<StreamContinuationsState>

    /// State for incoming stream AsyncStream (lazy initialization pattern)
    private struct IncomingStreamState: Sendable {
        var continuation: AsyncStream<any QUICStreamProtocol>.Continuation?
        var stream: AsyncStream<any QUICStreamProtocol>?
        var isShutdown: Bool = false
        /// Buffer for streams that arrive before incomingStreams is accessed
        var pendingStreams: [any QUICStreamProtocol] = []
    }
    private let incomingStreamState: Mutex<IncomingStreamState>

    /// State for incoming datagram AsyncStream (RFC 9221)
    private struct IncomingDatagramState: Sendable {
        var continuation: AsyncStream<Data>.Continuation?
        var stream: AsyncStream<Data>?
        var isShutdown: Bool = false
        /// Buffer for datagrams that arrive before incomingDatagrams is accessed
        var pendingDatagrams: [Data] = []
    }
    private let incomingDatagramState: Mutex<IncomingDatagramState>

    /// State for session ticket stream (lazy initialization pattern)
    private struct SessionTicketState: Sendable {
        var continuation: AsyncStream<NewSessionTicketInfo>.Continuation?
        var stream: AsyncStream<NewSessionTicketInfo>?
        var isShutdown: Bool = false
        /// Buffer for tickets that arrive before sessionTickets is accessed
        var pendingTickets: [NewSessionTicketInfo] = []
    }
    private let sessionTicketState: Mutex<SessionTicketState>

    /// Original connection ID (for Initial key derivation)
    /// This is the DCID from the first client Initial packet
    private let originalConnectionID: ConnectionID

    /// Transport parameters (stored for TLS)
    private let transportParameters: TransportParameters

    /// Local address
    public let localAddress: SocketAddress?

    /// Remote address
    public let remoteAddress: SocketAddress

    /// Closure called when a new connection ID is received
    /// Used to register the CID with the ConnectionRouter
    private let onNewConnectionID: Mutex<(@Sendable (ConnectionID) -> Void)?>

    // MARK: - Initialization

    /// Creates a new managed connection
    /// - Parameters:
    ///   - role: Connection role (client or server)
    ///   - version: QUIC version
    ///   - sourceConnectionID: Local connection ID
    ///   - destinationConnectionID: Remote connection ID
    ///   - originalConnectionID: Original DCID for Initial key derivation (defaults to destinationConnectionID)
    ///   - transportParameters: Transport parameters to use
    ///   - tlsProvider: TLS 1.3 provider
    ///   - localAddress: Local socket address (optional)
    ///   - remoteAddress: Remote socket address
    public init(
        role: ConnectionRole,
        version: QUICVersion,
        sourceConnectionID: ConnectionID,
        destinationConnectionID: ConnectionID,
        originalConnectionID: ConnectionID? = nil,
        transportParameters: TransportParameters,
        tlsProvider: any TLS13Provider,
        localAddress: SocketAddress? = nil,
        remoteAddress: SocketAddress
    ) {
        self.incomingDatagramState = Mutex(IncomingDatagramState())
        self.handler = QUICConnectionHandler(
            role: role,
            version: version,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: destinationConnectionID,
            transportParameters: transportParameters
        )
        self.packetProcessor = PacketProcessor(dcidLength: sourceConnectionID.length)
        self.tlsProvider = tlsProvider
        self.amplificationLimiter = AntiAmplificationLimiter(isServer: role == .server)
        self.pathValidationManager = PathValidationManager()
        self.connectionIDManager = ConnectionIDManager(
            activeConnectionIDLimit: transportParameters.activeConnectionIDLimit
        )
        self.localAddress = localAddress
        self.remoteAddress = remoteAddress
        // For clients, original DCID is the initial destination CID
        // For servers, original DCID is the DCID from the client's Initial packet
        self.originalConnectionID = originalConnectionID ?? destinationConnectionID
        self.transportParameters = transportParameters
        self.onNewConnectionID = Mutex(nil)  // Set later via setNewConnectionIDCallback
        var initialState = ManagedConnectionState(
            role: role,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: destinationConnectionID
        )
        initialState.currentRemoteAddress = remoteAddress
        self.state = Mutex(initialState)
        self.streamContinuationsState = Mutex(StreamContinuationsState())
        self.incomingStreamState = Mutex(IncomingStreamState())
        self.sessionTicketState = Mutex(SessionTicketState())

        // Set TLS provider on handler
        handler.setTLSProvider(tlsProvider)
    }

    // MARK: - Connection ID Management

    /// Sets the callback for new connection IDs
    /// - Parameter callback: Closure to call when a NEW_CONNECTION_ID frame is received
    public func setNewConnectionIDCallback(_ callback: (@Sendable (ConnectionID) -> Void)?) {
        onNewConnectionID.withLock { $0 = callback }
    }

    // MARK: - Connection Lifecycle

    /// Starts the connection handshake
    /// - Returns: Initial packets to send (for client)
    public func start() async throws -> [Data] {
        // Prevent double-start: check and set state atomically
        let role = try state.withLock { s -> ConnectionRole in
            guard s.handshakeState == .idle else {
                throw ManagedConnectionError.invalidState("Handshake already started")
            }
            s.handshakeState = .connecting
            return s.role
        }

        // Derive initial keys using the original connection ID
        // RFC 9001: Both client and server derive Initial keys from the
        // Destination Connection ID in the first Initial packet sent by the client
        // PacketProcessor is the single source of truth for crypto contexts
        let (_, _) = try packetProcessor.deriveAndInstallInitialKeys(
            connectionID: originalConnectionID,
            isClient: role == .client,
            version: handler.version
        )

        // Set transport parameters on TLS (use the stored parameters)
        let encodedParams = encodeTransportParameters(transportParameters)
        try tlsProvider.setLocalTransportParameters(encodedParams)

        // Start TLS handshake
        let outputs = try await tlsProvider.startHandshake(isClient: role == .client)

        // State was already set to connecting at the beginning of this method

        // Process TLS outputs
        return try await processTLSOutputs(outputs)
    }

    /// Starts the connection handshake with 0-RTT early data
    ///
    /// RFC 9001 Section 4.6.1: Client sends Initial + 0-RTT packets in first flight
    /// when resuming a session that supports early data.
    ///
    /// - Parameters:
    ///   - session: The cached session to use for resumption
    ///   - earlyData: Optional early data to send as 0-RTT
    /// - Returns: Tuple of (Initial packets, 0-RTT packets)
    public func startWith0RTT(
        session: ClientSessionCache.CachedSession,
        earlyData: Data?
    ) async throws -> (initialPackets: [Data], zeroRTTPackets: [Data]) {
        // Prevent double-start: check and set state atomically
        try state.withLock { s in
            guard s.handshakeState == .idle else {
                throw ManagedConnectionError.invalidState("Handshake already started")
            }
            guard s.role == .client else {
                throw QUICEarlyDataError.earlyDataNotSupported
            }
            s.handshakeState = .connecting
            s.is0RTTAttempted = true
        }

        // Derive initial keys using the original connection ID
        let (_, _) = try packetProcessor.deriveAndInstallInitialKeys(
            connectionID: originalConnectionID,
            isClient: true,
            version: handler.version
        )

        // Set transport parameters on TLS
        let encodedParams = encodeTransportParameters(transportParameters)
        try tlsProvider.setLocalTransportParameters(encodedParams)

        // Configure TLS for session resumption with 0-RTT
        // This must be done BEFORE startHandshake() so the ClientStateMachine
        // can derive 0-RTT keys using the correct ClientHello transcript hash
        try tlsProvider.configureResumption(
            ticket: session.sessionTicketData,
            attemptEarlyData: earlyData != nil
        )

        // Start TLS handshake (will include PSK extension for resumption)
        // The TLS provider will:
        // 1. Build ClientHello with PSK extension
        // 2. Derive early secret from PSK
        // 3. Compute ClientHello transcript hash
        // 4. Derive client_early_traffic_secret with correct transcript
        // 5. Return 0-RTT keys in the outputs
        let outputs = try await tlsProvider.startHandshake(isClient: true)

        // State was already set to connecting at the beginning of this method

        // Process TLS outputs (installs 0-RTT keys and generates Initial packets)
        let initialPackets = try await processTLSOutputs(outputs)

        // Generate 0-RTT packets with early data
        var zeroRTTPackets: [Data] = []
        if let data = earlyData, !data.isEmpty {
            // Open a stream for early data (stream ID 0 for client-initiated bidirectional)
            let streamID: UInt64 = 0
            handler.queueFrame(.stream(StreamFrame(
                streamID: streamID,
                offset: 0,
                data: data,
                fin: false
            )), level: .zeroRTT)

            // Generate 0-RTT packet
            let packets = try generate0RTTPackets()
            zeroRTTPackets.append(contentsOf: packets)
        }

        return (initialPackets, zeroRTTPackets)
    }

    /// Generates 0-RTT packets from queued frames
    private func generate0RTTPackets() throws -> [Data] {
        let outboundPackets = handler.getOutboundPackets()
        var result: [Data] = []

        for packet in outboundPackets where packet.level == .zeroRTT {
            let pn = handler.getNextPacketNumber(for: .zeroRTT)
            let header = build0RTTHeader(packetNumber: pn)

            let encrypted = try packetProcessor.encryptLongHeaderPacket(
                frames: packet.frames,
                header: header,
                packetNumber: pn,
                padToMinimum: false
            )
            result.append(encrypted)
        }

        return result
    }

    /// Builds a 0-RTT packet header
    private func build0RTTHeader(packetNumber: UInt64) -> LongHeader {
        let (scid, dcid) = state.withLock { ($0.sourceConnectionID, $0.destinationConnectionID) }
        return LongHeader(
            packetType: .zeroRTT,
            version: handler.version,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            packetNumber: packetNumber
        )
    }

    /// Processes an incoming packet
    /// - Parameter data: The encrypted packet data
    /// - Returns: Outbound packets to send in response
    public func processIncomingPacket(_ data: Data) async throws -> [Data] {
        // Record received bytes for anti-amplification limit
        amplificationLimiter.recordBytesReceived(UInt64(data.count))

        // RFC 9001 §5.8: Check for Retry packet and verify integrity tag
        // Retry packets use special handling - they don't use normal AEAD encryption
        if RetryIntegrityTag.isRetryPacket(data) {
            return try await processRetryPacket(data)
        }

        // Decrypt the packet
        let parsed = try packetProcessor.decryptPacket(data)

        // RFC 9000 Section 7.2: Client MUST update DCID to server's SCID from first Initial packet
        // This is critical for QUIC handshake: client uses server's SCID as DCID in all subsequent packets
        if parsed.encryptionLevel == .initial, case .long(let longHeader) = parsed.header {
            let (role, currentDCID) = state.withLock { ($0.role, $0.destinationConnectionID) }

            if role == .client {
                let serverSCID = longHeader.sourceConnectionID
                // Only update on first Initial packet (when DCIDs differ)
                if currentDCID != serverSCID {
                    Self.logger.debug("Client updating DCID from \(currentDCID) to server's SCID \(serverSCID)")
                    state.withLock { state in
                        state.destinationConnectionID = serverSCID
                    }
                    // Update PacketProcessor's DCID length for short header parsing
                    packetProcessor.setDCIDLength(serverSCID.bytes.count)
                }
            }
        }

        // RFC 9000 Section 8.1: Server validates client address upon receiving Handshake packet
        if parsed.encryptionLevel == .handshake {
            amplificationLimiter.validateAddress()
        }

        // Record received packet
        handler.recordReceivedPacket(
            packetNumber: parsed.packetNumber,
            level: parsed.encryptionLevel,
            isAckEliciting: parsed.frames.contains { $0.isAckEliciting },
            receiveTime: .now
        )

        // Process frames
        let result = try handler.processFrames(parsed.frames, level: parsed.encryptionLevel)

        // Handle frame results (common logic)
        var outboundPackets = try await processFrameResult(result)

        // Generate response packets (ACKs, etc.)
        let responsePackets = try generateOutboundPackets()
        outboundPackets.append(contentsOf: responsePackets)

        // Apply anti-amplification limit
        return applyAmplificationLimit(to: outboundPackets)
    }

    /// Processes a coalesced datagram (multiple packets)
    /// - Parameter datagram: The UDP datagram
    /// - Returns: Outbound packets to send in response
    ///
    /// RFC 9000 Section 12.2: A single UDP datagram may contain multiple
    /// coalesced QUIC packets at different encryption levels (e.g., Initial +
    /// Handshake).  We MUST decrypt and process each packet incrementally so
    /// that keys derived from processing one packet (e.g., the Initial packet
    /// containing ServerHello, which installs Handshake keys) are available
    /// when decrypting the next coalesced packet (e.g., the Handshake packet
    /// containing EncryptedExtensions / Certificate / Finished).
    ///
    /// The previous implementation called `decryptDatagram()` up-front, which
    /// tried to decrypt ALL coalesced packets before any frames were processed.
    /// This caused the Handshake packet to be silently dropped (no keys yet),
    /// losing the first 110 bytes of Handshake-level CRYPTO data and stalling
    /// the TLS handshake.
    public func processDatagram(_ datagram: Data) async throws -> [Data] {
        // Record received bytes for anti-amplification limit
        amplificationLimiter.recordBytesReceived(UInt64(datagram.count))

        // RFC 9001 §5.8: Check for Retry packet and verify integrity tag
        // Retry packets are never coalesced, but check the first packet anyway
        if RetryIntegrityTag.isRetryPacket(datagram) {
            return try await processRetryPacket(datagram)
        }

        // Step 1: Split the datagram into individual packet boundaries WITHOUT
        // decrypting.  CoalescedPacketParser uses the Length field in long
        // headers to find packet boundaries.
        let dcidLen = packetProcessor.dcidLengthValue
        let packetInfos: [CoalescedPacketParser.PacketInfo]
        do {
            packetInfos = try CoalescedPacketParser.parse(datagram: datagram, dcidLength: dcidLen)
        } catch {
            Self.logger.warning("Failed to parse coalesced datagram: \(error)")
            return []
        }

        var allOutbound: [Data] = []
        var processedAny = false

        // Step 2: Decrypt-then-process each packet sequentially.
        // This ensures that keys installed by processing packet N are
        // available when decrypting packet N+1.
        for info in packetInfos {
            // Attempt to decrypt this individual packet
            let parsed: ParsedPacket
            do {
                parsed = try packetProcessor.decryptPacket(info.data)
            } catch PacketCodecError.noOpener {
                // No keys for this encryption level yet.
                // This can still happen legitimately (e.g. 0-RTT keys not yet
                // available).  Log at trace level and skip.
                Self.logger.trace("Skipping coalesced packet at offset \(info.offset): no keys for this encryption level yet")
                continue
            } catch PacketCodecError.decryptionFailed {
                // Decryption failed — packet may be corrupted or keys are wrong
                Self.logger.trace("Skipping coalesced packet at offset \(info.offset): decryption failed")
                continue
            } catch QUICError.decryptionFailed {
                // AEAD authentication tag mismatch
                Self.logger.trace("Skipping coalesced packet at offset \(info.offset): AEAD decryption failed")
                continue
            } catch {
                // Unexpected error — propagate
                throw error
            }

            processedAny = true

            // RFC 9000 Section 7.2: Client MUST update DCID to server's SCID from first Initial packet
            // This is critical for QUIC handshake: client uses server's SCID as DCID in all subsequent packets
            if parsed.encryptionLevel == .initial, case .long(let longHeader) = parsed.header {
                let (role, currentDCID) = state.withLock { ($0.role, $0.destinationConnectionID) }

                if role == .client {
                    let serverSCID = longHeader.sourceConnectionID
                    // Only update on first Initial packet (when DCIDs differ)
                    if currentDCID != serverSCID {
                        Self.logger.debug("Client updating DCID from \(currentDCID) to server's SCID \(serverSCID)")
                        state.withLock { state in
                            state.destinationConnectionID = serverSCID
                        }
                        // Update PacketProcessor's DCID length for short header parsing
                        packetProcessor.setDCIDLength(serverSCID.bytes.count)
                    }
                }
            }

            // RFC 9000 Section 8.1: Server validates client address upon receiving Handshake packet
            if parsed.encryptionLevel == .handshake {
                amplificationLimiter.validateAddress()
            }

            // Record received packet
            handler.recordReceivedPacket(
                packetNumber: parsed.packetNumber,
                level: parsed.encryptionLevel,
                isAckEliciting: parsed.frames.contains { $0.isAckEliciting },
                receiveTime: .now
            )

            // Process frames — this may call processFrameResult → processTLSOutputs,
            // which installs new crypto keys (e.g., Handshake keys from ServerHello,
            // Application keys from Finished).  These keys are now available for
            // decrypting the next coalesced packet in the loop.
            let result = try handler.processFrames(parsed.frames, level: parsed.encryptionLevel)

            // Handle frame results (common logic)
            let outbound = try await processFrameResult(result)
            allOutbound.append(contentsOf: outbound)
        }

        // RFC 9000 Section 6.2: Mark that we've received a valid packet
        // This prevents late Version Negotiation packets from being processed
        if processedAny {
            state.withLock { $0.hasReceivedValidPacket = true }
        }

        // Generate response packets
        let responsePackets = try generateOutboundPackets()
        allOutbound.append(contentsOf: responsePackets)

        // Apply anti-amplification limit to outbound packets (servers only)
        return applyAmplificationLimit(to: allOutbound)
    }

    /// Applies the anti-amplification limit to outbound packets
    ///
    /// RFC 9000 Section 8.1: Before address validation, servers MUST NOT send
    /// more than 3 times the data received from the client.
    ///
    /// - Parameter packets: Packets to potentially send
    /// - Returns: Packets that fit within the amplification limit
    private func applyAmplificationLimit(to packets: [Data]) -> [Data] {
        var allowedPackets: [Data] = []

        for packet in packets {
            let packetSize = UInt64(packet.count)

            if amplificationLimiter.canSend(bytes: packetSize) {
                amplificationLimiter.recordBytesSent(packetSize)
                allowedPackets.append(packet)
            }
            // Packets that exceed the limit are dropped
            // They will be retransmitted once more data is received
        }

        return allowedPackets
    }

    // MARK: - Retry Packet Processing

    /// Processes a Retry packet from the server
    ///
    /// RFC 9001 Section 5.8: A client that receives a Retry packet MUST verify
    /// the Retry Integrity Tag before processing the packet.
    ///
    /// RFC 9000 Section 8.1:
    /// - A client MUST accept and process at most one Retry packet
    /// - A client MUST discard a Retry packet if it has received a valid packet
    /// - A client MUST discard a Retry packet with an invalid integrity tag
    ///
    /// - Parameter data: The Retry packet data
    /// - Returns: New Initial packets to send with the retry token
    private func processRetryPacket(_ data: Data) async throws -> [Data] {
        // Only clients process Retry packets
        let (role, hasProcessedRetry, hasReceivedValidPacket) = state.withLock { s in
            (s.role, s.hasProcessedRetry, s.hasReceivedValidPacket)
        }

        guard role == .client else {
            // Servers don't process Retry packets - silently discard
            return []
        }

        // RFC 9000: A client MUST accept and process at most one Retry packet
        guard !hasProcessedRetry else {
            // Already processed a Retry - discard this one
            return []
        }

        // RFC 9000: A client that has received and successfully processed a valid
        // Initial or Handshake packet MUST discard subsequent Retry packets
        guard !hasReceivedValidPacket else {
            return []
        }

        // Parse the Retry packet
        let (version, _, sourceCID, retryToken, integrityTag) =
            try RetryIntegrityTag.parseRetryPacket(data)

        // RFC 9001 §5.8: Verify the Retry Integrity Tag
        // The tag is computed using the ORIGINAL destination connection ID
        // (the one the client used in its first Initial packet)
        let packetWithoutTag = RetryIntegrityTag.retryPacketWithoutTag(data)

        let isValid = try RetryIntegrityTag.verify(
            tag: integrityTag,
            originalDCID: originalConnectionID,
            retryPacketWithoutTag: packetWithoutTag,
            version: version
        )

        guard isValid else {
            // RFC 9001 §5.8: Discard Retry packet with invalid integrity tag
            // Do NOT treat this as a connection error - just silently discard
            return []
        }

        // RFC 9000: The client MUST use the value from the Source Connection ID
        // field of the Retry packet in the Destination Connection ID field of
        // subsequent packets
        state.withLock { s in
            s.hasProcessedRetry = true
            s.retryToken = retryToken
            s.destinationConnectionID = sourceCID
        }

        // RFC 9001: The client MUST discard Initial keys derived from the original
        // Destination Connection ID and derive new Initial keys using the
        // Source Connection ID from the Retry packet
        packetProcessor.discardKeys(for: .initial)

        // Derive new Initial keys using the server's SCID (our new DCID)
        let (_, _) = try packetProcessor.deriveAndInstallInitialKeys(
            connectionID: sourceCID,
            isClient: true,
            version: version
        )

        // Update the handler's destination CID
        handler.updateDestinationConnectionID(sourceCID)

        // RFC 9000 Section 8.1.2: Resend Initial packet with the retry token
        // Get the current CRYPTO data to resend
        let cryptoData = handler.getCryptoDataForRetry(level: .initial)

        // Build and send new Initial packet with retry token
        var initialPackets: [Data] = []
        if !cryptoData.isEmpty {
            let (scid, dcid) = state.withLock { ($0.sourceConnectionID, $0.destinationConnectionID) }
            let pn = handler.getNextPacketNumber(for: .initial)

            let header = LongHeader(
                packetType: .initial,
                version: version,
                destinationConnectionID: dcid,
                sourceConnectionID: scid,
                token: retryToken,  // Include the retry token
                packetNumber: pn
            )

            let frames: [Frame] = [.crypto(CryptoFrame(offset: 0, data: cryptoData))]

            let encrypted = try packetProcessor.encryptLongHeaderPacket(
                frames: frames,
                header: header,
                packetNumber: pn,
                padToMinimum: true  // Initial packets must be padded to 1200 bytes
            )
            initialPackets.append(encrypted)
        }

        return applyAmplificationLimit(to: initialPackets)
    }

    /// Generates outbound packets ready to send
    /// - Returns: Array of encrypted packet data
    public func generateOutboundPackets() throws -> [Data] {
        let outboundPackets = handler.getOutboundPackets()
        var result: [Data] = []

        // Consolidate all frames by encryption level into a single packet
        // per level.  Previously each frame was wrapped in its own
        // OutboundPacket, leading to many tiny packets (one per CRYPTO
        // frame, one per ACK, etc.).  Consolidating reduces packet count,
        // saves packet numbers, and ensures the peer receives all handshake
        // CRYPTO data in a single packet that can be processed atomically.
        var framesByLevel: [EncryptionLevel: [Frame]] = [:]

        for packet in outboundPackets {
            // Skip levels whose keys have already been discarded.
            // This can happen due to a race between the outboundSendLoop
            // (which calls generateOutboundPackets via signalNeedsSend)
            // and the inline processTLSOutputs path that discards
            // Initial/Handshake keys after handshake completion.
            guard packetProcessor.hasKeys(for: packet.level) else {
                continue
            }

            framesByLevel[packet.level, default: []].append(contentsOf: packet.frames)
        }

        // Build one packet per encryption level (ordering: Initial, Handshake, Application)

        if let initialFrames = framesByLevel[.initial], !initialFrames.isEmpty {
            let pn = handler.getNextPacketNumber(for: .initial)
            let header = buildPacketHeader(for: .initial, packetNumber: pn)
            if case .long(let longHeader) = header {
                let encrypted = try packetProcessor.encryptLongHeaderPacket(
                    frames: initialFrames,
                    header: longHeader,
                    packetNumber: pn,
                    padToMinimum: true
                )
                result.append(encrypted)
            }
        }

        if let handshakeFrames = framesByLevel[.handshake], !handshakeFrames.isEmpty {
            let pn = handler.getNextPacketNumber(for: .handshake)
            let header = buildPacketHeader(for: .handshake, packetNumber: pn)
            if case .long(let longHeader) = header {
                let encrypted = try packetProcessor.encryptLongHeaderPacket(
                    frames: handshakeFrames,
                    header: longHeader,
                    packetNumber: pn,
                    padToMinimum: false
                )
                result.append(encrypted)
            }
        }

        if let appFrames = framesByLevel[.application], !appFrames.isEmpty {
            let pn = handler.getNextPacketNumber(for: .application)
            let header = buildPacketHeader(for: .application, packetNumber: pn)
            if case .short(let shortHeader) = header {
                let encrypted = try packetProcessor.encryptShortHeaderPacket(
                    frames: appFrames,
                    header: shortHeader,
                    packetNumber: pn
                )
                result.append(encrypted)
            }
        }

        return result
    }

    /// Called when a timer expires
    /// - Returns: Packets to send (probes, retransmits)
    public func onTimerExpired() throws -> [Data] {
        let action = handler.onTimerExpired()

        switch action {
        case .none:
            return []

        case .retransmit(_, let level):
            // SentPacket doesn't contain frame data, so we send a PING as probe
            // The actual retransmission is handled by the stream manager when
            // data hasn't been ACKed
            handler.queueFrame(.ping, level: level)
            return try generateOutboundPackets()

        case .probe:
            // Send a PING to probe
            let level: EncryptionLevel = isEstablished ? .application : .initial
            handler.queueFrame(.ping, level: level)
            return try generateOutboundPackets()
        }
    }

    /// Gets the next timer deadline
    public func nextTimerDeadline() -> ContinuousClock.Instant? {
        handler.nextTimerDeadline()
    }

    // MARK: - Handshake Helpers

    /// Processes TLS outputs and generates packets
    private func processTLSOutputs(_ outputs: [TLSOutput]) async throws -> [Data] {
        var outboundPackets: [Data] = []
        var handshakeCompleted = false

        for output in outputs {
            switch output {
            case .handshakeData(let data, let level):
                // Queue CRYPTO frames
                handler.queueCryptoData(data, level: level)
                // NOTE: Do NOT call signalNeedsSend() here.
                // The inline path (generateOutboundPackets at the end of this
                // method) will build and return these packets directly.
                // Signaling the outboundSendLoop here causes a race where
                // the loop drains partially-queued frames, splitting handshake
                // CRYPTO data across competing senders and losing packets.

            case .keysAvailable(let info):
                // Install keys via PacketProcessor (single source of truth for crypto)
                let isClient = state.withLock { $0.role == .client }
                try packetProcessor.installKeys(info, isClient: isClient)

            case .handshakeComplete(let info):
                state.withLock { $0.negotiatedALPN = info.alpn }

                // Parse peer transport parameters
                if let peerParams = tlsProvider.getPeerTransportParameters() {
                    Self.logger.debug("Received peer transport parameters: \(peerParams.count) bytes")
                    if let params = decodeTransportParameters(peerParams) {
                        Self.logger.debug("Decoded peer params: maxData=\(params.initialMaxData), bidiLocal=\(params.initialMaxStreamDataBidiLocal), bidiRemote=\(params.initialMaxStreamDataBidiRemote)")
                        handler.setPeerTransportParameters(params)
                    } else {
                        Self.logger.error("Failed to decode transport parameters!")
                    }
                } else {
                    Self.logger.error("No peer transport parameters received from TLS!")
                }

                // RFC 9000 Section 8.1: Lift amplification limit when handshake is confirmed
                amplificationLimiter.confirmHandshake()

                // RFC 9001 Section 4.1.1: Handshake is complete when TLS reports completion
                // Both client and server can send 1-RTT data immediately after handshake completes
                // HANDSHAKE_DONE frame is for "handshake confirmation", not a requirement to start sending data
                handler.markHandshakeComplete()
                Self.logger.info("TLS handshake complete - enabling 1-RTT data transmission")

                // Server: Send HANDSHAKE_DONE frame to client (RFC 9001 Section 4.1.2)
                let role = state.withLock { $0.role }
                if role == .server {
                    handler.queueFrame(.handshakeDone, level: .application)
                    Self.logger.debug("Server queued HANDSHAKE_DONE frame")
                    // NOTE: Do NOT signal here — the inline generateOutboundPackets()
                    // below will pick up HANDSHAKE_DONE along with all other queued frames.
                }

                // Mark handshake as established, drain waiters, and propagate 0-RTT result
                let waiters = state.withLock { s -> [(id: UUID, continuation: CheckedContinuation<Void, any Error>)] in
                    s.handshakeState = .established
                    // Propagate actual 0-RTT acceptance from the TLS provider
                    if s.is0RTTAttempted {
                        s.is0RTTAccepted = self.tlsProvider.is0RTTAccepted
                    }
                    let w = s.handshakeCompletionContinuations
                    s.handshakeCompletionContinuations.removeAll()
                    return w
                }
                handshakeCompleted = true

                // Resume all callers that are waiting in waitForHandshake()
                // (server-side: handshake completes here via TLS output)
                for waiter in waiters {
                    waiter.continuation.resume()
                }

            case .needMoreData:
                // Wait for more data
                break

            case .error(let error):
                throw error

            case .alert(let alert):
                // TLS Alert received - for QUIC, this results in CONNECTION_CLOSE
                // with crypto error code (0x100 + alert code) per RFC 9001 Section 4.8
                // For now, we throw an error which will be handled by the caller
                throw TLSError.handshakeFailed(
                    alert: alert.alertDescription.rawValue,
                    description: alert.description
                )

            case .newSessionTicket(let ticketInfo):
                // RFC 8446 Section 4.6.1: NewSessionTicket received post-handshake
                // Store it for the client to use for future connections
                notifySessionTicketReceived(ticketInfo)
            }
        }

        // Generate packets from queued frames (BEFORE discarding keys).
        // This is the ONLY place that should drain the outbound queue during
        // TLS processing — no signalNeedsSend() was issued above, so the
        // outboundSendLoop is not competing for the queue.
        let packets = try generateOutboundPackets()
        outboundPackets.append(contentsOf: packets)

        // Now signal the outboundSendLoop so it's ready for any future
        // packets (e.g. post-handshake stream data, session tickets).
        // At this point the queue has been drained, so the loop will find
        // nothing immediately — but it will be primed for the next write.
        signalNeedsSend()

        // Discard Initial and Handshake keys if handshake completed
        // RFC 9001 Section 4.9.2:
        // - Server: Discard when TLS handshake completes (here)
        // - Client: Discard when HANDSHAKE_DONE is received (in completeHandshake)
        if handshakeCompleted {
            let role = state.withLock { $0.role }
            if role == .server {
                // Server discards keys immediately after handshake completes
                packetProcessor.discardKeys(for: .initial)
                packetProcessor.discardKeys(for: .handshake)
                handler.discardLevel(.initial)
                handler.discardLevel(.handshake)
            }
            // Client waits for HANDSHAKE_DONE before discarding keys
        }

        return outboundPackets
    }

    /// Completes the handshake (called when HANDSHAKE_DONE frame is received)
    ///
    /// RFC 9001 Section 4.9.2:
    /// - Server: Already discarded keys in processTLSOutputs()
    /// - Client: Discards keys here when HANDSHAKE_DONE is received
    private func completeHandshake() throws {
        // Single lock acquisition to get role, update state, and drain waiters
        let (role, waiters) = state.withLock { s -> (ConnectionRole, [(id: UUID, continuation: CheckedContinuation<Void, any Error>)]) in
            s.handshakeState = .established
            let w = s.handshakeCompletionContinuations
            s.handshakeCompletionContinuations.removeAll()
            return (s.role, w)
        }

        // Client discards keys when HANDSHAKE_DONE is received (RFC 9001 compliance)
        if role == .client {
            packetProcessor.discardKeys(for: .initial)
            packetProcessor.discardKeys(for: .handshake)
            handler.discardLevel(.initial)
            handler.discardLevel(.handshake)

            // CRITICAL: Mark handshake complete to enable stream frame generation
            handler.markHandshakeComplete()
        }
        // Server already discarded keys in processTLSOutputs()

        // Resume all callers that are waiting in waitForHandshake()
        for waiter in waiters {
            waiter.continuation.resume()
        }
    }

    /// Processes frame processing result (common logic for packet handling)
    ///
    /// Handles:
    /// - Crypto data (TLS messages)
    /// - New peer-initiated streams
    /// - Stream data notifications
    /// - Handshake completion
    /// - Connection close
    ///
    /// - Parameter result: The frame processing result
    /// - Returns: Outbound packets generated from TLS processing
    private func processFrameResult(_ result: FrameProcessingResult) async throws -> [Data] {
        var outboundPackets: [Data] = []

        // Handle crypto data (TLS messages)
        for (level, cryptoData) in result.cryptoData {
            let tlsOutputs = try await tlsProvider.processHandshakeData(cryptoData, at: level)
            let packets = try await processTLSOutputs(tlsOutputs)
            outboundPackets.append(contentsOf: packets)
        }

        // Handle new peer-initiated streams
        let scidForDebug = state.withLock { $0.sourceConnectionID }
        if !result.newStreams.isEmpty {
            Self.logger.debug("processFrameResult: \(result.newStreams.count) new streams: \(result.newStreams) for SCID=\(scidForDebug)")
        }
        for streamID in result.newStreams {
            let isBidirectional = StreamID.isBidirectional(streamID)
            let stream = ManagedStream(
                id: streamID,
                connection: self,
                isUnidirectional: !isBidirectional
            )
            incomingStreamState.withLock { state in
                // Don't yield if shutdown
                guard !state.isShutdown else {
                    Self.logger.trace("NOT yielding stream \(streamID) - shutdown for SCID=\(scidForDebug)")
                    return
                }

                if let continuation = state.continuation {
                    // Continuation exists, yield directly
                    Self.logger.trace("Yielding stream \(streamID) directly to continuation for SCID=\(scidForDebug)")
                    continuation.yield(stream)
                } else {
                    // Buffer the stream until incomingStreams is accessed
                    Self.logger.trace("Buffering stream \(streamID) (no continuation yet, pendingCount=\(state.pendingStreams.count)) for SCID=\(scidForDebug)")
                    state.pendingStreams.append(stream)
                }
            }
        }

        // Handle stream data
        for (streamID, data) in result.streamData {
            notifyStreamDataReceived(streamID, data: data)
        }

        // Handle received datagrams (RFC 9221)
        for datagramPayload in result.datagramsReceived {
            notifyDatagramReceived(datagramPayload)
        }

        // Handle streams whose receive side is now complete (FIN received,
        // all data consumed).  If a reader is blocked waiting for more data
        // on one of these streams, resume it with empty Data to signal
        // end-of-stream.  Otherwise record the stream so that future
        // readFromStream() calls return immediately.
        for streamID in result.finishedStreams {
            streamContinuationsState.withLock { state in
                if let continuation = state.continuations.removeValue(forKey: streamID) {
                    // A reader is already waiting — wake it with end-of-stream
                    continuation.resume(returning: Data())
                } else {
                    // No reader yet — record so next readFromStream detects it
                    state.finishedStreams.insert(streamID)
                }
            }
        }

        // Handle handshake completion (from HANDSHAKE_DONE frame)
        if result.handshakeComplete {
            try completeHandshake()
        }

        // Handle connection close
        if result.connectionClosed {
            let scid = state.withLock { s -> ConnectionID in
                s.handshakeState = .closed
                return s.sourceConnectionID
            }
            Self.logger.info("shutdown() triggered by CONNECTION_CLOSE frame for SCID=\(scid)")
            shutdown()  // Finish async streams to prevent hanging for-await loops
        }

        // Handle new connection IDs - register them with the router
        for frame in result.newConnectionIDs {
            Self.logger.debug("Registering NEW_CONNECTION_ID: \(frame.connectionID)")
            onNewConnectionID.withLock { callback in
                callback?(frame.connectionID)
            }
        }

        return outboundPackets
    }

    /// Builds a packet header for the given level
    private func buildPacketHeader(for level: EncryptionLevel, packetNumber: UInt64) -> PacketHeader {
        let (scid, dcid, version) = state.withLock { state in
            (state.sourceConnectionID, state.destinationConnectionID, handler.version)
        }

        switch level {
        case .initial:
            Self.logger.trace("Building Initial packet: SCID=\(scid), DCID=\(dcid)")
            let longHeader = LongHeader(
                packetType: .initial,
                version: version,
                destinationConnectionID: dcid,
                sourceConnectionID: scid,
                token: nil
            )
            return .long(longHeader)

        case .handshake:
            Self.logger.trace("Building Handshake packet: SCID=\(scid), DCID=\(dcid)")
            let longHeader = LongHeader(
                packetType: .handshake,
                version: version,
                destinationConnectionID: dcid,
                sourceConnectionID: scid,
                token: nil
            )
            return .long(longHeader)

        case .application:
            Self.logger.trace("Building Application packet (1-RTT): SCID=\(scid), DCID=\(dcid)")
            let shortHeader = ShortHeader(
                destinationConnectionID: dcid,
                spinBit: false,
                keyPhase: false
            )
            return .short(shortHeader)

        default:
            // 0-RTT or other
            let longHeader = LongHeader(
                packetType: .zeroRTT,
                version: version,
                destinationConnectionID: dcid,
                sourceConnectionID: scid,
                token: nil
            )
            return .long(longHeader)
        }
    }

    // MARK: - Stream Helpers

    /// Notifies that data has been received on a stream
    ///
    /// Thread-safe: If a reader is waiting, resume it with the data.
    /// If no reader is waiting, buffer the data for later retrieval.
    ///
    /// - Parameters:
    ///   - streamID: The stream ID
    ///   - data: The received data
    private func notifyStreamDataReceived(_ streamID: UInt64, data: Data) {
        streamContinuationsState.withLock { state in
            // Don't process if shutdown
            guard !state.isShutdown else { return }

            // If someone is waiting, resume them with the data
            if let continuation = state.continuations.removeValue(forKey: streamID) {
                continuation.resume(returning: data)
            } else {
                // No reader waiting - buffer the data for later
                state.pendingData[streamID, default: []].append(data)
            }
        }
    }

    // MARK: - Transport Parameters

    /// Encodes transport parameters to wire format using RFC 9000 compliant codec
    private func encodeTransportParameters(_ params: TransportParameters) -> Data {
        // Use proper TransportParameterCodec for RFC 9000 compliant encoding
        // This includes mandatory initial_source_connection_id parameter
        return TransportParameterCodec.encode(params)
    }

    /// Decodes transport parameters from wire format
    private func decodeTransportParameters(_ data: Data) -> TransportParameters? {
        // Use proper TransportParameterCodec for RFC 9000 compliant decoding
        return try? TransportParameterCodec.decode(data)
    }
}

// MARK: - QUICConnectionProtocol

extension ManagedConnection: QUICConnectionProtocol {
    public var isEstablished: Bool {
        state.withLock { $0.handshakeState == .established }
    }

    public func openStream() async throws -> any QUICStreamProtocol {
        let streamID = try handler.openStream(bidirectional: true)
        return ManagedStream(
            id: streamID,
            connection: self,
            isUnidirectional: false
        )
    }

    public func openUniStream() async throws -> any QUICStreamProtocol {
        let streamID = try handler.openStream(bidirectional: false)
        return ManagedStream(
            id: streamID,
            connection: self,
            isUnidirectional: true
        )
    }

    public var incomingStreams: AsyncStream<any QUICStreamProtocol> {
        incomingStreamState.withLock { state in
            // If shutdown, return existing finished stream or create a finished one
            // This prevents new iterators from hanging after shutdown
            if state.isShutdown {
                if let existing = state.stream { return existing }
                // Create an already-finished stream
                let (stream, continuation) = AsyncStream<any QUICStreamProtocol>.makeStream()
                continuation.finish()
                state.stream = stream
                return stream
            }

            // Return existing stream if already created (lazy initialization)
            if let existing = state.stream { return existing }

            // Create new stream using makeStream() pattern (per coding guidelines)
            let (stream, continuation) = AsyncStream<any QUICStreamProtocol>.makeStream()
            state.stream = stream
            state.continuation = continuation

            // Drain any pending streams that arrived before this was accessed
            for pendingStream in state.pendingStreams {
                continuation.yield(pendingStream)
            }
            state.pendingStreams.removeAll()

            return stream
        }
    }

    /// Stream of session tickets received from the server
    ///
    /// Use this to receive `NewSessionTicket` messages for session resumption.
    /// Store these tickets in a `ClientSessionCache` for future 0-RTT connections.
    ///
    /// ## Usage
    /// ```swift
    /// let sessionCache = ClientSessionCache()
    /// Task {
    ///     for await ticketInfo in connection.sessionTickets {
    ///         sessionCache.storeTicket(
    ///             ticketInfo.ticket,
    ///             resumptionMasterSecret: ticketInfo.resumptionMasterSecret,
    ///             cipherSuite: ticketInfo.cipherSuite,
    ///             alpn: ticketInfo.alpn,
    ///             serverIdentity: "\(connection.remoteAddress)"
    ///         )
    ///     }
    /// }
    /// ```
    public var sessionTickets: AsyncStream<NewSessionTicketInfo> {
        sessionTicketState.withLock { state in
            // If shutdown, return existing finished stream or create a finished one
            if state.isShutdown {
                if let existing = state.stream { return existing }
                let (stream, continuation) = AsyncStream<NewSessionTicketInfo>.makeStream()
                continuation.finish()
                state.stream = stream
                return stream
            }

            // Return existing stream if already created
            if let existing = state.stream { return existing }

            // Create new stream
            let (stream, continuation) = AsyncStream<NewSessionTicketInfo>.makeStream()
            state.stream = stream
            state.continuation = continuation

            // Drain any pending tickets
            for pendingTicket in state.pendingTickets {
                continuation.yield(pendingTicket)
            }
            state.pendingTickets.removeAll()

            return stream
        }
    }

    /// Notifies that a session ticket was received (internal helper)
    private func notifySessionTicketReceived(_ ticketInfo: NewSessionTicketInfo) {
        sessionTicketState.withLock { state in
            guard !state.isShutdown else { return }

            if let continuation = state.continuation {
                // Stream is active, yield directly
                continuation.yield(ticketInfo)
            } else {
                // Buffer until sessionTickets is accessed
                state.pendingTickets.append(ticketInfo)
            }
        }
    }

    public func sendDatagram(_ data: Data) async throws {
        guard isEstablished else {
            throw QUICDatagramError.connectionNotReady
        }

        // Check that datagrams are supported via transport parameters
        let maxSize = transportParameters.maxDatagramFrameSize ?? 0
        guard maxSize > 0 else {
            throw QUICDatagramError.datagramsNotSupported
        }

        // Check payload size (the max includes framing overhead; be conservative)
        guard data.count <= Int(maxSize) else {
            throw QUICDatagramError.datagramTooLarge(size: data.count, maxAllowed: Int(maxSize))
        }

        // Write datagram payload through the handler
        // The handler encodes it as a DATAGRAM frame on the wire
        try handler.sendDatagram(data)
        signalNeedsSend()
    }

    public var incomingDatagrams: AsyncStream<Data> {
        incomingDatagramState.withLock { state in
            // If shutdown, return existing finished stream or create a finished one
            if state.isShutdown {
                if let existing = state.stream { return existing }
                let (stream, continuation) = AsyncStream<Data>.makeStream()
                continuation.finish()
                state.stream = stream
                return stream
            }

            // Return existing stream if already created (lazy initialization)
            if let existing = state.stream { return existing }

            // Create new stream
            let (stream, continuation) = AsyncStream<Data>.makeStream()
            state.stream = stream
            state.continuation = continuation

            // Drain any pending datagrams that arrived before this was accessed
            for pendingDatagram in state.pendingDatagrams {
                continuation.yield(pendingDatagram)
            }
            state.pendingDatagrams.removeAll()

            return stream
        }
    }

    /// Delivers an incoming datagram payload (internal helper called by packet processing)
    public func notifyDatagramReceived(_ data: Data) {
        incomingDatagramState.withLock { state in
            guard !state.isShutdown else { return }

            if let continuation = state.continuation {
                // Stream is active, yield directly
                continuation.yield(data)
            } else {
                // Buffer until incomingDatagrams is accessed
                state.pendingDatagrams.append(data)
            }
        }
    }

    public func close(error: UInt64?) async {
        let scid = state.withLock { $0.sourceConnectionID }
        Self.logger.info("close(error: \(String(describing: error))) called for SCID=\(scid)")
        handler.close(error: error.map { ConnectionCloseError(code: $0) })
        state.withLock { $0.handshakeState = .closing }
        shutdown()
    }

    public func close(applicationError errorCode: UInt64, reason: String) async {
        let scid = state.withLock { $0.sourceConnectionID }
        Self.logger.info("close(applicationError: \(errorCode), reason: \(reason)) called for SCID=\(scid)")
        handler.close(error: ConnectionCloseError(code: errorCode, reason: reason))
        state.withLock { $0.handshakeState = .closing }
        shutdown()
    }

    /// Shuts down the connection and finishes all async streams
    ///
    /// This is required per coding guidelines: AsyncStream services MUST
    /// call continuation.finish() to prevent for-await loops from hanging.
    ///
    /// Note: We set isShutdown=true but keep the stream reference.
    /// This allows existing iterators to complete normally while preventing
    /// new iterators from hanging (they get an already-finished stream).
    public func shutdown() {
        let (scid, handshakeWaiters) = state.withLock { s -> (ConnectionID, [(id: UUID, continuation: CheckedContinuation<Void, any Error>)]) in
            let w = s.handshakeCompletionContinuations
            s.handshakeCompletionContinuations.removeAll()
            return (s.sourceConnectionID, w)
        }
        Self.logger.info("shutdown() called for SCID=\(scid)")

        // Resume any callers waiting in waitForHandshake() with an error
        // This prevents them from hanging indefinitely when the connection
        // is torn down before handshake completes.
        for waiter in handshakeWaiters {
            waiter.continuation.resume(throwing: ManagedConnectionError.connectionClosed)
        }

        // Finish incoming stream continuation and mark as shutdown
        // Guard against concurrent calls - finish() is idempotent but we avoid duplicate work
        incomingStreamState.withLock { state in
            guard !state.isShutdown else { return }  // Already shutdown
            state.isShutdown = true  // Mark as shutdown FIRST
            state.continuation?.finish()
            state.continuation = nil
            state.pendingStreams.removeAll()  // Clear any buffered streams
            // DO NOT set stream = nil - existing iterators need it
        }

        // Finish session ticket stream and mark as shutdown
        sessionTicketState.withLock { state in
            guard !state.isShutdown else { return }  // Already shutdown
            state.isShutdown = true
            state.continuation?.finish()
            state.continuation = nil
            state.pendingTickets.removeAll()
        }

        // Finish incoming datagram stream and mark as shutdown
        incomingDatagramState.withLock { state in
            guard !state.isShutdown else { return }  // Already shutdown
            state.isShutdown = true
            state.continuation?.finish()
            state.continuation = nil
            state.pendingDatagrams.removeAll()
        }

        // Resume any waiting stream readers with connection closed error
        // and mark as shutdown to prevent new readers from hanging
        streamContinuationsState.withLock { state in
            guard !state.isShutdown else { return }  // Already shutdown
            state.isShutdown = true  // Mark as shutdown FIRST
            for (_, continuation) in state.continuations {
                continuation.resume(throwing: ManagedConnectionError.connectionClosed)
            }
            state.continuations.removeAll()
        }

        // Finish send signal stream to stop outboundSendLoop in QUICEndpoint
        state.withLock { s in
            guard !s.isSendSignalShutdown else { return }  // Already shutdown
            Self.logger.debug("shutdown() finishing sendSignal for SCID=\(s.sourceConnectionID), hasContinuation=\(s.sendSignalContinuation != nil)")
            s.isSendSignalShutdown = true
            s.sendSignalContinuation?.finish()
            s.sendSignalContinuation = nil
        }
    }
}

// MARK: - Internal Stream Access

extension ManagedConnection {
    /// Writes data to a stream (called by ManagedStream)
    func writeToStream(_ streamID: UInt64, data: Data) throws {
        try handler.writeToStream(streamID, data: data)
        signalNeedsSend()
    }

    /// Reads data from a stream (called by ManagedStream)
    ///
    /// Thread-safe: Prevents concurrent reads on the same stream.
    /// Only one reader can wait for data at a time per stream.
    /// Returns connectionClosed error if called after shutdown.
    ///
    /// Data sources (in priority order):
    /// 1. Pending data buffer (from processFrameResult)
    /// 2. Handler's stream buffer
    /// 3. Wait for data via continuation
    func readFromStream(_ streamID: UInt64) async throws -> Data {
        // Try to get data atomically - check buffer first, then handler
        return try await withCheckedThrowingContinuation { continuation in
            streamContinuationsState.withLock { state in
                // Check if shutdown
                guard !state.isShutdown else {
                    continuation.resume(throwing: ManagedConnectionError.connectionClosed)
                    return
                }

                // Priority 1: Check pending data buffer
                if var pending = state.pendingData[streamID], !pending.isEmpty {
                    let data = pending.removeFirst()
                    if pending.isEmpty {
                        state.pendingData.removeValue(forKey: streamID)
                    } else {
                        state.pendingData[streamID] = pending
                    }
                    continuation.resume(returning: data)
                    return
                }

                // Priority 2: Check handler's stream buffer
                if let data = handler.readFromStream(streamID) {
                    continuation.resume(returning: data)
                    return
                }

                // Priority 3: Check if stream receive side is complete (FIN)
                // or was reset by the peer.  Return empty Data to signal
                // end-of-stream so that callers break out of read loops.
                if state.finishedStreams.contains(streamID)
                    || handler.isStreamReceiveComplete(streamID)
                    || handler.isStreamResetByPeer(streamID)
                {
                    state.finishedStreams.insert(streamID)
                    continuation.resume(returning: Data())
                    return
                }

                // Priority 4: Wait for data
                // Prevent concurrent reads on the same stream
                guard state.continuations[streamID] == nil else {
                    continuation.resume(throwing: ManagedConnectionError.invalidState("Concurrent read on stream \(streamID)"))
                    return
                }
                state.continuations[streamID] = continuation
            }
        }
    }

    /// Finishes a stream (sends FIN)
    func finishStream(_ streamID: UInt64) throws {
        try handler.finishStream(streamID)
        signalNeedsSend()
    }

    /// Resets a stream
    func resetStream(_ streamID: UInt64, errorCode: UInt64) {
        handler.closeStream(streamID)
    }

    /// Stops sending on a stream
    func stopSending(_ streamID: UInt64, errorCode: UInt64) {
        // Handler will generate STOP_SENDING frame
        handler.closeStream(streamID)
    }
}

// MARK: - Send Signal

extension ManagedConnection {
    /// Signal that packets need to be sent.
    ///
    /// QUICEndpoint monitors this stream and, upon receiving a signal,
    /// calls `generateOutboundPackets()` to send packets.
    ///
    /// Multiple writes before signal processing will be coalesced into
    /// a single packet generation (efficient batching via `bufferingNewest(1)`).
    ///
    /// ## Usage
    /// ```swift
    /// // In QUICEndpoint
    /// Task {
    ///     for await _ in connection.sendSignal {
    ///         let packets = try connection.generateOutboundPackets()
    ///         for packet in packets {
    ///             socket.send(packet, to: address)
    ///         }
    ///     }
    /// }
    /// ```
    public var sendSignal: AsyncStream<Void> {
        state.withLock { s in
            // After shutdown, return an already-finished stream
            if s.isSendSignalShutdown {
                Self.logger.trace("sendSignal accessed AFTER shutdown for SCID=\(s.sourceConnectionID)")
                if let existing = s.sendSignalStream { return existing }
                let (stream, continuation) = AsyncStream<Void>.makeStream(
                    bufferingPolicy: .bufferingNewest(1)
                )
                continuation.finish()
                s.sendSignalStream = stream
                return stream
            }

            // Return existing stream if already created (lazy initialization)
            if let existing = s.sendSignalStream {
                Self.logger.trace("sendSignal returning EXISTING stream for SCID=\(s.sourceConnectionID), hasContinuation=\(s.sendSignalContinuation != nil)")
                return existing
            }

            // Create new stream with bufferingNewest(1) for coalescing
            // Multiple yields before consumption result in only one signal
            let (stream, continuation) = AsyncStream<Void>.makeStream(
                bufferingPolicy: .bufferingNewest(1)
            )
            s.sendSignalStream = stream
            s.sendSignalContinuation = continuation
            Self.logger.trace("sendSignal CREATED new stream for SCID=\(s.sourceConnectionID)")
            return stream
        }
    }

    /// Notifies that packets need to be sent.
    ///
    /// Called after `writeToStream()` or `finishStream()` to trigger
    /// packet generation and transmission in QUICEndpoint.
    public func signalNeedsSend() {
        state.withLock { s in
            guard !s.isSendSignalShutdown else {
                Self.logger.trace("signalNeedsSend SKIPPED (shutdown) for SCID=\(s.sourceConnectionID)")
                return
            }
            let hasContinuation = s.sendSignalContinuation != nil
            if !hasContinuation {
                Self.logger.warning("signalNeedsSend: no continuation for SCID=\(s.sourceConnectionID), streamExists=\(s.sendSignalStream != nil)")
            }
            s.sendSignalContinuation?.yield(())
        }
    }
}

// MARK: - Connection IDs

extension ManagedConnection {
    /// The TLS provider used for this connection.
    ///
    /// Provides access to the underlying TLS 1.3 provider for custom
    /// authentication schemes (e.g., certificate-based peer identity extraction).
    public var underlyingTLSProvider: any TLS13Provider {
        tlsProvider
    }

    /// Whether 0-RTT early data was accepted by the server.
    ///
    /// Only meaningful after handshake completes. Before that, always `false`.
    /// The value is propagated from the TLS provider's `is0RTTAccepted` once
    /// the server's EncryptedExtensions has been processed.
    public var is0RTTAccepted: Bool {
        state.withLock { $0.is0RTTAccepted }
    }

    // MARK: - Handshake Completion

    /// Suspends the caller until the QUIC handshake completes.
    ///
    /// - If the handshake is already complete (`.established`), returns
    ///   immediately.
    /// - If the connection is already closed/closing, throws
    ///   ``ManagedConnectionError/connectionClosed``.
    /// - Otherwise, the caller is suspended until one of the above
    ///   conditions is reached.
    ///
    /// This replaces the previous poll-based `while !isEstablished` loop
    /// in `QUICEndpoint.dial()` with an efficient continuation-based wait.
    ///
    /// ## Thread-Safety
    /// Multiple concurrent callers are supported; all are resumed together
    /// when the handshake completes.
    public func waitForHandshake() async throws {
        // We need a stable identity so the cancellation handler can
        // locate and remove the exact continuation that was parked.
        let id = UUID()

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                state.withLock { s in
                    // Re-check cancellation under the lock so we never
                    // park a continuation that is already doomed.
                    if Task.isCancelled {
                        continuation.resume(throwing: CancellationError())
                        return
                    }

                    switch s.handshakeState {
                    case .established:
                        // Already done — resume immediately
                        continuation.resume()
                    case .closed, .closing:
                        // Connection already torn down
                        continuation.resume(throwing: ManagedConnectionError.connectionClosed)
                    default:
                        // Handshake still in progress — park the continuation
                        s.handshakeCompletionContinuations.append((id: id, continuation: continuation))
                    }
                }
            }
        } onCancel: {
            // Task was cancelled (e.g. dial() timeout).
            // Remove our continuation from the list and resume it with
            // CancellationError so the structured-concurrency task group
            // can finish instead of hanging forever.
            let removed: CheckedContinuation<Void, any Error>? = state.withLock { s in
                if let idx = s.handshakeCompletionContinuations.firstIndex(where: { $0.id == id }) {
                    let entry = s.handshakeCompletionContinuations.remove(at: idx)
                    return entry.continuation
                }
                return nil
            }
            removed?.resume(throwing: CancellationError())
        }
    }

    /// Source connection ID
    public var sourceConnectionID: ConnectionID {
        state.withLock { $0.sourceConnectionID }
    }

    /// Destination connection ID
    public var destinationConnectionID: ConnectionID {
        state.withLock { $0.destinationConnectionID }
    }

    /// Current handshake state
    public var handshakeState: HandshakeState {
        state.withLock { $0.handshakeState }
    }

    /// Connection role
    public var role: ConnectionRole {
        state.withLock { $0.role }
    }

    // Note: Connection ID tracking is now managed by ConnectionRouter.
    // Use router.registeredConnectionIDs(for:) to query CIDs for a connection.

    // MARK: - Amplification Limit

    /// Whether the connection is blocked by the anti-amplification limit
    ///
    /// When blocked, the server must wait for more data from the client
    /// before it can send additional packets.
    public var isAmplificationBlocked: Bool {
        amplificationLimiter.isBlocked
    }

    /// Whether the client's address has been validated
    ///
    /// Address validation lifts the anti-amplification limit.
    public var isAddressValidated: Bool {
        amplificationLimiter.isAddressValidated
    }

    // MARK: - Version Negotiation

    /// Whether we have received and successfully processed any valid packet
    ///
    /// RFC 9000 Section 6.2: A client MUST discard any Version Negotiation packet
    /// if it has received and successfully processed any other packet.
    public var hasReceivedValidPacket: Bool {
        get async { state.withLock { $0.hasReceivedValidPacket } }
    }

    /// Retry the connection with a different QUIC version
    ///
    /// Called when a Version Negotiation packet is received offering a version we support.
    /// This resets the connection state and restarts the handshake with the new version.
    ///
    /// - Parameter version: The new version to use
    public func retryWithVersion(_ version: QUICVersion) async throws {
        // This is a complex operation that requires:
        // 1. Resetting TLS state
        // 2. Regenerating Initial keys with the new version
        // 3. Rebuilding and resending ClientHello
        // For now, throw an error indicating manual reconnection is needed
        throw QUICVersionError.versionNegotiationReceived(
            offeredVersions: [version]
        )
    }

    // MARK: - Connection Migration (RFC 9000 Section 9)

    /// The current remote address (may differ from initial address after migration)
    public var currentRemoteAddress: SocketAddress {
        state.withLock { $0.currentRemoteAddress ?? remoteAddress }
    }

    /// Whether the current path has been validated
    public var isPathValidated: Bool {
        state.withLock { $0.pathValidated }
    }

    /// Handles a packet received from a different address (potential migration)
    ///
    /// RFC 9000 Section 9.3: When receiving a packet from a new peer address,
    /// the endpoint MUST perform path validation if it has not previously done so.
    ///
    /// - Parameters:
    ///   - packet: The received packet data
    ///   - newAddress: The new remote address from which the packet was received
    /// - Returns: Packets to send in response (may include PATH_CHALLENGE)
    /// - Throws: `MigrationError` if migration is not allowed
    public func handleAddressChange(
        packet: Data,
        newAddress: SocketAddress
    ) async throws -> [Data] {
        // Check if migration is allowed
        let (allowMigration, currentAddress) = state.withLock { s in
            (
                !s.peerDisableActiveMigration,
                s.currentRemoteAddress ?? remoteAddress
            )
        }

        // If address hasn't changed, process normally
        if newAddress == currentAddress {
            return try await processIncomingPacket(packet)
        }

        // Check if peer allows migration
        guard allowMigration else {
            throw MigrationError.migrationDisabled
        }

        // Update address and mark path as not validated
        state.withLock { s in
            s.currentRemoteAddress = newAddress
            s.pathValidated = false
        }

        // For servers: reset anti-amplification limit for new path (RFC 9000 Section 9.3)
        // Note: Address validation needs to be completed via PATH_CHALLENGE/RESPONSE
        // The amplification limiter will be reset once path validation completes

        // Record bytes received for anti-amplification
        amplificationLimiter.recordBytesReceived(UInt64(packet.count))

        // Process the packet
        var responses = try await processIncomingPacket(packet)

        // Initiate path validation by sending PATH_CHALLENGE
        let path = NetworkPath(
            localAddress: localAddress?.description ?? "",
            remoteAddress: newAddress.description
        )
        let challengeData = pathValidationManager.startValidation(for: path)

        // Queue PATH_CHALLENGE to be sent with next packet
        state.withLock { s in
            s.pendingPathChallenges.append(challengeData)
        }

        // Generate a packet with PATH_CHALLENGE if we can
        if let challengePacket = try createPathChallengePacket(challengeData: challengeData) {
            responses.append(challengePacket)
        }

        return responses
    }

    /// Handles a PATH_CHALLENGE frame
    ///
    /// RFC 9000 Section 9.3.2: An endpoint MUST respond immediately to a
    /// PATH_CHALLENGE frame with a PATH_RESPONSE frame containing the same data.
    ///
    /// - Parameter data: The 8-byte challenge data
    /// - Returns: PATH_RESPONSE packet to send
    public func handlePathChallenge(_ data: Data) throws -> Data? {
        // Generate PATH_RESPONSE
        _ = pathValidationManager.handleChallenge(data)

        // Queue response to be sent
        state.withLock { s in
            s.pendingPathResponses.append(data)
        }

        // Create packet with PATH_RESPONSE
        return try createPathResponsePacket(data: data)
    }

    /// Handles a PATH_RESPONSE frame
    ///
    /// RFC 9000 Section 9.3.3: Receipt of a PATH_RESPONSE frame indicates
    /// that the path is valid.
    ///
    /// - Parameter data: The 8-byte response data
    /// - Returns: Whether this completes path validation
    public func handlePathResponse(_ data: Data) -> Bool {
        if let _ = pathValidationManager.handleResponse(data) {
            // Path validated successfully
            state.withLock { s in
                s.pathValidated = true
            }
            return true
        }
        return false
    }

    /// Sets whether peer allows active migration (from transport parameters)
    ///
    /// Called when processing peer's transport parameters.
    public func setPeerDisableActiveMigration(_ disabled: Bool) {
        state.withLock { s in
            s.peerDisableActiveMigration = disabled
        }
    }

    /// Gets pending PATH_CHALLENGE frames to include in next packet
    public func getPendingPathChallenges() -> [Data] {
        state.withLock { s in
            let challenges = s.pendingPathChallenges
            s.pendingPathChallenges.removeAll()
            return challenges
        }
    }

    /// Gets pending PATH_RESPONSE frames to include in next packet
    public func getPendingPathResponses() -> [Data] {
        state.withLock { s in
            let responses = s.pendingPathResponses
            s.pendingPathResponses.removeAll()
            return responses
        }
    }

    // MARK: - Migration Private Helpers

    /// Creates a packet containing a PATH_CHALLENGE frame
    ///
    /// - Note: This queues the frame to be sent with the next outbound packet.
    ///   The actual packet creation happens via the normal packet sending mechanism.
    private func createPathChallengePacket(challengeData: Data) throws -> Data? {
        // PATH_CHALLENGE will be included in the next 1-RTT packet
        // Queue the frame via the handler
        handler.queueFrame(.pathChallenge(challengeData), level: .application)

        // Return nil - the frame will be sent with normal packet flow
        // This avoids duplicating packet creation logic
        return nil
    }

    /// Creates a packet containing a PATH_RESPONSE frame
    ///
    /// - Note: This queues the frame to be sent with the next outbound packet.
    private func createPathResponsePacket(data: Data) throws -> Data? {
        // PATH_RESPONSE must be sent immediately (RFC 9000 Section 8.2.2)
        // Queue the frame via the handler
        handler.queueFrame(.pathResponse(data), level: .application)

        // Return nil - the frame will be sent with normal packet flow
        return nil
    }
}

/// Connection migration errors
public enum MigrationError: Error, Sendable {
    /// Migration is disabled by peer (disable_active_migration transport parameter)
    case migrationDisabled

    /// Path validation failed
    case pathValidationFailed(reason: String)

    /// No active connection ID available for migration
    case noActiveConnectionID
}

// MARK: - Internal State

private struct ManagedConnectionState: Sendable {
    var role: ConnectionRole
    var handshakeState: HandshakeState = .idle
    var sourceConnectionID: ConnectionID
    var destinationConnectionID: ConnectionID
    var negotiatedALPN: String? = nil
    /// Whether 0-RTT was attempted in this connection
    var is0RTTAttempted: Bool = false
    /// Whether 0-RTT was accepted by server (set after receiving EncryptedExtensions)
    var is0RTTAccepted: Bool = false
    /// Whether we have received and successfully processed any valid packet
    /// RFC 9000 Section 6.2: Used to discard late Version Negotiation packets
    var hasReceivedValidPacket: Bool = false

    // MARK: - Handshake Completion Signaling

    /// Continuations waiting for handshake completion.
    ///
    /// `waitForHandshake()` appends an `(id, continuation)` pair here when
    /// the handshake is still in progress.  The `id` allows the
    /// cancellation handler to locate and remove a specific entry.
    ///
    /// Once the handshake completes (server: `processTLSOutputs`, client:
    /// `completeHandshake`), or the connection is closed/shut down, all
    /// pending continuations are resumed.
    var handshakeCompletionContinuations: [(id: UUID, continuation: CheckedContinuation<Void, any Error>)] = []

    // MARK: - Retry State (RFC 9000 Section 8.1)

    /// Whether we have already processed a Retry packet
    /// RFC 9000: A client MUST accept and process at most one Retry packet
    var hasProcessedRetry: Bool = false

    /// Retry token received from server (to include in subsequent Initial packets)
    var retryToken: Data? = nil

    // MARK: - Connection Migration State

    /// Current remote address (may change during connection migration)
    var currentRemoteAddress: SocketAddress?

    /// Whether the current path has been validated (RFC 9000 Section 9.3)
    var pathValidated: Bool = true

    /// Whether peer allows active migration (from transport parameters)
    var peerDisableActiveMigration: Bool = false

    /// Pending PATH_CHALLENGE frames to send
    var pendingPathChallenges: [Data] = []

    /// Pending PATH_RESPONSE frames to send
    var pendingPathResponses: [Data] = []

    // MARK: - Send Signal State

    /// Continuation for send signal stream
    var sendSignalContinuation: AsyncStream<Void>.Continuation?

    /// Send signal stream (lazily initialized)
    var sendSignalStream: AsyncStream<Void>?

    /// Whether send signal has been shutdown
    var isSendSignalShutdown: Bool = false
}

// MARK: - Errors

/// Errors from ManagedConnection
public enum ManagedConnectionError: Error, Sendable {
    /// Connection is closed
    case connectionClosed

    /// Handshake not complete
    case handshakeNotComplete

    /// Stream not found
    case streamNotFound(UInt64)

    /// Invalid state
    case invalidState(String)
}
