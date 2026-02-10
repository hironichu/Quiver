/// QUIC Connection Handler
///
/// Main orchestrator for QUIC connection management.
/// Handles packet processing, loss detection, ACK generation,
/// and TLS handshake coordination.

import Foundation
import Logging
import Synchronization
import QUICCore
import QUICRecovery
import QUICCrypto
import QUICStream

// MARK: - Connection Handler Errors

/// Errors that can occur during connection handling
package enum QUICConnectionHandlerError: Error, Sendable {
    /// Missing required secret for key derivation
    case missingSecret(String)
    /// Invalid encryption level
    case invalidEncryptionLevel(EncryptionLevel)
    /// Key derivation failed
    case keyDerivationFailed(String)
    /// Crypto operation failed
    case cryptoError(String)
}

// MARK: - Connection Handler

/// Main handler for a QUIC connection
///
/// Orchestrates all connection components:
/// - Packet reception and transmission
/// - Loss detection and recovery
/// - ACK generation and processing
/// - TLS handshake coordination
/// - Key schedule management
package final class QUICConnectionHandler: Sendable {
    static let logger = QuiverLogging.logger(label: "quic.connection.handler")
    // MARK: - Properties

    /// Configured maximum datagram size (path MTU).
    ///
    /// Sourced from `QUICConfiguration.maxUDPPayloadSize` at connection
    /// creation time.  Used to cap stream-frame generation, CRYPTO frame
    /// chunking, and congestion-controller initialisation.
    let maxDatagramSize: Int

    /// Connection state
    let connectionState: Mutex<ConnectionState>

    /// Packet number space manager (loss detection + ACK management)
    let pnSpaceManager: PacketNumberSpaceManager

    /// Congestion controller
    let congestionController: any CongestionController

    /// Crypto stream manager
    let cryptoStreamManager: CryptoStreamManager

    /// Data stream manager
    let streamManager: StreamManager

    /// Key schedule
    let keySchedule: Mutex<KeySchedule>

    /// TLS provider (optional - can be set later)
    let tlsProvider: Mutex<(any TLS13Provider)?> = Mutex(nil)

    /// Local transport parameters
    let localTransportParams: TransportParameters

    /// Peer transport parameters (set after handshake)
    let peerTransportParams: Mutex<TransportParameters?> = Mutex(nil)

    /// Crypto contexts for each encryption level
    let cryptoContexts: Mutex<[EncryptionLevel: CryptoContext]>

    /// Pending outbound packets
    let outboundQueue: Mutex<[OutboundPacket]> = Mutex([])

    /// Whether handshake is complete
    let handshakeComplete: Mutex<Bool> = Mutex(false)

    // MARK: - Connection Migration Components

    /// Path validation manager for connection migration
    let pathValidationManager: PathValidationManager

    /// Connection ID manager for CID lifecycle
    let connectionIDManager: ConnectionIDManager

    /// Stateless reset manager
    let statelessResetManager: StatelessResetManager

    // MARK: - Initialization

    /// Creates a new connection handler
    /// - Parameters:
    ///   - role: Connection role (client or server)
    ///   - version: QUIC version
    ///   - sourceConnectionID: Local connection ID
    ///   - destinationConnectionID: Peer's connection ID
    ///   - transportParameters: Local transport parameters
    ///   - congestionControllerFactory: Factory for creating the congestion controller
    ///   - maxDatagramSize: Configured path MTU from
    ///     `QUICConfiguration.maxUDPPayloadSize`.  Defaults to
    ///     `ProtocolLimits.minimumMaximumDatagramSize` for test convenience.
    package init(
        role: ConnectionRole,
        version: QUICVersion,
        sourceConnectionID: ConnectionID,
        destinationConnectionID: ConnectionID,
        transportParameters: TransportParameters,
        congestionControllerFactory: any CongestionControllerFactory = NewRenoFactory(),
        maxDatagramSize: Int = ProtocolLimits.minimumMaximumDatagramSize
    ) {
        self.maxDatagramSize = maxDatagramSize

        self.connectionState = Mutex(ConnectionState(
            role: role,
            version: version,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: destinationConnectionID
        ))

        self.pnSpaceManager = PacketNumberSpaceManager()
        self.congestionController = congestionControllerFactory.makeCongestionController(
            maxDatagramSize: maxDatagramSize
        )
        self.cryptoStreamManager = CryptoStreamManager()

        // Initialize stream manager with transport parameters
        self.streamManager = StreamManager(
            isClient: role == .client,
            initialMaxData: transportParameters.initialMaxData,
            initialMaxStreamDataBidiLocal: transportParameters.initialMaxStreamDataBidiLocal,
            initialMaxStreamDataBidiRemote: transportParameters.initialMaxStreamDataBidiRemote,
            initialMaxStreamDataUni: transportParameters.initialMaxStreamDataUni,
            initialMaxStreamsBidi: transportParameters.initialMaxStreamsBidi,
            initialMaxStreamsUni: transportParameters.initialMaxStreamsUni
        )

        self.keySchedule = Mutex(KeySchedule())
        self.localTransportParams = transportParameters
        self.cryptoContexts = Mutex([:])

        // Initialize connection migration components
        self.pathValidationManager = PathValidationManager()
        self.connectionIDManager = ConnectionIDManager(
            activeConnectionIDLimit: UInt64(transportParameters.activeConnectionIDLimit)
        )
        self.statelessResetManager = StatelessResetManager()
    }

    // MARK: - TLS Provider

    /// Sets the TLS provider for this connection
    /// - Parameter provider: The TLS 1.3 provider to use
    package func setTLSProvider(_ provider: any TLS13Provider) {
        tlsProvider.withLock { $0 = provider }
    }

    // MARK: - Packet Reception

    /// Records a received packet for ACK tracking
    /// - Parameters:
    ///   - packetNumber: The packet number
    ///   - level: The encryption level
    ///   - isAckEliciting: Whether the packet is ACK-eliciting
    ///   - receiveTime: When the packet was received
    package func recordReceivedPacket(
        packetNumber: UInt64,
        level: EncryptionLevel,
        isAckEliciting: Bool,
        receiveTime: ContinuousClock.Instant = .now
    ) {
        pnSpaceManager.onPacketReceived(
            packetNumber: packetNumber,
            level: level,
            isAckEliciting: isAckEliciting,
            receiveTime: receiveTime
        )

        // Update connection state
        connectionState.withLock { state in
            state.updateLargestReceived(packetNumber, level: level)
        }
    }

    // MARK: - Handshake

    /// Marks handshake as complete.
    ///
    /// For servers: Called when TLS handshake completes (server doesn't receive HANDSHAKE_DONE).
    /// For clients: HANDSHAKE_DONE frame processing calls processHandshakeDone() instead.
    ///
    /// This enables stream frame generation in getOutboundPackets().
    package func markHandshakeComplete() {
        Self.logger.debug("Marking handshake complete")
        handshakeComplete.withLock { $0 = true }
        connectionState.withLock { $0.status = .established }
        pnSpaceManager.handshakeConfirmed = true
    }

    /// Sets peer transport parameters (called after TLS handshake)
    ///
    /// This updates various components with the peer's advertised limits and settings,
    /// including the critical `max_ack_delay` used for RTT/PTO calculations.
    ///
    /// - Parameter params: Peer's transport parameters
    package func setPeerTransportParameters(_ params: TransportParameters) {
        peerTransportParams.withLock { $0 = params }

        // RFC 9002: Set peer's max_ack_delay for RTT/PTO calculations
        pnSpaceManager.peerMaxAckDelay = .milliseconds(Int64(params.maxAckDelay))

        // Update stream manager with peer's limits
        streamManager.handleMaxData(MaxDataFrame(maxData: params.initialMaxData))
        streamManager.handleMaxStreams(MaxStreamsFrame(
            maxStreams: params.initialMaxStreamsBidi,
            isBidirectional: true
        ))
        streamManager.handleMaxStreams(MaxStreamsFrame(
            maxStreams: params.initialMaxStreamsUni,
            isBidirectional: false
        ))

        // Update per-stream data limits
        // Note: Peer's bidi_local is our send limit for streams WE open
        //       Peer's bidi_remote is our send limit for streams PEER opens
        streamManager.updatePeerStreamDataLimits(
            bidiLocal: params.initialMaxStreamDataBidiLocal,
            bidiRemote: params.initialMaxStreamDataBidiRemote,
            uni: params.initialMaxStreamDataUni
        )
    }

    // MARK: - Packet Transmission

    /// Gets pending packets to send
    /// - Returns: Array of outbound packets
    package func getOutboundPackets() -> [OutboundPacket] {
        let now = ContinuousClock.Instant.now
        let ackDelayExponent = localTransportParams.ackDelayExponent
        var packets: [OutboundPacket] = []

        // Check if ACKs need to be sent
        for level in [EncryptionLevel.initial, .handshake, .application] {
            if let ackFrame = pnSpaceManager.generateAckFrame(
                for: level,
                now: now,
                ackDelayExponent: ackDelayExponent
            ) {
                queueFrame(.ack(ackFrame), level: level)
            }
        }

        // Generate stream frames (only at application level)
        if handshakeComplete.withLock({ $0 }) {
            let streamFrames = streamManager.generateStreamFrames(maxBytes: maxDatagramSize)
            if !streamFrames.isEmpty {
                Self.logger.trace("Generated \(streamFrames.count) stream frames")
            }
            for streamFrame in streamFrames {
                queueFrame(.stream(streamFrame), level: .application)
            }

            // Generate flow control frames
            let flowFrames = streamManager.generateFlowControlFrames()
            for flowFrame in flowFrames {
                queueFrame(flowFrame, level: .application)
            }
        } else {
            Self.logger.trace("Handshake not complete, skipping stream frame generation")
        }

        // Get queued packets
        packets = outboundQueue.withLock { queue in
            let result = queue
            queue.removeAll()
            return result
        }

        return packets
    }

    /// Queues a frame to be sent
    package func queueFrame(_ frame: Frame, level: EncryptionLevel) {
        let packet = OutboundPacket(frames: [frame], level: level)
        outboundQueue.withLock { $0.append(packet) }
    }

    /// Queues CRYPTO frames to be sent
    package func queueCryptoData(_ data: Data, level: EncryptionLevel) {
        let frames = cryptoStreamManager.createFrames(for: data, at: level, maxFrameSize: maxDatagramSize)
        Self.logger.debug("Queueing \(frames.count) CRYPTO frames (\(data.count) bytes) at \(level)")
        for frame in frames {
            queueFrame(.crypto(frame), level: level)
        }
    }

    /// Records a sent packet for loss detection and congestion control
    /// - Parameter packet: The sent packet
    package func recordSentPacket(_ packet: SentPacket) {
        pnSpaceManager.onPacketSent(packet)

        // Notify congestion controller
        congestionController.onPacketSent(
            bytes: packet.sentBytes,
            now: packet.timeSent
        )
    }

    /// Gets the next packet number for an encryption level
    /// - Parameter level: The encryption level
    /// - Returns: The next packet number
    package func getNextPacketNumber(for level: EncryptionLevel) -> UInt64 {
        connectionState.withLock { state in
            state.getNextPacketNumber(for: level)
        }
    }

    // MARK: - Timer Management

    /// Called when a timer expires
    /// - Returns: Actions to take (retransmit, probe, etc.)
    package func onTimerExpired() -> TimerAction {
        let now = ContinuousClock.Instant.now

        // Check for loss timeout
        if let (level, lossTime) = pnSpaceManager.earliestLossTime(), lossTime <= now {
            if let detector = pnSpaceManager.lossDetectors[level] {
                let rtt = pnSpaceManager.rttEstimator
                let lostPackets = detector.detectLostPackets(now: now, rttEstimator: rtt)
                if !lostPackets.isEmpty {
                    return .retransmit(lostPackets, level: level)
                }
            }
        }

        // Check for PTO (uses internally managed peerMaxAckDelay)
        let ptoDeadline = pnSpaceManager.nextPTODeadline(now: now)
        if ptoDeadline <= now {
            pnSpaceManager.onPTOExpired()
            return .probe
        }

        return .none
    }

    /// Gets the next timer deadline
    /// - Returns: When the next timer should fire
    package func nextTimerDeadline() -> ContinuousClock.Instant? {
        let now = ContinuousClock.Instant.now

        // Get earliest loss time
        let lossTime = pnSpaceManager.earliestLossTime()?.time

        // Get PTO time (uses internally managed peerMaxAckDelay)
        let ptoTime = pnSpaceManager.nextPTODeadline(now: now)

        // Get ACK time
        let ackTime = pnSpaceManager.earliestAckTime()?.time

        // Get pacing time (for smooth transmission)
        let pacingTime = congestionController.nextSendTime()

        // Return earliest
        return [lossTime, ptoTime, ackTime, pacingTime].compactMap { $0 }.min()
    }

    // MARK: - Congestion Control

    /// Checks if a packet can be sent (congestion window and pacing check)
    /// - Parameters:
    ///   - size: Size of the packet in bytes
    ///   - now: Current time
    /// - Returns: `true` if the packet can be sent
    package func canSendPacket(size: Int, now: ContinuousClock.Instant = .now) -> Bool {
        // 1. Check congestion window
        let bytesInFlight = pnSpaceManager.totalBytesInFlight
        guard congestionController.availableWindow(bytesInFlight: bytesInFlight) >= size else {
            return false
        }

        // 2. Check pacing
        if let nextTime = congestionController.nextSendTime() {
            guard now >= nextTime else {
                return false
            }
        }

        return true
    }

    /// Current congestion window in bytes
    package var congestionWindow: Int {
        congestionController.congestionWindow
    }

    /// Available window for sending (congestion window minus bytes in flight)
    package var availableWindow: Int {
        congestionController.availableWindow(bytesInFlight: pnSpaceManager.totalBytesInFlight)
    }

    /// Current congestion control state
    package var congestionState: CongestionState {
        congestionController.currentState
    }

    // MARK: - Connection Close

    /// Closes the connection
    /// - Parameter error: Optional error reason
    package func close(error: ConnectionCloseError? = nil) {
        connectionState.withLock { state in
            state.status = .draining
        }

        // Queue CONNECTION_CLOSE frame
        let closeFrame = ConnectionCloseFrame(
            errorCode: error?.code ?? 0,
            frameType: nil,
            reasonPhrase: error?.reason ?? ""
        )
        queueFrame(.connectionClose(closeFrame), level: .application)
    }

    // MARK: - Status

    /// Current connection status
    package var status: ConnectionStatus {
        connectionState.withLock { $0.status }
    }

    /// Whether the handshake is complete
    package var isHandshakeComplete: Bool {
        handshakeComplete.withLock { $0 }
    }

    /// Current RTT estimate
    package var rttEstimate: Duration {
        pnSpaceManager.rttEstimator.smoothedRTT
    }

    /// Checks if a stream ID is from the remote peer
    /// - Parameter streamID: The stream ID to check
    /// - Returns: True if the stream was initiated by the remote peer
    package func isRemoteStream(_ streamID: UInt64) -> Bool {
        let isClient = connectionState.withLock { $0.role == .client }
        let isClientInitiated = StreamID.isClientInitiated(streamID)
        // Remote stream: if we're client and stream is server-initiated, or vice versa
        return isClient != isClientInitiated
    }

    /// Connection role
    package var role: ConnectionRole {
        connectionState.withLock { $0.role }
    }

    /// Current source connection ID
    package var sourceConnectionID: ConnectionID {
        connectionState.withLock { $0.currentSourceCID }
    }

    /// Current destination connection ID
    package var destinationConnectionID: ConnectionID {
        connectionState.withLock { $0.currentDestinationCID }
    }

    /// QUIC version
    package var version: QUICVersion {
        connectionState.withLock { $0.version }
    }

    // MARK: - Retry Handling

    /// Updates the destination connection ID after receiving a Retry packet
    ///
    /// RFC 9000 Section 8.1.2: The client MUST use the value from the
    /// Source Connection ID field of the Retry packet in the
    /// Destination Connection ID field of subsequent packets.
    ///
    /// - Parameter newCID: The new destination connection ID
    package func updateDestinationConnectionID(_ newCID: ConnectionID) {
        connectionState.withLock { s in
            // Replace the first (current) DCID with the new one
            if s.destinationConnectionIDs.isEmpty {
                s.destinationConnectionIDs = [newCID]
            } else {
                s.destinationConnectionIDs[0] = newCID
            }
        }
    }

    /// Gets the CRYPTO data for resending after a Retry packet
    ///
    /// RFC 9000 Section 8.1.2: After receiving a Retry packet, the client
    /// MUST resend its Initial CRYPTO data with the retry token.
    ///
    /// - Parameter level: The encryption level (should be .initial)
    /// - Returns: The accumulated CRYPTO data at this level
    package func getCryptoDataForRetry(level: EncryptionLevel) -> Data {
        // Get all unacknowledged CRYPTO data from the crypto stream manager
        return cryptoStreamManager.getDataForRetry(level: level)
    }
}