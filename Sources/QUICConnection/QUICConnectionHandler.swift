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
public enum QUICConnectionHandlerError: Error, Sendable {
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
public final class QUICConnectionHandler: Sendable {
    private static let logger = Logger(label: "quic.connection.handler")
    // MARK: - Properties

    /// Connection state
    private let connectionState: Mutex<ConnectionState>

    /// Packet number space manager (loss detection + ACK management)
    private let pnSpaceManager: PacketNumberSpaceManager

    /// Congestion controller
    private let congestionController: NewRenoCongestionController

    /// Crypto stream manager
    private let cryptoStreamManager: CryptoStreamManager

    /// Data stream manager
    private let streamManager: StreamManager

    /// Key schedule
    private let keySchedule: Mutex<KeySchedule>

    /// TLS provider (optional - can be set later)
    private let tlsProvider: Mutex<(any TLS13Provider)?> = Mutex(nil)

    /// Local transport parameters
    private let localTransportParams: TransportParameters

    /// Peer transport parameters (set after handshake)
    private let peerTransportParams: Mutex<TransportParameters?> = Mutex(nil)

    /// Crypto contexts for each encryption level
    private let cryptoContexts: Mutex<[EncryptionLevel: CryptoContext]>

    /// Pending outbound packets
    private let outboundQueue: Mutex<[OutboundPacket]> = Mutex([])

    /// Whether handshake is complete
    private let handshakeComplete: Mutex<Bool> = Mutex(false)

    // MARK: - Connection Migration Components

    /// Path validation manager for connection migration
    private let pathValidationManager: PathValidationManager

    /// Connection ID manager for CID lifecycle
    private let connectionIDManager: ConnectionIDManager

    /// Stateless reset manager
    private let statelessResetManager: StatelessResetManager

    // MARK: - Initialization

    /// Creates a new connection handler
    /// - Parameters:
    ///   - role: Connection role (client or server)
    ///   - version: QUIC version
    ///   - sourceConnectionID: Local connection ID
    ///   - destinationConnectionID: Peer's connection ID
    ///   - transportParameters: Local transport parameters
    public init(
        role: ConnectionRole,
        version: QUICVersion,
        sourceConnectionID: ConnectionID,
        destinationConnectionID: ConnectionID,
        transportParameters: TransportParameters
    ) {
        self.connectionState = Mutex(ConnectionState(
            role: role,
            version: version,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: destinationConnectionID
        ))

        self.pnSpaceManager = PacketNumberSpaceManager()
        self.congestionController = NewRenoCongestionController()
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
    public func setTLSProvider(_ provider: any TLS13Provider) {
        tlsProvider.withLock { $0 = provider }
    }

    // MARK: - Initial Key Derivation

    /// Derives and installs initial keys
    /// - Parameter connectionID: The connection ID to use for key derivation.
    ///   If nil, uses the current destination connection ID. Servers should pass
    ///   the original DCID from the client's first Initial packet.
    /// - Returns: Tuple of client and server key material
    public func deriveInitialKeys(connectionID: ConnectionID? = nil) throws -> (client: KeyMaterial, server: KeyMaterial) {
        let (defaultCID, version) = connectionState.withLock { state in
            (state.currentDestinationCID, state.version)
        }
        let cid = connectionID ?? defaultCID

        let (clientKeys, serverKeys) = try keySchedule.withLock { schedule in
            try schedule.deriveInitialKeys(connectionID: cid, version: version)
        }

        // Create and install crypto contexts
        // RFC 9001 Section 5.2: Initial keys MUST use AES-128-GCM-SHA256
        // The cipher suite for initial keys is not negotiated - it's fixed by the protocol
        let role = connectionState.withLock { $0.role }
        let (readKeys, writeKeys) = role == .client ?
            (serverKeys, clientKeys) : (clientKeys, serverKeys)

        // Initial keys always use AES-128-GCM per RFC 9001 Section 5.2
        let opener = try AES128GCMOpener(keyMaterial: readKeys)
        let sealer = try AES128GCMSealer(keyMaterial: writeKeys)

        cryptoContexts.withLock { contexts in
            contexts[.initial] = CryptoContext(opener: opener, sealer: sealer)
        }

        return (client: clientKeys, server: serverKeys)
    }

    // MARK: - Packet Reception

    /// Records a received packet for ACK tracking
    /// - Parameters:
    ///   - packetNumber: The packet number
    ///   - level: The encryption level
    ///   - isAckEliciting: Whether the packet is ACK-eliciting
    ///   - receiveTime: When the packet was received
    public func recordReceivedPacket(
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

    // MARK: - Frame Processing

    /// Processes frames from a decrypted packet
    /// - Parameters:
    ///   - frames: The frames to process
    ///   - level: The encryption level
    /// - Returns: Processing result
    /// - Throws: ProtocolViolation if a frame is not valid at the encryption level
    public func processFrames(
        _ frames: [Frame],
        level: EncryptionLevel
    ) throws -> FrameProcessingResult {
        var result = FrameProcessingResult()

        for frame in frames {
            // RFC 9000 §12.4: Validate frame type is allowed at this encryption level
            guard frame.isValid(at: level) else {
                throw QUICError.frameNotAllowed(
                    frameType: UInt64(frame.frameType.rawValue),
                    packetType: "\(level)"
                )
            }

            Self.logger.trace("Processing frame: \(frame) at level: \(level)")

            switch frame {
            case .ack(let ackFrame):
                try processAckFrame(ackFrame, level: level)

            case .crypto(let cryptoFrame):
                try processCryptoFrame(cryptoFrame, level: level, result: &result)

            case .connectionClose(let closeFrame):
                Self.logger.warning("CONNECTION_CLOSE received: errorCode=\(closeFrame.errorCode), frameType=\(String(describing: closeFrame.frameType)), reason=\(closeFrame.reasonPhrase), isAppError=\(closeFrame.isApplicationError)")
                processConnectionClose(closeFrame)
                result.connectionClosed = true

            case .handshakeDone:
                Self.logger.debug("Received HANDSHAKE_DONE frame")
                processHandshakeDone()
                result.handshakeComplete = true

            case .stream(let streamFrame):
                // Check if this is a new peer-initiated stream
                let isNewStream = !streamManager.hasStream(id: streamFrame.streamID)
                let isRemote = isRemoteStream(streamFrame.streamID)
                Self.logger.trace("STREAM frame: streamID=\(streamFrame.streamID), isNew=\(isNewStream), isRemote=\(isRemote), dataLen=\(streamFrame.data.count), fin=\(streamFrame.fin)")

                try streamManager.receive(frame: streamFrame)

                // Track new peer-initiated streams
                if isNewStream {
                    if isRemote {
                        Self.logger.debug("Adding streamID=\(streamFrame.streamID) to newStreams")
                        result.newStreams.append(streamFrame.streamID)
                    } else {
                        Self.logger.trace("Skipping streamID=\(streamFrame.streamID) - locally initiated")
                    }
                }

                // Read available data from the stream
                if let data = streamManager.read(streamID: streamFrame.streamID) {
                    Self.logger.trace("Read \(data.count) bytes from stream \(streamFrame.streamID)")
                    result.streamData.append((streamFrame.streamID, data))
                } else {
                    Self.logger.trace("No data available from stream \(streamFrame.streamID) after receive")
                }

                // Check if the stream's receive side is now complete (FIN
                // received and all contiguous data consumed).  Tracking this
                // allows ManagedConnection to resume any blocked reader with
                // an end-of-stream signal instead of letting it hang forever.
                if streamManager.isStreamReceiveComplete(streamID: streamFrame.streamID) {
                    Self.logger.debug("Stream \(streamFrame.streamID) receive complete (FIN)")
                    result.finishedStreams.append(streamFrame.streamID)
                }

            case .resetStream(let resetFrame):
                try streamManager.handleResetStream(resetFrame)

            case .stopSending(let stopFrame):
                streamManager.handleStopSending(stopFrame)

            case .maxData(let maxData):
                streamManager.handleMaxData(MaxDataFrame(maxData: maxData))

            case .maxStreamData(let maxStreamDataFrame):
                streamManager.handleMaxStreamData(maxStreamDataFrame)

            case .maxStreams(let maxStreamsFrame):
                streamManager.handleMaxStreams(maxStreamsFrame)

            case .dataBlocked, .streamDataBlocked, .streamsBlocked:
                // Generate flow control frames as needed
                break

            case .padding, .ping:
                // No action needed
                break

            // MARK: - Connection Migration Frames

            case .pathChallenge(let data):
                // Handle challenge using PathValidationManager
                // Queue PATH_RESPONSE frame to send back
                let responseFrame = pathValidationManager.handleChallenge(data)
                queueFrame(responseFrame, level: level)
                result.pathChallengeData.append(data)

            case .pathResponse(let data):
                // Handle response using PathValidationManager
                if let validatedPath = pathValidationManager.handleResponse(data) {
                    result.pathValidated = validatedPath
                }
                result.pathResponseData.append(data)

            case .newConnectionID(let frame):
                Self.logger.debug("Received NEW_CONNECTION_ID: CID=\(frame.connectionID), seq=\(frame.sequenceNumber), retirePriorTo=\(frame.retirePriorTo)")
                // Process using ConnectionIDManager
                // RFC 9000 §5.1.1: Validates duplicate sequence numbers and limit
                try connectionIDManager.handleNewConnectionID(frame)
                // Register the stateless reset token
                statelessResetManager.registerReceivedToken(frame.statelessResetToken)
                result.newConnectionIDs.append(frame)

            case .retireConnectionID(let sequenceNumber):
                // Process using ConnectionIDManager
                if let retired = connectionIDManager.handleRetireConnectionID(sequenceNumber) {
                    // Remove the associated reset token
                    statelessResetManager.removeReceivedToken(retired.statelessResetToken)
                }
                result.retiredConnectionIDs.append(sequenceNumber)

            case .datagram(let datagramFrame):
                // RFC 9221: DATAGRAM frames carry unreliable application data
                Self.logger.trace("DATAGRAM frame received: \(datagramFrame.data.count) bytes")
                result.datagramsReceived.append(datagramFrame.data)

            default:
                // Other frames handled as needed
                break
            }
        }

        return result
    }

    /// Processes an ACK frame
    ///
    /// RFC 9002 compliant ACK processing:
    /// 1. Process ACK to detect acked/lost packets and update RTT
    /// 2. Notify congestion controller of acknowledged packets
    /// 3. Handle packet loss with congestion control
    ///
    /// - Note: Uses internally managed `peerMaxAckDelay` for RTT/PTO calculations.
    private func processAckFrame(_ ackFrame: AckFrame, level: EncryptionLevel) throws {
        let now = ContinuousClock.Instant.now

        let result = pnSpaceManager.onAckReceived(
            ackFrame: ackFrame,
            level: level,
            receiveTime: now
        )

        // Congestion Control: process acknowledged packets
        if !result.ackedPackets.isEmpty {
            congestionController.onPacketsAcknowledged(
                packets: result.ackedPackets,
                now: now,
                rtt: pnSpaceManager.rttEstimator
            )
        }

        // Congestion Control: process lost packets
        if !result.lostPackets.isEmpty {
            // RFC 9002 Section 7.6.2 - Persistent Congestion
            //
            // Per the RFC, persistent congestion detection happens AFTER loss detection,
            // and causes an ADDITIONAL response beyond normal loss handling:
            // - Normal loss: cwnd reduced by half, enter recovery
            // - Persistent congestion: cwnd collapsed to minimum, ssthresh reset
            //
            // Implementation note:
            // We use if-else here because persistent congestion subsumes normal loss:
            // - Both would enter recovery, but persistent congestion also resets ssthresh
            // - Applying loss first (cwnd/2) then persistent congestion (cwnd=minimum)
            //   would give the same result as applying persistent congestion alone
            // - The key difference is ssthresh reset, which only persistent congestion does
            //
            // This optimization is valid because:
            // - minimum_window (2*MSS) < cwnd/2 for any cwnd > 4*MSS (always true after slow start)
            // - Persistent congestion resets to slow start (ssthresh=∞), which is the desired behavior
            if pnSpaceManager.checkPersistentCongestion(lostPackets: result.lostPackets) {
                congestionController.onPersistentCongestion()
            } else {
                congestionController.onPacketsLost(
                    packets: result.lostPackets,
                    now: now,
                    rtt: pnSpaceManager.rttEstimator
                )
            }
        }
    }

    /// Processes a CRYPTO frame
    private func processCryptoFrame(
        _ cryptoFrame: CryptoFrame,
        level: EncryptionLevel,
        result: inout FrameProcessingResult
    ) throws {
        // Buffer the crypto data
        try cryptoStreamManager.receive(cryptoFrame, at: level)

        // Try to read complete data
        if let data = cryptoStreamManager.read(at: level) {
            result.cryptoData.append((level, data))
        }
    }

    /// Processes CONNECTION_CLOSE frame
    private func processConnectionClose(_ closeFrame: ConnectionCloseFrame) {
        connectionState.withLock { state in
            state.status = .draining
        }
    }

    /// Processes HANDSHAKE_DONE frame
    private func processHandshakeDone() {
        handshakeComplete.withLock { $0 = true }
        connectionState.withLock { $0.status = .established }
        pnSpaceManager.handshakeConfirmed = true
    }

    /// Marks handshake as complete.
    ///
    /// For servers: Called when TLS handshake completes (server doesn't receive HANDSHAKE_DONE).
    /// For clients: HANDSHAKE_DONE frame processing calls processHandshakeDone() instead.
    ///
    /// This enables stream frame generation in getOutboundPackets().
    public func markHandshakeComplete() {
        Self.logger.info("Marking handshake complete")
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
    public func setPeerTransportParameters(_ params: TransportParameters) {
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

    // MARK: - Key Management

    /// Installs keys for an encryption level
    /// - Parameter info: Information about the available keys
    public func installKeys(_ info: KeysAvailableInfo) throws {
        let role = connectionState.withLock { $0.role }
        let cipherSuite = info.cipherSuite

        // Handle 0-RTT keys specially (only one direction)
        if info.level == .zeroRTT {
            guard let clientSecret = info.clientSecret else {
                throw QUICConnectionHandlerError.missingSecret("0-RTT requires client secret")
            }
            let clientKeys = try KeyMaterial.derive(from: clientSecret, cipherSuite: cipherSuite)
            let (opener, sealer) = try clientKeys.createCrypto()

            if role == .client {
                // Client writes 0-RTT data
                cryptoContexts.withLock { contexts in
                    // 0-RTT only has sealer for client
                    contexts[info.level] = CryptoContext(opener: nil, sealer: sealer)
                }
            } else {
                // Server reads 0-RTT data
                cryptoContexts.withLock { contexts in
                    // 0-RTT only has opener for server
                    contexts[info.level] = CryptoContext(opener: opener, sealer: nil)
                }
            }
            return
        }

        // Standard bidirectional keys
        guard let clientSecret = info.clientSecret,
              let serverSecret = info.serverSecret else {
            throw QUICConnectionHandlerError.missingSecret("Both client and server secrets required")
        }

        // Determine which keys to use for read/write based on role
        let readKeys: KeyMaterial
        let writeKeys: KeyMaterial
        if role == .client {
            readKeys = try KeyMaterial.derive(from: serverSecret, cipherSuite: cipherSuite)
            writeKeys = try KeyMaterial.derive(from: clientSecret, cipherSuite: cipherSuite)
        } else {
            readKeys = try KeyMaterial.derive(from: clientSecret, cipherSuite: cipherSuite)
            writeKeys = try KeyMaterial.derive(from: serverSecret, cipherSuite: cipherSuite)
        }

        // Create opener/sealer using factory method (selects AES or ChaCha20)
        let (opener, _) = try readKeys.createCrypto()
        let (_, sealer) = try writeKeys.createCrypto()

        cryptoContexts.withLock { contexts in
            contexts[info.level] = CryptoContext(opener: opener, sealer: sealer)
        }

        // Update key schedule
        keySchedule.withLock { schedule in
            switch info.level {
            case .handshake:
                _ = try? schedule.setHandshakeSecrets(
                    clientSecret: clientSecret,
                    serverSecret: serverSecret
                )
            case .application:
                _ = try? schedule.setApplicationSecrets(
                    clientSecret: clientSecret,
                    serverSecret: serverSecret
                )
            default:
                break
            }
        }
    }

    /// Gets the crypto context for an encryption level
    /// - Parameter level: The encryption level
    /// - Returns: The crypto context, if available
    public func cryptoContext(for level: EncryptionLevel) -> CryptoContext? {
        cryptoContexts.withLock { $0[level] }
    }

    // MARK: - Packet Transmission

    /// Gets pending packets to send
    /// - Returns: Array of outbound packets
    public func getOutboundPackets() -> [OutboundPacket] {
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
            let streamFrames = streamManager.generateStreamFrames(maxBytes: 1200)
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
    public func queueFrame(_ frame: Frame, level: EncryptionLevel) {
        let packet = OutboundPacket(frames: [frame], level: level)
        outboundQueue.withLock { $0.append(packet) }
    }

    /// Queues CRYPTO frames to be sent
    public func queueCryptoData(_ data: Data, level: EncryptionLevel) {
        let frames = cryptoStreamManager.createFrames(for: data, at: level)
        Self.logger.debug("Queueing \(frames.count) CRYPTO frames (\(data.count) bytes) at \(level)")
        for frame in frames {
            queueFrame(.crypto(frame), level: level)
        }
    }

    /// Records a sent packet for loss detection and congestion control
    /// - Parameter packet: The sent packet
    public func recordSentPacket(_ packet: SentPacket) {
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
    public func getNextPacketNumber(for level: EncryptionLevel) -> UInt64 {
        connectionState.withLock { state in
            state.getNextPacketNumber(for: level)
        }
    }

    // MARK: - Timer Management

    /// Called when a timer expires
    /// - Returns: Actions to take (retransmit, probe, etc.)
    public func onTimerExpired() -> TimerAction {
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
    public func nextTimerDeadline() -> ContinuousClock.Instant? {
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
    public func canSendPacket(size: Int, now: ContinuousClock.Instant = .now) -> Bool {
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
    public var congestionWindow: Int {
        congestionController.congestionWindow
    }

    /// Available window for sending (congestion window minus bytes in flight)
    public var availableWindow: Int {
        congestionController.availableWindow(bytesInFlight: pnSpaceManager.totalBytesInFlight)
    }

    /// Current congestion control state
    public var congestionState: CongestionState {
        congestionController.currentState
    }

    // MARK: - Stream Management

    /// Opens a new stream
    /// - Parameter bidirectional: Whether to create a bidirectional stream
    /// - Returns: The new stream ID
    /// - Throws: StreamManagerError if stream limit reached
    public func openStream(bidirectional: Bool) throws -> UInt64 {
        try streamManager.openStream(bidirectional: bidirectional)
    }

    /// Writes data to a stream
    /// - Parameters:
    ///   - streamID: Stream to write to
    ///   - data: Data to write
    /// - Throws: StreamManagerError on failures
    public func writeToStream(_ streamID: UInt64, data: Data) throws {
        try streamManager.write(streamID: streamID, data: data)
    }

    /// Finishes writing to a stream (sends FIN)
    /// - Parameter streamID: Stream to finish
    /// - Throws: StreamManagerError on failures
    public func finishStream(_ streamID: UInt64) throws {
        try streamManager.finish(streamID: streamID)
    }

    /// Reads data from a stream
    /// - Parameter streamID: Stream to read from
    /// - Returns: Available data, or nil if none
    public func readFromStream(_ streamID: UInt64) -> Data? {
        streamManager.read(streamID: streamID)
    }

    /// Closes a stream
    /// - Parameter streamID: Stream to close
    public func closeStream(_ streamID: UInt64) {
        streamManager.closeStream(id: streamID)
    }

    /// Whether the receive side of a stream is complete (FIN received, all data read)
    ///
    /// Use this to detect end-of-stream without blocking.  Returns `true`
    /// when the peer has sent FIN and all contiguous data has been consumed.
    public func isStreamReceiveComplete(_ streamID: UInt64) -> Bool {
        streamManager.isStreamReceiveComplete(streamID: streamID)
    }

    /// Whether the stream was reset by the peer (RESET_STREAM received)
    public func isStreamResetByPeer(_ streamID: UInt64) -> Bool {
        streamManager.isStreamResetByPeer(streamID: streamID)
    }

    /// Checks if a stream has data to read
    /// - Parameter streamID: Stream to check
    /// - Returns: true if data available
    public func streamHasDataToRead(_ streamID: UInt64) -> Bool {
        streamManager.hasDataToRead(streamID: streamID)
    }

    /// Checks if a stream has data to send
    /// - Parameter streamID: Stream to check
    /// - Returns: true if data pending
    public func streamHasDataToSend(_ streamID: UInt64) -> Bool {
        streamManager.hasDataToSend(streamID: streamID)
    }

    /// Gets all active stream IDs
    public var activeStreamIDs: [UInt64] {
        streamManager.activeStreamIDs
    }

    /// Gets the number of active streams
    public var activeStreamCount: Int {
        streamManager.activeStreamCount
    }

    /// Whether any stream has data waiting to be sent
    ///
    /// Use this to check if outbound packets need to be generated and sent.
    public var hasPendingStreamData: Bool {
        streamManager.hasPendingStreamData
    }

    // MARK: - Datagram Support (RFC 9221)

    /// Sends a QUIC DATAGRAM frame with the given payload.
    ///
    /// Queues a DATAGRAM frame (with explicit length) to be sent in the
    /// next outbound packet at the application encryption level.
    ///
    /// - Parameter data: The datagram payload
    /// - Throws: `QUICConnectionHandlerError.connectionClosed` if the connection is draining/closed
    public func sendDatagram(_ data: Data) throws {
        let status = connectionState.withLock { $0.status }
        guard status == .established else {
            throw QUICConnectionHandlerError.cryptoError("Connection not established for datagram send")
        }

        let frame = Frame.datagram(DatagramFrame(data: data, hasLength: true))
        queueFrame(frame, level: .application)
    }

    // MARK: - Connection Close

    /// Closes the connection
    /// - Parameter error: Optional error reason
    public func close(error: ConnectionCloseError? = nil) {
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
    public var status: ConnectionStatus {
        connectionState.withLock { $0.status }
    }

    /// Whether the handshake is complete
    public var isHandshakeComplete: Bool {
        handshakeComplete.withLock { $0 }
    }

    /// Current RTT estimate
    public var rttEstimate: Duration {
        pnSpaceManager.rttEstimator.smoothedRTT
    }

    /// Checks if a stream ID is from the remote peer
    /// - Parameter streamID: The stream ID to check
    /// - Returns: True if the stream was initiated by the remote peer
    private func isRemoteStream(_ streamID: UInt64) -> Bool {
        let isClient = connectionState.withLock { $0.role == .client }
        let isClientInitiated = StreamID.isClientInitiated(streamID)
        // Remote stream: if we're client and stream is server-initiated, or vice versa
        return isClient != isClientInitiated
    }

    /// Connection role
    public var role: ConnectionRole {
        connectionState.withLock { $0.role }
    }

    /// Current source connection ID
    public var sourceConnectionID: ConnectionID {
        connectionState.withLock { $0.currentSourceCID }
    }

    /// Current destination connection ID
    public var destinationConnectionID: ConnectionID {
        connectionState.withLock { $0.currentDestinationCID }
    }

    /// QUIC version
    public var version: QUICVersion {
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
    public func updateDestinationConnectionID(_ newCID: ConnectionID) {
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
    public func getCryptoDataForRetry(level: EncryptionLevel) -> Data {
        // Get all unacknowledged CRYPTO data from the crypto stream manager
        return cryptoStreamManager.getDataForRetry(level: level)
    }

    // MARK: - Connection Migration API

    /// Initiates path validation for a new network path
    /// - Parameter path: The network path to validate
    /// - Returns: PATH_CHALLENGE frame to send
    public func initiatePathValidation(for path: NetworkPath) -> Frame {
        pathValidationManager.createChallengeFrame(for: path)
    }

    /// Checks if a network path is validated
    /// - Parameter path: The path to check
    /// - Returns: True if the path has been validated
    public func isPathValidated(_ path: NetworkPath) -> Bool {
        pathValidationManager.isValidated(path)
    }

    /// Gets all validated network paths
    public var validatedPaths: Set<NetworkPath> {
        pathValidationManager.validatedPaths
    }

    /// Checks for path validation timeouts
    /// - Returns: Paths that failed validation due to timeout
    public func checkPathValidationTimeouts() -> [NetworkPath] {
        pathValidationManager.checkTimeouts()
    }

    /// Issues a new connection ID to the peer
    /// - Parameter length: Length of the connection ID (default 8)
    /// - Returns: NEW_CONNECTION_ID frame to send
    /// - Throws: If the length is invalid or frame creation fails
    public func issueNewConnectionID(length: Int = 8) throws -> NewConnectionIDFrame {
        try connectionIDManager.issueNewConnectionID(length: length)
    }

    /// Gets the current active peer connection ID for sending
    public var activePeerConnectionID: ConnectionID? {
        connectionIDManager.activePeerConnectionID
    }

    /// Switches to a different peer connection ID
    /// - Parameter sequenceNumber: The sequence number of the CID to use
    /// - Returns: True if switch was successful
    public func switchToConnectionID(sequenceNumber: UInt64) -> Bool {
        connectionIDManager.switchToConnectionID(sequenceNumber: sequenceNumber)
    }

    /// Gets all available peer connection IDs
    public var availablePeerCIDs: [ConnectionIDManager.PeerConnectionID] {
        connectionIDManager.availablePeerCIDs
    }

    /// Retires a peer connection ID
    /// - Parameter sequenceNumber: The sequence number to retire
    /// - Returns: RETIRE_CONNECTION_ID frame to send, or nil if not found
    public func retirePeerConnectionID(sequenceNumber: UInt64) -> Frame? {
        connectionIDManager.retirePeerConnectionID(sequenceNumber: sequenceNumber)
    }

    /// Checks if a packet is a stateless reset
    /// - Parameter data: The received packet data
    /// - Returns: True if this is a stateless reset packet
    public func isStatelessReset(_ data: Data) -> Bool {
        statelessResetManager.isStatelessReset(data)
    }

    /// Creates a stateless reset packet
    /// - Parameter connectionID: The connection ID being reset
    /// - Returns: The encoded stateless reset packet, or nil if no token exists
    public func createStatelessReset(for connectionID: ConnectionID) -> Data? {
        statelessResetManager.createStatelessReset(for: connectionID)
    }

    /// Discards an encryption level
    /// - Parameter level: The level to discard
    public func discardLevel(_ level: EncryptionLevel) {
        pnSpaceManager.discardLevel(level)
        cryptoStreamManager.discardLevel(level)
        _ = cryptoContexts.withLock { $0.removeValue(forKey: level) }
        keySchedule.withLock { $0.discardKeys(for: level) }
    }
}

// MARK: - Supporting Types

/// Result of processing frames
public struct FrameProcessingResult: Sendable {
    /// Crypto data received at each level
    public var cryptoData: [(EncryptionLevel, Data)] = []

    /// Stream data received (stream ID, data)
    public var streamData: [(UInt64, Data)] = []

    /// New peer-initiated streams that were created
    public var newStreams: [UInt64] = []

    /// Whether the handshake completed
    public var handshakeComplete: Bool = false

    /// Whether the connection was closed
    public var connectionClosed: Bool = false

    /// Streams whose receive side is now complete (FIN received, all data read)
    ///
    /// These streams will not produce any more data.  Readers that are
    /// waiting for data on these streams should be woken with an
    /// end-of-stream signal (empty `Data`).
    public var finishedStreams: [UInt64] = []

    // MARK: - Datagrams (RFC 9221)

    /// DATAGRAM frame payloads received from the peer
    public var datagramsReceived: [Data] = []

    // MARK: - Connection Migration

    /// PATH_CHALLENGE data received (requires PATH_RESPONSE)
    public var pathChallengeData: [Data] = []

    /// PATH_RESPONSE data received (validates our challenge)
    public var pathResponseData: [Data] = []

    /// Path that was successfully validated (if any)
    public var pathValidated: NetworkPath? = nil

    /// New connection IDs issued by peer
    public var newConnectionIDs: [NewConnectionIDFrame] = []

    /// Connection IDs retired by peer
    public var retiredConnectionIDs: [UInt64] = []
}

/// Packet to be sent
public struct OutboundPacket: Sendable {
    /// Frames in this packet
    public let frames: [Frame]

    /// Encryption level
    public let level: EncryptionLevel

    /// Creation time
    public let createdAt: ContinuousClock.Instant

    /// Creates an outbound packet
    public init(frames: [Frame], level: EncryptionLevel) {
        self.frames = frames
        self.level = level
        self.createdAt = .now
    }
}

/// Action to take on timer expiry
public enum TimerAction: Sendable {
    /// No action needed
    case none

    /// Retransmit lost packets at the specified level
    case retransmit([SentPacket], level: EncryptionLevel)

    /// Send probe packets
    case probe
}

/// Error for connection close
public struct ConnectionCloseError: Sendable {
    /// Error code
    public let code: UInt64

    /// Reason phrase
    public let reason: String

    /// Creates a connection close error
    public init(code: UInt64, reason: String = "") {
        self.code = code
        self.reason = reason
    }
}
