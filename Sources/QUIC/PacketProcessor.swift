/// Packet Processor
///
/// High-level integration layer for QUIC packet encoding/decoding.
/// Combines PacketEncoder, PacketDecoder, and crypto contexts for
/// convenient packet processing.

import Crypto
import QUICCore
import QUICCrypto
import Synchronization

#if canImport(FoundationEssentials)
    import FoundationEssentials
#else
    import Foundation
#endif

// MARK: - Packet Processor

/// High-level packet processor for QUIC connections
///
/// Provides a simplified API for packet encryption/decryption by combining:
/// - PacketEncoder/PacketDecoder for wire format handling
/// - CryptoContext for encryption/decryption at each level
/// - Coalesced packet handling
///
/// Thread-safe via Mutex for crypto context updates.
package final class PacketProcessor: Sendable {
    private static let logger = QuiverLogging.logger(label: "quic.core.packet-processor")

    // MARK: - Properties

    /// Crypto contexts per encryption level (Initial, Handshake, 0-RTT)
    private let contexts: Mutex<[EncryptionLevel: CryptoContext]>

    /// Application key contexts per Key Phase (0 or 1)
    private let applicationContexts: Mutex<[UInt8: CryptoContext]>

    /// Current Key Phase for sending (0 or 1)
    private let _currentKeyPhase: Atomic<UInt8>

    /// Packet encoder
    private let encoder = PacketEncoder()

    /// Packet decoder
    private let decoder = PacketDecoder()

    /// Local DCID length (for short header parsing)
    /// Uses Atomic for lock-free reads on the hot path
    private let _dcidLength: Atomic<Int>

    /// Largest packet numbers received per level (for PN decoding)
    private let largestReceivedPN: Mutex<[EncryptionLevel: UInt64]>

    /// Configured maximum datagram size (path MTU).
    ///
    /// Sourced from `QUICConfiguration.maxUDPPayloadSize` at connection
    /// creation time.  Used for packet encryption size checks and
    /// coalesced-packet building.  Never hard-codes 1200 — the value
    /// is whatever the caller supplies.
    let maxDatagramSize: Int

    /// Current DCID length (lock-free read)
    @inline(__always)
    package var dcidLengthValue: Int {
        _dcidLength.load(ordering: .relaxed)
    }

    /// Current Key Phase (lock-free read)
    package var currentKeyPhase: UInt8 {
        _currentKeyPhase.load(ordering: .relaxed)
    }

    // MARK: - Initialization

    /// Maximum allowed DCID length per RFC 9000 Section 17.2
    private static let maxDCIDLength = 20

    /// Creates a new packet processor
    /// - Parameters:
    ///   - dcidLength: Expected DCID length for short headers (0-20)
    ///   - maxDatagramSize: Configured path MTU from
    ///     `QUICConfiguration.maxUDPPayloadSize`.  Defaults to
    ///     `ProtocolLimits.minimumMaximumDatagramSize` (1200) so that
    ///     call-sites that genuinely have no configuration (e.g. unit
    ///     tests) still produce RFC-compliant packets.
    package init(
        dcidLength: Int = 8,
        maxDatagramSize: Int = ProtocolLimits.minimumMaximumDatagramSize
    ) {
        // Clamp to valid range (RFC 9000 Section 17.2: 0-20 bytes)
        let validLength = max(0, min(dcidLength, Self.maxDCIDLength))
        self.contexts = Mutex([:])
        self.applicationContexts = Mutex([:])
        self._currentKeyPhase = Atomic(0)
        self._dcidLength = Atomic(validLength)
        self.largestReceivedPN = Mutex([:])
        self.maxDatagramSize = maxDatagramSize
    }

    // MARK: - Crypto Context Management

    /// Installs a crypto context for an encryption level
    /// - Parameters:
    ///   - context: The crypto context
    ///   - level: The encryption level
    package func installContext(_ context: CryptoContext, for level: EncryptionLevel) {
        if level == .application {
            // Install as Phase 0 by default for new application keys
            applicationContexts.withLock { $0[0] = context }
        } else {
            contexts.withLock { $0[level] = context }
        }
    }

    /// Discards crypto context for an encryption level
    /// - Parameter level: The level to discard
    package func discardContext(for level: EncryptionLevel) {
        if level == .application {
            applicationContexts.withLock { $0.removeAll() }
        } else {
            _ = contexts.withLock { $0.removeValue(forKey: level) }
        }
    }

    /// Gets the crypto context for a level
    /// - Parameter level: The encryption level
    /// - Returns: The context, or nil if not installed
    package func context(for level: EncryptionLevel) -> CryptoContext? {
        if level == .application {
            // Return current phase context
            let phase = currentKeyPhase
            return applicationContexts.withLock { $0[phase] }
        } else {
            return contexts.withLock { $0[level] }
        }
    }

    /// Updates the DCID length (for short header parsing)
    /// - Parameter length: The new DCID length (0-20, clamped if out of range)
    package func setDCIDLength(_ length: Int) {
        // Clamp to valid range (RFC 9000 Section 17.2: 0-20 bytes)
        let validLength = max(0, min(length, Self.maxDCIDLength))
        _dcidLength.store(validLength, ordering: .relaxed)
    }

    // MARK: - Unified Key Management

    /// Installs keys from TLS keying material
    ///
    /// This is the unified entry point for key installation.
    /// PacketProcessor is the single source of truth for crypto contexts.
    ///
    /// - Parameters:
    ///   - info: Keys available info from TLS provider
    ///   - isClient: Whether this is the client side
    /// - Throws: Error if key derivation or context creation fails
    /// Installs keys from TLS keying material
    ///
    /// This is the unified entry point for key installation.
    /// PacketProcessor is the single source of truth for crypto contexts.
    ///
    /// - Parameters:
    ///   - info: Keys available info from TLS provider
    ///   - isClient: Whether this is the client side
    /// - Throws: Error if key derivation or context creation fails
    package func installKeys(_ info: KeysAvailableInfo, isClient: Bool) throws {
        let cipherSuite = info.cipherSuite

        // Handle 0-RTT keys specially (only one direction)
        if info.level == .zeroRTT {
            guard let clientSecret = info.clientSecret else {
                throw PacketCodecError.invalidPacketFormat("0-RTT requires client secret")
            }
            let clientKeys = try KeyMaterial.derive(from: clientSecret, cipherSuite: cipherSuite)
            let (opener, sealer) = try clientKeys.createCrypto()

            if isClient {
                // Client writes 0-RTT data
                let secretData = clientSecret.withUnsafeBytes { Data($0) }
                let context = CryptoContext(
                    opener: nil,
                    sealer: sealer,
                    readTrafficSecret: nil,
                    writeTrafficSecret: secretData,
                    cipherSuite: cipherSuite
                )
                installContext(context, for: info.level)
            } else {
                // Server reads 0-RTT data
                let secretData = clientSecret.withUnsafeBytes { Data($0) }
                let context = CryptoContext(
                    opener: opener,
                    sealer: nil,
                    readTrafficSecret: secretData,
                    writeTrafficSecret: nil,
                    cipherSuite: cipherSuite
                )
                installContext(context, for: info.level)
            }
            return
        }

        // Standard bidirectional keys
        guard let clientSecret = info.clientSecret,
            let serverSecret = info.serverSecret
        else {
            throw PacketCodecError.invalidPacketFormat("Both client and server secrets required")
        }

        // Derive key material from traffic secrets using negotiated cipher suite
        let clientKeys = try KeyMaterial.derive(from: clientSecret, cipherSuite: cipherSuite)
        let serverKeys = try KeyMaterial.derive(from: serverSecret, cipherSuite: cipherSuite)

        // Client reads server keys, writes client keys (and vice versa)
        let readKeys = isClient ? serverKeys : clientKeys
        let writeKeys = isClient ? clientKeys : serverKeys

        // Create opener (for decryption) and sealer (for encryption) using factory method
        let (opener, _) = try readKeys.createCrypto()
        let (_, sealer) = try writeKeys.createCrypto()

        // Traffic secrets for Key Update
        // Store the secrets used to DERIVE these keys.
        let readSecretKey = isClient ? serverSecret : clientSecret
        let writeSecretKey = isClient ? clientSecret : serverSecret

        let readSecretData = readSecretKey.withUnsafeBytes { Data($0) }
        let writeSecretData = writeSecretKey.withUnsafeBytes { Data($0) }

        let context = CryptoContext(
            opener: opener,
            sealer: sealer,
            readTrafficSecret: readSecretData,
            writeTrafficSecret: writeSecretData,
            cipherSuite: cipherSuite
        )

        installContext(context, for: info.level)
    }

    /// Discards keys for an encryption level
    ///
    /// This is the unified entry point for key discarding.
    /// Call this after all packets at this level have been sent.
    ///
    /// - Parameter level: The encryption level to discard
    package func discardKeys(for level: EncryptionLevel) {
        discardContext(for: level)
    }

    /// Checks if keys are installed for a level
    /// - Parameter level: The encryption level
    /// - Returns: True if keys are available for this level
    package func hasKeys(for level: EncryptionLevel) -> Bool {
        if level == .application {
            return applicationContexts.withLock { !$0.isEmpty }
        } else {
            return contexts.withLock { $0[level] != nil }
        }
    }

    // MARK: - Packet Decryption

    /// Decrypts a single QUIC packet
    /// - Parameter data: The encrypted packet data
    /// - Returns: The parsed packet with decrypted frames
    /// - Throws: PacketCodecError if decryption fails
    package func decryptPacket(_ data: Data) throws -> ParsedPacket {
        // Peek at first byte to determine encryption level
        guard !data.isEmpty else {
            throw PacketCodecError.insufficientData
        }

        let firstByte = data[data.startIndex]
        let isLongHeader = (firstByte & 0x80) != 0

        // Determine encryption level from protected header
        // For long headers, packet type (bits 5-4) is NOT protected, so we can read it safely
        // For short headers, it's always application level
        let level: EncryptionLevel
        if isLongHeader {
            // Parse protected header to get packet type (no validation of protected bits)
            let (protectedHeader, _) = try ProtectedPacketHeader.parse(from: data)
            level = protectedHeader.encryptionLevel
        } else {
            level = .application
            // Key Phase extraction from protected first byte is useless/incorrect.
            // We handle it via trial decryption.
        }

        // Get opener for this level
        if level == .application {
            // Short Header: Trial Decryption (RFC 9001 Section 6.3)
            // We must try decrypting with the current phase keys, and if that fails,
            // try with the next phase keys to detect a Key Update.

            let currentPhase = currentKeyPhase
            let nextPhase = currentPhase ^ 1

            // 1. Try Current Phase
            if let ctx = applicationContexts.withLock({ $0[currentPhase] }),
                let opener = ctx.opener
            {
                do {
                    return try decoder.decodePacket(
                        data: data,
                        dcidLength: dcidLengthValue,
                        opener: opener,
                        largestPN: largestReceivedPN.withLock { $0[.application] ?? 0 }
                    )
                } catch {
                    // Decryption failed with current keys. This might be a Key Update.
                    // Fall through to try next phase.
                }
            }

            // 2. Try Next Phase
            // We might need to derive the keys if we haven't seen this phase yet.
            var nextCtx = applicationContexts.withLock { $0[nextPhase] }
            var derivedNextCtx: CryptoContext? = nil

            if nextCtx == nil {
                // Try to derive next keys from current keys
                if let currentCtx = applicationContexts.withLock({ $0[currentPhase] }),
                    let readSecret = currentCtx.readTrafficSecret,
                    let writeSecret = currentCtx.writeTrafficSecret,
                    let suite = currentCtx.cipherSuite
                {
                    try? derivedNextCtx = deriveNextGenerationContext(
                        readSecret: readSecret,
                        writeSecret: writeSecret,
                        cipherSuite: suite
                    )
                    nextCtx = derivedNextCtx
                }
            }

            if let ctx = nextCtx, let opener = ctx.opener {
                do {
                    let packet = try decoder.decodePacket(
                        data: data,
                        dcidLength: dcidLengthValue,
                        opener: opener,
                        largestPN: largestReceivedPN.withLock { $0[.application] ?? 0 }
                    )

                    // Success with Next Phase keys! This is a Key Update.
                    // Install the keys if we derived them
                    if let newCtx = derivedNextCtx {
                        applicationContexts.withLock { $0[nextPhase] = newCtx }
                    }

                    // Confirm the key update
                    // RFC 9001 Section 6.3: "The endpoint MUST update its keys... and SHOULD send a packet with the new key phase."
                    let oldPhase = currentKeyPhase
                    if oldPhase != nextPhase {
                        _currentKeyPhase.store(nextPhase, ordering: .relaxed)
                        Self.logger.info(
                            "Passive Key Update detected: Phase \(oldPhase) -> \(nextPhase)")
                    }

                    // Update largest PN (decodePacket doesn't do this, it just uses it for decoding)
                    let pn = packet.packetNumber
                    largestReceivedPN.withLock { pns in
                        if pn > (pns[.application] ?? 0) {
                            pns[.application] = pn
                        }
                    }

                    return packet

                } catch {
                    // Decryption failed with next keys too.
                    throw PacketCodecError.decryptionFailed
                }
            }

            throw PacketCodecError.decryptionFailed

        } else {
            // Long Header (Initial, Handshake)
            guard let ctx = contexts.withLock({ $0[level] }), let opener = ctx.opener else {
                throw PacketCodecError.noOpener
            }

            let largestPN = largestReceivedPN.withLock { $0[level] ?? 0 }

            let packet = try decoder.decodePacket(
                data: data,
                dcidLength: dcidLengthValue,
                opener: opener,
                largestPN: largestPN
            )

            // Update largest PN
            if packet.packetNumber > largestPN {
                largestReceivedPN.withLock { $0[level] = packet.packetNumber }
            }

            return packet
        }

    }

    /// Decrypts all packets from a coalesced UDP datagram
    ///
    /// RFC 9000 Section 12.2: A receiver MUST be able to process multiple QUIC packets in a single UDP datagram.
    /// Packets that cannot be decrypted (e.g., no keys available yet) are skipped, and successfully
    /// decrypted packets are returned. This is important for coalesced datagrams containing packets
    /// at different encryption levels (e.g., Initial + Handshake).
    ///
    /// - Parameter datagram: The UDP datagram
    /// - Returns: Array of successfully parsed packets (may be empty if none decrypt)
    /// - Throws: Only throws for fatal errors like invalid datagram format
    package func decryptDatagram(_ datagram: Data) throws -> [ParsedPacket] {
        // Split coalesced packets (lock-free read)
        let dcid = dcidLengthValue
        let packetInfos = try CoalescedPacketParser.parse(datagram: datagram, dcidLength: dcid)

        var results: [ParsedPacket] = []
        for info in packetInfos {
            do {
                let parsed = try decryptPacket(info.data)
                results.append(parsed)
            } catch PacketCodecError.noOpener {
                // No keys for this encryption level yet - skip this packet
                // This is normal for coalesced datagrams during handshake
                continue
            } catch PacketCodecError.decryptionFailed {
                // Decryption failed - packet may be corrupted or keys are wrong
                continue
            } catch QUICError.decryptionFailed {
                // AEAD decryption failed - authentication tag mismatch
                continue
            } catch {
                throw error
            }
        }
        return results
    }

    // MARK: - Packet Encryption

    /// Encrypts a Long Header packet using the configured ``maxDatagramSize``.
    /// - Parameters:
    ///   - frames: Frames to include
    ///   - header: The long header template
    ///   - packetNumber: The packet number
    ///   - padToMinimum: If true and this is an Initial packet, pad to
    ///     `ProtocolLimits.minimumInitialPacketSize` bytes
    /// - Returns: The encrypted packet data
    /// - Throws: PacketCodecError if encryption fails
    package func encryptLongHeaderPacket(
        frames: [Frame],
        header: LongHeader,
        packetNumber: UInt64,
        padToMinimum: Bool = true
    ) throws -> Data {
        let level = header.packetType.encryptionLevel

        guard let ctx = contexts.withLock({ $0[level] }),
            let sealer = ctx.sealer
        else {
            throw PacketCodecError.noSealer
        }

        return try encoder.encodeLongHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: packetNumber,
            sealer: sealer,
            maxPacketSize: maxDatagramSize,
            padToMinimum: padToMinimum
        )
    }

    /// Encrypts a Short Header packet using the configured ``maxDatagramSize``.
    /// - Parameters:
    ///   - frames: Frames to include
    ///   - header: The short header template
    ///   - packetNumber: The packet number
    /// - Returns: The encrypted packet data
    /// - Throws: PacketCodecError if encryption fails
    package func encryptShortHeaderPacket(
        frames: [Frame],
        header: ShortHeader,
        packetNumber: UInt64,
        maxPacketSize overrideMaxSize: Int? = nil
    ) throws -> Data {
        let phase = currentKeyPhase
        guard let ctx = applicationContexts.withLock({ $0[phase] }),
            let sealer = ctx.sealer
        else {
            throw PacketCodecError.noSealer
        }

        // Ensure header has correct Key Phase bit
        var header = header
        header.keyPhase = (phase == 1)

        return try encoder.encodeShortHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: packetNumber,
            sealer: sealer,
            maxPacketSize: overrideMaxSize ?? maxDatagramSize
        )
    }

    // MARK: - Coalesced Packet Building

    /// Builds a coalesced packet from multiple packets.
    ///
    /// Uses the processor's ``maxDatagramSize`` unless the caller
    /// provides an explicit override.
    ///
    /// - Parameters:
    ///   - packets: Array of (frames, header, packetNumber) tuples
    ///   - maxSize: Maximum datagram size.  Defaults to the configured
    ///     ``maxDatagramSize``.
    /// - Returns: The coalesced datagram
    /// - Throws: Error if encryption fails
    package func buildCoalescedPacket(
        packets: [(frames: [Frame], header: PacketHeader, packetNumber: UInt64)],
        maxSize: Int? = nil
    ) throws -> Data {
        var builder = CoalescedPacketBuilder(maxDatagramSize: maxSize ?? maxDatagramSize)

        // Sort by packet type order (Initial -> Handshake -> 0-RTT -> 1-RTT)
        let sorted = packets.sorted { lhs, rhs in
            CoalescedPacketOrder.sortOrder(for: lhs.header.packetType)
                < CoalescedPacketOrder.sortOrder(for: rhs.header.packetType)
        }

        for (frames, header, pn) in sorted {
            let encoded: Data
            switch header {
            case .long(let longHeader):
                encoded = try encryptLongHeaderPacket(
                    frames: frames,
                    header: longHeader,
                    packetNumber: pn
                )
            case .short(let shortHeader):
                encoded = try encryptShortHeaderPacket(
                    frames: frames,
                    header: shortHeader,
                    packetNumber: pn
                )
            }

            if !builder.addPacket(encoded) {
                break  // No more room
            }
        }

        return builder.build()
    }

    // MARK: - Key Update (RFC 9001 Section 6)

    /// Initiates a key update
    ///
    /// Derives next generation keys and switches to the new key phase.
    /// The next packet sent will use the new keys and toggle the Key Phase bit.
    package func initiateKeyUpdate() throws {
        let phase = currentKeyPhase
        let nextPhase = phase ^ 1

        // Check if we already have next phase keys (e.g. from peer update)
        let hasNextKeys = applicationContexts.withLock { $0[nextPhase] != nil }
        if hasNextKeys {
            // Just switch phase for sending
            _currentKeyPhase.store(nextPhase, ordering: .relaxed)
            return
        }

        // Derive next keys from current phase
        guard let currentContext = applicationContexts.withLock({ $0[phase] }),
            let readSecret = currentContext.readTrafficSecret,
            let writeSecret = currentContext.writeTrafficSecret,
            let cipherSuite = currentContext.cipherSuite
        else {
            throw PacketCodecError.keyUpdateFailed("No current application keys available")
        }

        let nextContext = try deriveNextGenerationContext(
            readSecret: readSecret,
            writeSecret: writeSecret,
            cipherSuite: cipherSuite
        )

        // Install new keys and switch phase
        applicationContexts.withLock { $0[nextPhase] = nextContext }
        _currentKeyPhase.store(nextPhase, ordering: .relaxed)
    }

    /// Handles a passive key update (detected from received packet)
    ///
    /// RFC 9001 Section 6.3: "An endpoint detects a key update when the Key Phase bit
    /// in a received Short Header packet differs from the value expected."
    private func handlePassiveKeyUpdate(newPhase: UInt8) throws -> CryptoContext {
        // We expect `newPhase` but don't have it yet.
        // It must be derived from the OLD phase (newPhase ^ 1).
        let oldPhase = newPhase ^ 1

        guard let oldContext = applicationContexts.withLock({ $0[oldPhase] }),
            let readSecret = oldContext.readTrafficSecret,
            let writeSecret = oldContext.writeTrafficSecret,
            let cipherSuite = oldContext.cipherSuite
        else {
            throw PacketCodecError.keyUpdateFailed("Cannot derive new keys: old keys missing")
        }

        let nextContext = try deriveNextGenerationContext(
            readSecret: readSecret,
            writeSecret: writeSecret,
            cipherSuite: cipherSuite
        )

        // Install derived keys for the new phase
        applicationContexts.withLock { $0[newPhase] = nextContext }

        // Note: We do NOT switch our sending phase immediately upon receiving an update.
        // RFC 9001 Section 6.3: "The endpoint MUST update its keys to the new key phase...
        // and it SHOULD send a packet with the new key phase."
        // We can optionally switch sending phase here or let the application decide.
        // For simplicity and compliance, let's switch sending phase too.
        _currentKeyPhase.store(newPhase, ordering: .relaxed)

        return nextContext
    }

    /// Derives the next generation of keys from current secrets
    private func deriveNextGenerationContext(
        readSecret: Data,
        writeSecret: Data,
        cipherSuite: QUICCipherSuite
    ) throws -> CryptoContext {
        let currentReadSecret = SymmetricKey(data: readSecret)
        let currentWriteSecret = SymmetricKey(data: writeSecret)

        // Derive next traffic secrets
        let nextReadSecretData = try hkdfExpandLabel(
            secret: currentReadSecret,
            label: "quic ku",
            context: Data(),
            length: 32  // Always 32 bytes for traffic secret (SHA-256)
        )
        let nextWriteSecretData = try hkdfExpandLabel(
            secret: currentWriteSecret,
            label: "quic ku",
            context: Data(),
            length: 32
        )

        let nextReadSecret = SymmetricKey(data: nextReadSecretData)
        let nextWriteSecret = SymmetricKey(data: nextWriteSecretData)

        // Derive key material
        let nextReadKeys = try KeyMaterial.derive(from: nextReadSecret, cipherSuite: cipherSuite)
        let nextWriteKeys = try KeyMaterial.derive(from: nextWriteSecret, cipherSuite: cipherSuite)

        // Create crypto
        let (opener, _) = try nextReadKeys.createCrypto()
        let (_, sealer) = try nextWriteKeys.createCrypto()

        return CryptoContext(
            opener: opener,
            sealer: sealer,
            readTrafficSecret: nextReadSecretData,
            writeTrafficSecret: nextWriteSecretData,
            cipherSuite: cipherSuite
        )
    }

    // MARK: - Header Extraction (No Decryption)

    /// Extracts the destination connection ID from a packet without decryption
    ///
    /// Useful for routing packets to the correct connection.
    ///
    /// - Parameter data: The packet data
    /// - Returns: The destination connection ID
    /// - Throws: Error if the header cannot be parsed
    package func extractDestinationConnectionID(from data: Data) throws -> ConnectionID {
        guard !data.isEmpty else {
            throw PacketCodecError.insufficientData
        }

        let firstByte = data[data.startIndex]

        if (firstByte & 0x80) != 0 {
            // Long header: use fast path extraction
            return try extractLongHeaderDCIDFast(from: data)
        } else {
            // Short header: DCID follows first byte (lock-free read)
            let dcid = dcidLengthValue
            guard data.count >= 1 + dcid else {
                throw PacketCodecError.insufficientData
            }
            let dcidBytes = data[(data.startIndex + 1)..<(data.startIndex + 1 + dcid)]
            return try ConnectionID(bytes: dcidBytes)  // Slice is already Data
        }
    }

    /// Fast path for extracting DCID from long header without full parsing
    /// - Parameter data: The packet data
    /// - Returns: The destination connection ID
    /// - Throws: Error if the header cannot be parsed
    @inline(__always)
    private func extractLongHeaderDCIDFast(from data: Data) throws -> ConnectionID {
        // Long header format:
        // 1 byte: header form + type
        // 4 bytes: version
        // 1 byte: DCID length
        // N bytes: DCID
        guard data.count >= 6 else {
            throw PacketCodecError.insufficientData
        }

        let startIndex = data.startIndex
        let dcidLen = Int(data[startIndex + 5])

        guard dcidLen <= 20 else {
            throw PacketCodecError.invalidPacketFormat("DCID length exceeds maximum (20)")
        }

        guard data.count >= 6 + dcidLen else {
            throw PacketCodecError.insufficientData
        }

        let dcidBytes = data[(startIndex + 6)..<(startIndex + 6 + dcidLen)]
        return try ConnectionID(bytes: dcidBytes)  // Slice is already Data
    }

    /// Extracts packet type from a packet without decryption
    /// - Parameter data: The packet data
    /// - Returns: The packet type
    /// - Throws: Error if the header cannot be parsed
    package func extractPacketType(from data: Data) throws -> PacketType {
        guard !data.isEmpty else {
            throw PacketCodecError.insufficientData
        }

        let firstByte = data[data.startIndex]

        if (firstByte & 0x80) != 0 {
            // Check for version negotiation first
            guard data.count >= 5 else {
                throw PacketCodecError.insufficientData
            }
            let version =
                UInt32(data[data.startIndex + 1]) << 24 | UInt32(data[data.startIndex + 2]) << 16
                | UInt32(data[data.startIndex + 3]) << 8 | UInt32(data[data.startIndex + 4])

            if version == 0 {
                return .versionNegotiation
            }

            // Extract type from first byte
            let typeValue = (firstByte >> 4) & 0x03
            switch typeValue {
            case 0x00: return .initial
            case 0x01: return .zeroRTT
            case 0x02: return .handshake
            case 0x03: return .retry
            default: return .initial
            }
        } else {
            return .oneRTT
        }
    }

    // MARK: - Optimized Header Extraction

    /// Header information extracted in a single pass
    public struct HeaderInfo: Sendable {
        public let dcid: ConnectionID
        public let packetType: PacketType
        public let scid: ConnectionID?
    }

    /// Extracts all routing-relevant header information in a single pass
    ///
    /// This is more efficient than calling extractDestinationConnectionID()
    /// and extractPacketType() separately, as it parses the header only once.
    ///
    /// - Parameter data: The packet data
    /// - Returns: Header information including DCID, packet type, and SCID (for Initial)
    /// - Throws: Error if the header cannot be parsed
    @inline(__always)
    package func extractHeaderInfo(from data: Data) throws -> HeaderInfo {
        guard !data.isEmpty else {
            throw PacketCodecError.insufficientData
        }

        let startIndex = data.startIndex
        let firstByte = data[startIndex]

        if (firstByte & 0x80) != 0 {
            return try extractLongHeaderInfo(from: data, firstByte: firstByte)
        } else {
            // Short header: 1-RTT packet
            let dcidLen = dcidLengthValue
            guard data.count >= 1 + dcidLen else {
                throw PacketCodecError.insufficientData
            }
            let dcidBytes = data[(startIndex + 1)..<(startIndex + 1 + dcidLen)]
            return HeaderInfo(
                dcid: try ConnectionID(bytes: dcidBytes),  // Slice is already Data
                packetType: .oneRTT,
                scid: nil
            )
        }
    }

    /// Extracts header info from long header packets
    @inline(__always)
    private func extractLongHeaderInfo(from data: Data, firstByte: UInt8) throws -> HeaderInfo {
        // Long header format:
        // 1 byte: header form + type
        // 4 bytes: version
        // 1 byte: DCID length
        // N bytes: DCID
        // 1 byte: SCID length
        // M bytes: SCID

        guard data.count >= 6 else {
            throw PacketCodecError.insufficientData
        }

        let startIndex = data.startIndex

        // Check version for version negotiation
        let version =
            UInt32(data[startIndex + 1]) << 24 | UInt32(data[startIndex + 2]) << 16 | UInt32(
                data[startIndex + 3]) << 8 | UInt32(data[startIndex + 4])

        let packetType: PacketType
        if version == 0 {
            packetType = .versionNegotiation
        } else {
            let typeValue = (firstByte >> 4) & 0x03
            switch typeValue {
            case 0x00: packetType = .initial
            case 0x01: packetType = .zeroRTT
            case 0x02: packetType = .handshake
            case 0x03: packetType = .retry
            default: packetType = .initial
            }
        }

        // Extract DCID
        let dcidLen = Int(data[startIndex + 5])
        guard dcidLen <= 20 else {
            throw PacketCodecError.invalidPacketFormat("DCID length exceeds maximum (20)")
        }

        var offset = startIndex + 6
        guard data.count >= offset + dcidLen else {
            throw PacketCodecError.insufficientData
        }

        let dcidBytes = data[offset..<(offset + dcidLen)]
        let dcid = try ConnectionID(bytes: dcidBytes)  // Slice is already Data, no copy needed
        offset += dcidLen

        // Extract SCID for Initial packets (needed for routing)
        var scid: ConnectionID? = nil
        if packetType == .initial {
            guard data.count >= offset + 1 else {
                throw PacketCodecError.insufficientData
            }
            let scidLen = Int(data[offset])
            guard scidLen <= 20 else {
                throw PacketCodecError.invalidPacketFormat("SCID length exceeds maximum (20)")
            }
            offset += 1

            guard data.count >= offset + scidLen else {
                throw PacketCodecError.insufficientData
            }
            let scidBytes = data[offset..<(offset + scidLen)]
            scid = try ConnectionID(bytes: scidBytes)  // Slice is already Data, no copy needed
        }

        return HeaderInfo(dcid: dcid, packetType: packetType, scid: scid)
    }
}

// MARK: - Utility Extensions

extension PacketProcessor {
    /// Creates initial crypto contexts from a connection ID
    /// - Parameters:
    ///   - connectionID: The destination connection ID from the first Initial packet
    ///   - isClient: Whether this is the client side
    ///   - version: The QUIC version
    /// - Returns: The client and server key material
    package func deriveAndInstallInitialKeys(
        connectionID: ConnectionID,
        isClient: Bool,
        version: QUICVersion
    ) throws -> (client: KeyMaterial, server: KeyMaterial) {
        // Derive initial secrets
        let initialSecrets = try InitialSecrets.derive(connectionID: connectionID, version: version)

        // Initial keys always use AES-128-GCM per RFC 9001 Section 5.2
        let cipherSuite: QUICCipherSuite = .aes128GcmSha256

        // Derive key material from secrets
        let clientKeys = try KeyMaterial.derive(
            from: initialSecrets.clientSecret, cipherSuite: cipherSuite)
        let serverKeys = try KeyMaterial.derive(
            from: initialSecrets.serverSecret, cipherSuite: cipherSuite)

        // Create opener/sealer using factory method
        let readKeys = isClient ? serverKeys : clientKeys
        let writeKeys = isClient ? clientKeys : serverKeys

        let (opener, _) = try readKeys.createCrypto()
        let (_, sealer) = try writeKeys.createCrypto()

        // Install context
        let context = CryptoContext(opener: opener, sealer: sealer)
        installContext(context, for: .initial)

        return (client: clientKeys, server: serverKeys)
    }
}
