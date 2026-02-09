/// QUIC Connection State Machine
///
/// Manages the lifecycle of a QUIC connection.

import Foundation
import QUICCore

// MARK: - Connection State

/// The state of a QUIC connection
public enum ConnectionStatus: Sendable, Hashable {
    /// Connection is being established (handshake in progress)
    case handshaking

    /// Connection is established and ready for use
    case established

    /// Connection is being closed (draining period)
    case draining

    /// Connection is closed
    case closed
}

// MARK: - Connection Role

/// The role of this endpoint in the connection
public enum ConnectionRole: Sendable {
    /// This endpoint initiated the connection (client)
    case client

    /// This endpoint accepted the connection (server)
    case server
}

// MARK: - Connection State

/// Internal state for a QUIC connection
public struct ConnectionState: Sendable {
    /// Current connection status
    public var status: ConnectionStatus

    /// This endpoint's role
    public let role: ConnectionRole

    /// QUIC version being used
    public var version: QUICVersion

    /// Source connection IDs (ours)
    public var sourceConnectionIDs: [ConnectionID]

    /// Destination connection IDs (peer's)
    public var destinationConnectionIDs: [ConnectionID]

    /// Current destination connection ID
    public var currentDestinationCID: ConnectionID {
        destinationConnectionIDs.first ?? .empty
    }

    /// Current source connection ID
    public var currentSourceCID: ConnectionID {
        sourceConnectionIDs.first ?? .empty
    }

    /// Next packet number to send for each encryption level
    public var nextPacketNumber: [EncryptionLevel: UInt64]

    /// Largest packet number received for each encryption level
    public var largestReceivedPacketNumber: [EncryptionLevel: UInt64]

    /// Creates initial connection state
    public init(
        role: ConnectionRole,
        version: QUICVersion,
        sourceConnectionID: ConnectionID,
        destinationConnectionID: ConnectionID
    ) {
        self.status = .handshaking
        self.role = role
        self.version = version
        self.sourceConnectionIDs = [sourceConnectionID]
        self.destinationConnectionIDs = [destinationConnectionID]
        self.nextPacketNumber = [
            .initial: 0,
            .handshake: 0,
            .application: 0,
        ]
        self.largestReceivedPacketNumber = [:]
    }

    /// Gets the next packet number for the given level and increments it
    public mutating func getNextPacketNumber(for level: EncryptionLevel) -> UInt64 {
        let pn = nextPacketNumber[level] ?? 0
        nextPacketNumber[level] = pn + 1
        return pn
    }

    /// Updates the largest received packet number if the new one is larger
    public mutating func updateLargestReceived(_ pn: UInt64, level: EncryptionLevel) {
        if let current = largestReceivedPacketNumber[level] {
            if pn > current {
                largestReceivedPacketNumber[level] = pn
            }
        } else {
            largestReceivedPacketNumber[level] = pn
        }
    }
}
