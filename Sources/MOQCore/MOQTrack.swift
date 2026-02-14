/// MOQ Track Management
///
/// An `MOQTrack` represents a single media track (e.g. video, audio).
/// It manages the sequence of objects produced by the application.

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import QUIC
import QUICCore

/// A producer-side Media Over QUIC Track.
///
/// Responsible for packetizing media samples into MOQ Objects and
/// scheduling them for transmission via the session.
public actor MOQTrack {
    /// The unique track identifier.
    public let id: UInt64

    /// The track alias (short ID used on wire).
    public let alias: UInt64

    /// The current group ID (incremented on keyframes).
    private var currentGroupID: UInt64 = 0

    /// The current object ID (incremented per object).
    private var currentObjectID: UInt64 = 0

    /// The assigned priority for this track.
    public let priority: UInt8

    /// The default TTL for objects in this track.
    public let defaultTTL: Duration?

    /// The delegate to handle object transmission (usually the Session).
    private weak var delegate: MOQTrackDelegate?

    public init(
        id: UInt64,
        alias: UInt64,
        priority: UInt8,
        defaultTTL: Duration? = nil,
        delegate: MOQTrackDelegate? = nil
    ) {
        self.id = id
        self.alias = alias
        self.priority = priority
        self.defaultTTL = defaultTTL
        self.delegate = delegate
    }

    /// Sets the delegate for transmission.
    public func setDelegate(_ delegate: MOQTrackDelegate) {
        self.delegate = delegate
    }

    /// Pushes a media sample to the track.
    ///
    /// - Parameters:
    ///   - payload: The media data.
    ///   - isKeyframe: If true, starts a new Group.
    ///   - ttl: Optional override for Time-To-Live.
    public func push(_ payload: Data, isKeyframe: Bool = false, ttl: Duration? = nil) async throws {
        if isKeyframe {
            currentGroupID += 1
            currentObjectID = 0
        } else {
            currentObjectID += 1
        }

        let header = MOQObjectHeader(
            trackID: alias,
            groupID: currentGroupID,
            objectID: currentObjectID,
            priority: self.priority
        )

        let object = MOQObject(header: header, payload: payload)

        // Determine strategy
        let objectTTL = ttl ?? defaultTTL
        let strategy: DatagramSendingStrategy

        if let ttl = objectTTL {
            strategy = .combined(priority: priority, ttl: ttl)
        } else {
            strategy = .priority(priority)
        }

        try await delegate?.send(object: object, strategy: strategy)
    }
}

/// Delegate protocol for sending objects.
public protocol MOQTrackDelegate: AnyObject, Sendable {
    func send(object: MOQObject, strategy: DatagramSendingStrategy) async throws
}
