/// MOQ Relay Implementation
///
/// A relay acts as a central hub for Media Over QUIC distribution.
/// It accepts tracks from publishers and forwards them to subscribers.

import Foundation
import Logging
import MOQCore
import QUICCore

/// A Media Over QUIC Relay.
public actor MOQRelay {
    private let logger: Logger

    /// Active publisher sessions (Producers).
    /// Kept alive to maintain the connection.
    private var publishers: Set<MOQSession> = []

    /// Active subscriber sessions (Consumers).
    private var subscribers: Set<MOQSession> = []

    /// Routing table: Track ID -> List of Subscribers
    /// The Relay forwards objects received on Track ID to all sessions in the set.
    private var routes: [UInt64: Set<MOQSession>] = [:]

    public init(logger: Logger = Logger(label: "MOQRelay")) {
        self.logger = logger
    }

    /// Registers a new publisher session.
    /// The relay effectively "consumes" tracks from this publisher.
    public func addPublisher(_ session: MOQSession) async {
        logger.info("New publisher connected")
        publishers.insert(session)

        // Listen to all objects from this publisher and forward them
        Task { [weak self] in
            for await object in session.allIncomingObjects() {
                await self?.forward(object: object)
            }
        }
    }

    /// Registers a new subscriber session.
    public func addSubscriber(_ session: MOQSession) async {
        logger.info("New subscriber connected")
        subscribers.insert(session)
    }

    /// Subscribes a session to a specific track.
    public func subscribe(session: MOQSession, trackID: UInt64) {
        logger.info("Session subscribing to track \(trackID)")
        routes[trackID, default: []].insert(session)
    }

    /// Handles an incoming object from a publisher.
    /// This should be called by the listener loop that reads from the publisher's transport.
    public func forward(object: MOQObject) async {
        guard let targets = routes[object.header.trackID], !targets.isEmpty else {
            // No subscribers for this track
            return
        }

        // Fan-out
        for session in targets {
            do {
                // Forward with same priority/TTL strategy as received (or default)
                // Ideally we'd map the object priority to a strategy
                let strategy: DatagramSendingStrategy = .combined(
                    priority: object.header.priority,
                    ttl: .milliseconds(500)  // Default TTL for relay forwarding
                )
                try await session.send(object: object, strategy: strategy)
            } catch {
                logger.warning("Failed to forward object to session: \(error)")
            }
        }
    }
}
