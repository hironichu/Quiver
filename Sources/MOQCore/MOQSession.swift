/// MOQ Session Management
///
/// The `MOQSession` is the central coordinator for a Media Over QUIC connection.
/// It manages tracks, subscriptions, and the underlying transport.

import Foundation
import QUICCore

/// Protocol defining the transport capabilities required by MOQ.
///
/// Implemented by `WebTransportSession` or `QUICConnection`.
public protocol MOQTransport: Sendable {
    /// Sends a datagram with the specified strategy.
    func sendDatagram(_ data: Data, strategy: DatagramSendingStrategy) async throws
    /// Stream of incoming datagrams.
    var incomingDatagrams: AsyncStream<Data> { get }
}

/// A Media Over QUIC (MOQ) Session.
///
/// Manages the full lifecycle of a media session, including:
/// - Creating and publishing tracks (Producer)
/// - Subscribing to tracks (Consumer)
/// - Routing incoming objects to the appropriate handlers
public actor MOQSession: MOQTrackDelegate, Hashable {
    public static func == (lhs: MOQSession, rhs: MOQSession) -> Bool {
        lhs === rhs
    }

    public nonisolated func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(self))
    }

    /// The underlying transport interaction (WebTransport or Raw QUIC).
    private let transport: any MOQTransport

    /// Active local tracks (published by us), keyed by ID.
    private var localTracks: [UInt64: MOQTrack] = [:]

    /// Active subscriptions (requested by us), keyed by Track Alias.
    /// Maps TrackAlias -> Continuation for yielding objects to the consumer.
    private var subscriptions: [UInt64: AsyncStream<MOQObject>.Continuation] = [:]

    /// Global listener for all incoming objects (used by Relays/Debuggers).
    private var allObjectsContinuation: AsyncStream<MOQObject>.Continuation?

    /// Background task for reading incoming datagrams.
    private var listenerTask: Task<Void, Never>?

    public init(transport: any MOQTransport) {
        self.transport = transport

        // We cannot use 'self' in a Task closure inside init().
        // So we defer starting the loop until after initialization?
        // Or we use a non-isolated startup method?
        //
        // Workaround: We define a separate startup method that the user MUST call,
        // OR we launch the task in an unstructured way that doesn't capture `self` until later?
        // No, 'self' is actor.

        // Standard pattern: initialize everything, then kick off background work.
        // But init is synchronous.
        // Swift 6 Actors: tasks in init are tricky.

        // We'll leave listenerTask nil here and start it lazily or require a start() call.
        // For simplicity in this demo, let's add a `start()` method.
    }

    public func start() {
        guard listenerTask == nil else { return }
        self.listenerTask = Task { [weak self] in
            await self?.runListenerLoop()
        }
    }

    deinit {
        listenerTask?.cancel()
        for continuation in subscriptions.values {
            continuation.finish()
        }
        allObjectsContinuation?.finish()
    }

    /// Stream of ALL incoming objects, regardless of subscription.
    /// Useful for Relays to inspect/forward everything.
    public nonisolated func allIncomingObjects() -> AsyncStream<MOQObject> {
        let (stream, continuation) = AsyncStream<MOQObject>.makeStream()
        Task {
            await self.setAllObjectsContinuation(continuation)
        }
        return stream
    }

    private func setAllObjectsContinuation(_ continuation: AsyncStream<MOQObject>.Continuation) {
        self.allObjectsContinuation = continuation
    }

    // MARK: - Producer API

    /// Creates and publishes a new media track.
    ///
    /// - Parameters:
    ///   - id: The unique track identifier (e.g. 0 for video, 1 for audio).
    ///   - alias: The wire alias (usually same as ID for simple cases).
    ///   - priority: The default priority for objects in this track.
    ///   - defaultTTL: The default TTL for objects in this track.
    /// - Returns: A `MOQTrack` instance to push media to.
    public func createTrack(
        id: UInt64,
        alias: UInt64,
        priority: UInt8,
        defaultTTL: Duration? = nil
    ) -> MOQTrack {
        let track = MOQTrack(
            id: id,
            alias: alias,
            priority: priority,
            defaultTTL: defaultTTL,
            delegate: self
        )
        localTracks[id] = track
        return track
    }

    // MARK: - MOQTrackDelegate

    /// Sends an object via the underlying transport.
    ///
    /// Serializes the object header and payload into the MOQ wire format
    /// and sends it as a datagram.
    public func send(object: MOQObject, strategy: DatagramSendingStrategy) async throws {
        let data = object.encode()
        try await transport.sendDatagram(data, strategy: strategy)
    }

    // MARK: - Consumer API

    /// Subscribes to a remote track.
    ///
    /// - Parameter trackID: The track alias to subscribe to.
    /// - Returns: An async stream of `MOQObject`s received for this track.
    public func subscribe(trackID: UInt64) -> AsyncStream<MOQObject> {
        // In a real implementation, we would send a SUBSCRIBE control message here.

        let (stream, continuation) = AsyncStream<MOQObject>.makeStream()
        subscriptions[trackID] = continuation
        return stream
    }

    // MARK: - Internal Listener Loop

    private func runListenerLoop() async {
        // transport is let, safe to access
        for await datagram in transport.incomingDatagrams {
            do {
                let object = try MOQObject.decode(from: datagram)
                self.dispatch(object)
            } catch {
                // Log and drop malformed datagrams
                print("MOQSession: Failed to decode object: \(error)")
            }
        }
    }

    private func dispatch(_ object: MOQObject) {
        // 1. Dispatch to specific subscriber (Consumer)
        if let subscriber = subscriptions[object.header.trackID] {
            subscriber.yield(object)
        }

        // 2. Dispatch to global listener (Relay/Debug)
        allObjectsContinuation?.yield(object)

        if subscriptions[object.header.trackID] == nil && allObjectsContinuation == nil {
            print(
                "MOQSession: No subscriber or relay for track \(object.header.trackID) - dropping")
        }
    }
}
