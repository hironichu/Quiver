/// QUIC UDP Socket Integration
///
/// Integrates swift-nio-udp for QUIC packet I/O.

import Foundation
import NIOCore
import NIOUDPTransport
import QUICCore
import Synchronization

// MARK: - QUIC Socket

/// A UDP socket for QUIC communication
public protocol QUICSocket: Sendable {
    /// The local address bound to
    var localAddress: SocketAddress? { get async }

    /// Sends a QUIC packet
    /// - Parameters:
    ///   - data: The packet data
    ///   - address: The destination address
    func send(_ data: Data, to address: SocketAddress) async throws

    /// Receives incoming packets
    var incomingPackets: AsyncStream<IncomingPacket> { get }

    /// Starts the socket
    func start() async throws

    /// Stops the socket
    func stop() async
}

/// An incoming QUIC packet
public struct IncomingPacket: Sendable {
    /// The packet data as ByteBuffer (zero-copy from NIO).
    public let buffer: ByteBuffer

    /// The remote address that sent this packet
    public let remoteAddress: SocketAddress

    /// The time the packet was received
    public let receivedAt: ContinuousClock.Instant

    public init(buffer: ByteBuffer, remoteAddress: SocketAddress, receivedAt: ContinuousClock.Instant) {
        self.buffer = buffer
        self.remoteAddress = remoteAddress
        self.receivedAt = receivedAt
    }

    /// The packet data as Data (convenience, copies bytes).
    @inlinable
    public var data: Data {
        Data(buffer: buffer)
    }
}

// MARK: - NIO QUIC Socket

/// A QUIC socket using NIOUDPTransport
public final class NIOQUICSocket: QUICSocket, Sendable {
    private let transport: NIOUDPTransport
    private let incomingStream: AsyncStream<IncomingPacket>
    private let incomingContinuation: AsyncStream<IncomingPacket>.Continuation

    /// The forwarding task handle, stored to allow cancellation on stop.
    private let forwardingTask: Mutex<Task<Void, Never>?>

    /// The local address
    public var localAddress: SocketAddress? {
        get async {
            await transport.localAddress
        }
    }

    /// Incoming packets stream
    public var incomingPackets: AsyncStream<IncomingPacket> {
        incomingStream
    }

    /// Creates a new QUIC socket
    /// - Parameter configuration: UDP configuration
    public init(configuration: UDPConfiguration) {
        self.transport = NIOUDPTransport(configuration: configuration)

        let (stream, continuation) = AsyncStream<IncomingPacket>.makeStream(
            bufferingPolicy: .bufferingNewest(100)
        )
        self.incomingStream = stream
        self.incomingContinuation = continuation
        self.forwardingTask = Mutex(nil)
    }

    /// Starts the socket and begins receiving packets
    public func start() async throws {
        try await transport.start()

        // Forward incoming datagrams to our stream.
        // The Task is stored so it can be cancelled in stop().
        // The Task owns stream termination via finish() when the loop exits.
        let continuation = self.incomingContinuation
        let transport = self.transport
        let task = Task {
            for await datagram in transport.incomingDatagrams {
                let packet = IncomingPacket(
                    buffer: datagram.buffer,
                    remoteAddress: datagram.remoteAddress,
                    receivedAt: .now
                )
                continuation.yield(packet)
            }
            continuation.finish()
        }
        forwardingTask.withLock { $0 = task }
    }

    /// Stops the socket
    ///
    /// This method stops the underlying transport, which finishes
    /// its incoming datagrams stream, causing the forwarding task
    /// to exit and call finish() on the packets stream.
    public func stop() async {
        await transport.stop()

        // Cancel the forwarding task in case transport.stop()
        // didn't cause the for-await loop to exit promptly.
        let task = forwardingTask.withLock { t -> Task<Void, Never>? in
            let existing = t
            t = nil
            return existing
        }
        task?.cancel()

        // Defensive finish — idempotent if the task already called it.
        incomingContinuation.finish()
    }

    /// Sends packet data to the specified address
    public func send(_ data: Data, to address: SocketAddress) async throws {
        try await transport.send(data, to: address)
    }
}
