/// QUIC UDP Socket Integration
///
/// Integrates swift-nio-udp for QUIC packet I/O.

import Foundation
import NIOCore
import NIOUDPTransport
import QUICCore

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
    /// The packet data
    public let data: Data

    /// The remote address that sent this packet
    public let remoteAddress: SocketAddress

    /// The time the packet was received
    public let receivedAt: ContinuousClock.Instant

    public init(data: Data, remoteAddress: SocketAddress, receivedAt: ContinuousClock.Instant) {
        self.data = data
        self.remoteAddress = remoteAddress
        self.receivedAt = receivedAt
    }
}

// MARK: - NIO QUIC Socket

/// A QUIC socket using NIOUDPTransport
public final class NIOQUICSocket: QUICSocket, Sendable {
    private let transport: NIOUDPTransport
    private let incomingStream: AsyncStream<IncomingPacket>
    private let incomingContinuation: AsyncStream<IncomingPacket>.Continuation

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

        var continuation: AsyncStream<IncomingPacket>.Continuation!
        self.incomingStream = AsyncStream { cont in
            continuation = cont
        }
        self.incomingContinuation = continuation
    }

    /// Starts the socket and begins receiving packets
    public func start() async throws {
        try await transport.start()

        // Forward incoming datagrams to our stream
        Task {
            for await datagram in transport.incomingDatagrams {
                let packet = IncomingPacket(
                    data: datagram.data,
                    remoteAddress: datagram.remoteAddress,
                    receivedAt: .now
                )
                incomingContinuation.yield(packet)
            }
            incomingContinuation.finish()
        }
    }

    /// Stops the socket
    ///
    /// This method stops the underlying transport and finishes the incoming
    /// packets AsyncStream, allowing any `for await` loops to exit gracefully.
    public func stop() async {
        await transport.stop()
        // Finish the incoming stream to unblock any waiting consumers
        incomingContinuation.finish()
    }

    /// Sends packet data to the specified address
    public func send(_ data: Data, to address: SocketAddress) async throws {
        try await transport.send(data, to: address)
    }
}
