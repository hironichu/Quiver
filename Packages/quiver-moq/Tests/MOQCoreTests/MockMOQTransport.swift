import Foundation
import MOQCore
import QUICCore
import Synchronization

/// A mock transport for verifying MOQ behavior in isolation.
/// Captures sent datagrams for inspection.
public final class MockMOQTransport: MOQTransport, @unchecked Sendable {
    public struct SentDatagram: Sendable, Equatable {
        public let data: Data
        public let strategy: DatagramSendingStrategy
    }

    private let _sentDatagrams = Mutex<[SentDatagram]>([])

    public var sentDatagrams: [SentDatagram] {
        _sentDatagrams.withLock { $0 }
    }

    // Incoming datagram stream for verification
    public var incomingDatagrams: AsyncStream<Data>
    private let incomingContinuation: AsyncStream<Data>.Continuation

    public init() {
        var continuation: AsyncStream<Data>.Continuation!
        self.incomingDatagrams = AsyncStream { cont in
            continuation = cont
        }
        self.incomingContinuation = continuation
    }

    public func receiveDatagram(_ data: Data) {
        incomingContinuation.yield(data)
    }

    public func sendDatagram(_ data: Data, strategy: DatagramSendingStrategy) async throws {
        _sentDatagrams.withLock {
            $0.append(SentDatagram(data: data, strategy: strategy))
        }
    }
}
