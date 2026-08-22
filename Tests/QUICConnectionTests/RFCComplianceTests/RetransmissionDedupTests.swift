import Testing
import Foundation
@testable import QUICCore
@testable import QUICConnection

/// RFC 9002 §6.2.4 — a PTO probe re-sends the oldest unacked frames but does NOT
/// consume them from the sent-packet record (the probe is a pure read; the data
/// is only released when its packet is acked or declared lost). So a *later*
/// loss-detection pass — or a second probe — can resurface the very same frame.
///
/// Re-queuing it blindly puts duplicate copies of the same CRYPTO/STREAM bytes on
/// the wire: correctness survives (retransmission is idempotent at the receiver)
/// but the congestion window is spent on redundant data, which on a lossy path is
/// exactly the budget you can least afford to waste. `queueFrameIfAbsent`
/// collapses those duplicates at the outbound queue.
///
/// (Surfaced 2026-06-11 by the loss-recovery adversarial review: the probe→loss
/// requeue path could enqueue the same frame twice under sustained loss.)
@Suite("Retransmission requeue dedup (RFC 9002 §6.2.4)")
struct RetransmissionDedupTests {

    private func makeHandler() throws -> QUICConnectionHandler {
        let scid = try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04]))
        let dcid = try ConnectionID(bytes: Data([0x05, 0x06, 0x07, 0x08]))
        return QUICConnectionHandler(
            role: .client,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            transportParameters: TransportParameters())
    }

    private func queueDepth(_ handler: QUICConnectionHandler) -> Int {
        handler.outboundQueue.withLock { $0.count }
    }

    @Test("queueFrameIfAbsent does not enqueue a second identical frame at the same level")
    func dedupSuppressesDuplicate() throws {
        let handler = try makeHandler()
        let crypto = Frame.crypto(CryptoFrame(offset: 0, data: Data([0xAA, 0xBB])))

        handler.queueFrameIfAbsent(crypto, level: .initial)
        handler.queueFrameIfAbsent(crypto, level: .initial)

        #expect(queueDepth(handler) == 1,
            "the second requeue of an already-pending frame must be suppressed (probe + later loss detection both resurface it)")
    }

    @Test("queueFrameIfAbsent still enqueues a distinct frame")
    func dedupAllowsDistinctFrame() throws {
        let handler = try makeHandler()
        let crypto0 = Frame.crypto(CryptoFrame(offset: 0, data: Data([0xAA, 0xBB])))
        let crypto1 = Frame.crypto(CryptoFrame(offset: 2, data: Data([0xCC, 0xDD])))

        handler.queueFrameIfAbsent(crypto0, level: .initial)
        handler.queueFrameIfAbsent(crypto1, level: .initial)

        #expect(queueDepth(handler) == 2,
            "a different frame is real new data and must NOT be deduped away")
    }

    @Test("the same frame bytes at a different encryption level are not deduped")
    func dedupIsPerEncryptionLevel() throws {
        let handler = try makeHandler()
        // Identical frame value, two levels: these are genuinely distinct sends
        // (different packet-number space / keys), so neither suppresses the other.
        let ping = Frame.ping
        handler.queueFrameIfAbsent(ping, level: .initial)
        handler.queueFrameIfAbsent(ping, level: .handshake)

        #expect(queueDepth(handler) == 2,
            "dedup is scoped to (frame, level); the same frame at another level is a separate send")
    }
}
