import Testing
import Foundation
@testable import QUICRecovery
@testable import QUICCore

/// Deterministic regression tests for the loss-recovery RETRANSMISSION path
/// (RFC 9002 §13.3 / §6.2.4). Before the fix, a declared-lost packet carried no
/// frame data, so the connection could only emit a content-free PING and the
/// lost CRYPTO/STREAM data was never resent — any packet loss stalled the
/// handshake or a stream. These pin that lost packets retain their frames and
/// that the PTO probe re-sends the oldest unacked data.
///
/// (See PTODeadlineTests for the companion §6.2.1 PTO-anchoring regression.)
@Suite("Loss-recovery retransmission (RFC 9002 §13.3 / §6.2.4)")
struct LossRecoveryTests {

    @Test("a declared-lost packet retains its frames so the data can be retransmitted")
    func lostPacketCarriesFramesForRetransmission() {
        let mgr = PacketNumberSpaceManager()
        let t0 = ContinuousClock.now

        // Send Initial packets 0…3. Packet 0 carries the CRYPTO data we expect
        // to be available for retransmission once it is declared lost.
        let crypto0 = Frame.crypto(CryptoFrame(offset: 0, data: Data([0xAA, 0xBB])))
        for pn: UInt64 in 0...3 {
            mgr.onPacketSent(SentPacket(
                packetNumber: pn,
                encryptionLevel: .initial,
                timeSent: t0,
                ackEliciting: true,
                inFlight: true,
                sentBytes: 1200,
                frames: pn == 0 ? [crypto0] : []))
        }

        // The peer ACKs only packet 3. Packet 0 is then `kPacketThreshold` (3)
        // behind the largest acked packet → declared lost by the packet
        // threshold (RFC 9002 §6.1.1).
        let ack = AckFrame(
            largestAcknowledged: 3,
            ackDelay: 0,
            ackRanges: [AckRange(gap: 0, rangeLength: 1)])
        let result = mgr.onAckReceived(
            ackFrame: ack, level: .initial, receiveTime: t0 + .milliseconds(50))

        let lost0 = result.lostPackets.first { $0.packetNumber == 0 }
        #expect(lost0 != nil,
            "packet 0 (kPacketThreshold behind the acked packet) must be declared lost")
        #expect(lost0?.frames.contains(crypto0) == true,
            "the lost packet must RETAIN its CRYPTO frame so the data can be re-queued (else loss only triggers a content-free PING)")
    }

    @Test("a PTO probe re-sends the oldest unacked data, not a bare PING")
    func probeReturnsOldestUnackedFrames() {
        let mgr = PacketNumberSpaceManager()
        let crypto = Frame.crypto(CryptoFrame(offset: 0, data: Data([0x01, 0x02, 0x03])))

        // One ack-eliciting Initial in flight, never acked — the tail-loss case
        // (e.g. a dropped Initial: no later ACK to declare it lost).
        mgr.onPacketSent(SentPacket(
            packetNumber: 0,
            encryptionLevel: .initial,
            timeSent: .now,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200,
            frames: [crypto]))

        let probes = mgr.oldestUnackedRetransmittableFrames()
        #expect(probes.contains { $0.frame == crypto && $0.level == .initial },
            "a PTO probe must carry the oldest unacked data (the lost Initial's CRYPTO) so a tail-lost packet still makes progress")
    }

    @Test("nothing in flight ⇒ no probe data (no spurious retransmission)")
    func noProbeWhenNothingUnacked() {
        let mgr = PacketNumberSpaceManager()
        #expect(mgr.oldestUnackedRetransmittableFrames().isEmpty,
            "with no ack-eliciting packet in flight there is nothing to retransmit")
    }
}
