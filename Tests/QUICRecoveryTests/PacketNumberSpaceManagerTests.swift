import Testing
import Foundation
@testable import QUICRecovery
@testable import QUICCore

@Suite("Packet Number Space Manager Tests")
struct PacketNumberSpaceManagerTests {

    @Test("Confirmed idle connection has no PTO deadline")
    func confirmedIdleConnectionHasNoPTODeadline() {
        let manager = PacketNumberSpaceManager()
        manager.handshakeConfirmed = true

        #expect(manager.nextPTODeadlineIfNeeded(now: .now) == nil)
    }

    @Test("Connection with in-flight ack-eliciting packet has PTO deadline")
    func inFlightAckElicitingPacketHasPTODeadline() {
        let manager = PacketNumberSpaceManager()
        manager.handshakeConfirmed = true
        manager.onPacketSent(SentPacket(
            packetNumber: 0,
            encryptionLevel: .application,
            timeSent: .now,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        ))

        #expect(manager.nextPTODeadlineIfNeeded(now: .now) != nil)
    }
}