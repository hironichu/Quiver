/// Unit tests for the BBR congestion controller.

import Foundation
import Testing
@testable import QUICCore
@testable import QUICRecovery

@Suite("BBR Congestion Controller Tests")
struct BBRCongestionControllerTests {
    @Test("Initial window matches RFC 9002 initial window")
    func initialWindow() {
        let cc = BBRCongestionController(maxDatagramSize: 1200)

        #expect(cc.congestionWindow == LossDetectionConstants.initialWindow(maxDatagramSize: 1200))
        #expect(cc.currentState == .slowStart)
        #expect(cc.availableWindow(bytesInFlight: 5_000) == 7_000)
    }

    @Test("Factory creates BBR controller")
    func factoryCreatesController() {
        let cc = BBRFactory().makeCongestionController(maxDatagramSize: 1200)

        #expect(cc.congestionWindow == LossDetectionConstants.initialWindow(maxDatagramSize: 1200))
        #expect(String(describing: cc).contains("BBR"))
    }

    @Test("ACK feedback grows startup window and establishes pacing")
    func ackFeedbackGrowsStartupWindowAndPacing() {
        let cc = BBRCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let rtt = rttEstimator(sample: .milliseconds(50))
        let packets = packetBatch(count: 10, startPacketNumber: 0, sentAt: now)
        let initialWindow = cc.congestionWindow

        for packet in packets {
            cc.onPacketSent(bytes: packet.sentBytes, now: packet.timeSent)
        }
        cc.onPacketsAcknowledged(packets: packets, now: now + .milliseconds(50), rtt: rtt)

        #expect(cc.congestionWindow > initialWindow)

        cc.onPacketSent(bytes: 1200, now: now + .milliseconds(60))
        #expect(cc.nextSendTime() != nil)
    }

    @Test("Startup exits after bottleneck bandwidth plateaus")
    func startupExitsAfterBandwidthPlateau() {
        let cc = BBRCongestionController(maxDatagramSize: 1200)
        let start = ContinuousClock.Instant.now
        let rtt = rttEstimator(sample: .milliseconds(50))

        for round in 0..<5 {
            let sentAt = start + .milliseconds(50 * round)
            let packets = packetBatch(
                count: 10,
                startPacketNumber: UInt64(round * 10),
                sentAt: sentAt
            )
            cc.onPacketsAcknowledged(packets: packets, now: sentAt + .milliseconds(50), rtt: rtt)
        }

        #expect(cc.currentState == .congestionAvoidance)
    }

    @Test("Isolated loss trims BBR window without NewReno halving")
    func isolatedLossTrimsWindowWithoutHalving() {
        let cc = BBRCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let rtt = rttEstimator(sample: .milliseconds(50))
        let packets = packetBatch(count: 10, startPacketNumber: 0, sentAt: now)

        cc.onPacketsAcknowledged(packets: packets, now: now + .milliseconds(50), rtt: rtt)
        let windowBeforeLoss = cc.congestionWindow

        let lost = packet(number: 99, sentAt: now + .milliseconds(60))
        cc.onPacketsLost(packets: [lost], now: now + .milliseconds(100), rtt: rtt)

        #expect(cc.currentState == .recovery(startTime: now + .milliseconds(100)))
        #expect(cc.congestionWindow < windowBeforeLoss)
        #expect(cc.congestionWindow > windowBeforeLoss / 2)
    }

    @Test("Pre-recovery ACK does not undo BBR loss reduction")
    func preRecoveryACKDoesNotUndoLossReduction() {
        let cc = BBRCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let rtt = rttEstimator(sample: .milliseconds(50))
        let initialPackets = packetBatch(count: 10, startPacketNumber: 0, sentAt: now)

        cc.onPacketsAcknowledged(packets: initialPackets, now: now + .milliseconds(50), rtt: rtt)
        let lost = packet(number: 99, sentAt: now + .milliseconds(60))
        let recoveryStart = now + .milliseconds(100)
        cc.onPacketsLost(packets: [lost], now: recoveryStart, rtt: rtt)
        let reducedWindow = cc.congestionWindow

        let oldAck = packet(number: 100, sentAt: now + .milliseconds(70))
        cc.onPacketsAcknowledged(packets: [oldAck], now: now + .milliseconds(120), rtt: rtt)

        #expect(cc.currentState == .recovery(startTime: recoveryStart))
        #expect(cc.congestionWindow == reducedWindow)
    }

    @Test("Persistent congestion resets BBR model to minimum window")
    func persistentCongestionResetsModel() {
        let cc = BBRCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let rtt = rttEstimator(sample: .milliseconds(50))
        let packets = packetBatch(count: 10, startPacketNumber: 0, sentAt: now)

        cc.onPacketsAcknowledged(packets: packets, now: now + .milliseconds(50), rtt: rtt)
        #expect(cc.congestionWindow > LossDetectionConstants.minimumWindow(maxDatagramSize: 1200))

        cc.onPersistentCongestion()

        #expect(cc.congestionWindow == LossDetectionConstants.minimumWindow(maxDatagramSize: 1200))
        #expect(cc.currentState == .slowStart)
        #expect(cc.nextSendTime() == nil)
    }
}

private func rttEstimator(sample: Duration) -> RTTEstimator {
    var rtt = RTTEstimator()
    rtt.updateRTT(
        rttSample: sample,
        ackDelay: .zero,
        maxAckDelay: .milliseconds(25),
        handshakeConfirmed: true
    )
    return rtt
}

private func packetBatch(
    count: Int,
    startPacketNumber: UInt64,
    sentAt: ContinuousClock.Instant,
    bytes: Int = 1200
) -> [SentPacket] {
    (0..<count).map { offset in
        packet(number: startPacketNumber + UInt64(offset), sentAt: sentAt, bytes: bytes)
    }
}

private func packet(
    number: UInt64,
    sentAt: ContinuousClock.Instant,
    bytes: Int = 1200,
    inFlight: Bool = true
) -> SentPacket {
    SentPacket(
        packetNumber: number,
        encryptionLevel: .application,
        timeSent: sentAt,
        ackEliciting: true,
        inFlight: inFlight,
        sentBytes: bytes
    )
}
