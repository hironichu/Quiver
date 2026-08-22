/// QUIC BBR congestion controller.
///
/// This is a BBR v1-style model-based controller: it estimates bottleneck
/// bandwidth and minimum RTT from ACK feedback, paces near the estimated
/// bottleneck rate, and keeps the congestion window near a BDP-derived target.

import Foundation
import Synchronization

/// Factory that creates `BBRCongestionController` instances.
public struct BBRFactory: CongestionControllerFactory {
    public init() {}

    public func makeCongestionController(maxDatagramSize: Int) -> any CongestionController {
        BBRCongestionController(maxDatagramSize: maxDatagramSize)
    }
}

/// BBR v1-style congestion controller with integrated pacing.
public final class BBRCongestionController: CongestionController, Sendable {
    private let state: Mutex<BBRState>

    private enum Mode: Sendable {
        case startup
        case drain
        case probeBandwidth
        case probeRTT
    }

    private struct BBRState: Sendable {
        var congestionWindow: Int
        var recoveryStartTime: ContinuousClock.Instant?
        var nextSendTime: ContinuousClock.Instant
        var pacingRate: Double
        var burstTokens: Int

        var mode: Mode
        var modeStartTime: ContinuousClock.Instant
        var probeBandwidthCycleIndex: Int

        var bandwidthSamples: [Double]
        var bottleneckBandwidth: Double
        var fullBandwidth: Double
        var fullBandwidthCount: Int
        var lastAckTime: ContinuousClock.Instant?

        var minRTT: Duration
        var minRTTTimestamp: ContinuousClock.Instant?

        let initialWindow: Int
        let maxDatagramSize: Int
        let minimumWindow: Int
    }

    private enum Constants {
        static let startupPacingGain = 2.885
        static let drainPacingGain = 1.0 / startupPacingGain
        static let congestionWindowGain = 2.0
        static let fullBandwidthGrowthTarget = 1.25
        static let fullBandwidthCountThreshold = 3
        static let bandwidthSampleWindow = 10
        static let lossWindowReduction = 0.85
        static let probeRTTInterval: Duration = .seconds(10)
        static let probeRTTDuration: Duration = .milliseconds(200)
        static let probeBandwidthPacingGains = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]
    }

    public init(maxDatagramSize: Int = LossDetectionConstants.defaultMaxDatagramSize) {
        let initialWindow = LossDetectionConstants.initialWindow(maxDatagramSize: maxDatagramSize)
        let minimumWindow = LossDetectionConstants.minimumWindow(maxDatagramSize: maxDatagramSize)
        let now = ContinuousClock.Instant.now

        self.state = Mutex(BBRState(
            congestionWindow: initialWindow,
            recoveryStartTime: nil,
            nextSendTime: now,
            pacingRate: 0,
            burstTokens: LossDetectionConstants.initialBurstTokens,
            mode: .startup,
            modeStartTime: now,
            probeBandwidthCycleIndex: 0,
            bandwidthSamples: [],
            bottleneckBandwidth: 0,
            fullBandwidth: 0,
            fullBandwidthCount: 0,
            lastAckTime: nil,
            minRTT: .zero,
            minRTTTimestamp: nil,
            initialWindow: initialWindow,
            maxDatagramSize: maxDatagramSize,
            minimumWindow: minimumWindow
        ))
    }

    public var congestionWindow: Int {
        state.withLock { $0.congestionWindow }
    }

    public var currentState: CongestionState {
        state.withLock { s in
            if let recoveryStart = s.recoveryStartTime {
                return .recovery(startTime: recoveryStart)
            }
            switch s.mode {
            case .startup:
                return .slowStart
            case .drain, .probeBandwidth, .probeRTT:
                return .congestionAvoidance
            }
        }
    }

    public func availableWindow(bytesInFlight: Int) -> Int {
        state.withLock { s in
            max(0, s.congestionWindow - bytesInFlight)
        }
    }

    public func nextSendTime() -> ContinuousClock.Instant? {
        state.withLock { s in
            if s.burstTokens > 0 || s.pacingRate <= 0 {
                return nil
            }
            return s.nextSendTime
        }
    }

    public func onPacketSent(bytes: Int, now: ContinuousClock.Instant) {
        state.withLock { s in
            if s.burstTokens > 0 {
                s.burstTokens -= 1
                return
            }
            guard s.pacingRate > 0 else { return }
            let intervalNanos = max(1, Int64(Double(bytes) / s.pacingRate))
            s.nextSendTime = now + .nanoseconds(intervalNanos)
        }
    }

    public func onPacketsAcknowledged(
        packets: [SentPacket],
        now: ContinuousClock.Instant,
        rtt: RTTEstimator
    ) {
        state.withLock { s in
            let ackedPackets = packets.filter(\.inFlight)
            guard !ackedPackets.isEmpty else { return }

            let exitedRecovery = s.recoveryStartTime.map { recoveryStart in
                ackedPackets.contains { $0.timeSent > recoveryStart }
            } ?? false
            if exitedRecovery { s.recoveryStartTime = nil }

            updateRTTModel(&s, now: now, rtt: rtt)
            let ackedBytes = updateBandwidthModel(&s, ackedPackets: ackedPackets, now: now, rtt: rtt)
            guard s.recoveryStartTime == nil else {
                updatePacingRate(&s, rtt: rtt)
                return
            }
            updateMode(&s, now: now)
            updateCongestionWindow(&s, ackedBytes: ackedBytes)
            updatePacingRate(&s, rtt: rtt)
        }
    }

    public func onPacketsLost(
        packets: [SentPacket],
        now: ContinuousClock.Instant,
        rtt: RTTEstimator
    ) {
        guard !packets.isEmpty else { return }

        state.withLock { s in
            if s.recoveryStartTime != nil { return }
            s.recoveryStartTime = now
            s.congestionWindow = max(
                s.minimumWindow,
                Int(Double(s.congestionWindow) * Constants.lossWindowReduction)
            )
            updatePacingRate(&s, rtt: rtt)
        }
    }

    public func onECNCongestionEvent(now: ContinuousClock.Instant) {
        state.withLock { s in
            if s.recoveryStartTime != nil { return }
            s.recoveryStartTime = now
            s.congestionWindow = max(
                s.minimumWindow,
                Int(Double(s.congestionWindow) * Constants.lossWindowReduction)
            )
            updatePacingRate(&s)
        }
    }

    public func onPersistentCongestion() {
        state.withLock { s in
            s.congestionWindow = s.minimumWindow
            s.recoveryStartTime = nil
            s.nextSendTime = .now
            s.pacingRate = 0
            s.burstTokens = LossDetectionConstants.initialBurstTokens
            s.mode = .startup
            s.modeStartTime = .now
            s.probeBandwidthCycleIndex = 0
            s.bandwidthSamples.removeAll(keepingCapacity: true)
            s.bottleneckBandwidth = 0
            s.fullBandwidth = 0
            s.fullBandwidthCount = 0
            s.lastAckTime = nil
            s.minRTT = .zero
            s.minRTTTimestamp = nil
        }
    }

    private func updateRTTModel(_ s: inout BBRState, now: ContinuousClock.Instant, rtt: RTTEstimator) {
        guard rtt.hasEstimate else { return }
        if s.minRTT == .zero || rtt.minRTT < s.minRTT {
            s.minRTT = rtt.minRTT
            s.minRTTTimestamp = now
        }
    }

    private func updateBandwidthModel(
        _ s: inout BBRState,
        ackedPackets: [SentPacket],
        now: ContinuousClock.Instant,
        rtt: RTTEstimator
    ) -> Int {
        let ackedBytes = ackedPackets.reduce(0) { $0 + $1.sentBytes }
        let earliestSent = ackedPackets.map(\.timeSent).min() ?? now
        let latestSent = ackedPackets.map(\.timeSent).max() ?? earliestSent
        let sendElapsed = max(.zero, latestSent - earliestSent)
        let ackElapsed = s.lastAckTime.map { now - $0 }
        let fallbackInterval = rtt.hasEstimate ? rtt.smoothedRTT : RTTEstimator.initialRTT
        let sampleInterval = max(sendElapsed, ackElapsed ?? fallbackInterval, .milliseconds(1))
        s.lastAckTime = now

        let intervalNanos = max(1, Self.nanoseconds(sampleInterval))
        let sample = Double(ackedBytes) / Double(intervalNanos)

        if sample > 0 && sample.isFinite {
            s.bandwidthSamples.append(sample)
            if s.bandwidthSamples.count > Constants.bandwidthSampleWindow {
                s.bandwidthSamples.removeFirst(s.bandwidthSamples.count - Constants.bandwidthSampleWindow)
            }
            s.bottleneckBandwidth = s.bandwidthSamples.max() ?? sample
        } else if s.bottleneckBandwidth <= 0 {
            let baseRTT = rtt.hasEstimate ? rtt.smoothedRTT : RTTEstimator.initialRTT
            let baseNanos = max(1, Self.nanoseconds(baseRTT))
            s.bottleneckBandwidth = Double(max(s.congestionWindow, ackedBytes)) / Double(baseNanos)
        }

        return ackedBytes
    }

    private func updateMode(_ s: inout BBRState, now: ContinuousClock.Instant) {
        if shouldEnterProbeRTT(s, now: now) {
            enterProbeRTT(&s, now: now)
            return
        }

        switch s.mode {
        case .startup:
            updateStartupMode(&s, now: now)
        case .drain:
            let drainDuration = effectiveMinRTT(s)
            if now - s.modeStartTime >= drainDuration {
                enterProbeBandwidth(&s, now: now)
            }
        case .probeBandwidth:
            let cycleDuration = effectiveMinRTT(s)
            if now - s.modeStartTime >= cycleDuration {
                s.probeBandwidthCycleIndex = (s.probeBandwidthCycleIndex + 1) % Constants.probeBandwidthPacingGains.count
                s.modeStartTime = now
            }
        case .probeRTT:
            if now - s.modeStartTime >= Constants.probeRTTDuration {
                s.minRTTTimestamp = now
                enterProbeBandwidth(&s, now: now)
            }
        }
    }

    private func updateStartupMode(_ s: inout BBRState, now: ContinuousClock.Instant) {
        guard s.bottleneckBandwidth > 0 else { return }

        if s.fullBandwidth <= 0 || s.bottleneckBandwidth >= s.fullBandwidth * Constants.fullBandwidthGrowthTarget {
            s.fullBandwidth = s.bottleneckBandwidth
            s.fullBandwidthCount = 0
            return
        }

        s.fullBandwidthCount += 1
        if s.fullBandwidthCount >= Constants.fullBandwidthCountThreshold {
            s.mode = .drain
            s.modeStartTime = now
        }
    }

    private func updateCongestionWindow(_ s: inout BBRState, ackedBytes: Int) {
        if s.mode == .probeRTT {
            s.congestionWindow = s.minimumWindow
            return
        }

        let target = targetCongestionWindow(s)
        switch s.mode {
        case .startup:
            s.congestionWindow += ackedBytes
        case .drain, .probeBandwidth:
            s.congestionWindow = max(s.minimumWindow, target)
        case .probeRTT:
            break
        }
    }

    private func updatePacingRate(_ s: inout BBRState, rtt: RTTEstimator? = nil) {
        let rttDuration = rtt?.hasEstimate == true ? rtt!.smoothedRTT : effectiveMinRTT(s)
        let rttNanos = max(1, Self.nanoseconds(rttDuration))
        let fallbackBandwidth = Double(max(s.congestionWindow, s.maxDatagramSize)) / Double(rttNanos)
        let bandwidth = max(s.bottleneckBandwidth, fallbackBandwidth)
        s.pacingRate = max(
            Double(s.maxDatagramSize) / Double(rttNanos),
            bandwidth * pacingGain(s)
        )
    }

    private func targetCongestionWindow(_ s: BBRState) -> Int {
        guard s.bottleneckBandwidth > 0 else {
            return s.initialWindow
        }
        let rttNanos = max(1, Self.nanoseconds(effectiveMinRTT(s)))
        let bdp = s.bottleneckBandwidth * Double(rttNanos)
        guard bdp.isFinite && bdp > 0 else {
            return s.initialWindow
        }
        return max(s.minimumWindow, Int(bdp * Constants.congestionWindowGain))
    }

    private func shouldEnterProbeRTT(_ s: BBRState, now: ContinuousClock.Instant) -> Bool {
        guard s.mode != .probeRTT, let timestamp = s.minRTTTimestamp else { return false }
        return now - timestamp >= Constants.probeRTTInterval
    }

    private func enterProbeRTT(_ s: inout BBRState, now: ContinuousClock.Instant) {
        s.mode = .probeRTT
        s.modeStartTime = now
        s.congestionWindow = s.minimumWindow
        s.burstTokens = 0
    }

    private func enterProbeBandwidth(_ s: inout BBRState, now: ContinuousClock.Instant) {
        s.mode = .probeBandwidth
        s.modeStartTime = now
        s.probeBandwidthCycleIndex = 0
    }

    private func pacingGain(_ s: BBRState) -> Double {
        switch s.mode {
        case .startup:
            return Constants.startupPacingGain
        case .drain:
            return Constants.drainPacingGain
        case .probeBandwidth:
            return Constants.probeBandwidthPacingGains[s.probeBandwidthCycleIndex]
        case .probeRTT:
            return 1.0
        }
    }

    private func effectiveMinRTT(_ s: BBRState) -> Duration {
        s.minRTT > .zero ? s.minRTT : RTTEstimator.initialRTT
    }

    private static func nanoseconds(_ duration: Duration) -> Int64 {
        let components = duration.components
        return components.seconds * 1_000_000_000 + components.attoseconds / 1_000_000_000
    }
}

extension BBRCongestionController: CustomStringConvertible {
    public var description: String {
        state.withLock { s in
            let mode: String
            switch s.mode {
            case .startup:
                mode = "startup"
            case .drain:
                mode = "drain"
            case .probeBandwidth:
                mode = "probe_bandwidth"
            case .probeRTT:
                mode = "probe_rtt"
            }
            return "BBR(cwnd=\(s.congestionWindow), mode=\(mode), bw=\(s.bottleneckBandwidth))"
        }
    }
}
