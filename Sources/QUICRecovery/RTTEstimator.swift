/// QUIC RTT Estimation (RFC 9002 Section 5)
///
/// Round-trip time estimation for loss detection and congestion control.

import Foundation

// MARK: - RTT Estimator

/// Estimates round-trip time for a QUIC connection
public struct RTTEstimator: Sendable {
    /// Minimum RTT observed
    public private(set) var minRTT: Duration

    /// Smoothed RTT (EWMA)
    public private(set) var smoothedRTT: Duration

    /// RTT variance
    public private(set) var rttVariance: Duration

    /// Latest RTT sample
    public private(set) var latestRTT: Duration

    /// Whether we have received at least one RTT sample
    public private(set) var hasEstimate: Bool

    /// Initial RTT (used before first sample)
    public static let initialRTT: Duration = .milliseconds(333)

    /// Creates a new RTT estimator
    public init() {
        self.minRTT = .zero
        self.smoothedRTT = Self.initialRTT
        self.rttVariance = Self.initialRTT / 2
        self.latestRTT = .zero
        self.hasEstimate = false
    }

    /// Updates the RTT estimate with a new sample
    ///
    /// RFC 9002 Section 5.3: The ack_delay is used to adjust the RTT sample,
    /// but only after the handshake is confirmed. Before handshake confirmation,
    /// the ack_delay is not applied because the peer may not yet be using its
    /// final max_ack_delay value.
    ///
    /// - Parameters:
    ///   - rttSample: The new RTT sample
    ///   - ackDelay: The acknowledgment delay reported by the peer
    ///   - maxAckDelay: The peer's max_ack_delay transport parameter
    ///   - handshakeConfirmed: Whether the handshake has been confirmed
    public mutating func updateRTT(
        rttSample: Duration,
        ackDelay: Duration,
        maxAckDelay: Duration,
        handshakeConfirmed: Bool
    ) {
        latestRTT = rttSample

        if !hasEstimate {
            // First RTT sample
            hasEstimate = true
            minRTT = rttSample
            smoothedRTT = rttSample
            // Use FastDuration for division
            rttVariance = (rttSample.fast / 2).duration
            return
        }

        // Update minimum RTT
        if rttSample < minRTT {
            minRTT = rttSample
        }

        // Use FastDuration for all calculations (avoids repeated components decomposition)
        let fastSample = rttSample.fast
        let fastMinRTT = minRTT.fast
        var fastAdjusted = fastSample

        // Adjust for ack delay only after handshake is confirmed
        // RFC 9002 Section 5.3: "An endpoint MUST NOT subtract the acknowledgment
        // delay from the RTT sample if the resulting value is smaller than the min_rtt."
        if handshakeConfirmed {
            let fastAckDelay = ackDelay.fast
            let fastMaxAckDelay = maxAckDelay.fast
            let cappedAckDelay = FastDuration.min(fastAckDelay, fastMaxAckDelay)
            if fastAdjusted > fastMinRTT + cappedAckDelay {
                fastAdjusted = fastSample - cappedAckDelay
            }
        }

        // Update smoothed RTT and variance using EWMA with FastDuration
        // smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
        // rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|
        let fastSmoothed = smoothedRTT.fast
        let fastVariance = rttVariance.fast
        let rttDiff = FastDuration.abs(fastSmoothed - fastAdjusted)
        let newVariance = (fastVariance * 3 + rttDiff) / 4
        let newSmoothed = (fastSmoothed * 7 + fastAdjusted) / 8

        rttVariance = newVariance.duration
        smoothedRTT = newSmoothed.duration
    }

    /// Calculates the Probe Timeout (PTO) value
    /// - Parameter maxAckDelay: The peer's max_ack_delay transport parameter
    /// - Returns: The PTO duration
    public func probeTimeout(maxAckDelay: Duration) -> Duration {
        // PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
        let granularity: Duration = .milliseconds(1)
        let k = max(rttVariance * 4, granularity)
        return smoothedRTT + k + maxAckDelay
    }
}

// MARK: - Duration Extensions

extension Duration {
    /// Divides a duration by an integer
    /// Note: +, - operators exist in standard library, but * and / with Int do not
    static func / (lhs: Duration, rhs: Int) -> Duration {
        let (seconds, attoseconds) = lhs.components
        let totalNs = seconds * 1_000_000_000 + attoseconds / 1_000_000_000
        return .nanoseconds(totalNs / Int64(rhs))
    }

    /// Multiplies a duration by an integer
    static func * (lhs: Duration, rhs: Int) -> Duration {
        let (seconds, attoseconds) = lhs.components
        let totalNs = seconds * 1_000_000_000 + attoseconds / 1_000_000_000
        return .nanoseconds(totalNs * Int64(rhs))
    }

    /// Absolute value of a duration
    static func abs(_ duration: Duration) -> Duration {
        let (seconds, attoseconds) = duration.components
        let totalNs = seconds * 1_000_000_000 + attoseconds / 1_000_000_000
        if totalNs < 0 {
            return .nanoseconds(-totalNs)
        }
        return duration
    }
}
