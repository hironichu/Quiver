/// QUIC Loss Detection Constants (RFC 9002)
///
/// Constants used for loss detection and probe timeout calculation.

import Foundation

/// RFC 9002 loss detection constants
public enum LossDetectionConstants {
    /// Packet threshold for declaring loss (kPacketThreshold)
    /// RFC 9002 Section 4.3: "A packet is declared lost if it was sent
    /// kPacketThreshold packets before an acknowledged packet."
    public static let packetThreshold: UInt64 = 3

    /// Time threshold numerator (9/8 = 1.125)
    /// RFC 9002 Section 4.3: "kTimeThreshold * max(smoothed_rtt, latest_rtt)"
    public static let timeThresholdNumerator: Int = 9
    public static let timeThresholdDenominator: Int = 8

    /// Timer granularity (kGranularity)
    /// RFC 9002 Section 4.3: "System timer granularity"
    public static let granularity: Duration = .milliseconds(1)

    /// Initial RTT estimate (used before first sample)
    /// RFC 9002 Section 5.1: "333 milliseconds"
    public static let initialRTT: Duration = .milliseconds(333)

    /// Maximum number of packets to track for reordering
    /// Implementation-specific limit for memory management
    public static let maxReorderingWindow: UInt64 = 128

    /// Maximum ACK delay (default value)
    /// RFC 9002 Section 3: "25 milliseconds"
    public static let defaultMaxAckDelay: Duration = .milliseconds(25)

    /// Default ACK delay exponent
    /// RFC 9000 Section 18.2: "3"
    public static let defaultAckDelayExponent: UInt64 = 3

    /// Maximum ACK ranges to include in a single ACK frame
    /// Implementation-specific limit to prevent excessive frame size
    public static let maxAckRanges: Int = 256

    /// Persistent congestion threshold (in PTO periods)
    /// RFC 9002 Section 6.4: "3 consecutive PTOs"
    public static let persistentCongestionThreshold: Int = 3

    // MARK: - Congestion Control Constants (RFC 9002 Section 7)

    /// Default maximum datagram size (bytes)
    /// RFC 9002 Section 7.2: Used to calculate initial window
    public static let maxDatagramSize: Int = 1200

    /// Initial congestion window
    /// RFC 9002 Section 7.2: "The initial congestion window is the minimum of
    /// 10 * max_datagram_size and max(14720, 2 * max_datagram_size)"
    public static var initialWindow: Int {
        min(10 * maxDatagramSize, max(14720, 2 * maxDatagramSize))
    }

    /// Minimum congestion window (in bytes)
    /// RFC 9002 Section 7.2: "2 * max_datagram_size"
    public static var minimumWindow: Int {
        2 * maxDatagramSize
    }

    /// Loss reduction factor
    /// RFC 9002 Section 7.3.2: Multiplicative decrease factor (0.5 for NewReno)
    public static let lossReductionFactor: Double = 0.5

    /// Initial burst tokens for pacing
    /// Number of packets that can be sent immediately at connection start
    public static let initialBurstTokens: Int = 10
}
