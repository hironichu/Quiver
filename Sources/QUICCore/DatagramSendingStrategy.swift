/// Datagram Sending Strategy
///
/// Defines how a datagram should be handled in the outbound queue.
/// Used to implement real-time media requirements (MOQ/MOQT) where
/// old data should be dropped and important data prioritized.
///
/// ## Usage
/// ```swift
/// // Send immediately or drop if older than 100ms
/// let strategy = .ttl(.milliseconds(100))
/// try connection.sendDatagram(data, strategy: strategy)
/// ```
public enum DatagramSendingStrategy: Sendable, Hashable {
    /// Standard FIFO behavior (default).
    /// Reliable-ish: Application expects it to be sent unless connection closes.
    case fifo

    /// Discard if not sent within the specified duration.
    /// Useful for real-time media (e.g., "don't send old video frames").
    case ttl(Duration)

    /// Priority-based ordering (higher values sent first).
    /// Useful for audio vs video prioritization.
    /// Range: 0 (lowest) to 255 (highest).
    case priority(UInt8)

    /// Combined priority and TTL.
    /// Drops if expired; otherwise sorts by priority.
    case combined(priority: UInt8, ttl: Duration)
}
