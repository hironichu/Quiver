/// Stream Scheduler
///
/// Priority-based stream scheduler with fair queuing within priority levels.
/// Implements RFC 9218 Extensible Priorities for HTTP/3 integration.

import Foundation

// MARK: - RFC 9218 Priority Header Parsing

/// Parser for the RFC 9218 Priority header field value.
///
/// The Priority header uses the Structured Fields syntax (RFC 8941) in
/// Dictionary form. It supports the following parameters:
///
/// - `u` (urgency): Integer 0-7, default 3. Lower is higher priority.
/// - `i` (incremental): Boolean, default false. Whether the response
///   benefits from incremental delivery.
///
/// ## Wire Format
///
/// ```
/// Priority: u=3, i
/// Priority: u=0
/// Priority: i
/// Priority: u=7, i=?0
/// ```
///
/// ## Usage
///
/// ```swift
/// let priority = PriorityHeaderParser.parse("u=1, i")
/// // StreamPriority(urgency: 1, incremental: true)
///
/// let defaultPriority = PriorityHeaderParser.parse(nil)
/// // StreamPriority(urgency: 3, incremental: false) — the default
/// ```
public enum PriorityHeaderParser {

    /// Parses an RFC 9218 Priority header field value into a StreamPriority.
    ///
    /// If the header value is nil or empty, returns the default priority
    /// (urgency=3, incremental=false) per RFC 9218 Section 4.
    ///
    /// Unknown parameters are ignored per RFC 9218 Section 4.
    ///
    /// - Parameter headerValue: The raw Priority header field value
    /// - Returns: The parsed StreamPriority
    public static func parse(_ headerValue: String?) -> StreamPriority {
        guard let value = headerValue, !value.isEmpty else {
            return .default
        }

        var urgency: UInt8 = 3
        var incremental: Bool = false

        // Split on commas to get individual parameters
        let parameters = value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }

        for param in parameters {
            if param.hasPrefix("u=") {
                // Parse urgency value
                let valueStr = String(param.dropFirst(2))
                if let parsed = UInt8(valueStr), parsed <= 7 {
                    urgency = parsed
                }
                // Invalid urgency values are ignored (use default)
            } else if param == "i" || param == "i=?1" {
                // Boolean true in Structured Fields syntax
                incremental = true
            } else if param == "i=?0" {
                // Boolean false in Structured Fields syntax
                incremental = false
            }
            // Unknown parameters are silently ignored per RFC 9218
        }

        return StreamPriority(urgency: urgency, incremental: incremental)
    }

    /// Serializes a StreamPriority into an RFC 9218 Priority header field value.
    ///
    /// Only includes parameters that differ from the defaults:
    /// - `u` is omitted if urgency == 3 (the default)
    /// - `i` is omitted if incremental == false (the default)
    ///
    /// - Parameter priority: The priority to serialize
    /// - Returns: The Priority header field value string
    public static func serialize(_ priority: StreamPriority) -> String {
        var parts: [String] = []

        if priority.urgency != 3 {
            parts.append("u=\(priority.urgency)")
        }

        if priority.incremental {
            parts.append("i")
        }

        if parts.isEmpty {
            // All defaults — return minimal representation
            // An empty value is technically valid, but some implementations
            // prefer at least one parameter, so we include the default urgency.
            return "u=3"
        }

        return parts.joined(separator: ", ")
    }
}

// MARK: - PRIORITY_UPDATE Frame (RFC 9218 Section 7)

/// PRIORITY_UPDATE frame for dynamic stream reprioritization.
///
/// HTTP/3 uses two PRIORITY_UPDATE frame types:
/// - Type 0x0f0700: For request streams (client-initiated bidirectional)
/// - Type 0x0f0701: For push streams
///
/// ## Wire Format
///
/// ```
/// PRIORITY_UPDATE Frame {
///   Type (i) = 0x0f0700 or 0x0f0701,
///   Length (i),
///   Prioritized Element ID (i),    // Stream ID or Push ID
///   Priority Field Value (..),     // ASCII, Structured Fields Dictionary
/// }
/// ```
///
/// ## Usage
///
/// ```swift
/// // Create a priority update for request stream 4
/// let update = PriorityUpdate(
///     elementID: 4,
///     priority: StreamPriority(urgency: 1, incremental: true),
///     isRequestStream: true
/// )
///
/// // Encode to bytes
/// let encoded = update.encode()
///
/// // Decode from bytes
/// let decoded = try PriorityUpdate.decode(from: data, isRequestStream: true)
/// ```
public struct PriorityUpdate: Sendable, Hashable {
    /// Frame type for request stream PRIORITY_UPDATE (RFC 9218 Section 7.1)
    public static let requestStreamFrameType: UInt64 = 0x0f0700

    /// Frame type for push stream PRIORITY_UPDATE (RFC 9218 Section 7.2)
    public static let pushStreamFrameType: UInt64 = 0x0f0701

    /// The stream ID or push ID being reprioritized.
    public let elementID: UInt64

    /// The new priority for the element.
    public let priority: StreamPriority

    /// Whether this update targets a request stream (true) or push stream (false).
    public let isRequestStream: Bool

    /// Creates a PRIORITY_UPDATE.
    ///
    /// - Parameters:
    ///   - elementID: The stream or push ID to reprioritize
    ///   - priority: The new priority
    ///   - isRequestStream: Whether this targets a request stream (default: true)
    public init(elementID: UInt64, priority: StreamPriority, isRequestStream: Bool = true) {
        self.elementID = elementID
        self.priority = priority
        self.isRequestStream = isRequestStream
    }

    /// The HTTP/3 frame type for this update.
    public var frameType: UInt64 {
        isRequestStream ? Self.requestStreamFrameType : Self.pushStreamFrameType
    }

    /// Encodes the PRIORITY_UPDATE payload (without frame type/length).
    ///
    /// The payload consists of:
    /// 1. Prioritized Element ID (varint)
    /// 2. Priority Field Value (ASCII bytes)
    ///
    /// - Returns: The encoded payload data
    public func encodePayload() -> Data {
        var data = Data()

        // Encode element ID as varint
        data.append(contentsOf: Self.varintEncode(elementID))

        // Encode Priority Field Value as ASCII
        let fieldValue = PriorityHeaderParser.serialize(priority)
        data.append(contentsOf: fieldValue.utf8)

        return data
    }

    /// Decodes a PRIORITY_UPDATE from its payload data.
    ///
    /// - Parameters:
    ///   - data: The payload data (after frame type and length)
    ///   - isRequestStream: Whether this is a request stream update
    /// - Returns: The decoded PriorityUpdate
    /// - Throws: If the payload is malformed
    public static func decode(from data: Data, isRequestStream: Bool) throws -> PriorityUpdate {
        guard !data.isEmpty else {
            throw PriorityUpdateError.emptyPayload
        }

        // Decode element ID varint
        let (elementID, consumed) = try varintDecode(from: data)

        // Remaining bytes are the Priority Field Value
        let remaining = data.suffix(from: data.startIndex + consumed)
        let fieldValue = String(data: Data(remaining), encoding: .utf8)

        let priority = PriorityHeaderParser.parse(fieldValue)

        return PriorityUpdate(
            elementID: elementID,
            priority: priority,
            isRequestStream: isRequestStream
        )
    }

    /// Checks if a frame type is a PRIORITY_UPDATE frame.
    ///
    /// - Parameter frameType: The frame type to check
    /// - Returns: A `PriorityUpdateClassification` if this is a PRIORITY_UPDATE, or nil otherwise
    public static func classify(_ frameType: UInt64) -> PriorityUpdateClassification? {
        switch frameType {
        case requestStreamFrameType:
            return PriorityUpdateClassification(isRequestStream: true)
        case pushStreamFrameType:
            return PriorityUpdateClassification(isRequestStream: false)
        default:
            return nil
        }
    }

    // MARK: - Varint Helpers (minimal, self-contained)

    /// Encodes a UInt64 as a QUIC variable-length integer.
    private static func varintEncode(_ value: UInt64) -> [UInt8] {
        if value <= 63 {
            return [UInt8(value)]
        } else if value <= 16383 {
            return [
                UInt8(0x40 | (value >> 8)),
                UInt8(value & 0xFF)
            ]
        } else if value <= 1_073_741_823 {
            return [
                UInt8(0x80 | (value >> 24)),
                UInt8((value >> 16) & 0xFF),
                UInt8((value >> 8) & 0xFF),
                UInt8(value & 0xFF)
            ]
        } else {
            return [
                UInt8(0xC0 | (value >> 56)),
                UInt8((value >> 48) & 0xFF),
                UInt8((value >> 40) & 0xFF),
                UInt8((value >> 32) & 0xFF),
                UInt8((value >> 24) & 0xFF),
                UInt8((value >> 16) & 0xFF),
                UInt8((value >> 8) & 0xFF),
                UInt8(value & 0xFF)
            ]
        }
    }

    /// Decodes a QUIC variable-length integer from data.
    private static func varintDecode(from data: Data) throws -> (UInt64, Int) {
        guard let firstByte = data.first else {
            throw PriorityUpdateError.insufficientData
        }

        let prefix = firstByte >> 6
        let length: Int

        switch prefix {
        case 0: length = 1
        case 1: length = 2
        case 2: length = 4
        case 3: length = 8
        default: length = 1  // unreachable
        }

        guard data.count >= length else {
            throw PriorityUpdateError.insufficientData
        }

        var value = UInt64(firstByte & 0x3F)
        for i in 1..<length {
            value = (value << 8) | UInt64(data[data.startIndex + i])
        }

        return (value, length)
    }
}

/// Result of classifying a frame type as a PRIORITY_UPDATE.
public struct PriorityUpdateClassification: Sendable, Hashable {
    /// Whether this targets a request stream (true) or push stream (false).
    public let isRequestStream: Bool
}

/// Errors from PRIORITY_UPDATE decoding.
public enum PriorityUpdateError: Error, Sendable, CustomStringConvertible {
    /// The payload was empty
    case emptyPayload

    /// Not enough data to decode the varint
    case insufficientData

    public var description: String {
        switch self {
        case .emptyPayload:
            return "PRIORITY_UPDATE payload is empty"
        case .insufficientData:
            return "Insufficient data for PRIORITY_UPDATE varint"
        }
    }
}

// MARK: - Scheduling Strategy

/// Scheduling strategy that determines how streams within the same
/// urgency group are served.
///
/// RFC 9218 Section 5 describes the expected server behavior:
///
/// - **Non-incremental** streams: The server should dedicate resources to
///   a single stream at a time, completing it before moving to the next.
///   This minimizes time-to-first-byte for individual resources.
///
/// - **Incremental** streams: The server should interleave data from
///   multiple streams, sharing bandwidth. This enables progressive
///   rendering and streaming use cases.
///
/// ## Example
///
/// Urgency group with streams A (non-incremental), B (incremental), C (incremental):
/// - A is served exclusively first (non-incremental takes priority)
/// - B and C are interleaved after A completes
public enum SchedulingStrategy: Sendable, Hashable {
    /// Serve one stream at a time until completion (non-incremental default)
    case sequential

    /// Interleave data from multiple streams (incremental)
    case interleaved

    /// Round-robin within the group (fair sharing regardless of incremental flag)
    case roundRobin
}

// MARK: - StreamScheduler

/// Priority-based stream scheduler with fair queuing
///
/// This scheduler orders streams by their priority (urgency level) and implements
/// RFC 9218-compliant scheduling behavior:
///
/// 1. Group streams by urgency level (0-7)
/// 2. Process groups in priority order (0 first, 7 last)
/// 3. Within each group, apply incremental/non-incremental scheduling:
///    - Non-incremental streams are served one at a time (sequential)
///    - Incremental streams are interleaved (round-robin)
/// 4. Non-incremental streams within a group are served before incremental ones
/// 5. Cursors persist between calls for fairness
///
/// ## Thread Safety
/// This struct is not thread-safe by itself. It should be used within a synchronized context.
public struct StreamScheduler: Sendable {
    /// Round-robin cursors per urgency level
    ///
    /// Key: urgency level (0-7)
    /// Value: cursor position for next scheduling round
    private var cursors: [UInt8: Int] = [:]

    /// Scheduling mode (default: RFC 9218 compliant incremental-aware scheduling)
    public var useIncrementalScheduling: Bool = true

    /// Creates a new StreamScheduler
    public init() {}

    /// Schedules streams and returns them in priority order.
    ///
    /// When `useIncrementalScheduling` is true (default), the scheduler
    /// implements RFC 9218 behavior:
    /// - Non-incremental streams are placed first in each urgency group
    ///   (only the "active" one, determined by cursor)
    /// - Incremental streams are interleaved via round-robin after
    ///   non-incremental streams
    ///
    /// When `useIncrementalScheduling` is false, simple round-robin
    /// is used within each group (legacy behavior).
    ///
    /// - Parameter streams: Dictionary of stream ID to DataStream
    /// - Returns: Array of (streamID, stream) tuples ordered by priority with fair queuing
    public mutating func scheduleStreams(
        _ streams: [UInt64: DataStream]
    ) -> [(streamID: UInt64, stream: DataStream)] {
        // Group streams by urgency
        var groups: [UInt8: [(UInt64, DataStream)]] = [:]
        for (streamID, stream) in streams {
            let urgency = stream.priority.urgency
            groups[urgency, default: []].append((streamID, stream))
        }

        // Sort each group by stream ID for deterministic ordering
        for (urgency, group) in groups {
            groups[urgency] = group.sorted { $0.0 < $1.0 }
        }

        // Build result in priority order
        var result: [(streamID: UInt64, stream: DataStream)] = []

        // Process urgency levels in order (0 = highest priority first)
        for urgency in UInt8(0)...7 {
            guard let group = groups[urgency], !group.isEmpty else {
                continue
            }

            if useIncrementalScheduling {
                // RFC 9218 incremental-aware scheduling
                result.append(contentsOf: scheduleGroupIncremental(group, urgency: urgency))
            } else {
                // Legacy round-robin scheduling
                result.append(contentsOf: scheduleGroupRoundRobin(group, urgency: urgency))
            }
        }

        return result
    }

    /// Schedules a group with RFC 9218 incremental-aware behavior.
    ///
    /// Non-incremental streams are served one at a time (the current
    /// cursor-selected one goes first). Incremental streams are all
    /// included and interleaved via round-robin.
    ///
    /// The ordering within a group is:
    /// 1. The active non-incremental stream (cursor-selected)
    /// 2. All incremental streams (round-robin from cursor)
    /// 3. Remaining non-incremental streams
    private mutating func scheduleGroupIncremental(
        _ group: [(UInt64, DataStream)],
        urgency: UInt8
    ) -> [(streamID: UInt64, stream: DataStream)] {
        // Partition into non-incremental and incremental
        let nonIncremental = group.filter { !$0.1.priority.incremental }
        let incremental = group.filter { $0.1.priority.incremental }

        var result: [(streamID: UInt64, stream: DataStream)] = []

        // Handle non-incremental streams: serve only the active one first
        if !nonIncremental.isEmpty {
            let cursor = cursors[urgency] ?? 0
            let validCursor = cursor % nonIncremental.count

            // The active non-incremental stream goes first
            let active = nonIncremental[validCursor]
            result.append((streamID: active.0, stream: active.1))

            // Remaining non-incremental streams go after incremental ones
            var remaining: [(streamID: UInt64, stream: DataStream)] = []
            for (i, entry) in nonIncremental.enumerated() where i != validCursor {
                remaining.append((streamID: entry.0, stream: entry.1))
            }

            // Incremental streams interleaved after active non-incremental
            if !incremental.isEmpty {
                // Use a separate cursor space for incremental within same urgency
                let incrementalCursorKey = urgency &+ 128  // offset to avoid collision
                let incCursor = cursors[incrementalCursorKey] ?? 0
                let validIncCursor = incCursor % incremental.count
                let rotated = rotateArray(incremental, startingAt: validIncCursor)
                for entry in rotated {
                    result.append((streamID: entry.0, stream: entry.1))
                }
            }

            // Append remaining non-incremental
            result.append(contentsOf: remaining)
        } else if !incremental.isEmpty {
            // Only incremental streams — round-robin all of them
            let cursor = cursors[urgency] ?? 0
            let validCursor = cursor % incremental.count
            let rotated = rotateArray(incremental, startingAt: validCursor)
            for entry in rotated {
                result.append((streamID: entry.0, stream: entry.1))
            }
        }

        return result
    }

    /// Schedules a group with simple round-robin (legacy behavior).
    private mutating func scheduleGroupRoundRobin(
        _ group: [(UInt64, DataStream)],
        urgency: UInt8
    ) -> [(streamID: UInt64, stream: DataStream)] {
        let cursor = cursors[urgency] ?? 0
        let validCursor = cursor % group.count

        // Rotate the group to start from cursor position
        let rotated = rotateArray(group, startingAt: validCursor)

        var result: [(streamID: UInt64, stream: DataStream)] = []
        for entry in rotated {
            result.append((streamID: entry.0, stream: entry.1))
        }

        // Update cursor for next round (advance by group size)
        cursors[urgency] = (validCursor + group.count) % group.count

        return result
    }

    /// Advances the cursor for a specific urgency level.
    ///
    /// Call this after a stream at the given urgency has sent data.
    /// This ensures the next stream in the group gets priority next time.
    public mutating func advanceCursor(for urgency: UInt8, groupSize: Int) {
        guard groupSize > 0 else { return }
        let current = cursors[urgency] ?? 0
        cursors[urgency] = (current + 1) % groupSize
    }

    /// Advances the incremental cursor for a specific urgency level.
    ///
    /// Call this after an incremental stream has sent data to rotate
    /// to the next incremental stream in the group.
    public mutating func advanceIncrementalCursor(for urgency: UInt8, groupSize: Int) {
        guard groupSize > 0 else { return }
        let cursorKey = urgency &+ 128
        let current = cursors[cursorKey] ?? 0
        cursors[cursorKey] = (current + 1) % groupSize
    }

    /// Resets all cursors.
    ///
    /// Call this when streams are significantly added/removed.
    public mutating func resetCursors() {
        cursors.removeAll()
    }

    /// Removes cursor for a specific urgency level.
    public mutating func removeCursor(for urgency: UInt8) {
        cursors.removeValue(forKey: urgency)
        cursors.removeValue(forKey: urgency &+ 128)
    }

    // MARK: - Priority Updates

    /// Applies a PRIORITY_UPDATE to the stream map.
    ///
    /// This updates the priority of the specified stream if it exists.
    /// If the stream doesn't exist yet (it may be created later), the
    /// update is returned as pending.
    ///
    /// - Parameters:
    ///   - update: The PRIORITY_UPDATE to apply
    ///   - streams: The current stream map
    /// - Returns: true if the stream was found and updated, false if pending
    public mutating func applyPriorityUpdate(
        _ update: PriorityUpdate,
        to streams: [UInt64: DataStream]
    ) -> Bool {
        if let stream = streams[update.elementID] {
            stream.priority = update.priority
            return true
        }
        return false
    }

    // MARK: - Private

    /// Rotates an array to start at a specific index.
    private func rotateArray<T>(_ array: [T], startingAt index: Int) -> [T] {
        guard !array.isEmpty, index > 0, index < array.count else {
            return array
        }
        return Array(array[index...]) + Array(array[..<index])
    }
}

// MARK: - StreamScheduler Statistics

extension StreamScheduler {
    /// Returns the current cursor positions for debugging.
    public var cursorPositions: [UInt8: Int] {
        cursors
    }

    /// Returns the number of tracked cursor positions.
    public var cursorCount: Int {
        cursors.count
    }
}

// MARK: - StreamPriority HTTP/3 Extensions

extension StreamPriority {
    /// Creates a StreamPriority from an HTTP/3 Priority header field value.
    ///
    /// Convenience initializer that delegates to `PriorityHeaderParser.parse`.
    ///
    /// - Parameter headerValue: The Priority header field value (e.g., "u=1, i")
    /// - Returns: The parsed StreamPriority
    public static func fromHeader(_ headerValue: String?) -> StreamPriority {
        PriorityHeaderParser.parse(headerValue)
    }

    /// Serializes this priority to an HTTP/3 Priority header field value.
    ///
    /// - Returns: The Priority header value string (e.g., "u=1, i")
    public func toHeader() -> String {
        PriorityHeaderParser.serialize(self)
    }

    // MARK: - HTTP/3 Stream Type Defaults

    /// Default priority for control streams.
    ///
    /// Control streams should have highest priority since they carry
    /// critical protocol data (SETTINGS, GOAWAY, etc.).
    public static let controlStream = StreamPriority(urgency: 0, incremental: false)

    /// Default priority for QPACK streams.
    ///
    /// QPACK encoder/decoder streams should have high priority to
    /// avoid blocking header decompression.
    public static let qpackStream = StreamPriority(urgency: 0, incremental: false)

    /// Default priority for server push streams.
    ///
    /// Push streams default to lower priority than regular requests
    /// since they're speculative.
    public static let pushStream = StreamPriority(urgency: 7, incremental: true)

    // MARK: - WebTransport Stream Type Defaults

    /// Default priority for WebTransport bidirectional streams.
    ///
    /// Bidi streams are typically interactive (request/response, echo, RPC),
    /// so they use the default HTTP/3 urgency with incremental delivery
    /// enabled to allow interleaving of concurrent bidi streams.
    public static let webTransportBidi = StreamPriority(urgency: 3, incremental: true)

    /// Default priority for WebTransport unidirectional streams.
    ///
    /// Uni streams are typically used for server-push notifications or
    /// one-shot data transfers. Slightly lower urgency than bidi streams
    /// since they're often less latency-sensitive.
    public static let webTransportUni = StreamPriority(urgency: 4, incremental: false)

    /// Default priority for WebTransport datagrams.
    ///
    /// Datagrams are unreliable and unordered, used for real-time data
    /// (game state, telemetry) that tolerates loss. Lower urgency than
    /// streams, with incremental delivery for fair sharing.
    public static let webTransportDatagram = StreamPriority(urgency: 5, incremental: true)

    /// Default priority for the WebTransport session CONNECT stream.
    ///
    /// The Extended CONNECT stream carries capsules (CLOSE, DRAIN) that
    /// control session lifecycle. It must have high priority to ensure
    /// timely session teardown and signaling.
    public static let webTransportSessionControl = StreamPriority(urgency: 1, incremental: false)
}