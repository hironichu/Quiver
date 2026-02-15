/// Datagram Queue
///
/// Manages pending datagrams with support for:
/// - FIFO ordering (default)
/// - Expiry (TTL)
/// - Prioritization
///
/// Thread-safe (actor-marshalled or mutex-protected by owner).
/// This struct is intended to be held inside `QUICConnectionHandler`.
import Foundation
import QUICCore
import Synchronization

package struct DatagramQueue: Sendable {
    /// A queued datagram entry
    struct Entry: Sendable {
        let data: Data
        let strategy: DatagramSendingStrategy
        let timeEnqueued: ContinuousClock.Instant
        let id: UInt64  // Monotonic ID for FIFO stability
    }

    private var queue: [Entry] = []
    private var nextID: UInt64 = 0

    /// Current number of pending datagrams
    package var count: Int {
        queue.count
    }

    /// Whether the queue is empty
    package var isEmpty: Bool {
        queue.isEmpty
    }

    /// Enqueues a datagram
    package mutating func enqueue(_ data: Data, strategy: DatagramSendingStrategy) {
        let entry = Entry(
            data: data,
            strategy: strategy,
            timeEnqueued: .now,
            id: nextID
        )
        queue.append(entry)
        nextID += 1
    }

    /// Dequeues up to `maxBytes` of datagrams, respecting strategies.
    ///
    /// - Parameters:
    ///   - maxBytes: Maximum total payload size to return
    ///   - now: Current time (for TTL checks)
    /// - Returns: Array of `DatagramFrame` fit for inclusion in a packet
    package mutating func dequeue(maxBytes: Int, now: ContinuousClock.Instant) -> [DatagramFrame] {
        // 1. Filter expired items first (lazy prune)
        pruneExpired(now: now)

        // 2. Sort by priority
        // Stable sort: explicit priority desc, then ID asc (FIFO)
        // Note: This O(N log N) sort happens on every packet gen.
        // Optimization: For high throughput, we might want separate queues per priority.
        // 2. Sort by priority
        // Stable sort: explicit priority desc, then ID asc (FIFO)
        queue.sort { lhs, rhs in
            let lhsPriority = Self.priorityValue(lhs.strategy)
            let rhsPriority = Self.priorityValue(rhs.strategy)

            if lhsPriority != rhsPriority {
                return lhsPriority > rhsPriority  // Higher priority first
            }
            return lhs.id < rhs.id  // FIFO fallback
        }

        // 3. Select items that fit
        var selectedFrames: [DatagramFrame] = []
        var remainingBytes = maxBytes
        var indicesToRemove: IndexSet = []

        for (index, entry) in queue.enumerated() {
            // Frame overhead: 1 type byte + varint length.
            // Conservative estimate: 1 + 2 = 3 bytes overhead
            // plus the payload size.
            let frameSize = entry.data.count + 3

            if frameSize <= remainingBytes {
                selectedFrames.append(DatagramFrame(data: entry.data, hasLength: true))
                remainingBytes -= frameSize
                indicesToRemove.insert(index)
            } else {
                // If we can't fit this high-priority item, do we skip to the next?
                // QUIC RFC says datagrams are atomic. We generally STOP if the
                // highest priority doesn't fit, to avoid reordering unless
                // strict HOL blocking is undesirable.
                // For simplified "best effort", we stop filling here to preserve order uniqueness
                // for this priority level.
                break
            }
        }

        // 4. Remove selected items
        // Filter in place is efficient for removing set of indices
        if !indicesToRemove.isEmpty {
            var newQueue: [Entry] = []
            newQueue.reserveCapacity(queue.count - indicesToRemove.count)
            for (i, entry) in queue.enumerated() {
                if !indicesToRemove.contains(i) {
                    newQueue.append(entry)
                }
            }
            queue = newQueue
        }

        return selectedFrames
    }

    /// Prune items that have exceeded their TTL
    private mutating func pruneExpired(now: ContinuousClock.Instant) {
        queue.removeAll { entry in
            switch entry.strategy {
            case .ttl(let duration), .combined(_, let duration):
                return now > (entry.timeEnqueued + duration)
            default:
                return false
            }
        }
    }

    /// Extract numeric priority (0-255) from strategy
    private static func priorityValue(_ strategy: DatagramSendingStrategy) -> UInt8 {
        switch strategy {
        case .fifo, .ttl:
            return 128  // Default middle priority
        case .priority(let p), .combined(let p, _):
            return p
        }
    }
}
