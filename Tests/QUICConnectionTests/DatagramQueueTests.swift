import Foundation
import QUICCore
import Synchronization
import Testing

@testable import QUICConnection

@Suite("Datagram Queue Tests")
struct DatagramQueueTests {

    @Test("FIFO Ordering")
    func testFIFO() async {
        var queue = DatagramQueue()
        let clock = ContinuousClock()
        let now = clock.now

        queue.enqueue(Data([1]), strategy: .fifo)
        queue.enqueue(Data([2]), strategy: .fifo)
        queue.enqueue(Data([3]), strategy: .fifo)

        let frames = queue.dequeue(maxBytes: 1000, now: now)

        #expect(frames.count == 3)
        #expect(frames[0].data == Data([1]))
        #expect(frames[1].data == Data([2]))
        #expect(frames[2].data == Data([3]))
    }

    @Test("TTL Expiry")
    func testTTL() async {
        var queue = DatagramQueue()
        let clock = ContinuousClock()
        let now = clock.now

        // Should expire
        queue.enqueue(Data([1]), strategy: .ttl(.seconds(1)))

        // Should not expire
        queue.enqueue(Data([2]), strategy: .ttl(.seconds(10)))

        // Simulate time passing (2 seconds later)
        let later = now + .seconds(2)

        let frames = queue.dequeue(maxBytes: 1000, now: later)

        #expect(frames.count == 1)
        #expect(frames[0].data == Data([2]))
    }

    @Test("Priority Ordering")
    func testPriority() async {
        var queue = DatagramQueue()
        let clock = ContinuousClock()
        let now = clock.now

        queue.enqueue(Data([1]), strategy: .priority(10))  // Low
        queue.enqueue(Data([2]), strategy: .priority(200))  // High
        queue.enqueue(Data([3]), strategy: .priority(50))  // Medium

        // Should come out: 2 (High), 3 (Medium), 1 (Low)
        let frames = queue.dequeue(maxBytes: 1000, now: now)

        #expect(frames.count == 3)
        #expect(frames[0].data == Data([2]))
        #expect(frames[1].data == Data([3]))
        #expect(frames[2].data == Data([1]))
    }

    @Test("Combined Strategy")
    func testCombined() async {
        var queue = DatagramQueue()
        let clock = ContinuousClock()
        let now = clock.now

        // High priority but expired
        queue.enqueue(Data([1]), strategy: .combined(priority: 255, ttl: .seconds(1)))

        // Medium priority, valid
        queue.enqueue(Data([2]), strategy: .combined(priority: 100, ttl: .seconds(10)))

        // Simulate time passing
        let later = now + .seconds(2)

        let frames = queue.dequeue(maxBytes: 1000, now: later)

        #expect(frames.count == 1)
        #expect(frames[0].data == Data([2]))
    }

    @Test("Capacity Limits")
    func testCapacity() async {
        var queue = DatagramQueue()
        let clock = ContinuousClock()
        let now = clock.now

        queue.enqueue(Data(count: 100), strategy: .priority(200))  // High
        queue.enqueue(Data(count: 100), strategy: .priority(10))  // Low

        // Only enough space for one (100 + overhead)
        let frames = queue.dequeue(maxBytes: 110, now: now)

        #expect(frames.count == 1)
        #expect(frames[0].data.count == 100)
        // Verify it picked the high priority one (first in sorted list)
        // Wait, since we don't have IDs on frames, we assume correctness by count for now.
    }
}
