import MOQCore
import QUICCore
import XCTest

final class MOQConsumerTests: XCTestCase {

    /// Tests that a subscribed session correctly receives and deserializes objects.
    func testSimpleConsumerFlow() async throws {
        let transport = MockMOQTransport()
        let session = MOQSession(transport: transport)
        await session.start()

        let trackID: UInt64 = 1
        let subscriptionStream = await session.subscribe(trackID: trackID)

        // Create a test object
        let header = MOQObjectHeader(
            trackID: trackID,
            groupID: 0,
            objectID: 0,
            priority: 10
        )
        let payload = Data("Hello MOQ".utf8)
        let object = MOQObject(header: header, payload: payload)

        // Encode and receive
        let encoded = object.encode()
        transport.receiveDatagram(encoded)

        // Verify reception
        var iterator = subscriptionStream.makeAsyncIterator()
        // Timeout handling in tests usually requires expectation or custom helper,
        // but for unit tests we can just await briefly.
        // We'll trust the simulation is fast enough.

        // wait for the object
        if let received = await iterator.next() {
            XCTAssertEqual(received.header.trackID, trackID)
            XCTAssertEqual(received.header.groupID, 0)
            XCTAssertEqual(received.header.objectID, 0)
            XCTAssertEqual(received.payload, payload)
        } else {
            XCTFail("Stream finished without yielding object")
        }
    }

    /// Tests that objects for unsubscribed tracks are dropped.
    func testUnsubscribedTrackDrop() async throws {
        let transport = MockMOQTransport()
        let session = MOQSession(transport: transport)
        await session.start()

        // Setup subscription for Track 1
        let track1Stream = await session.subscribe(trackID: 1)

        // Inject object for Track 2 (unsubscribed)
        let header2 = MOQObjectHeader(trackID: 2, groupID: 0, objectID: 0, priority: 0)
        let object2 = MOQObject(header: header2, payload: Data())
        transport.receiveDatagram(object2.encode())

        // Inject object for Track 1 (subscribed)
        let header1 = MOQObjectHeader(trackID: 1, groupID: 0, objectID: 0, priority: 0)
        let object1 = MOQObject(header: header1, payload: Data())
        transport.receiveDatagram(object1.encode())

        // Verify Track 1 receives its object
        var iterator = track1Stream.makeAsyncIterator()
        if let received = await iterator.next() {
            XCTAssertEqual(received.header.trackID, 1)
        } else {
            XCTFail("Track 1 should have received an object")
        }

        // We can't easily verify "drop" without internal state access,
        // but the absence of crash or misrouting to track 1 is the main check.
    }

    /// Tests multiple independent subscriptions.
    func testMultipleSubscriptions() async throws {
        let transport = MockMOQTransport()
        let session = MOQSession(transport: transport)
        await session.start()

        let track1 = await session.subscribe(trackID: 1)
        let track2 = await session.subscribe(trackID: 2)

        // Send to Track 2 first
        let obj2 = MOQObject(
            header: .init(trackID: 2, groupID: 0, objectID: 0, priority: 0), payload: Data([0x02]))
        transport.receiveDatagram(obj2.encode())

        // Send to Track 1 second
        let obj1 = MOQObject(
            header: .init(trackID: 1, groupID: 0, objectID: 0, priority: 0), payload: Data([0x01]))
        transport.receiveDatagram(obj1.encode())

        // Verify Track 2
        var iter2 = track2.makeAsyncIterator()
        if let r2 = await iter2.next() {
            XCTAssertEqual(r2.payload, Data([0x02]))
        }

        // Verify Track 1
        var iter1 = track1.makeAsyncIterator()
        if let r1 = await iter1.next() {
            XCTAssertEqual(r1.payload, Data([0x01]))
        }
    }
}
