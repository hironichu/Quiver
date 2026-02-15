import MOQCore
import MOQRelay
import QUICCore
import XCTest

final class MOQRelayTests: XCTestCase {

    /// Tests that the relay forwards objects from a publisher to a subscriber.
    func testRelayForwarding() async throws {
        let relay = MOQRelay()

        // Setup Publisher
        let pubTransport = MockMOQTransport()
        let pubSession = MOQSession(transport: pubTransport)
        await pubSession.start()
        await relay.addPublisher(pubSession)

        // Setup Subscriber
        let subTransport = MockMOQTransport()
        let subSession = MOQSession(transport: subTransport)
        await subSession.start()
        await relay.addSubscriber(subSession)

        // Subscribe to Track 1
        await relay.subscribe(session: subSession, trackID: 1)

        // Publish object to Track 1
        let header = MOQObjectHeader(trackID: 1, groupID: 0, objectID: 0, priority: 0)
        let object = MOQObject(header: header, payload: Data([0xAA, 0xBB]))
        let encoded = object.encode()

        // Inject into Publisher's transport (simulating network receive)
        pubTransport.receiveDatagram(encoded)

        // Verify Subscriber received it
        // We need to wait a bit for the async tasks to propagate
        try await Task.sleep(for: .milliseconds(100))

        // Check subscriber transport sentDatagrams
        let sent = subTransport.sentDatagrams
        XCTAssertEqual(sent.count, 1)
        if let first = sent.first {
            let receivedObj = try MOQObject.decode(from: first.data)
            XCTAssertEqual(receivedObj.header.trackID, 1)
            XCTAssertEqual(receivedObj.payload, Data([0xAA, 0xBB]))
        }
    }

    /// Tests that the relay does not forward to unsubscribed sessions.
    func testRelayNoForwardingWithoutSubscription() async throws {
        let relay = MOQRelay()

        let pubTransport = MockMOQTransport()
        let pubSession = MOQSession(transport: pubTransport)
        await pubSession.start()
        await relay.addPublisher(pubSession)

        let subTransport = MockMOQTransport()
        let subSession = MOQSession(transport: subTransport)
        await subSession.start()
        await relay.addSubscriber(subSession)

        // NO subscription

        let header = MOQObjectHeader(trackID: 1, groupID: 0, objectID: 0, priority: 0)
        let object = MOQObject(header: header, payload: Data([0xFF]))
        pubTransport.receiveDatagram(object.encode())

        try await Task.sleep(for: .milliseconds(50))

        XCTAssertEqual(subTransport.sentDatagrams.count, 0)
    }
}
