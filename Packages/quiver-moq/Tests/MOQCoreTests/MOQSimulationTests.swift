import Foundation
import Testing

@testable import MOQCore
@testable import QUICCore

@Suite("MOQ Simulation Tests")
struct MOQSimulationTests {
    @Test("Producer Flow: Track -> Session -> Transport")
    func testProducerFlow() async throws {
        // 1. Setup
        let transport = MockMOQTransport()
        let session = MOQSession(transport: transport)

        // 2. Create a track (Video, ID=1, Priority=10)
        let track = await session.createTrack(
            id: 1,
            alias: 1,
            priority: 10,
            defaultTTL: .milliseconds(100)
        )

        // 3. Push an object (Keyframe)
        let payload = Data([0xAA, 0xBB, 0xCC])
        try await track.push(payload, isKeyframe: true)

        // 4. Verify transport received the datagram
        let sent = transport.sentDatagrams
        #expect(sent.count == 1)

        guard let datagram = sent.first else { return }

        // 5. Verify Strategy
        // Should be combined(priority: 10, ttl: 100ms)
        if case .combined(let p, let ttl) = datagram.strategy {
            #expect(p == 10)
            #expect(ttl == .milliseconds(100))
        } else {
            #expect(Bool(false), "Expected combined strategy")
        }

        // 6. Verify Payload (Wire Format Check)
        // [Alias:1][Group:1][Obj:0][Pri:10][Status:0][Payload]
        // Varints: 1 -> 01, 1 -> 01, 0 -> 00
        let data = datagram.data
        #expect(data.count >= 6)  // At least headers + payload

        // Simple check for payload at the end
        #expect(data.suffix(3) == payload)
    }

    @Test("Track ID and Group logic")
    func testTrackGroupLogic() async throws {
        let transport = MockMOQTransport()
        let session = MOQSession(transport: transport)
        let track = await session.createTrack(id: 2, alias: 2, priority: 5)

        // Object 0 (Group 0)
        try await track.push(Data([0x01]), isKeyframe: true)

        // Object 1 (Group 0)
        try await track.push(Data([0x02]), isKeyframe: false)

        // Object 0 (Group 1) - Keyframe resets object ID
        try await track.push(Data([0x03]), isKeyframe: true)

        let sent = transport.sentDatagrams
        #expect(sent.count == 3)

        // Decode helper would be nice, but checking raw bytes for now
        // Inspecting properties indirectly through behavior
    }
}
