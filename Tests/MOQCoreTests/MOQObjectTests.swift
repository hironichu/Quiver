import Foundation
import Testing

@testable import MOQCore

@Suite("MOQ Object Tests")
struct MOQObjectTests {
    @Test("MOQObjectHeader Init")
    func testHeaderInit() {
        let header = MOQObjectHeader(
            trackID: 1,
            groupID: 2,
            objectID: 3,
            priority: 10,
            status: .normal
        )

        #expect(header.trackID == 1)
        #expect(header.groupID == 2)
        #expect(header.objectID == 3)
        #expect(header.priority == 10)
        #expect(header.status == .normal)
    }

    @Test("MOQObject Init")
    func testObjectInit() {
        let header = MOQObjectHeader(
            trackID: 1,
            groupID: 2,
            objectID: 3,
            priority: 10
        )
        let payload = Data([0x01, 0x02, 0x03])
        let object = MOQObject(header: header, payload: payload)

        #expect(object.header == header)
        #expect(object.payload == payload)
    }
}
