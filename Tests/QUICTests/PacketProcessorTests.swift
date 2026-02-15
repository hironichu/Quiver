import Crypto
import Foundation
import Synchronization
import Testing

@testable import QUIC
@testable import QUICCore
@testable import QUICCrypto

@Suite("Packet Processor Tests")
struct PacketProcessorTests {

    @Test("PacketProcessor handles Key Update via Trial Decryption")
    func testKeyUpdateTrialDecryption() async throws {
        let client = PacketProcessor()
        let server = PacketProcessor()

        let clientSecret = SymmetricKey(size: .bits256)
        let serverSecret = SymmetricKey(size: .bits256)

        let keysInfo = KeysAvailableInfo(
            level: .application,
            clientSecret: clientSecret,
            serverSecret: serverSecret,
            cipherSuite: .aes128GcmSha256
        )

        // Install initial keys
        try client.installKeys(keysInfo, isClient: true)
        try server.installKeys(keysInfo, isClient: false)

        // Setup Packet Headers
        let dcid = ConnectionID.random(length: 8)!

        // 1. Server sends packet with Phase 0
        // We use client's DCID as destination
        let frame = Frame.ping

        // Server sends to Client
        // Note: Packet must be long enough for header protection sampling (at least 4 bytes + sample length)
        // For ChaCha20, sample is 16 bytes.
        // We add a PADDING frame to ensure sufficient length.
        let paddingFrame = Frame.padding(count: 20)

        let packet0 = try server.encryptShortHeaderPacket(
            frames: [frame, paddingFrame],
            header: ShortHeader(
                destinationConnectionID: dcid,
                packetNumber: 0,
                packetNumberLength: 2,
                spinBit: false,
                keyPhase: false  // Phase 0
            ),
            packetNumber: 0
        )

        // Client receives Phase 0
        client.setDCIDLength(8)
        let parsed0 = try client.decryptPacket(packet0)
        #expect(parsed0.frames.contains(Frame.ping))
        switch parsed0.header {
        case .short(let short):
            #expect(short.keyPhase == false)
            break
        default:
            break
        }

        // 2. Server initiates Key Update (Phase 0 -> 1)
        try server.initiateKeyUpdate()

        // Server sends packet with Phase 1
        let packet1 = try server.encryptShortHeaderPacket(
            frames: [frame, paddingFrame],
            header: ShortHeader(
                destinationConnectionID: dcid,
                packetNumber: 1,
                packetNumberLength: 2,
                spinBit: false,
                keyPhase: true  // Phase 1
            ),
            packetNumber: 1
        )

        // Client receives Phase 1 (should trial decrypt and succeed)
        let parsed1 = try client.decryptPacket(packet1)
        #expect(parsed1.frames.contains(Frame.ping))
        switch parsed1.header {
        case .short(let short):
            #expect(short.keyPhase == true)
            break
        default:
            break
        }

        // 3. Server sends another Phase 1 packet
        let packet2 = try server.encryptShortHeaderPacket(
            frames: [frame, paddingFrame],
            header: ShortHeader(
                destinationConnectionID: dcid,
                packetNumber: 2,
                packetNumberLength: 2,
                spinBit: false,
                keyPhase: true
            ),
            packetNumber: 2
        )

        let parsed2 = try client.decryptPacket(packet2)
        #expect(parsed2.frames.contains(Frame.ping))
        switch parsed1.header {
        case .short(let short):
            #expect(short.keyPhase == true)
            break
        default:
            break
        }
    }
}
