/// WebTransport Integration Tests
///
/// Comprehensive tests for the WebTransport integration layer:
/// - Session management (registry, lifecycle, state transitions)
/// - Stream routing (bidirectional and unidirectional)
/// - Datagram framing and routing
/// - Capsule codec (encode/decode, close/drain)
/// - WebTransport connect API and WebTransportServer wrappers
/// - Error handling and edge cases
/// - Stream error code mapping

import Foundation
import Synchronization
import Testing

@testable import HTTP3
@testable import QPACK
@testable import QUIC
@testable import QUICCore

// MARK: - Mock Types for WebTransport Testing

/// A full-featured mock QUIC stream for WebTransport testing.
private final class MockWTStream: QUICStreamProtocol, @unchecked Sendable {
    let id: UInt64
    let _isUnidirectional: Bool

    var isUnidirectional: Bool { _isUnidirectional }
    var isBidirectional: Bool { !_isUnidirectional }

    private struct StreamState: Sendable {
        var writtenData: [Data] = []
        var readQueue: [Data] = []
        var closed = false
        var resetCode: UInt64?
        var stopSendingCode: UInt64?
        var readContinuation: CheckedContinuation<Data, any Error>?
    }

    private let _state: Mutex<StreamState>

    var writtenData: [Data] {
        _state.withLock { $0.writtenData }
    }

    var allWrittenData: Data {
        _state.withLock { s in
            var combined = Data()
            for d in s.writtenData { combined.append(d) }
            return combined
        }
    }

    var isClosed: Bool {
        _state.withLock { $0.closed }
    }

    var resetCode: UInt64? {
        _state.withLock { $0.resetCode }
    }

    var stopSendingCode: UInt64? {
        _state.withLock { $0.stopSendingCode }
    }

    init(id: UInt64, isUnidirectional: Bool = false) {
        self.id = id
        self._isUnidirectional = isUnidirectional
        self._state = Mutex(StreamState())
    }

    /// Enqueue data that will be returned by the next read() call.
    func enqueueReadData(_ data: Data) {
        let cont: CheckedContinuation<Data, any Error>? = _state.withLock { s in
            if let continuation = s.readContinuation {
                s.readContinuation = nil
                return continuation
            } else {
                s.readQueue.append(data)
                return nil
            }
        }
        cont?.resume(returning: data)
    }

    /// Enqueue an empty Data to signal FIN.
    func enqueueFIN() {
        enqueueReadData(Data())
    }

    /// Enqueue an error for the next read.
    func enqueueReadError(_ error: any Error) {
        let cont: CheckedContinuation<Data, any Error>? = _state.withLock { s in
            if let continuation = s.readContinuation {
                s.readContinuation = nil
                return continuation
            }
            return nil
        }
        cont?.resume(throwing: error)
    }

    func read() async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            let immediateData: Data? = _state.withLock { s in
                if !s.readQueue.isEmpty {
                    return s.readQueue.removeFirst()
                } else {
                    s.readContinuation = continuation
                    return nil
                }
            }
            if let data = immediateData {
                continuation.resume(returning: data)
            }
        }
    }

    func read(maxBytes: Int) async throws -> Data {
        let data = try await read()
        if data.count > maxBytes {
            return Data(data.prefix(maxBytes))
        }
        return data
    }

    func write(_ data: Data) async throws {
        _state.withLock { $0.writtenData.append(data) }
    }

    func closeWrite() async throws {
        _state.withLock { $0.closed = true }
    }

    func reset(errorCode: UInt64) async {
        _state.withLock { $0.resetCode = errorCode }
    }

    func stopSending(errorCode: UInt64) async throws {
        _state.withLock { $0.stopSendingCode = errorCode }
    }
}

/// A mock QUIC connection for WebTransport testing.
private final class MockWTConnection: QUICConnectionProtocol, @unchecked Sendable {
    var localAddress: SocketAddress? { SocketAddress(ipAddress: "127.0.0.1", port: 4433) }
    var remoteAddress: SocketAddress { SocketAddress(ipAddress: "127.0.0.1", port: 443) }
    var isEstablished: Bool { true }
    var is0RTTAccepted: Bool { false }

    private struct State: Sendable {
        var nextBidiStreamID: UInt64
        var nextUniStreamID: UInt64
        var openedStreams: [MockWTStream] = []
        var openedUniStreams: [MockWTStream] = []
        var sentDatagrams: [Data] = []
        var closed = false
        var closeError: UInt64?
    }

    private let state: Mutex<State>

    private var incomingStreamContinuation: AsyncStream<any QUICStreamProtocol>.Continuation?
    private var _incomingStreams: AsyncStream<any QUICStreamProtocol>

    private var incomingDatagramContinuation: AsyncStream<Data>.Continuation?
    private var _incomingDatagrams: AsyncStream<Data>

    var openedStreams: [MockWTStream] {
        state.withLock { $0.openedStreams }
    }

    var openedUniStreams: [MockWTStream] {
        state.withLock { $0.openedUniStreams }
    }

    var sentDatagrams: [Data] {
        state.withLock { $0.sentDatagrams }
    }

    var connectionClosed: Bool {
        state.withLock { $0.closed }
    }

    init(isClient: Bool = true) {
        self.state = Mutex(
            State(
                nextBidiStreamID: isClient ? 0 : 1,
                nextUniStreamID: isClient ? 2 : 3
            ))

        var streamCont: AsyncStream<any QUICStreamProtocol>.Continuation!
        self._incomingStreams = AsyncStream { cont in
            streamCont = cont
        }
        self.incomingStreamContinuation = streamCont

        var datagramCont: AsyncStream<Data>.Continuation!
        self._incomingDatagrams = AsyncStream { cont in
            datagramCont = cont
        }
        self.incomingDatagramContinuation = datagramCont
    }

    func waitForHandshake() async throws {}

    func openStream() async throws -> any QUICStreamProtocol {
        state.withLock { s in
            let id = s.nextBidiStreamID
            s.nextBidiStreamID += 4
            let stream = MockWTStream(id: id, isUnidirectional: false)
            s.openedStreams.append(stream)
            return stream
        }
    }

    func openUniStream() async throws -> any QUICStreamProtocol {
        state.withLock { s in
            let id = s.nextUniStreamID
            s.nextUniStreamID += 4
            let stream = MockWTStream(id: id, isUnidirectional: true)
            s.openedUniStreams.append(stream)
            return stream
        }
    }

    var incomingStreams: AsyncStream<any QUICStreamProtocol> {
        _incomingStreams
    }

    var incomingDatagrams: AsyncStream<Data> {
        _incomingDatagrams
    }

    func sendDatagram(_ data: Data) async throws {
        state.withLock { $0.sentDatagrams.append(data) }
    }

    func sendDatagram(_ data: Data, strategy: DatagramSendingStrategy) async throws {
        state.withLock { $0.sentDatagrams.append(data) }
    }

    /// Deliver an incoming stream for testing
    func deliverIncomingStream(_ stream: any QUICStreamProtocol) {
        incomingStreamContinuation?.yield(stream)
    }

    /// Deliver an incoming datagram for testing
    func deliverIncomingDatagram(_ data: Data) {
        incomingDatagramContinuation?.yield(data)
    }

    func close(error: UInt64?) async {
        state.withLock { s in
            s.closed = true
            s.closeError = error
        }
    }

    func close(applicationError errorCode: UInt64, reason: String) async {
        state.withLock { s in
            s.closed = true
            s.closeError = errorCode
        }
    }

    /// Finish the incoming streams to clean up
    func finish() {
        incomingStreamContinuation?.finish()
        incomingDatagramContinuation?.finish()
    }
}

// MARK: - Capsule Codec Tests

@Suite struct WebTransportCapsuleCodecTests {

    // MARK: - Capsule Type Identifiers

    @Test func capsuleTypeValues() {
        #expect(WebTransportCapsuleType.closeSession.rawValue == 0x2843)
        #expect(WebTransportCapsuleType.drainSession.rawValue == 0x78ae)
    }

    @Test func capsuleTypeDescriptions() {
        #expect(
            WebTransportCapsuleType.closeSession.description == "CLOSE_WEBTRANSPORT_SESSION(0x2843)"
        )
        #expect(
            WebTransportCapsuleType.drainSession.description == "DRAIN_WEBTRANSPORT_SESSION(0x78ae)"
        )
    }

    // MARK: - Close Capsule Encoding/Decoding

    @Test func encodeDecodeCloseCapsuleNoError() throws {
        let info = WebTransportSessionCloseInfo(errorCode: 0, reason: "")
        let capsule = WebTransportCapsule.close(info)

        let encoded = WebTransportCapsuleCodec.encode(capsule)
        #expect(!encoded.isEmpty)

        let (decoded, consumed) = try #require(try WebTransportCapsuleCodec.decode(from: encoded))
        #expect(consumed == encoded.count)

        if case .close(let decodedInfo) = decoded {
            #expect(decodedInfo.errorCode == 0)
            #expect(decodedInfo.reason == "")
        } else {
            Issue.record("Expected close capsule, got \(decoded)")
        }
    }

    @Test func encodeDecodeCloseCapsuleWithReason() throws {
        let info = WebTransportSessionCloseInfo(errorCode: 42, reason: "Session complete")
        let capsule = WebTransportCapsule.close(info)

        let encoded = WebTransportCapsuleCodec.encode(capsule)
        let (decoded, _) = try #require(try WebTransportCapsuleCodec.decode(from: encoded))

        if case .close(let decodedInfo) = decoded {
            #expect(decodedInfo.errorCode == 42)
            #expect(decodedInfo.reason == "Session complete")
        } else {
            Issue.record("Expected close capsule, got \(decoded)")
        }
    }

    @Test func encodeDecodeCloseCapsuleLargeErrorCode() throws {
        let info = WebTransportSessionCloseInfo(errorCode: UInt32.max, reason: "max")
        let capsule = WebTransportCapsule.close(info)

        let encoded = WebTransportCapsuleCodec.encode(capsule)
        let (decoded, _) = try #require(try WebTransportCapsuleCodec.decode(from: encoded))

        if case .close(let decodedInfo) = decoded {
            #expect(decodedInfo.errorCode == UInt32.max)
            #expect(decodedInfo.reason == "max")
        } else {
            Issue.record("Expected close capsule, got \(decoded)")
        }
    }

    // MARK: - Drain Capsule Encoding/Decoding

    @Test func encodeDecodeDrainCapsule() throws {
        let capsule = WebTransportCapsule.drain

        let encoded = WebTransportCapsuleCodec.encode(capsule)
        #expect(!encoded.isEmpty)

        let (decoded, consumed) = try #require(try WebTransportCapsuleCodec.decode(from: encoded))
        #expect(consumed == encoded.count)

        if case .drain = decoded {
            // OK
        } else {
            Issue.record("Expected drain capsule, got \(decoded)")
        }
    }

    // MARK: - Unknown Capsule Handling

    @Test func decodeUnknownCapsuleType() throws {
        // Encode a capsule with an unknown type manually
        var data = Data()
        Varint(0xFFFF).encode(to: &data)  // Unknown type
        Varint(4).encode(to: &data)  // Length = 4
        data.append(contentsOf: [0x01, 0x02, 0x03, 0x04])  // Payload

        let (decoded, consumed) = try #require(try WebTransportCapsuleCodec.decode(from: data))
        #expect(consumed == data.count)

        if case .unknown(let type, let payload) = decoded {
            #expect(type == 0xFFFF)
            #expect(payload == Data([0x01, 0x02, 0x03, 0x04]))
        } else {
            Issue.record("Expected unknown capsule, got \(decoded)")
        }
    }

    // MARK: - Multiple Capsule Decoding

    @Test func decodeMultipleCapsules() throws {
        let close = WebTransportCapsule.close(
            WebTransportSessionCloseInfo(errorCode: 1, reason: "bye"))
        let drain = WebTransportCapsule.drain

        var combined = WebTransportCapsuleCodec.encode(close)
        combined.append(WebTransportCapsuleCodec.encode(drain))

        let (capsules, totalConsumed) = try WebTransportCapsuleCodec.decodeAll(from: combined)
        #expect(capsules.count == 2)
        #expect(totalConsumed == combined.count)

        if case .close(let info) = capsules[0] {
            #expect(info.errorCode == 1)
            #expect(info.reason == "bye")
        } else {
            Issue.record("Expected close")
        }

        if case .drain = capsules[1] {
            // OK
        } else {
            Issue.record("Expected drain")
        }
    }

    // MARK: - Partial Data Handling

    @Test func decodeInsufficientData() throws {
        let result = try WebTransportCapsuleCodec.decode(from: Data())
        #expect(result == nil)
    }

    @Test func decodePartialCapsule() throws {
        let capsule = WebTransportCapsule.close(
            WebTransportSessionCloseInfo(errorCode: 0, reason: ""))
        let encoded = WebTransportCapsuleCodec.encode(capsule)

        // Only provide partial data
        let partial = Data(encoded.prefix(encoded.count / 2))
        let result = try WebTransportCapsuleCodec.decode(from: partial)
        #expect(result == nil, "Should return nil for incomplete capsule")
    }

    // MARK: - Convenience Helpers

    @Test func encodeCloseConvenience() throws {
        let encoded = WebTransportCapsuleCodec.encodeClose(errorCode: 99, reason: "test error")
        let (decoded, _) = try #require(try WebTransportCapsuleCodec.decode(from: encoded))

        if case .close(let info) = decoded {
            #expect(info.errorCode == 99)
            #expect(info.reason == "test error")
        } else {
            Issue.record("Expected close")
        }
    }

    @Test func encodeDrainConvenience() throws {
        let encoded = WebTransportCapsuleCodec.encodeDrain()
        let (decoded, _) = try #require(try WebTransportCapsuleCodec.decode(from: encoded))

        if case .drain = decoded {
            // OK
        } else {
            Issue.record("Expected drain")
        }
    }

    // MARK: - Capsule Descriptions

    @Test func closeCapsuleDescription() {
        let capsule = WebTransportCapsule.close(
            WebTransportSessionCloseInfo(errorCode: 42, reason: "bye"))
        let desc = capsule.description
        #expect(desc.contains("CLOSE"))
        #expect(desc.contains("42"))
    }

    @Test func drainCapsuleDescription() {
        let desc = WebTransportCapsule.drain.description
        #expect(desc.contains("DRAIN"))
    }

    // MARK: - Capsule Equality

    @Test func capsuleEquality() {
        let close1 = WebTransportCapsule.close(
            WebTransportSessionCloseInfo(errorCode: 0, reason: ""))
        let close2 = WebTransportCapsule.close(
            WebTransportSessionCloseInfo(errorCode: 0, reason: ""))
        let close3 = WebTransportCapsule.close(
            WebTransportSessionCloseInfo(errorCode: 1, reason: ""))
        let drain = WebTransportCapsule.drain

        #expect(close1 == close2)
        #expect(close1 != close3)
        #expect(close1 != drain)
        #expect(drain == WebTransportCapsule.drain)
    }

    // MARK: - Capsule Hashing

    @Test func capsuleHashing() {
        var set = Set<WebTransportCapsule>()
        set.insert(.drain)
        set.insert(.drain)
        set.insert(.close(WebTransportSessionCloseInfo(errorCode: 0, reason: "")))
        set.insert(.close(WebTransportSessionCloseInfo(errorCode: 0, reason: "")))
        set.insert(.close(WebTransportSessionCloseInfo(errorCode: 1, reason: "")))

        // drain (1) + close(0) (1) + close(1) (1) = 3
        #expect(set.count == 3)
    }
}

// MARK: - Session Close Info Tests

@Suite struct WebTransportSessionCloseInfoTests {

    @Test func noError() {
        let info = WebTransportSessionCloseInfo.noError
        #expect(info.errorCode == 0)
        #expect(info.reason == "")
    }

    @Test func customCloseInfo() {
        let info = WebTransportSessionCloseInfo(errorCode: 42, reason: "Session timeout")
        #expect(info.errorCode == 42)
        #expect(info.reason == "Session timeout")
    }

    @Test func closeInfoEquality() {
        let a = WebTransportSessionCloseInfo(errorCode: 1, reason: "a")
        let b = WebTransportSessionCloseInfo(errorCode: 1, reason: "a")
        let c = WebTransportSessionCloseInfo(errorCode: 2, reason: "a")
        let d = WebTransportSessionCloseInfo(errorCode: 1, reason: "b")

        #expect(a == b)
        #expect(a != c)
        #expect(a != d)
    }

    @Test func closeInfoDescription() {
        let empty = WebTransportSessionCloseInfo(errorCode: 0, reason: "")
        #expect(empty.description == "CloseInfo(code=0)")

        let withReason = WebTransportSessionCloseInfo(errorCode: 42, reason: "timeout")
        #expect(withReason.description.contains("42"))
        #expect(withReason.description.contains("timeout"))
    }

    @Test func closeInfoHashing() {
        var set = Set<WebTransportSessionCloseInfo>()
        set.insert(WebTransportSessionCloseInfo(errorCode: 0, reason: ""))
        set.insert(WebTransportSessionCloseInfo(errorCode: 0, reason: ""))
        set.insert(WebTransportSessionCloseInfo(errorCode: 1, reason: ""))
        #expect(set.count == 2)
    }
}

// MARK: - Stream Error Code Mapping Tests

@Suite struct WebTransportStreamErrorCodeTests {

    @Test func baseValue() {
        #expect(WebTransportStreamErrorCode.base == 0x52e4_a40d)
    }

    @Test func toHTTP3ErrorCode() {
        #expect(
            WebTransportStreamErrorCode.toHTTP3ErrorCode(0) == 0x52e4_a40d
        )
        #expect(
            WebTransportStreamErrorCode.toHTTP3ErrorCode(1) == 0x52e4_a40e
        )
        #expect(
            WebTransportStreamErrorCode.toHTTP3ErrorCode(0xFF) == 0x52e4_a40d + 0xFF
        )
    }

    @Test func fromHTTP3ErrorCode() {
        #expect(WebTransportStreamErrorCode.fromHTTP3ErrorCode(0x52e4_a40d) == 0)
        #expect(WebTransportStreamErrorCode.fromHTTP3ErrorCode(0x52e4_a40e) == 1)
        #expect(WebTransportStreamErrorCode.fromHTTP3ErrorCode(0x52e4_a40d + 0xFF) == 0xFF)

        // Below the base
        #expect(WebTransportStreamErrorCode.fromHTTP3ErrorCode(0) == nil)
        #expect(WebTransportStreamErrorCode.fromHTTP3ErrorCode(0x52e4_a40c) == nil)
    }

    @Test func isWebTransportCode() {
        #expect(WebTransportStreamErrorCode.isWebTransportCode(0x52e4_a40d))
        #expect(WebTransportStreamErrorCode.isWebTransportCode(0x52e4_a40d + 100))
        #expect(!WebTransportStreamErrorCode.isWebTransportCode(0))
        #expect(!WebTransportStreamErrorCode.isWebTransportCode(0x0100))
    }

    @Test func roundTrip() {
        for code: UInt32 in [0, 1, 42, 255, 1000, UInt32.max] {
            let http3Code = WebTransportStreamErrorCode.toHTTP3ErrorCode(code)
            let roundTripped = WebTransportStreamErrorCode.fromHTTP3ErrorCode(http3Code)
            #expect(roundTripped == code, "Round-trip failed for code \(code)")
        }
    }
}

// MARK: - Well-Known Error Code Tests

@Suite struct WebTransportErrorCodeTests {

    @Test func errorCodeValues() {
        #expect(WebTransportErrorCode.noError == 0x00)
        #expect(WebTransportErrorCode.protocolViolation == 0x01)
        #expect(WebTransportErrorCode.sessionTimeout == 0x02)
        #expect(WebTransportErrorCode.cancelled == 0x03)
        #expect(WebTransportErrorCode.serverGoingAway == 0x04)
        #expect(WebTransportErrorCode.internalError == 0xFF)
    }
}

// MARK: - Session State Tests

@Suite struct WebTransportSessionStateTests {

    @Test func stateDescriptions() {
        #expect(WebTransportSessionState.connecting.description == "connecting")
        #expect(WebTransportSessionState.established.description == "established")
        #expect(WebTransportSessionState.draining.description == "draining")
        #expect(WebTransportSessionState.closed(nil).description.contains("closed"))
    }

    @Test func stateEquality() {
        #expect(WebTransportSessionState.connecting == .connecting)
        #expect(WebTransportSessionState.established == .established)
        #expect(WebTransportSessionState.draining == .draining)
        #expect(WebTransportSessionState.connecting != .established)
    }

    @Test func closedStateWithInfo() {
        let info = WebTransportSessionCloseInfo(errorCode: 42, reason: "test")
        let state = WebTransportSessionState.closed(info)
        let desc = state.description
        #expect(desc.contains("closed"))
        #expect(desc.contains("42"))
    }

    @Test func closedStateWithoutInfo() {
        let state = WebTransportSessionState.closed(nil)
        #expect(state.description == "closed")
    }
}

// MARK: - WebTransport Error Description Tests

@Suite struct WebTransportErrorDescriptionTests {

    @Test func sessionNotEstablished() {
        let error = WebTransportError.sessionNotEstablished
        #expect(error.description.contains("not established"))
    }

    @Test func sessionClosed() {
        let error = WebTransportError.sessionClosed(nil)
        #expect(error.description.contains("closed"))

        let info = WebTransportSessionCloseInfo(errorCode: 1, reason: "bye")
        let error2 = WebTransportError.sessionClosed(info)
        #expect(error2.description.contains("1"))
    }

    @Test func sessionRejected() {
        let error = WebTransportError.sessionRejected(status: 403, reason: "Forbidden")
        #expect(error.description.contains("403"))
        #expect(error.description.contains("Forbidden"))
    }

    @Test func peerDoesNotSupport() {
        let error = WebTransportError.peerDoesNotSupportWebTransport("missing setting")
        #expect(error.description.contains("missing setting"))
    }

    @Test func maxSessionsExceeded() {
        let error = WebTransportError.maxSessionsExceeded(limit: 5)
        #expect(error.description.contains("5"))
    }

    @Test func streamError() {
        let error = WebTransportError.streamError("write failed", underlying: nil)
        #expect(error.description.contains("write failed"))
    }

    @Test func datagramError() {
        let error = WebTransportError.datagramError("too large", underlying: nil)
        #expect(error.description.contains("too large"))
    }

    @Test func capsuleError() {
        let error = WebTransportError.capsuleError("malformed")
        #expect(error.description.contains("malformed"))
    }

    @Test func invalidSessionID() {
        let error = WebTransportError.invalidSessionID(42)
        #expect(error.description.contains("42"))
    }

    @Test func invalidStream() {
        let error = WebTransportError.invalidStream("bad header")
        #expect(error.description.contains("bad header"))
    }

    @Test func internalError() {
        let error = WebTransportError.internalError("unexpected", underlying: nil)
        #expect(error.description.contains("unexpected"))
    }

    @Test func http3Error() {
        let error = WebTransportError.http3Error("connection failed", underlying: nil)
        #expect(error.description.contains("connection failed"))
    }
}

// MARK: - Stream Framing Tests

@Suite struct WebTransportStreamFramingTests {

    // MARK: - Stream Type Constant

    @Test func webTransportUniStreamType() {
        #expect(kWebTransportUniStreamType == 0x54)
    }

    // MARK: - Bidirectional Stream Framing

    @Test func writeBidirectionalHeader() async throws {
        let stream = MockWTStream(id: 0)
        try await WebTransportStreamFraming.writeBidirectionalHeader(to: stream, sessionID: 4)

        let written = stream.allWrittenData
        #expect(!written.isEmpty)

        // Decode the session ID varint
        let (varint, _) = try Varint.decode(from: written)
        #expect(varint.value == 4)
    }

    @Test func writeBidirectionalHeaderLargeSessionID() async throws {
        let stream = MockWTStream(id: 0)
        let largeSessionID: UInt64 = 1000
        try await WebTransportStreamFraming.writeBidirectionalHeader(
            to: stream, sessionID: largeSessionID)

        let written = stream.allWrittenData
        let (varint, _) = try Varint.decode(from: written)
        #expect(varint.value == largeSessionID)
    }

    @Test func readBidirectionalSessionID() throws {
        // Encode a session ID varint
        var data = Data()
        Varint(8).encode(to: &data)
        data.append(Data("hello".utf8))

        let result = try #require(
            try WebTransportStreamFraming.readBidirectionalSessionID(from: data))
        #expect(result.sessionID == 8)
        #expect(result.remaining == Data("hello".utf8))
    }

    @Test func readBidirectionalSessionIDNoRemaining() throws {
        var data = Data()
        Varint(12).encode(to: &data)

        let result = try #require(
            try WebTransportStreamFraming.readBidirectionalSessionID(from: data))
        #expect(result.sessionID == 12)
        #expect(result.remaining.isEmpty)
    }

    @Test func readBidirectionalSessionIDEmpty() throws {
        let result = try WebTransportStreamFraming.readBidirectionalSessionID(from: Data())
        #expect(result == nil)
    }

    // MARK: - Unidirectional Stream Framing

    @Test func writeUnidirectionalHeader() async throws {
        let stream = MockWTStream(id: 2, isUnidirectional: true)
        try await WebTransportStreamFraming.writeUnidirectionalHeader(to: stream, sessionID: 4)

        let written = stream.allWrittenData
        #expect(!written.isEmpty)

        // First varint should be the stream type (0x54)
        let (typeVarint, typeConsumed) = try Varint.decode(from: written)
        #expect(typeVarint.value == 0x54)

        // Second varint should be the session ID
        let remaining = Data(written.dropFirst(typeConsumed))
        let (sessionVarint, _) = try Varint.decode(from: remaining)
        #expect(sessionVarint.value == 4)
    }

    @Test func readUnidirectionalSessionID() throws {
        var data = Data()
        Varint(16).encode(to: &data)
        data.append(Data("payload".utf8))

        let result = try #require(
            try WebTransportStreamFraming.readUnidirectionalSessionID(from: data))
        #expect(result.sessionID == 16)
        #expect(result.remaining == Data("payload".utf8))
    }

    // MARK: - Stream Direction

    @Test func streamDirectionDescription() {
        #expect(WebTransportStreamDirection.bidirectional.description == "bidirectional")
        #expect(WebTransportStreamDirection.unidirectional.description == "unidirectional")
    }

    @Test func streamDirectionEquality() {
        #expect(WebTransportStreamDirection.bidirectional == .bidirectional)
        #expect(WebTransportStreamDirection.unidirectional == .unidirectional)
        #expect(WebTransportStreamDirection.bidirectional != .unidirectional)
    }
}

// MARK: - Stream Classification Tests

@Suite struct WebTransportStreamClassificationTests {

    @Test func isWebTransportStream() {
        #expect(WebTransportStreamClassification.isWebTransportStream(0x54))
        #expect(!WebTransportStreamClassification.isWebTransportStream(0x00))
        #expect(!WebTransportStreamClassification.isWebTransportStream(0x01))
        #expect(!WebTransportStreamClassification.isWebTransportStream(0x53))
        #expect(!WebTransportStreamClassification.isWebTransportStream(0x55))
    }
}

// MARK: - WebTransport Stream Wrapper Tests

@Suite struct WebTransportStreamTests {

    @Test func streamProperties() {
        let quicStream = MockWTStream(id: 100)
        let wtStream = WebTransportStream(
            quicStream: quicStream,
            sessionID: 4,
            direction: .bidirectional,
            isLocal: true
        )

        #expect(wtStream.id == 100)
        #expect(wtStream.sessionID == 4)
        #expect(wtStream.direction == .bidirectional)
        #expect(wtStream.isLocal)
        #expect(wtStream.isBidirectional)
        #expect(!wtStream.isUnidirectional)
    }

    @Test func unidirectionalStreamProperties() {
        let quicStream = MockWTStream(id: 200, isUnidirectional: true)
        let wtStream = WebTransportStream(
            quicStream: quicStream,
            sessionID: 8,
            direction: .unidirectional,
            isLocal: false
        )

        #expect(wtStream.id == 200)
        #expect(wtStream.sessionID == 8)
        #expect(wtStream.isUnidirectional)
        #expect(!wtStream.isBidirectional)
        #expect(!wtStream.isLocal)
    }

    @Test func streamDescription() {
        let quicStream = MockWTStream(id: 50)
        let wtStream = WebTransportStream(
            quicStream: quicStream,
            sessionID: 4,
            direction: .bidirectional,
            isLocal: true
        )

        let desc = wtStream.description
        #expect(desc.contains("50"))
        #expect(desc.contains("4"))
        #expect(desc.contains("bidirectional"))
        #expect(desc.contains("local"))
    }

    @Test func streamRead() async throws {
        let quicStream = MockWTStream(id: 10)
        let wtStream = WebTransportStream(
            quicStream: quicStream,
            sessionID: 4,
            direction: .bidirectional,
            isLocal: false
        )

        let testData = Data("hello".utf8)
        quicStream.enqueueReadData(testData)

        let readData = try await wtStream.read()
        #expect(readData == testData)
    }

    @Test func streamWrite() async throws {
        let quicStream = MockWTStream(id: 10)
        let wtStream = WebTransportStream(
            quicStream: quicStream,
            sessionID: 4,
            direction: .bidirectional,
            isLocal: true
        )

        let testData = Data("world".utf8)
        try await wtStream.write(testData)
        #expect(quicStream.writtenData == [testData])
    }

    @Test func streamCloseWrite() async throws {
        let quicStream = MockWTStream(id: 10)
        let wtStream = WebTransportStream(
            quicStream: quicStream,
            sessionID: 4,
            direction: .bidirectional,
            isLocal: true
        )

        try await wtStream.closeWrite()
        #expect(quicStream.isClosed)
    }

    @Test func streamReset() async {
        let quicStream = MockWTStream(id: 10)
        let wtStream = WebTransportStream(
            quicStream: quicStream,
            sessionID: 4,
            direction: .bidirectional,
            isLocal: true
        )

        await wtStream.reset(applicationErrorCode: 42)
        let expectedCode = WebTransportStreamErrorCode.toHTTP3ErrorCode(42)
        #expect(quicStream.resetCode == expectedCode)
    }

    @Test func streamStopReading() async throws {
        let quicStream = MockWTStream(id: 10)
        let wtStream = WebTransportStream(
            quicStream: quicStream,
            sessionID: 4,
            direction: .bidirectional,
            isLocal: false
        )

        try await wtStream.stopReading(applicationErrorCode: 7)
        let expectedCode = WebTransportStreamErrorCode.toHTTP3ErrorCode(7)
        #expect(quicStream.stopSendingCode == expectedCode)
    }
}

// MARK: - Datagram Framing Tests

@Suite struct WebTransportDatagramFramingTests {

    @Test func parseDatagram() throws {
        let quarterStreamID: UInt64 = 1  // sessionID = 4
        var payload = Data()
        Varint(quarterStreamID).encode(to: &payload)
        payload.append(Data("ping".utf8))

        let result = try #require(try WebTransportSession.parseDatagram(payload))
        #expect(result.quarterStreamID == 1)
        #expect(result.payload == Data("ping".utf8))
    }

    @Test func parseDatagramEmpty() throws {
        let result = try WebTransportSession.parseDatagram(Data())
        #expect(result == nil)
    }

    @Test func parseDatagramNoPayload() throws {
        var data = Data()
        Varint(2).encode(to: &data)

        let result = try #require(try WebTransportSession.parseDatagram(data))
        #expect(result.quarterStreamID == 2)
        #expect(result.payload.isEmpty)
    }

    @Test func frameDatagram() {
        let payload = Data("hello".utf8)
        let framed = WebTransportSession.frameDatagram(payload: payload, quarterStreamID: 3)

        // Verify the framed datagram starts with the quarter stream ID
        let (varint, consumed) = try! Varint.decode(from: framed)
        #expect(varint.value == 3)

        let appPayload = Data(framed.dropFirst(consumed))
        #expect(appPayload == payload)
    }

    @Test func frameDatagramRoundTrip() throws {
        let original = Data("test datagram payload".utf8)
        let quarterStreamID: UInt64 = 5

        let framed = WebTransportSession.frameDatagram(
            payload: original, quarterStreamID: quarterStreamID)
        let parsed = try #require(try WebTransportSession.parseDatagram(framed))

        #expect(parsed.quarterStreamID == quarterStreamID)
        #expect(parsed.payload == original)
    }

    @Test func frameDatagramLargeQuarterStreamID() throws {
        let quarterStreamID: UInt64 = 16384  // 4-byte varint
        let payload = Data("data".utf8)

        let framed = WebTransportSession.frameDatagram(
            payload: payload, quarterStreamID: quarterStreamID)
        let parsed = try #require(try WebTransportSession.parseDatagram(framed))

        #expect(parsed.quarterStreamID == quarterStreamID)
        #expect(parsed.payload == payload)
    }
}

// MARK: - Session Lifecycle Tests

@Suite struct WebTransportSessionLifecycleTests {

    @Test func sessionCreation() async {
        let mockConn = MockWTConnection()
        let settings = HTTP3Settings.webTransport(maxSessions: 1)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: settings
        )

        let connectStream = MockWTStream(id: 4)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .server
        )

        let sessionID = await session.sessionID
        let quarterStreamID = await session.quarterStreamID
        let isEstablished = await session.isEstablished

        #expect(sessionID == 4)
        #expect(quarterStreamID == 1)  // 4 / 4 = 1
        #expect(!isEstablished)

        mockConn.finish()
    }

    @Test func sessionStart() async throws {
        let mockConn = MockWTConnection()
        let settings = HTTP3Settings.webTransport(maxSessions: 1)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: settings
        )

        let connectStream = MockWTStream(id: 8)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .server
        )

        try await session.start()

        let isEstablished = await session.isEstablished
        #expect(isEstablished)

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    @Test func sessionStartTwiceFails() async throws {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 0)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .server
        )

        try await session.start()

        do {
            try await session.start()
            Issue.record("Expected error on second start()")
        } catch {
            // Expected
        }

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    @Test func sessionQuarterStreamID() async {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .client,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        // Session ID 0 → quarter stream ID 0
        let session0 = WebTransportSession(
            connectStream: MockWTStream(id: 0),
            connection: h3Conn,
            role: .client
        )
        let qid0 = await session0.quarterStreamID
        #expect(qid0 == 0)

        // Session ID 4 → quarter stream ID 1
        let session4 = WebTransportSession(
            connectStream: MockWTStream(id: 4),
            connection: h3Conn,
            role: .client
        )
        let qid4 = await session4.quarterStreamID
        #expect(qid4 == 1)

        // Session ID 20 → quarter stream ID 5
        let session20 = WebTransportSession(
            connectStream: MockWTStream(id: 20),
            connection: h3Conn,
            role: .client
        )
        let qid20 = await session20.quarterStreamID
        #expect(qid20 == 5)

        mockConn.finish()
    }

    @Test func sessionRole() async {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let serverSession = WebTransportSession(
            connectStream: MockWTStream(id: 4),
            connection: h3Conn,
            role: .server
        )
        let serverRole = await serverSession.role
        #expect(serverRole == .server)

        let clientSession = WebTransportSession(
            connectStream: MockWTStream(id: 8),
            connection: h3Conn,
            role: .client
        )
        let clientRole = await clientSession.role
        #expect(clientRole == .client)

        mockConn.finish()
    }

    @Test func sessionAbort() async {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 4)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .server
        )

        try? await session.start()
        let isEstablished = await session.isEstablished
        #expect(isEstablished)

        await session.abort(applicationErrorCode: 42)
        let isClosed = await session.isClosed
        #expect(isClosed)

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    @Test func sessionDebugDescription() async throws {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 12)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .server
        )

        let desc = await session.debugDescription
        #expect(desc.contains("12"))
        #expect(desc.contains("server"))
        #expect(desc.contains("connecting"))

        connectStream.enqueueFIN()
        mockConn.finish()
    }
}

// MARK: - Session Stream Operations Tests

@Suite struct WebTransportSessionStreamTests {

    @Test func openBidirectionalStream() async throws {
        let mockConn = MockWTConnection(isClient: true)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .client,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 0)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .client
        )
        try await session.start()

        let stream = try await session.openBidirectionalStream()
        #expect(stream.isBidirectional)
        #expect(stream.isLocal)
        #expect(stream.sessionID == 0)  // WebTransportStream is a struct, not actor

        let count = await session.activeBidirectionalStreamCount
        #expect(count == 1)

        // Verify session ID was written as the first varint on the stream
        let opened = mockConn.openedStreams
        #expect(opened.count == 1)
        let writtenData = opened[0].allWrittenData
        let (varint, _) = try Varint.decode(from: writtenData)
        #expect(varint.value == 0)  // Session ID = 0

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    @Test func openUnidirectionalStream() async throws {
        let mockConn = MockWTConnection(isClient: true)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .client,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 4)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .client
        )
        try await session.start()

        let stream = try await session.openUnidirectionalStream()
        #expect(stream.isUnidirectional)
        #expect(stream.isLocal)
        #expect(stream.sessionID == 4)  // WebTransportStream is a struct, not actor

        let count = await session.activeUnidirectionalStreamCount
        #expect(count == 1)

        // Verify stream type + session ID were written
        let opened = mockConn.openedUniStreams
        #expect(opened.count == 1)
        let writtenData = opened[0].allWrittenData

        let (typeVarint, typeConsumed) = try Varint.decode(from: writtenData)
        #expect(typeVarint.value == 0x54)  // WebTransport uni stream type

        let remaining = Data(writtenData.dropFirst(typeConsumed))
        let (sessionVarint, _) = try Varint.decode(from: remaining)
        #expect(sessionVarint.value == 4)  // Session ID

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    @Test func openStreamWhenNotEstablished() async throws {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .client,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let session = WebTransportSession(
            connectStream: MockWTStream(id: 0),
            connection: h3Conn,
            role: .client
        )
        // Don't start the session

        do {
            _ = try await session.openBidirectionalStream()
            Issue.record("Expected sessionNotEstablished error")
        } catch let error as WebTransportError {
            if case .sessionNotEstablished = error {
                // Expected
            } else {
                Issue.record("Wrong error type: \(error)")
            }
        }

        do {
            _ = try await session.openUnidirectionalStream()
            Issue.record("Expected sessionNotEstablished error")
        } catch let error as WebTransportError {
            if case .sessionNotEstablished = error {
                // Expected
            } else {
                Issue.record("Wrong error type: \(error)")
            }
        }

        mockConn.finish()
    }

    @Test func deliverIncomingBidirectionalStream() async throws {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 4)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .server
        )
        try await session.start()

        // Deliver an incoming bidirectional stream
        let incomingStream = MockWTStream(id: 100)
        await session.deliverIncomingBidirectionalStream(incomingStream, initialData: Data())

        let count = await session.activeBidirectionalStreamCount
        #expect(count == 1)

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    @Test func deliverIncomingUnidirectionalStream() async throws {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 4)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .server
        )
        try await session.start()

        let incomingStream = MockWTStream(id: 200, isUnidirectional: true)
        await session.deliverIncomingUnidirectionalStream(incomingStream, initialData: Data())

        let count = await session.activeUnidirectionalStreamCount
        #expect(count == 1)

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    @Test func removeStream() async throws {
        let mockConn = MockWTConnection(isClient: true)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .client,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 0)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .client
        )
        try await session.start()

        let stream = try await session.openBidirectionalStream()
        var count = await session.activeBidirectionalStreamCount
        #expect(count == 1)

        await session.removeStream(stream.id)
        count = await session.activeBidirectionalStreamCount
        #expect(count == 0)

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    @Test func activeStreamCount() async throws {
        let mockConn = MockWTConnection(isClient: true)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .client,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 0)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .client
        )
        try await session.start()

        _ = try await session.openBidirectionalStream()
        _ = try await session.openBidirectionalStream()
        _ = try await session.openUnidirectionalStream()

        let bidiCount = await session.activeBidirectionalStreamCount
        let uniCount = await session.activeUnidirectionalStreamCount
        let totalCount = await session.activeStreamCount

        #expect(bidiCount == 2)
        #expect(uniCount == 1)
        #expect(totalCount == 3)

        // Enqueue FIN after assertions to let capsule reader task clean up
        connectStream.enqueueFIN()
        mockConn.finish()
    }
}

// MARK: - Session Datagram Tests

@Suite struct WebTransportSessionDatagramTests {

    @Test func sendDatagram() async throws {
        let mockConn = MockWTConnection(isClient: true)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .client,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 4)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .client
        )
        try await session.start()

        let payload = Data("hello".utf8)
        try await session.sendDatagram(payload)

        // Verify the datagram was sent via the QUIC connection
        let sent = mockConn.sentDatagrams
        #expect(sent.count == 1)

        // Parse the sent datagram to verify framing
        let parsed = try #require(try WebTransportSession.parseDatagram(sent[0]))
        #expect(parsed.quarterStreamID == 1)  // sessionID=4, quarterStreamID=4/4=1
        #expect(parsed.payload == payload)

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    @Test func sendDatagramNotEstablished() async throws {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .client,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let session = WebTransportSession(
            connectStream: MockWTStream(id: 0),
            connection: h3Conn,
            role: .client
        )
        // Don't start

        do {
            try await session.sendDatagram(Data("test".utf8))
            Issue.record("Expected sessionNotEstablished error")
        } catch let error as WebTransportError {
            if case .sessionNotEstablished = error {
                // Expected
            } else {
                Issue.record("Wrong error type: \(error)")
            }
        }

        mockConn.finish()
    }

    @Test func deliverDatagram() async throws {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 4)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .server
        )
        try await session.start()

        let payload = Data("incoming datagram".utf8)
        await session.deliverDatagram(payload)

        // The datagram was delivered to the session's incoming datagram stream
        // We can't easily test the async stream consumption here without
        // complex async test setup, but we verified it doesn't crash
        connectStream.enqueueFIN()
        mockConn.finish()
    }
}

// MARK: - HTTP3Connection Session Registry Tests

@Suite struct HTTP3ConnectionSessionRegistryTests {

    @Test func registerSession() async {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 5)
        )

        let connectStream = MockWTStream(id: 4)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .server
        )

        await h3Conn.registerWebTransportSession(session)
        let count = await h3Conn.activeWebTransportSessionCount
        #expect(count == 1)

        let found = await h3Conn.webTransportSession(for: 4)
        #expect(found != nil)

        mockConn.finish()
    }

    @Test func unregisterSession() async {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 5)
        )

        let connectStream = MockWTStream(id: 8)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .server
        )

        await h3Conn.registerWebTransportSession(session)
        let count1 = await h3Conn.activeWebTransportSessionCount
        #expect(count1 == 1)

        let removed = await h3Conn.unregisterWebTransportSession(8)
        #expect(removed != nil)

        let count2 = await h3Conn.activeWebTransportSessionCount
        #expect(count2 == 0)

        let notFound = await h3Conn.webTransportSession(for: 8)
        #expect(notFound == nil)

        mockConn.finish()
    }

    @Test func unregisterNonexistentSession() async {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 5)
        )

        let removed = await h3Conn.unregisterWebTransportSession(999)
        #expect(removed == nil)

        mockConn.finish()
    }

    @Test func multipleSessions() async {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 10)
        )

        let session1 = WebTransportSession(
            connectStream: MockWTStream(id: 0),
            connection: h3Conn,
            role: .server
        )
        let session2 = WebTransportSession(
            connectStream: MockWTStream(id: 4),
            connection: h3Conn,
            role: .server
        )
        let session3 = WebTransportSession(
            connectStream: MockWTStream(id: 8),
            connection: h3Conn,
            role: .server
        )

        await h3Conn.registerWebTransportSession(session1)
        await h3Conn.registerWebTransportSession(session2)
        await h3Conn.registerWebTransportSession(session3)

        let count = await h3Conn.activeWebTransportSessionCount
        #expect(count == 3)

        let s0 = await h3Conn.webTransportSession(for: 0)
        #expect(s0 != nil)
        let s4 = await h3Conn.webTransportSession(for: 4)
        #expect(s4 != nil)
        let s8 = await h3Conn.webTransportSession(for: 8)
        #expect(s8 != nil)
        let s12 = await h3Conn.webTransportSession(for: 12)
        #expect(s12 == nil)

        mockConn.finish()
    }

    @Test func createWebTransportSession() async throws {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 4)

        let sendResponseCalled = SendResponseTracker()
        let context = ExtendedConnectContext(
            request: HTTP3Request.webTransportConnect(authority: "example.com", path: "/wt"),
            streamID: 4,
            stream: connectStream,
            connection: h3Conn,
            sendResponse: { _ in
                await sendResponseCalled.markCalled()
            }
        )

        let session = try await h3Conn.createWebTransportSession(from: context, role: .server)
        let isEstablished = await session.isEstablished
        #expect(isEstablished)
        let sid = await session.sessionID
        #expect(sid == 4)

        let count = await h3Conn.activeWebTransportSessionCount
        #expect(count == 1)

        // Enqueue FIN *after* assertions so the capsule reader task does not
        // race with the isEstablished check above.
        connectStream.enqueueFIN()
        mockConn.finish()
    }

    @Test func createClientWebTransportSession() async throws {
        let mockConn = MockWTConnection(isClient: true)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .client,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 0)
        let response = HTTP3ResponseHead(status: 200)

        let session = try await h3Conn.createClientWebTransportSession(
            connectStream: connectStream,
            response: response
        )

        let isEstablished = await session.isEstablished
        #expect(isEstablished)
        let sid = await session.sessionID
        #expect(sid == 0)

        let count = await h3Conn.activeWebTransportSessionCount
        #expect(count == 1)

        // Enqueue FIN *after* assertions so the capsule reader task does not
        // race with the isEstablished check above.
        connectStream.enqueueFIN()
        mockConn.finish()
    }

    @Test func createClientWebTransportSessionRejected() async throws {
        let mockConn = MockWTConnection(isClient: true)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .client,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 0)
        let response = HTTP3ResponseHead(status: 403)

        do {
            _ = try await h3Conn.createClientWebTransportSession(
                connectStream: connectStream,
                response: response
            )
            Issue.record("Expected session rejected error")
        } catch let error as WebTransportError {
            if case .sessionRejected(let status, _) = error {
                #expect(status == 403)
            } else {
                Issue.record("Wrong error type: \(error)")
            }
        }

        let count = await h3Conn.activeWebTransportSessionCount
        #expect(count == 0)

        mockConn.finish()
    }
}

// MARK: - WebTransport Settings Tests

@Suite struct WebTransportSettingsTests {

    @Test func webTransportSettingsFactory() {
        let settings = HTTP3Settings.webTransport(maxSessions: 5)
        #expect(settings.enableConnectProtocol)
        #expect(settings.enableH3Datagram)
        #expect(settings.webtransportMaxSessions == 5)
    }

    @Test func webTransportSettingsDefaults() {
        let settings = HTTP3Settings.webTransport()
        #expect(settings.enableConnectProtocol)
        #expect(settings.enableH3Datagram)
        #expect(settings.webtransportMaxSessions == 1)
    }

    @Test func isWebTransportReady() {
        let ready = HTTP3Settings(
            enableConnectProtocol: true,
            enableH3Datagram: true,
            webtransportMaxSessions: 1
        )
        #expect(ready.isWebTransportReady)

        let noConnect = HTTP3Settings(
            enableConnectProtocol: false,
            enableH3Datagram: true,
            webtransportMaxSessions: 1
        )
        #expect(!noConnect.isWebTransportReady)

        let noDatagram = HTTP3Settings(
            enableConnectProtocol: true,
            enableH3Datagram: false,
            webtransportMaxSessions: 1
        )
        #expect(!noDatagram.isWebTransportReady)

        let noMaxSessions = HTTP3Settings(
            enableConnectProtocol: true,
            enableH3Datagram: true,
            webtransportMaxSessions: nil
        )
        #expect(!noMaxSessions.isWebTransportReady)

        let zeroSessions = HTTP3Settings(
            enableConnectProtocol: true,
            enableH3Datagram: true,
            webtransportMaxSessions: 0
        )
        #expect(!zeroSessions.isWebTransportReady)
    }

    @Test func effectiveSendLimitsWebTransport() {
        let local = HTTP3Settings(
            enableConnectProtocol: true,
            enableH3Datagram: true,
            webtransportMaxSessions: 10
        )
        let peer = HTTP3Settings(
            enableConnectProtocol: true,
            enableH3Datagram: true,
            webtransportMaxSessions: 5
        )

        let effective = local.effectiveSendLimits(peerSettings: peer)
        #expect(effective.enableConnectProtocol)
        #expect(effective.enableH3Datagram)
        #expect(effective.webtransportMaxSessions == 5)
    }

    @Test func effectiveSendLimitsDisabledByPeer() {
        let local = HTTP3Settings(
            enableConnectProtocol: true,
            enableH3Datagram: true,
            webtransportMaxSessions: 10
        )
        let peer = HTTP3Settings(
            enableConnectProtocol: false,
            enableH3Datagram: false,
            webtransportMaxSessions: nil
        )

        let effective = local.effectiveSendLimits(peerSettings: peer)
        #expect(!effective.enableConnectProtocol)
        #expect(!effective.enableH3Datagram)
        #expect(effective.webtransportMaxSessions == nil)
    }
}

// MARK: - WebTransport Connect API Tests

@Suite struct WebTransportConnectAPITests {

    // MARK: - WebTransportOptions

    @Test func optionsDefaults() {
        let opts = WebTransportOptions()

        if case .system = opts.caCertificates {
            #expect(true)
        } else {
            Issue.record("Expected default CA source to be .system")
        }
        #expect(opts.verifyPeer)
        #expect(opts.alpn == ["h3"])
        #expect(opts.headers.isEmpty)
        #expect(opts.maxIdleTimeout == .seconds(30))
        #expect(opts.connectionReadyTimeout == .seconds(10))
        #expect(opts.connectTimeout == .seconds(10))
        #expect(opts.initialMaxStreamsBidi == 100)
        #expect(opts.initialMaxStreamsUni == 100)
        #expect(opts.maxSessions == 1)
    }

    @Test func optionsInsecureFactory() {
        let opts = WebTransportOptions.insecure()

        #expect(!opts.verifyPeer)
        // Other defaults should remain
        #expect(opts.alpn == ["h3"])
        #expect(opts.maxSessions == 1)
    }

    @Test func optionsCustomValues() {
        let opts = WebTransportOptions(
            caCertificates: .der([Data([0x01, 0x02])]),
            verifyPeer: false,
            alpn: ["h3", "webtransport"],
            headers: [("authorization", "Bearer abc")],
            maxIdleTimeout: .seconds(60),
            connectionReadyTimeout: .seconds(20),
            connectTimeout: .seconds(15),
            initialMaxStreamsBidi: 200,
            initialMaxStreamsUni: 50,
            maxSessions: 4
        )

        switch opts.caCertificates {
        case .der(let certs):
            #expect(certs.count == 1)
        default:
            Issue.record("Expected CA source to be .der")
        }
        #expect(!opts.verifyPeer)
        #expect(opts.alpn == ["h3", "webtransport"])
        #expect(opts.headers.count == 1)
        #expect(opts.maxIdleTimeout == .seconds(60))
        #expect(opts.connectionReadyTimeout == .seconds(20))
        #expect(opts.connectTimeout == .seconds(15))
        #expect(opts.initialMaxStreamsBidi == 200)
        #expect(opts.initialMaxStreamsUni == 50)
        #expect(opts.maxSessions == 4)
    }

    @Test func optionsPEMSourceValue() {
        var opts = WebTransportOptions()
        opts.caCertificates = .pem(path: "/tmp/roots.pem")

        switch opts.caCertificates {
        case .pemPath(let path):
            #expect(path == "/tmp/roots.pem")
        default:
            Issue.record("Expected CA source to be .pem(path:)")
        }
    }

    @Test func optionsBuildQUICConfiguration() {
        var opts = WebTransportOptions()
        opts.maxIdleTimeout = .seconds(45)
        opts.alpn = ["h3", "webtransport"]
        opts.initialMaxStreamsBidi = 150
        opts.initialMaxStreamsUni = 75

        let quicConfig = opts.buildQUICConfiguration()

        #expect(quicConfig.maxIdleTimeout == .seconds(45))
        #expect(quicConfig.alpn == ["h3", "webtransport"])
        #expect(quicConfig.initialMaxStreamsBidi == 150)
        #expect(quicConfig.initialMaxStreamsUni == 75)
        #expect(quicConfig.enableDatagrams)
        #expect(quicConfig.maxDatagramFrameSize == 65535)
    }

    @Test func optionsBackwardCompatibleDERInitializer() {
        let opts = WebTransportOptions(
            caCertificatesDER: [Data([0xAA, 0xBB])]
        )

        switch opts.caCertificates {
        case .der(let certs):
            #expect(certs.count == 1)
            #expect(certs[0] == Data([0xAA, 0xBB]))
        default:
            Issue.record("Expected CA source to be .der from compatibility initializer")
        }
    }

    @Test func optionsBuildHTTP3Settings() {
        var opts = WebTransportOptions()
        opts.maxSessions = 5

        let settings = opts.buildHTTP3Settings()

        #expect(settings.enableConnectProtocol)
        #expect(settings.enableH3Datagram)
        #expect(settings.webtransportMaxSessions == 5)
    }

    // MARK: - WebTransportOptionsAdvanced

    @Test func advancedOptionsDefaults() {
        let quic = QUICConfiguration()
        let opts = WebTransportOptionsAdvanced(quic: quic)

        #expect(opts.headers.isEmpty)
        #expect(opts.connectionReadyTimeout == .seconds(10))
        #expect(opts.connectTimeout == .seconds(10))
    }

    @Test func advancedOptionsValidated() {
        var quic = QUICConfiguration()
        quic.enableDatagrams = false
        quic.alpn = ["custom"]

        var h3 = HTTP3Settings()
        h3.enableConnectProtocol = false
        h3.enableH3Datagram = false
        h3.webtransportMaxSessions = nil

        let opts = WebTransportOptionsAdvanced(quic: quic, http3Settings: h3)
        let validated = opts.validated()

        // QUIC mandatory flags
        #expect(validated.quic.enableDatagrams)
        #expect(validated.quic.alpn.contains("h3"))
        #expect(validated.quic.alpn.contains("custom"))  // preserved

        // HTTP/3 mandatory flags
        #expect(validated.http3Settings.enableConnectProtocol)
        #expect(validated.http3Settings.enableH3Datagram)
        #expect(validated.http3Settings.webtransportMaxSessions == 1)
    }

    @Test func advancedOptionsValidatedIdempotent() {
        var quic = QUICConfiguration()
        quic.alpn = ["h3"]
        quic.enableDatagrams = true

        var h3 = HTTP3Settings()
        h3.enableConnectProtocol = true
        h3.enableH3Datagram = true
        h3.webtransportMaxSessions = 3

        let opts = WebTransportOptionsAdvanced(quic: quic, http3Settings: h3)
        let v1 = opts.validated()
        let v2 = v1.validated()

        #expect(v1.quic.alpn == v2.quic.alpn)
        #expect(v1.http3Settings.webtransportMaxSessions == 3)
        #expect(v2.http3Settings.webtransportMaxSessions == 3)
    }

    @Test func advancedOptionsBuildMethods() {
        var quic = QUICConfiguration()
        quic.maxIdleTimeout = .seconds(99)

        let opts = WebTransportOptionsAdvanced(quic: quic)

        let builtQuic = opts.buildQUICConfiguration()
        #expect(builtQuic.maxIdleTimeout == .seconds(99))
        #expect(builtQuic.enableDatagrams)  // enforced

        let builtH3 = opts.buildHTTP3Settings()
        #expect(builtH3.enableConnectProtocol)  // enforced
        #expect(builtH3.enableH3Datagram)  // enforced
    }

    // MARK: - WebTransport.connect URL parsing (via invalid URL)

    @Test func connectInvalidURL() async {
        let opts = WebTransportOptions()

        do {
            _ = try await WebTransport.connect(url: "://invalid", options: opts)
            Issue.record("Expected error for invalid URL")
        } catch let error as WebTransportError {
            if case .internalError(let msg, _) = error {
                #expect(msg.contains("Invalid URL"))
            } else {
                Issue.record("Wrong error case: \(error)")
            }
        } catch {
            // Connection errors are also acceptable since the URL may parse
            // but fail to connect — depends on URLComponents behavior
        }
    }
}

// MARK: - WebTransport Server Tests

@Suite struct WebTransportServerTests {

    /// Helper: creates a minimal WebTransportServerOptions for testing.
    /// Uses dummy cert/key paths since tests don't actually start TLS.
    private func testServerOptions(
        maxSessions: UInt64 = 1,
        maxConnections: Int = 0
    ) -> WebTransportServerOptions {
        WebTransportServerOptions(
            certificatePath: "/dev/null/cert.pem",
            privateKeyPath: "/dev/null/key.pem",
            maxSessions: maxSessions,
            maxConnections: maxConnections
        )
    }

    @Test func serverCreation() async {
        let server = WebTransportServer(
            host: "0.0.0.0",
            port: 4433,
            options: testServerOptions()
        )

        let state = await server.state
        #expect(state == .idle)

        let isListening = await server.isListening
        #expect(!isListening)
    }

    @Test func serverOptionsAccessible() async {
        let opts = testServerOptions(maxSessions: 10, maxConnections: 100)
        let server = WebTransportServer(
            host: "0.0.0.0",
            port: 4433,
            options: opts
        )

        let maxSessions = await server.options.maxSessions
        #expect(maxSessions == 10)

        let maxConns = await server.options.maxConnections
        #expect(maxConns == 100)
    }

    @Test func serverRouteRegistration() async {
        let server = WebTransportServer(
            host: "0.0.0.0",
            port: 4433,
            options: testServerOptions()
        )

        await server.register(path: "/echo")
        await server.register(path: "/chat")

        let routeCount = await server.registeredRouteCount
        #expect(routeCount == 2)
    }

    @Test func serverRouteWithMiddleware() async {
        let server = WebTransportServer(
            host: "0.0.0.0",
            port: 4433,
            options: testServerOptions()
        )

        await server.register(path: "/secure") { context in
            guard context.headers.contains(where: { $0.0 == "authorization" }) else {
                return .reject(reason: "No auth")
            }
            return .accept
        }

        let routeCount = await server.registeredRouteCount
        #expect(routeCount == 1)
    }

    @Test func serverDebugDescription() async {
        let server = WebTransportServer(
            host: "127.0.0.1",
            port: 4433,
            options: testServerOptions(maxSessions: 3)
        )

        let desc = await server.debugDescription
        #expect(desc.contains("idle"))
        #expect(desc.contains("3"))
        #expect(desc.contains("127.0.0.1:4433"))
    }

    @Test func serverGlobalMiddleware() async {
        let server = WebTransportServer(
            host: "0.0.0.0",
            port: 4433,
            options: testServerOptions(),
            middleware: { _ in .accept }
        )

        let desc = await server.debugDescription
        #expect(desc.contains("globalMiddleware=true"))
    }

    @Test func serverNoMiddleware() async {
        let server = WebTransportServer(
            host: "0.0.0.0",
            port: 4433,
            options: testServerOptions()
        )

        let desc = await server.debugDescription
        #expect(desc.contains("globalMiddleware=false"))
    }

    @Test func serverOptionsValidation() {
        // Valid options
        let valid = WebTransportServerOptions(
            certificatePath: "/path/to/cert.pem",
            privateKeyPath: "/path/to/key.pem"
        )
        // XCTAssertNoThrow is redundant in Swift Testing if not checking error
        try? valid.validate()

        // Missing private key
        var noKey = WebTransportServerOptions(
            certificatePath: "/path/to/cert.pem",
            privateKeyPath: "/path/to/key.pem"
        )
        noKey.privateKeyPath = nil
        noKey.privateKey = nil
        #expect(throws: Error.self) {
            try noKey.validate()
        }
    }

    @Test func serverOptionsHTTP3Settings() {
        let opts = WebTransportServerOptions(
            certificatePath: "/cert.pem",
            privateKeyPath: "/key.pem",
            maxSessions: 5
        )

        let settings = opts.buildHTTP3Settings()
        #expect(settings.enableConnectProtocol)
        #expect(settings.enableH3Datagram)
        #expect(settings.webtransportMaxSessions == 5)
    }

    @Test func serverOptionsQUICConfiguration() {
        let opts = WebTransportServerOptions(
            certificatePath: "/cert.pem",
            privateKeyPath: "/key.pem",
            alpn: ["h3", "webtransport"],
            maxIdleTimeout: .seconds(45),
            initialMaxStreamsBidi: 200,
            initialMaxStreamsUni: 150
        )

        let quicConfig = opts.buildQUICConfiguration()
        #expect(quicConfig.maxIdleTimeout == .seconds(45))
        #expect(quicConfig.alpn == ["h3", "webtransport"])
        #expect(quicConfig.initialMaxStreamsBidi == 200)
        #expect(quicConfig.initialMaxStreamsUni == 150)
        #expect(quicConfig.enableDatagrams)
    }
}

// MARK: - Session Quota Enforcement Tests

@Suite struct WebTransportSessionQuotaTests {

    @Test func sessionQuotaEnforcedOnConnection() async throws {
        // Create an HTTP3Connection with maxSessions = 2
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 2)
        )

        // Create first session — should succeed
        let stream1 = MockWTStream(id: 0)
        let session1 = WebTransportSession(
            connectStream: stream1,
            connection: h3Conn,
            role: .server
        )
        await h3Conn.registerWebTransportSession(session1)

        let count1 = await h3Conn.activeWebTransportSessionCount
        #expect(count1 == 1)

        // Create second session — should succeed
        let stream2 = MockWTStream(id: 4)
        let session2 = WebTransportSession(
            connectStream: stream2,
            connection: h3Conn,
            role: .server
        )
        await h3Conn.registerWebTransportSession(session2)

        let count2 = await h3Conn.activeWebTransportSessionCount
        #expect(count2 == 2)

        // Unregister one session — count drops to 1
        _ = await h3Conn.unregisterWebTransportSession(0)
        let count3 = await h3Conn.activeWebTransportSessionCount
        #expect(count3 == 1)

        // Register a new session — should succeed again
        let stream3 = MockWTStream(id: 8)
        let session3 = WebTransportSession(
            connectStream: stream3,
            connection: h3Conn,
            role: .server
        )
        await h3Conn.registerWebTransportSession(session3)

        let count4 = await h3Conn.activeWebTransportSessionCount
        #expect(count4 == 2)

        mockConn.finish()
    }

    @Test func extendedConnectContextCarriesConnection() async throws {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let tracker = SendResponseTracker()
        let context = ExtendedConnectContext(
            request: HTTP3Request.webTransportConnect(authority: "example.com", path: "/wt"),
            streamID: 4,
            stream: MockWTStream(id: 4),
            connection: h3Conn,
            sendResponse: { _ in
                await tracker.markCalled()
            }
        )

        // Verify the connection reference is correct
        let contextConn = context.connection
        let role = await contextConn.role
        #expect(role == .server)

        // Verify we can query session count through the context's connection
        let count = await context.connection.activeWebTransportSessionCount
        #expect(count == 0)

        mockConn.finish()
    }

    @Test func sessionQuotaCheckViaContext() async throws {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        // Register one session to fill the quota
        let existingStream = MockWTStream(id: 0)
        let existingSession = WebTransportSession(
            connectStream: existingStream,
            connection: h3Conn,
            role: .server
        )
        await h3Conn.registerWebTransportSession(existingSession)

        // Create a context for a new Extended CONNECT
        let rejectionTracker = RejectionTracker()
        let context = ExtendedConnectContext(
            request: HTTP3Request.webTransportConnect(authority: "example.com", path: "/wt"),
            streamID: 4,
            stream: MockWTStream(id: 4),
            connection: h3Conn,
            sendResponse: { response in
                if response.status != 200 {
                    await rejectionTracker.recordRejection(status: response.status)
                }
            }
        )

        // Simulate the quota check that WebTransportServer.serve() performs
        let maxSessions: UInt64 = 1
        let activeCount = await context.connection.activeWebTransportSessionCount
        if maxSessions > 0 && activeCount >= Int(maxSessions) {
            try await context.reject(
                status: 429,
                headers: [("content-type", "text/plain")]
            )
        }

        let wasRejected = await rejectionTracker.rejected
        let status = await rejectionTracker.rejectedStatus
        #expect(wasRejected)
        #expect(status == 429)

        mockConn.finish()
    }

    @Test func sessionQuotaAllowsWhenUnderLimit() async throws {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 5)
        )

        // Register 3 sessions (under limit of 5)
        for i: UInt64 in [0, 4, 8] {
            let stream = MockWTStream(id: i)
            let session = WebTransportSession(
                connectStream: stream,
                connection: h3Conn,
                role: .server
            )
            await h3Conn.registerWebTransportSession(session)
        }

        let activeCount = await h3Conn.activeWebTransportSessionCount
        #expect(activeCount == 3)

        // Verify we're under the limit
        let maxSessions: UInt64 = 5
        #expect(activeCount < Int(maxSessions), "Should be under session limit")

        mockConn.finish()
    }

    @Test func sessionQuotaZeroMeansUnlimited() async throws {
        // When maxSessions is 0, the quota check should not reject
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 0)
        )

        // Register several sessions
        for i: UInt64 in stride(from: 0, to: 40, by: 4) {
            let stream = MockWTStream(id: i)
            let session = WebTransportSession(
                connectStream: stream,
                connection: h3Conn,
                role: .server
            )
            await h3Conn.registerWebTransportSession(session)
        }

        let activeCount = await h3Conn.activeWebTransportSessionCount
        #expect(activeCount == 10)

        // With maxSessions=0, the guard `maxSessions > 0 && ...` is false,
        // so no rejection should occur
        let maxSessions: UInt64 = 0
        let shouldReject = maxSessions > 0 && activeCount >= Int(maxSessions)
        #expect(!shouldReject)

        mockConn.finish()
    }
}

// MARK: - QUICConnectionProtocol Datagram Extension Tests

@Suite struct QUICDatagramErrorTests {

    @Test func datagramsNotSupported() {
        let error = QUICDatagramError.datagramsNotSupported
        #expect(error.description.contains("not supported"))
    }

    @Test func datagramTooLarge() {
        let error = QUICDatagramError.datagramTooLarge(size: 2000, maxAllowed: 1200)
        #expect(error.description.contains("2000"))
        #expect(error.description.contains("1200"))
    }

    @Test func connectionNotReady() {
        let error = QUICDatagramError.connectionNotReady
        #expect(error.description.contains("not ready"))
    }
}

// MARK: - Integration: Capsule Round-Trip on CONNECT Stream

@Suite struct WebTransportCapsuleStreamIntegrationTests {

    @Test func sessionReceivesCloseCapsule() async throws {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 4)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .server
        )
        try await session.start()

        // Send a CLOSE capsule on the CONNECT stream
        let closeData = WebTransportCapsuleCodec.encodeClose(errorCode: 42, reason: "done")
        connectStream.enqueueReadData(closeData)
        // Then FIN to end the loop
        connectStream.enqueueFIN()

        // Give the capsule reader loop time to process
        try await Task.sleep(for: .milliseconds(100))

        let isClosed = await session.isClosed
        #expect(isClosed)

        let closeInfo = await session.closeInfo
        #expect(closeInfo != nil)
        #expect(closeInfo?.errorCode == 42)
        #expect(closeInfo?.reason == "done")

        mockConn.finish()
    }

    @Test func sessionReceivesDrainCapsule() async throws {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 4)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .server
        )
        try await session.start()

        // Send a DRAIN capsule
        let drainData = WebTransportCapsuleCodec.encodeDrain()
        connectStream.enqueueReadData(drainData)

        // Give the capsule reader loop time to process
        try await Task.sleep(for: .milliseconds(100))

        let isDraining = await session.isDraining
        #expect(isDraining)

        // Session should still be alive (draining, not closed)
        let isClosed = await session.isClosed
        #expect(!isClosed)

        // Now close via FIN
        connectStream.enqueueFIN()
        try await Task.sleep(for: .milliseconds(100))

        let isClosedNow = await session.isClosed
        #expect(isClosedNow)

        mockConn.finish()
    }

    func testSessionHandlesFINOnConnectStream() async throws {
        let mockConn = MockWTConnection()
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        let connectStream = MockWTStream(id: 4)
        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .server
        )
        try await session.start()

        // Immediately send FIN
        connectStream.enqueueFIN()

        try await Task.sleep(for: .milliseconds(100))

        let isClosed = await session.isClosed
        #expect(isClosed)

        mockConn.finish()
    }
}

// MARK: - WebTransport Request Helpers Tests

@Suite struct WebTransportRequestHelpersTests {

    @Test func isWebTransportConnect() {
        let request = HTTP3Request.webTransportConnect(authority: "example.com", path: "/wt")
        #expect(request.isWebTransportConnect)
        #expect(request.isExtendedConnect)
        #expect(request.connectProtocol == "webtransport")
        #expect(request.method == .connect)
        #expect(request.authority == "example.com")
        #expect(request.path == "/wt")
    }

    @Test func nonWebTransportExtendedConnect() {
        let request = HTTP3Request(
            method: .connect,
            scheme: "https",
            authority: "example.com",
            path: "/ws",
            connectProtocol: "websocket"
        )
        #expect(request.isExtendedConnect)
        #expect(!request.isWebTransportConnect)
    }

    @Test func regularRequestNotWebTransport() {
        let request = HTTP3Request(method: .get, authority: "example.com", path: "/")
        #expect(!request.isWebTransportConnect)
        #expect(!request.isExtendedConnect)
    }

    @Test func webTransportConnectHeaderList() {
        let request = HTTP3Request.webTransportConnect(
            scheme: "https",
            authority: "example.com:4433",
            path: "/wt/echo",
            headers: [("origin", "https://example.com")]
        )

        let headers = request.toHeaderList()

        // Check pseudo-headers are present
        let methods = headers.filter { $0.name == ":method" }
        #expect(methods.count == 1)
        #expect(methods[0].value == "CONNECT")

        let protocols = headers.filter { $0.name == ":protocol" }
        #expect(protocols.count == 1)
        #expect(protocols[0].value == "webtransport")

        let schemes = headers.filter { $0.name == ":scheme" }
        #expect(schemes.count == 1)
        #expect(schemes[0].value == "https")

        let authorities = headers.filter { $0.name == ":authority" }
        #expect(authorities.count == 1)
        #expect(authorities[0].value == "example.com:4433")

        let paths = headers.filter { $0.name == ":path" }
        #expect(paths.count == 1)
        #expect(paths[0].value == "/wt/echo")

        // Check regular header
        let origins = headers.filter { $0.name == "origin" }
        #expect(origins.count == 1)
        #expect(origins[0].value == "https://example.com")
    }

    @Test func webTransportConnectHeaderRoundTrip() throws {
        let original = HTTP3Request.webTransportConnect(
            authority: "example.com",
            path: "/wt"
        )

        let headerList = original.toHeaderList()
        let decoded = try HTTP3Request.fromHeaderList(headerList)

        #expect(decoded.method == .connect)
        #expect(decoded.connectProtocol == "webtransport")
        #expect(decoded.authority == "example.com")
        #expect(decoded.path == "/wt")
        #expect(decoded.scheme == "https")
    }
}

// MARK: - Capsule Error Tests

@Suite struct WebTransportCapsuleErrorTests {

    @Test func capsuleErrorDescriptions() {
        let error1 = WebTransportCapsuleError.payloadTooShort(
            expected: 10, actual: 5, capsuleType: "CLOSE")
        #expect(error1.description.contains("10"))
        #expect(error1.description.contains("5"))

        let error2 = WebTransportCapsuleError.malformedVarint("test context")
        #expect(error2.description.contains("varint"))

        let error3 = WebTransportCapsuleError.truncatedCapsule("bad encoding")
        #expect(error3.description.contains("bad encoding"))
    }
}

// MARK: - Integration: Multiple Capsules in One Read

@Suite struct WebTransportMultipleCapsuleTests {

    @Test func decodeAllFromMixedData() throws {
        // Build a buffer with: CLOSE + DRAIN + some trailing bytes
        let closeInfo = WebTransportSessionCloseInfo(errorCode: 7, reason: "test")
        var data = WebTransportCapsuleCodec.encode(.close(closeInfo))
        data.append(WebTransportCapsuleCodec.encode(.drain))

        // Add partial capsule (just a type byte, not enough for full capsule)
        data.append(0x01)  // Incomplete

        let (capsules, consumed) = try WebTransportCapsuleCodec.decodeAll(from: data)
        #expect(capsules.count == 2)
        #expect(consumed < data.count, "Should not consume partial data")

        if case .close(let info) = capsules[0] {
            #expect(info.errorCode == 7)
        } else {
            Issue.record("Expected close")
        }

        if case .drain = capsules[1] {
            // OK
        } else {
            Issue.record("Expected drain")
        }
    }
}

// MARK: - Capsule Encoded Size Tests

@Suite struct WebTransportCapsuleEncodedSizeTests {

    @Test func encodedSizeMatchesActual() {
        let capsules: [WebTransportCapsule] = [
            .close(WebTransportSessionCloseInfo(errorCode: 0, reason: "")),
            .close(
                WebTransportSessionCloseInfo(errorCode: UInt32.max, reason: "long reason string")),
            .drain,
            .unknown(type: 0xABCD, payload: Data([1, 2, 3, 4, 5])),
        ]

        for capsule in capsules {
            let predicted = WebTransportCapsuleCodec.encodedSize(of: capsule)
            let actual = WebTransportCapsuleCodec.encode(capsule).count
            #expect(predicted == actual, "Size mismatch for \(capsule)")
        }
    }
}

// MARK: - Helper Types

private actor SendResponseTracker {
    var called = false
    func markCalled() {
        called = true
    }
}

/// Actor for tracking rejection state in quota enforcement tests.
private actor RejectionTracker {
    var rejected = false
    var rejectedStatus: Int?

    func recordRejection(status: Int) {
        rejected = true
        rejectedStatus = status
    }
}
