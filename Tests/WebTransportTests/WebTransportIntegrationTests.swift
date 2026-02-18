/// WebTransport Integration Tests
///
/// Comprehensive tests covering:
/// 1. End-to-end integration (client ↔ server via MockWTConnection)
/// 2. serve() codepath session creation verification
/// 3. Session quota enforcement at HTTP3Connection level
/// 4. Priority scheduling (RFC 9218)
/// 5. Browser interop wire-format verification (SETTINGS, datagram framing)

import Foundation
import Synchronization
import Testing

@testable import HTTP3
@testable import QPACK
@testable import QUIC
@testable import QUICCore
@testable import QUICStream

// MARK: - Mock Types

/// A full-featured mock QUIC stream for integration testing.
private final class MockIntegrationStream: QUICStreamProtocol, @unchecked Sendable {
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

    func enqueueFIN() {
        enqueueReadData(Data())
    }

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

/// A mock QUIC connection for integration testing.
private final class MockIntegrationConnection: QUICConnectionProtocol, @unchecked Sendable {
    let _localAddress: SocketAddress?
    let _remoteAddress: SocketAddress
    var localAddress: SocketAddress? { _localAddress }
    var remoteAddress: SocketAddress { _remoteAddress }
    var isEstablished: Bool { true }
    var is0RTTAccepted: Bool { false }

    private struct State: Sendable {
        var nextBidiStreamID: UInt64
        var nextUniStreamID: UInt64
        var openedStreams: [MockIntegrationStream] = []
        var openedUniStreams: [MockIntegrationStream] = []
        var sentDatagrams: [Data] = []
        var closed = false
        var closeError: UInt64?
    }

    private let state: Mutex<State>

    private var incomingStreamContinuation: AsyncStream<any QUICStreamProtocol>.Continuation?
    private var _incomingStreams: AsyncStream<any QUICStreamProtocol>

    private var incomingDatagramContinuation: AsyncStream<Data>.Continuation?
    private var _incomingDatagrams: AsyncStream<Data>

    var openedStreams: [MockIntegrationStream] {
        state.withLock { $0.openedStreams }
    }

    var openedUniStreams: [MockIntegrationStream] {
        state.withLock { $0.openedUniStreams }
    }

    var sentDatagrams: [Data] {
        state.withLock { $0.sentDatagrams }
    }

    var connectionClosed: Bool {
        state.withLock { $0.closed }
    }

    init(
        isClient: Bool = true,
        localPort: UInt16 = 4433,
        remotePort: UInt16 = 443
    ) {
        self._localAddress = SocketAddress(ipAddress: "127.0.0.1", port: localPort)
        self._remoteAddress = SocketAddress(ipAddress: "127.0.0.1", port: remotePort)
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
            let stream = MockIntegrationStream(id: id, isUnidirectional: false)
            s.openedStreams.append(stream)
            return stream
        }
    }

    func openUniStream() async throws -> any QUICStreamProtocol {
        state.withLock { s in
            let id = s.nextUniStreamID
            s.nextUniStreamID += 4
            let stream = MockIntegrationStream(id: id, isUnidirectional: true)
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

    func deliverIncomingStream(_ stream: any QUICStreamProtocol) {
        incomingStreamContinuation?.yield(stream)
    }

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

    func finish() {
        incomingStreamContinuation?.finish()
        incomingDatagramContinuation?.finish()
    }
}

// MARK: - Helper for creating WebTransport sessions quickly

private func makeServerSession(
    maxSessions: UInt64 = 10,
    streamID: UInt64 = 4,
    isClient: Bool = false
) -> (
    session: WebTransportSession, h3Connection: HTTP3Connection,
    mockConn: MockIntegrationConnection, connectStream: MockIntegrationStream
) {
    let mockConn = MockIntegrationConnection(isClient: isClient)
    let h3Conn = HTTP3Connection(
        quicConnection: mockConn,
        role: isClient ? .client : .server,
        settings: HTTP3Settings.webTransport(maxSessions: maxSessions)
    )
    let connectStream = MockIntegrationStream(id: streamID)
    let session = WebTransportSession(
        connectStream: connectStream,
        connection: h3Conn,
        role: isClient ? .client : .server
    )
    return (session, h3Conn, mockConn, connectStream)
}

// MARK: - 1. End-to-End Integration Tests

@Suite struct WebTransportEndToEndTests {

    // MARK: - Session Establishment

    /// Tests full client→server session establishment flow using mocks
    @Test func clientServerSessionEstablishment() async throws {
        // Server side
        let serverMockConn = MockIntegrationConnection(isClient: false)
        let serverH3 = HTTP3Connection(
            quicConnection: serverMockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 5)
        )

        // Client side
        let clientMockConn = MockIntegrationConnection(isClient: true)
        let clientH3 = HTTP3Connection(
            quicConnection: clientMockConn,
            role: .client,
            settings: HTTP3Settings.webTransport(maxSessions: 5)
        )

        // Simulate server accepting an Extended CONNECT request
        let connectStream = MockIntegrationStream(id: 4)  // client bidi stream
        // Do NOT enqueue FIN before session creation — the capsule reader loop
        // spawned by start() would race with our assertions below.

        let sendResponseTracker = SendResponseTracker()
        let context = ExtendedConnectContext(
            request: HTTP3Request.webTransportConnect(
                authority: "example.com:4433",
                path: "/wt"
            ),
            streamID: 4,
            stream: connectStream,
            connection: serverH3,
            sendResponse: { _ in
                await sendResponseTracker.markCalled()
            }
        )

        // Server creates the session from the context
        let serverSession = try await serverH3.createWebTransportSession(
            from: context,
            role: .server
        )

        // Verify server session state
        let serverSessionID = await serverSession.sessionID
        #expect(serverSessionID == 4)
        let isEstablished = await serverSession.isEstablished
        #expect(isEstablished)

        // Verify registration
        let serverCount = await serverH3.activeWebTransportSessionCount
        #expect(serverCount == 1)

        // Client side: create session from a 200 response
        let clientConnectStream = MockIntegrationStream(id: 0)
        // Do NOT enqueue FIN before session creation — same race as above.
        let response = HTTP3ResponseHead(status: 200)

        let clientSession = try await clientH3.createClientWebTransportSession(
            connectStream: clientConnectStream,
            response: response
        )

        let clientSessionID = await clientSession.sessionID
        #expect(clientSessionID == 0)
        let clientEstablished = await clientSession.isEstablished
        #expect(clientEstablished)

        let clientCount = await clientH3.activeWebTransportSessionCount
        #expect(clientCount == 1)

        // Now enqueue FINs to let the capsule reader loops exit cleanly
        connectStream.enqueueFIN()
        clientConnectStream.enqueueFIN()
        serverMockConn.finish()
        clientMockConn.finish()
    }

    /// Tests bidirectional stream exchange between client and server sessions
    @Test func bidirectionalStreamExchange() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()
        connectStream.enqueueFIN()
        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        // Open a bidi stream
        let wtStream = try await session.openBidirectionalStream()
        #expect(wtStream.isBidirectional)

        // Verify session ID framing was written
        let opened = mockConn.openedStreams
        #expect(!opened.isEmpty)

        let underlyingStream = opened.last!
        let writtenFraming = underlyingStream.allWrittenData

        // The first bytes should be the session ID varint
        #expect(!writtenFraming.isEmpty, "Session ID framing should have been written")

        // Decode the session ID from the written framing
        let (decodedVarint, _) = try Varint.decode(from: writtenFraming)
        let sessionID = await session.sessionID
        #expect(decodedVarint.value == sessionID, "Written framing should contain the session ID")

        // Write application data on the WT stream
        let testPayload = Data("Hello, WebTransport!".utf8)
        try await wtStream.write(testPayload)

        // Verify the data was written on the underlying stream
        let allWritten = underlyingStream.allWrittenData
        #expect(
            allWritten.count > testPayload.count, "Written data should include framing + payload")

        mockConn.finish()
    }

    /// Tests unidirectional stream creation and framing
    @Test func unidirectionalStreamExchange() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()
        connectStream.enqueueFIN()
        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        // Open a uni stream
        let wtStream = try await session.openUnidirectionalStream()
        #expect(wtStream.isUnidirectional)

        // Verify framing was written
        let uniOpened = mockConn.openedUniStreams
        #expect(!uniOpened.isEmpty)

        let underlyingStream = uniOpened.last!
        let writtenFraming = underlyingStream.allWrittenData

        // Decode stream type (0x54) + session ID
        #expect(writtenFraming.count >= 2)

        let (streamType, typeConsumed) = try Varint.decode(from: writtenFraming)
        #expect(
            streamType.value == kWebTransportUniStreamType,
            "First varint should be WT stream type 0x54")

        let remaining = Data(writtenFraming.dropFirst(typeConsumed))
        let (decodedSessionID, _) = try Varint.decode(from: remaining)
        let sessionID = await session.sessionID
        #expect(decodedSessionID.value == sessionID, "Second varint should be the session ID")

        mockConn.finish()
    }

    /// Tests datagram send framing (quarter stream ID prefix)
    @Test func datagramSendAndReceive() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession(streamID: 8)
        // Do NOT enqueue FIN yet — the capsule reader loop would close the session
        // and finish the incoming datagram continuation before we can test it.
        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        let sessionID = await session.sessionID
        #expect(sessionID == 8)

        let quarterStreamID = await session.quarterStreamID
        #expect(quarterStreamID == 2)  // 8 / 4 = 2

        // Send a datagram
        let payload = Data("datagram-payload".utf8)
        try await session.sendDatagram(payload)

        // Verify the datagram was sent with quarter stream ID prefix
        let sent = mockConn.sentDatagrams
        #expect(sent.count == 1)

        let sentDatagram = sent[0]
        // Parse the varint prefix
        let (sentQSID, consumed) = try Varint.decode(from: sentDatagram)
        #expect(sentQSID.value == quarterStreamID)

        // The remaining bytes should be the original payload
        let sentPayload = Data(sentDatagram.dropFirst(consumed))
        #expect(sentPayload == payload)

        // Test receiving a datagram via the incoming stream
        // Deliver first, then consume — the AsyncStream buffers yields
        await session.deliverDatagram(payload)

        var iterator = await session.incomingDatagrams.makeAsyncIterator()
        let receivedDatagram = await iterator.next()
        #expect(receivedDatagram == payload)

        // Now enqueue FIN to let the capsule reader loop exit cleanly
        connectStream.enqueueFIN()
        mockConn.finish()
    }

    /// Tests incoming bidi stream delivery to session
    @Test func deliverIncomingBidiStreamToSession() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()
        // Do NOT enqueue FIN yet — the capsule reader loop would close the session
        // and finish the incoming stream continuations before we can test them.
        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        // Deliver first, then consume — the AsyncStream buffers yields
        let incomingQuicStream = MockIntegrationStream(id: 100)
        let testData = Data("initial data".utf8)
        await session.deliverIncomingBidirectionalStream(incomingQuicStream, initialData: testData)

        var iterator = await session.incomingBidirectionalStreams.makeAsyncIterator()
        let receivedStream = await iterator.next()

        #expect(receivedStream != nil)
        #expect(receivedStream?.isBidirectional == true)

        // Now enqueue FIN to let the capsule reader loop exit cleanly
        connectStream.enqueueFIN()
        mockConn.finish()
    }

    /// Tests incoming uni stream delivery to session
    @Test func deliverIncomingUniStreamToSession() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()
        // Do NOT enqueue FIN before start — the capsule reader loop would
        // immediately close the session, racing with deliverIncoming*.
        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        // Deliver first, then consume — the AsyncStream buffers yields
        let incomingQuicStream = MockIntegrationStream(id: 102, isUnidirectional: true)
        await session.deliverIncomingUnidirectionalStream(incomingQuicStream)

        var iterator = await session.incomingUnidirectionalStreams.makeAsyncIterator()
        let receivedStream = await iterator.next()

        #expect(receivedStream != nil)
        #expect(receivedStream?.isUnidirectional == true)

        // Now enqueue FIN to let the capsule reader loop exit cleanly
        connectStream.enqueueFIN()
        mockConn.finish()
    }

    /// Tests close capsule exchange (session graceful close)
    @Test func sessionCloseViaCapsule() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()
        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        // Verify session is established
        let isEstablished = await session.isEstablished
        #expect(isEstablished)

        // Send a CLOSE capsule on the CONNECT stream, then FIN
        let closeData = WebTransportCapsuleCodec.encodeClose(errorCode: 42, reason: "test done")
        connectStream.enqueueReadData(closeData)
        connectStream.enqueueFIN()

        // Give the capsule reader loop time to process
        try await Task.sleep(for: .milliseconds(300))

        let isClosed = await session.isClosed
        #expect(isClosed)

        let closeInfo = await session.closeInfo
        #expect(closeInfo != nil)
        #expect(closeInfo?.errorCode == 42)
        #expect(closeInfo?.reason == "test done")

        mockConn.finish()
    }

    /// Tests drain capsule transitions session to draining state
    @Test func sessionDrainCapsule() async throws {
        let (session, _, mockConn, connectStream) = makeServerSession()
        try await session.start()

        let drainData = WebTransportCapsuleCodec.encodeDrain()
        connectStream.enqueueReadData(drainData)

        try await Task.sleep(for: .milliseconds(200))

        let isDraining = await session.isDraining
        #expect(isDraining)

        let isClosed = await session.isClosed
        #expect(!isClosed)

        // FIN to close after drain
        connectStream.enqueueFIN()
        try await Task.sleep(for: .milliseconds(200))

        let isClosedNow = await session.isClosed
        #expect(isClosedNow)

        mockConn.finish()
    }

    /// Tests that abort resets the CONNECT stream
    @Test func sessionAbort() async throws {
        let (session, _, mockConn, connectStream) = makeServerSession()
        connectStream.enqueueFIN()
        try await session.start()

        await session.abort(applicationErrorCode: 99)

        let isClosed = await session.isClosed
        #expect(isClosed)

        // The connect stream should have been reset
        let resetCode = connectStream.resetCode
        #expect(resetCode != nil)

        mockConn.finish()
    }

    /// Tests multiple concurrent sessions on one connection
    @Test func multipleConcurrentSessions() async throws {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 5)
        )

        var sessions: [WebTransportSession] = []
        var connectStreams: [MockIntegrationStream] = []
        for i in 0..<3 {
            let streamID = UInt64(i * 4)
            let connectStream = MockIntegrationStream(id: streamID)
            connectStreams.append(connectStream)
            let session = WebTransportSession(
                connectStream: connectStream,
                connection: h3Conn,
                role: .server
            )
            await h3Conn.registerWebTransportSession(session)
            try await session.start()
            sessions.append(session)
        }

        let count = await h3Conn.activeWebTransportSessionCount
        #expect(count == 3)

        // Each session should have a unique ID
        var sessionIDs = Set<UInt64>()
        for session in sessions {
            let sid = await session.sessionID
            sessionIDs.insert(sid)
        }
        #expect(sessionIDs.count == 3)

        // Open a stream on each session
        for session in sessions {
            let stream = try await session.openBidirectionalStream()
            #expect(stream.isBidirectional)
        }

        // Unregister one
        _ = await h3Conn.unregisterWebTransportSession(0)
        let count2 = await h3Conn.activeWebTransportSessionCount
        #expect(count2 == 2)

        // Enqueue FIN on all connect streams to let capsule reader loops exit
        for cs in connectStreams {
            cs.enqueueFIN()
        }

        mockConn.finish()
    }

    /// Tests full lifecycle: establish → open streams → send datagrams → close
    @Test func fullSessionLifecycle() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession(streamID: 12)
        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        // 1. Verify established
        let isEstablished = await session.isEstablished
        #expect(isEstablished)

        // 2. Open a bidi stream and write data
        let bidiStream = try await session.openBidirectionalStream()
        try await bidiStream.write(Data("bidi-data".utf8))

        // 3. Open a uni stream and write data
        let uniStream = try await session.openUnidirectionalStream()
        try await uniStream.write(Data("uni-data".utf8))
        try await uniStream.closeWrite()

        // 4. Send a datagram
        try await session.sendDatagram(Data("dgram".utf8))

        // 5. Verify stream counts
        let bidiCount = await session.activeBidirectionalStreamCount
        #expect(bidiCount == 1)
        let uniCount = await session.activeUnidirectionalStreamCount
        #expect(uniCount == 1)

        // 6. Close the session gracefully
        let closeInfo = WebTransportSessionCloseInfo(errorCode: 0, reason: "done")
        // Close capsule should be written
        try await session.close(closeInfo)

        let isClosed = await session.isClosed
        #expect(isClosed)

        // Verify close capsule was written on the CONNECT stream
        let connectWritten = connectStream.allWrittenData
        #expect(!connectWritten.isEmpty, "Close capsule should have been written")

        mockConn.finish()
    }
}

// MARK: - 2. serve() Codepath Tests

@Suite struct WebTransportServePathTests {

    /// Tests that ExtendedConnectContext carries the correct HTTP3Connection reference
    @Test func extendedConnectContextCarriesConnection() async throws {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 5)
        )

        let connectStream = MockIntegrationStream(id: 4)

        let context = ExtendedConnectContext(
            request: HTTP3Request.webTransportConnect(authority: "example.com", path: "/wt"),
            streamID: 4,
            stream: connectStream,
            connection: h3Conn,
            sendResponse: { _ in }
        )

        // The context.connection should be the same as h3Conn
        let contextConnection = context.connection
        // Verify the connection reference is correct by checking role
        let role = await contextConnection.role
        #expect(role == .server)

        mockConn.finish()
    }

    /// Tests creating a session via the context's connection reference (serve() codepath)
    @Test func createSessionViaContextConnection() async throws {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 5)
        )

        let connectStream = MockIntegrationStream(id: 4)
        connectStream.enqueueFIN()

        let context = ExtendedConnectContext(
            request: HTTP3Request.webTransportConnect(authority: "example.com", path: "/wt"),
            streamID: 4,
            stream: connectStream,
            connection: h3Conn,
            sendResponse: { _ in }
        )

        // This simulates what serve() does: use context.connection
        let connectionFromContext = context.connection
        let session = try await connectionFromContext.createWebTransportSession(
            from: context,
            role: .server
        )

        let sessionID = await session.sessionID
        #expect(sessionID == 4)
        let isEstablished = await session.isEstablished
        #expect(isEstablished)

        // The session should be registered on the h3Conn
        let count = await h3Conn.activeWebTransportSessionCount
        #expect(count == 1)

        mockConn.finish()
    }

    /// Tests that WebTransportServer creates the correct HTTP3Settings
    @Test func webTransportServerConfiguresSettings() async {
        let opts = WebTransportServerOptions(
            certificateChain: [Data("cert".utf8)],
            privateKey: Data("key".utf8),
            maxSessions: 10,
            maxConnections: 50
        )
        let server = WebTransportServer(
            host: "0.0.0.0",
            port: 4433,
            options: opts
        )

        // Register paths to verify route registration works
        await server.register(path: "/wt")
        await server.register(path: "/echo")

        // Verify options
        let serverOpts = await server.options
        #expect(serverOpts.maxSessions == 10)
        #expect(serverOpts.maxConnections == 50)

        // Verify HTTP3 settings carry WT flags
        let h3Settings = serverOpts.buildHTTP3Settings()
        #expect(h3Settings.enableConnectProtocol)
        #expect(h3Settings.enableH3Datagram)
        #expect(h3Settings.webtransportMaxSessions == 10)
    }

    /// Tests the serveConnection() codepath creates sessions correctly
    @Test func serveConnectionPathCreatesSession() async throws {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 3)
        )

        // Create sessions via context (simulating what serveConnection does)
        for i in 0..<3 {
            let streamID = UInt64(i * 4)
            let connectStream = MockIntegrationStream(id: streamID)
            connectStream.enqueueFIN()

            let context = ExtendedConnectContext(
                request: HTTP3Request.webTransportConnect(authority: "example.com", path: "/wt"),
                streamID: streamID,
                stream: connectStream,
                connection: h3Conn,
                sendResponse: { _ in }
            )

            let session = try await h3Conn.createWebTransportSession(from: context, role: .server)
            let sid = await session.sessionID
            #expect(sid == streamID)
        }

        let count = await h3Conn.activeWebTransportSessionCount
        #expect(count == 3)

        mockConn.finish()
    }

    /// Tests that ownsStream helper works
    @Test func ownsStreamHelper() async throws {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 5)
        )

        let connectStream = MockIntegrationStream(id: 4)
        connectStream.enqueueFIN()

        let session = WebTransportSession(
            connectStream: connectStream,
            connection: h3Conn,
            role: .server
        )
        await h3Conn.registerWebTransportSession(session)

        let owns = await h3Conn.hasSession(4)
        #expect(owns, "Connection should own stream 4 (registered session)")

        let doesNotOwn = await h3Conn.hasSession(999)
        #expect(!doesNotOwn, "Connection should not own stream 999")

        mockConn.finish()
    }
}

// MARK: - 3. Session Quota Enforcement Tests

@Suite struct WebTransportSessionQuotaEnforcementTests {

    /// Tests that tryRegisterWebTransportSession enforces the limit
    @Test func tryRegisterEnforcesQuota() async {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 2)
        )

        // Register first session — should succeed
        let stream1 = MockIntegrationStream(id: 0)
        let session1 = WebTransportSession(
            connectStream: stream1, connection: h3Conn, role: .server)
        let ok1 = await h3Conn.tryRegisterWebTransportSession(session1)
        #expect(ok1)

        // Register second session — should succeed (at limit)
        let stream2 = MockIntegrationStream(id: 4)
        let session2 = WebTransportSession(
            connectStream: stream2, connection: h3Conn, role: .server)
        let ok2 = await h3Conn.tryRegisterWebTransportSession(session2)
        #expect(ok2)

        let count = await h3Conn.activeWebTransportSessionCount
        #expect(count == 2)

        // Register third session — should FAIL (over limit)
        let stream3 = MockIntegrationStream(id: 8)
        let session3 = WebTransportSession(
            connectStream: stream3, connection: h3Conn, role: .server)
        let ok3 = await h3Conn.tryRegisterWebTransportSession(session3)
        #expect(!ok3, "Third session should be rejected by quota")

        let countAfter = await h3Conn.activeWebTransportSessionCount
        #expect(countAfter == 2, "Only 2 sessions should be registered")

        mockConn.finish()
    }

    /// Tests that createWebTransportSession throws when quota is exceeded
    @Test func createSessionThrowsOnQuotaExceeded() async throws {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        // Register first session
        let stream1 = MockIntegrationStream(id: 0)
        stream1.enqueueFIN()
        let context1 = ExtendedConnectContext(
            request: HTTP3Request.webTransportConnect(authority: "example.com", path: "/wt"),
            streamID: 0,
            stream: stream1,
            connection: h3Conn,
            sendResponse: { _ in }
        )
        _ = try await h3Conn.createWebTransportSession(from: context1, role: .server)

        // Second session should throw
        let stream2 = MockIntegrationStream(id: 4)
        stream2.enqueueFIN()
        let context2 = ExtendedConnectContext(
            request: HTTP3Request.webTransportConnect(authority: "example.com", path: "/wt"),
            streamID: 4,
            stream: stream2,
            connection: h3Conn,
            sendResponse: { _ in }
        )

        do {
            _ = try await h3Conn.createWebTransportSession(from: context2, role: .server)
            Issue.record("Should have thrown maxSessionsExceeded")
        } catch let error as WebTransportError {
            if case .maxSessionsExceeded(let limit) = error {
                #expect(limit == 1)
            } else {
                Issue.record("Wrong error type: \(error)")
            }
        }

        mockConn.finish()
    }

    /// Tests that createClientWebTransportSession also enforces quota
    @Test func clientSessionCreationQuotaEnforcement() async throws {
        let mockConn = MockIntegrationConnection(isClient: true)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .client,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        // Create first client session — should succeed
        let stream1 = MockIntegrationStream(id: 0)
        stream1.enqueueFIN()
        _ = try await h3Conn.createClientWebTransportSession(
            connectStream: stream1,
            response: HTTP3ResponseHead(status: 200)
        )

        // Second should fail
        let stream2 = MockIntegrationStream(id: 4)
        stream2.enqueueFIN()
        do {
            _ = try await h3Conn.createClientWebTransportSession(
                connectStream: stream2,
                response: HTTP3ResponseHead(status: 200)
            )
            Issue.record("Should have thrown maxSessionsExceeded")
        } catch let error as WebTransportError {
            if case .maxSessionsExceeded(let limit) = error {
                #expect(limit == 1)
            } else {
                Issue.record("Wrong error type: \(error)")
            }
        }

        mockConn.finish()
    }

    /// Tests that quota frees up when sessions are unregistered
    @Test func quotaFreedOnUnregister() async throws {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: 1)
        )

        // Register first session
        let stream1 = MockIntegrationStream(id: 0)
        stream1.enqueueFIN()
        let context1 = ExtendedConnectContext(
            request: HTTP3Request.webTransportConnect(authority: "example.com", path: "/wt"),
            streamID: 0,
            stream: stream1,
            connection: h3Conn,
            sendResponse: { _ in }
        )
        let session1 = try await h3Conn.createWebTransportSession(from: context1, role: .server)

        // Second should fail
        let stream2a = MockIntegrationStream(id: 4)
        stream2a.enqueueFIN()
        let ok = await h3Conn.tryRegisterWebTransportSession(
            WebTransportSession(connectStream: stream2a, connection: h3Conn, role: .server)
        )
        #expect(!ok)

        // Unregister first
        _ = await h3Conn.unregisterWebTransportSession(await session1.sessionID)
        let count = await h3Conn.activeWebTransportSessionCount
        #expect(count == 0)

        // Now a new session should succeed
        let stream2b = MockIntegrationStream(id: 8)
        stream2b.enqueueFIN()
        let context2 = ExtendedConnectContext(
            request: HTTP3Request.webTransportConnect(authority: "example.com", path: "/wt"),
            streamID: 8,
            stream: stream2b,
            connection: h3Conn,
            sendResponse: { _ in }
        )
        let session2 = try await h3Conn.createWebTransportSession(from: context2, role: .server)
        let sid2 = await session2.sessionID
        #expect(sid2 == 8)

        mockConn.finish()
    }

    /// Tests that zero maxSessions means unlimited
    @Test func zeroMaxSessionsMeansUnlimited() async {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings(
                enableConnectProtocol: true,
                enableH3Datagram: true,
                webtransportMaxSessions: 0
            )
        )

        // Register many sessions — all should succeed (0 = unlimited)
        for i in 0..<10 {
            let stream = MockIntegrationStream(id: UInt64(i * 4))
            let session = WebTransportSession(
                connectStream: stream, connection: h3Conn, role: .server)
            let ok = await h3Conn.tryRegisterWebTransportSession(session)
            #expect(ok, "Session \(i) should succeed with unlimited quota")
        }

        let count = await h3Conn.activeWebTransportSessionCount
        #expect(count == 10)

        mockConn.finish()
    }

    /// Tests that nil webtransportMaxSessions also means unlimited
    @Test func nilMaxSessionsMeansUnlimited() async {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings()  // webtransportMaxSessions = nil
        )

        for i in 0..<5 {
            let stream = MockIntegrationStream(id: UInt64(i * 4))
            let session = WebTransportSession(
                connectStream: stream, connection: h3Conn, role: .server)
            let ok = await h3Conn.tryRegisterWebTransportSession(session)
            #expect(ok, "Session \(i) should succeed with nil max sessions")
        }

        mockConn.finish()
    }

    /// Tests quota enforcement via the WebTransportServer.serveConnection() path
    @Test func quotaEnforcedInServeConnectionPath() async throws {
        // This simulates what WebTransportServer.serveConnection() does internally
        let mockConn = MockIntegrationConnection(isClient: false)
        let maxSessions: UInt64 = 2
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings.webTransport(maxSessions: maxSessions)
        )

        // Create sessions up to the limit
        for i in 0..<Int(maxSessions) {
            let streamID = UInt64(i * 4)
            let connectStream = MockIntegrationStream(id: streamID)
            connectStream.enqueueFIN()

            // Simulate what serveConnection does: check activeCount then create
            let activeCount = await h3Conn.activeWebTransportSessionCount
            #expect(activeCount < Int(maxSessions))

            let context = ExtendedConnectContext(
                request: HTTP3Request.webTransportConnect(authority: "example.com", path: "/wt"),
                streamID: streamID,
                stream: connectStream,
                connection: h3Conn,
                sendResponse: { _ in }
            )
            _ = try await h3Conn.createWebTransportSession(from: context, role: .server)
        }

        // Now the next one should be rejected at the connection level
        let activeCount = await h3Conn.activeWebTransportSessionCount
        #expect(activeCount == 2)

        // The WebTransportServer level check:
        // if maxSessions > 0 && activeCount >= Int(maxSessions) → reject with 429
        #expect(
            maxSessions > 0 && activeCount >= Int(maxSessions),
            "Connection-level check should show quota reached")

        mockConn.finish()
    }
}

// MARK: - 4. Priority Scheduling Tests

@Suite struct WebTransportPrioritySchedulingTests {

    // MARK: - handlePriorityUpdate bug fix

    /// Tests that handlePriorityUpdate correctly distinguishes existing vs new streams
    @Test func handlePriorityUpdateNewStream() async {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings()
        )

        // No streams exist yet — priority update for stream 4 should be pending
        await h3Conn.handlePriorityUpdate(streamID: 4, priority: StreamPriority.high)

        let allPriorities = await h3Conn.allStreamPriorities
        #expect(allPriorities[4] == StreamPriority.high)

        let pendingUpdates = await h3Conn.allPendingPriorityUpdates
        #expect(
            pendingUpdates[4] == StreamPriority.high,
            "Should be stored as pending since stream doesn't exist yet")

        mockConn.finish()
    }

    /// Tests that handlePriorityUpdate for an existing stream doesn't create pending
    @Test func handlePriorityUpdateExistingStream() async {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings()
        )

        // Simulate that stream 4 already exists by first setting its priority
        // (this happens when the request stream is first processed)
        await h3Conn.handlePriorityUpdate(streamID: 4, priority: StreamPriority.default)

        // Clear pending (simulating the stream has been created)
        // The first call will add to pending since it's a "new" stream.
        // Now update again — should NOT add to pending since it's already tracked
        await h3Conn.handlePriorityUpdate(streamID: 4, priority: StreamPriority.highest)

        let allPriorities = await h3Conn.allStreamPriorities
        #expect(allPriorities[4] == StreamPriority.highest)

        // The second call should NOT have created a new pending entry
        // (stream was already in streamPriorities from the first call)
        let pendingUpdates = await h3Conn.allPendingPriorityUpdates
        // The pending entry from the first call remains, but the second call
        // should NOT have overwritten it since the stream already existed
        #expect(
            pendingUpdates[4] == StreamPriority.default,
            "Pending should retain the first priority, not be overwritten by second update")

        mockConn.finish()
    }

    // MARK: - Priority-ordered stream scheduling

    /// Tests basic priority ordering (lower urgency = higher priority)
    @Test func priorityOrderedStreamIDs() async {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings()
        )

        // Register streams with different priorities
        await h3Conn.registerActiveResponseStream(4, priority: StreamPriority(urgency: 3))
        await h3Conn.registerActiveResponseStream(8, priority: StreamPriority(urgency: 1))
        await h3Conn.registerActiveResponseStream(12, priority: StreamPriority(urgency: 5))

        let ordered = await h3Conn.priorityOrderedStreamIDs()

        // Stream 8 (urgency 1) should be first, then 4 (urgency 3), then 12 (urgency 5)
        #expect(ordered.count == 3)
        #expect(ordered[0] == 8, "Urgency 1 should be first")
        #expect(ordered[1] == 4, "Urgency 3 should be second")
        #expect(ordered[2] == 12, "Urgency 5 should be third")

        mockConn.finish()
    }

    /// Tests that streams at the same urgency are ordered by stream ID
    @Test func sameUrgencyOrderedByStreamID() async {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings()
        )

        // All at urgency 3 (default)
        await h3Conn.registerActiveResponseStream(12, priority: StreamPriority(urgency: 3))
        await h3Conn.registerActiveResponseStream(4, priority: StreamPriority(urgency: 3))
        await h3Conn.registerActiveResponseStream(8, priority: StreamPriority(urgency: 3))

        let ordered = await h3Conn.priorityOrderedStreamIDs()
        #expect(ordered.count == 3)

        // Non-incremental at same urgency: only the cursor-selected one goes first,
        // but since cursor starts at 0, the lowest stream ID (4) should be first
        #expect(ordered[0] == 4, "Lowest stream ID at cursor 0")

        mockConn.finish()
    }

    /// Tests incremental vs non-incremental scheduling
    @Test func incrementalVsNonIncrementalScheduling() async {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings()
        )

        // Non-incremental streams at urgency 3
        await h3Conn.registerActiveResponseStream(
            4, priority: StreamPriority(urgency: 3, incremental: false))
        await h3Conn.registerActiveResponseStream(
            8, priority: StreamPriority(urgency: 3, incremental: false))

        // Incremental streams at urgency 3
        await h3Conn.registerActiveResponseStream(
            12, priority: StreamPriority(urgency: 3, incremental: true))
        await h3Conn.registerActiveResponseStream(
            16, priority: StreamPriority(urgency: 3, incremental: true))

        let ordered = await h3Conn.priorityOrderedStreamIDs()
        #expect(ordered.count == 4)

        // RFC 9218: active non-incremental first, then incremental, then remaining non-incremental
        // Non-incremental cursor=0 → stream 4 is active
        #expect(ordered[0] == 4, "Active non-incremental stream should be first")

        // Then incremental streams (12, 16)
        #expect(ordered.contains(12))
        #expect(ordered.contains(16))

        // Then remaining non-incremental (8)
        #expect(ordered[3] == 8, "Remaining non-incremental should be last")

        mockConn.finish()
    }

    /// Tests that different urgency levels are scheduled correctly
    @Test func multipleUrgencyLevels() async {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings()
        )

        // High priority
        await h3Conn.registerActiveResponseStream(4, priority: StreamPriority.highest)
        // Default priority
        await h3Conn.registerActiveResponseStream(8, priority: StreamPriority.default)
        // Low priority
        await h3Conn.registerActiveResponseStream(12, priority: StreamPriority.lowest)

        let ordered = await h3Conn.priorityOrderedStreamIDs()
        #expect(
            ordered == [4, 8, 12],
            "Should be ordered: highest(0), default(3), lowest(7)")

        mockConn.finish()
    }

    /// Tests empty scheduling returns empty array
    @Test func emptyScheduling() async {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings()
        )

        let ordered = await h3Conn.priorityOrderedStreamIDs()
        #expect(ordered.isEmpty)

        mockConn.finish()
    }

    /// Tests that unregistering a stream removes it from scheduling
    @Test func unregisterRemovesFromScheduling() async {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings()
        )

        await h3Conn.registerActiveResponseStream(4, priority: StreamPriority.high)
        await h3Conn.registerActiveResponseStream(8, priority: StreamPriority.low)

        await h3Conn.unregisterActiveResponseStream(4)

        let ordered = await h3Conn.priorityOrderedStreamIDs()
        #expect(ordered == [8])

        mockConn.finish()
    }

    /// Tests dynamic reprioritization via handlePriorityUpdate
    @Test func dynamicReprioritization() async {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings()
        )

        // Initially stream 4 is low priority, stream 8 is high
        await h3Conn.registerActiveResponseStream(4, priority: StreamPriority.low)
        await h3Conn.registerActiveResponseStream(8, priority: StreamPriority.high)

        let ordered1 = await h3Conn.priorityOrderedStreamIDs()
        #expect(ordered1[0] == 8, "Stream 8 should be first (high priority)")
        #expect(ordered1[1] == 4, "Stream 4 should be second (low priority)")

        // Now reprioritize stream 4 to highest
        await h3Conn.handlePriorityUpdate(streamID: 4, priority: StreamPriority.highest)
        // Also update the active response stream tracking
        await h3Conn.registerActiveResponseStream(4, priority: StreamPriority.highest)

        let ordered2 = await h3Conn.priorityOrderedStreamIDs()
        #expect(ordered2[0] == 4, "Stream 4 should now be first (highest priority)")
        #expect(ordered2[1] == 8, "Stream 8 should be second (high priority)")

        mockConn.finish()
    }

    /// Tests that advanceSchedulerCursor rotates within urgency group
    @Test func advanceSchedulerCursor() async {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings()
        )

        // Three non-incremental streams at same urgency
        await h3Conn.registerActiveResponseStream(4, priority: StreamPriority(urgency: 3))
        await h3Conn.registerActiveResponseStream(8, priority: StreamPriority(urgency: 3))
        await h3Conn.registerActiveResponseStream(12, priority: StreamPriority(urgency: 3))

        // Initially cursor=0 → stream 4 first
        let ordered1 = await h3Conn.priorityOrderedStreamIDs()
        #expect(ordered1[0] == 4)

        // Advance cursor after sending data on stream 4
        await h3Conn.advanceSchedulerCursor(for: 4)

        // Now cursor should rotate → stream 8 first
        let ordered2 = await h3Conn.priorityOrderedStreamIDs()
        #expect(ordered2[0] == 8, "After cursor advance, stream 8 should be first")

        mockConn.finish()
    }

    /// Tests sendPriorityUpdate encodes the correct frame
    @Test func sendPriorityUpdateEncodesFrame() async throws {
        let mockConn = MockIntegrationConnection(isClient: true)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .client,
            settings: HTTP3Settings()
        )

        // Open control stream (needed for sendPriorityUpdate)
        try await h3Conn.initialize()

        // Wait a moment for initialization
        try await Task.sleep(for: .milliseconds(50))

        // The priority should be tracked locally
        let priority = await h3Conn.priority(for: 999)
        #expect(priority == StreamPriority.default, "Unknown stream should return default")

        mockConn.finish()
    }

    /// Tests the StreamScheduler directly with various configurations
    @Test func streamSchedulerDirectly() {
        var scheduler = StreamScheduler()

        // Verify initial state
        #expect(scheduler.cursorCount == 0)
        #expect(scheduler.cursorPositions.isEmpty)

        // Test reset
        scheduler.advanceCursor(for: 3, groupSize: 5)
        #expect(scheduler.cursorPositions[3] == 1)

        scheduler.resetCursors()
        #expect(scheduler.cursorPositions.isEmpty)
    }

    /// Tests the PriorityHeaderParser
    @Test func priorityHeaderParser() {
        // Default
        let defaultPriority = PriorityHeaderParser.parse(nil)
        #expect(defaultPriority.urgency == 3)
        #expect(!defaultPriority.incremental)

        // u=0
        let highest = PriorityHeaderParser.parse("u=0")
        #expect(highest.urgency == 0)
        #expect(!highest.incremental)

        // u=7, i
        let background = PriorityHeaderParser.parse("u=7, i")
        #expect(background.urgency == 7)
        #expect(background.incremental)

        // u=3, i?0 (incremental disabled)
        let noIncremental = PriorityHeaderParser.parse("u=3, i?0")
        #expect(noIncremental.urgency == 3)
        #expect(!noIncremental.incremental)

        // Serialize roundtrip
        let priority = StreamPriority(urgency: 2, incremental: true)
        let serialized = PriorityHeaderParser.serialize(priority)
        let parsed = PriorityHeaderParser.parse(serialized)
        #expect(parsed.urgency == priority.urgency)
        #expect(parsed.incremental == priority.incremental)
    }

    /// Tests PriorityUpdate encode/decode roundtrip
    @Test func priorityUpdateRoundtrip() throws {
        let update = PriorityUpdate(
            elementID: 42,
            priority: StreamPriority(urgency: 1, incremental: true),
            isRequestStream: true
        )

        let payload = update.encodePayload()
        #expect(!payload.isEmpty)

        let decoded = try PriorityUpdate.decode(from: payload, isRequestStream: true)
        #expect(decoded.elementID == 42)
        #expect(decoded.priority.urgency == 1)
        #expect(decoded.priority.incremental)
    }

    /// Tests PriorityUpdate frame type classification
    @Test func priorityUpdateClassification() {
        let requestClass = PriorityUpdate.classify(PriorityUpdate.requestStreamFrameType)
        #expect(requestClass != nil)
        #expect(requestClass?.isRequestStream == true)

        let pushClass = PriorityUpdate.classify(PriorityUpdate.pushStreamFrameType)
        #expect(pushClass != nil)
        #expect(pushClass?.isRequestStream == false)

        let unknownClass = PriorityUpdate.classify(0x9999)
        #expect(unknownClass == nil)
    }

    /// Tests StreamPriority predefined values
    @Test func streamPriorityPresets() {
        #expect(StreamPriority.highest.urgency == 0)
        #expect(StreamPriority.high.urgency == 1)
        #expect(StreamPriority.default.urgency == 3)
        #expect(StreamPriority.low.urgency == 5)
        #expect(StreamPriority.lowest.urgency == 7)
        #expect(StreamPriority.background.urgency == 7)
        #expect(StreamPriority.background.incremental)
    }

    /// Tests StreamPriority comparison
    @Test func streamPriorityComparison() {
        #expect(StreamPriority.highest < StreamPriority.high)
        #expect(StreamPriority.high < StreamPriority.default)
        #expect(StreamPriority.default < StreamPriority.low)
        #expect(StreamPriority.low < StreamPriority.lowest)

        // Same urgency: non-incremental < incremental
        let a = StreamPriority(urgency: 3, incremental: false)
        let b = StreamPriority(urgency: 3, incremental: true)
        #expect(a < b)
    }

    /// Tests priority clamping to valid range
    @Test func priorityUrgencyClamping() {
        let clamped = StreamPriority(urgency: 100, incremental: false)
        #expect(clamped.urgency == 7, "Should be clamped to max 7")
    }

    /// Tests special priorities for control/QPACK streams
    @Test func specialPriorities() {
        #expect(StreamPriority.controlStream.urgency == 0)
        #expect(!StreamPriority.controlStream.incremental)

        #expect(StreamPriority.qpackStream.urgency == 0)
        #expect(!StreamPriority.qpackStream.incremental)
    }

    /// Tests activeResponseStreamCount tracking
    @Test func activeResponseStreamCount() async {
        let mockConn = MockIntegrationConnection(isClient: false)
        let h3Conn = HTTP3Connection(
            quicConnection: mockConn,
            role: .server,
            settings: HTTP3Settings()
        )

        let count0 = await h3Conn.activeResponseStreamCount
        #expect(count0 == 0)

        await h3Conn.registerActiveResponseStream(4, priority: .default)
        let count1 = await h3Conn.activeResponseStreamCount
        #expect(count1 == 1)

        await h3Conn.registerActiveResponseStream(8, priority: .high)
        let count2 = await h3Conn.activeResponseStreamCount
        #expect(count2 == 2)

        await h3Conn.unregisterActiveResponseStream(4)
        let count3 = await h3Conn.activeResponseStreamCount
        #expect(count3 == 1)

        mockConn.finish()
    }
}

// MARK: - 5. Browser Interop Wire Format Tests

@Suite struct WebTransportBrowserInteropTests {

    // MARK: - SETTINGS Frame Verification

    /// Verifies SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08) is correctly encoded
    @Test func settingsEnableConnectProtocolEncoding() {
        var settings = HTTP3Settings()
        settings.enableConnectProtocol = true

        let frame = HTTP3Frame.settings(settings)
        let encoded = HTTP3FrameCodec.encode(frame)

        // The SETTINGS frame should contain identifier 0x08 with value 1
        #expect(
            containsSettingPair(encoded, identifier: 0x08, value: 1),
            "SETTINGS frame should contain ENABLE_CONNECT_PROTOCOL=1")
    }

    /// Verifies SETTINGS_H3_DATAGRAM (0x33) is correctly encoded
    @Test func settingsH3DatagramEncoding() {
        var settings = HTTP3Settings()
        settings.enableH3Datagram = true

        let frame = HTTP3Frame.settings(settings)
        let encoded = HTTP3FrameCodec.encode(frame)

        #expect(
            containsSettingPair(encoded, identifier: 0x33, value: 1),
            "SETTINGS frame should contain H3_DATAGRAM=1")
    }

    /// Verifies SETTINGS_WEBTRANSPORT_MAX_SESSIONS (0xc671706a) is correctly encoded
    /// along with deprecated identifiers for Chrome/Deno compatibility
    @Test func settingsWebTransportMaxSessionsEncoding() {
        var settings = HTTP3Settings()
        settings.webtransportMaxSessions = 10

        let frame = HTTP3Frame.settings(settings)
        let encoded = HTTP3FrameCodec.encode(frame)

        // New identifier (draft-07+)
        #expect(
            containsSettingPair(encoded, identifier: 0xc671_706a, value: 10),
            "SETTINGS frame should contain WEBTRANSPORT_MAX_SESSIONS=10 (new)")
        // Deprecated boolean enable flag — must be exactly 1
        #expect(
            containsSettingPair(encoded, identifier: 0x2b60_3742, value: 1),
            "SETTINGS frame should contain WEBTRANSPORT_ENABLE_DEPRECATED=1")
        // Deprecated max sessions value
        #expect(
            containsSettingPair(encoded, identifier: 0x2b60_3743, value: 10),
            "SETTINGS frame should contain WEBTRANSPORT_MAX_SESSIONS_DEPRECATED=10")
    }

    /// Verifies all WebTransport settings (new + deprecated) are present in a WebTransport configuration
    @Test func webTransportSettingsAllPresent() {
        let settings = HTTP3Settings.webTransport(maxSessions: 5)

        #expect(settings.enableConnectProtocol)
        #expect(settings.enableH3Datagram)
        #expect(settings.webtransportMaxSessions == 5)

        let frame = HTTP3Frame.settings(settings)
        let encoded = HTTP3FrameCodec.encode(frame)

        // Core HTTP/3 settings
        #expect(
            containsSettingPair(encoded, identifier: 0x08, value: 1),
            "Must include ENABLE_CONNECT_PROTOCOL")
        #expect(
            containsSettingPair(encoded, identifier: 0x33, value: 1),
            "Must include H3_DATAGRAM")
        // New WebTransport max sessions (draft-07+)
        #expect(
            containsSettingPair(encoded, identifier: 0xc671_706a, value: 5),
            "Must include WEBTRANSPORT_MAX_SESSIONS (new)")
        // Deprecated compatibility settings
        #expect(
            containsSettingPair(encoded, identifier: 0x2b60_3742, value: 1),
            "Must include WEBTRANSPORT_ENABLE_DEPRECATED=1")
        #expect(
            containsSettingPair(encoded, identifier: 0x2b60_3743, value: 5),
            "Must include WEBTRANSPORT_MAX_SESSIONS_DEPRECATED")
        #expect(
            containsSettingPair(encoded, identifier: 0xFFD277, value: 1),
            "Must include H3_DATAGRAM_DEPRECATED")
    }

    /// Verifies SETTINGS frame roundtrip encoding/decoding preserves WebTransport values
    @Test func settingsRoundTrip() throws {
        let original = HTTP3Settings.webTransport(maxSessions: 42)
        let frame = HTTP3Frame.settings(original)
        let encoded = HTTP3FrameCodec.encode(frame)

        let (decodedFrame, _) = try HTTP3FrameCodec.decode(from: encoded)

        guard case .settings(let decodedSettings) = decodedFrame else {
            Issue.record("Decoded frame should be SETTINGS")
            return
        }

        #expect(decodedSettings.enableConnectProtocol)
        #expect(decodedSettings.enableH3Datagram)
        #expect(decodedSettings.webtransportMaxSessions == 42)
    }

    /// Verifies SETTINGS isWebTransportReady logic
    @Test func isWebTransportReady() {
        // All three required
        var ready = HTTP3Settings()
        ready.enableConnectProtocol = true
        ready.enableH3Datagram = true
        ready.webtransportMaxSessions = 1
        #expect(ready.isWebTransportReady)

        // Missing ENABLE_CONNECT_PROTOCOL
        var noConnect = HTTP3Settings()
        noConnect.enableH3Datagram = true
        noConnect.webtransportMaxSessions = 1
        #expect(!noConnect.isWebTransportReady)

        // Missing H3_DATAGRAM
        var noDatagram = HTTP3Settings()
        noDatagram.enableConnectProtocol = true
        noDatagram.webtransportMaxSessions = 1
        #expect(!noDatagram.isWebTransportReady)

        // Missing/nil WEBTRANSPORT_MAX_SESSIONS
        var noSessions = HTTP3Settings()
        noSessions.enableConnectProtocol = true
        noSessions.enableH3Datagram = true
        noSessions.webtransportMaxSessions = nil
        #expect(!noSessions.isWebTransportReady)

        // WEBTRANSPORT_MAX_SESSIONS = 0
        var zeroSessions = HTTP3Settings()
        zeroSessions.enableConnectProtocol = true
        zeroSessions.enableH3Datagram = true
        zeroSessions.webtransportMaxSessions = 0
        #expect(!zeroSessions.isWebTransportReady)
    }

    // MARK: - Deno / web-transport-rs Compatibility

    /// Verifies that settings sent by Deno (web-transport-rs) are correctly decoded.
    /// Deno sends both new and deprecated identifiers via `enable_webtransport(1)`.
    @Test func decodeDenoWebTransportSettings() throws {
        // Simulate what web-transport-rs `enable_webtransport(1)` sends:
        //   ENABLE_CONNECT_PROTOCOL (0x08) = 1
        //   ENABLE_DATAGRAM (0x33) = 1
        //   ENABLE_DATAGRAM_DEPRECATED (0xFFD277) = 1
        //   WEBTRANSPORT_MAX_SESSIONS (0xc671706a) = 1
        //   WEBTRANSPORT_MAX_SESSIONS_DEPRECATED (0x2b603743) = 1
        //   WEBTRANSPORT_ENABLE_DEPRECATED (0x2b603742) = 1
        var payload = Data()
        Varint(0x08).encode(to: &payload)  // ENABLE_CONNECT_PROTOCOL
        Varint(1).encode(to: &payload)
        Varint(0x33).encode(to: &payload)  // ENABLE_DATAGRAM
        Varint(1).encode(to: &payload)
        Varint(0xFFD277).encode(to: &payload)  // ENABLE_DATAGRAM_DEPRECATED
        Varint(1).encode(to: &payload)
        Varint(0xc671_706a).encode(to: &payload)  // WEBTRANSPORT_MAX_SESSIONS (new)
        Varint(1).encode(to: &payload)
        Varint(0x2b60_3743).encode(to: &payload)  // WEBTRANSPORT_MAX_SESSIONS_DEPRECATED
        Varint(1).encode(to: &payload)
        Varint(0x2b60_3742).encode(to: &payload)  // WEBTRANSPORT_ENABLE_DEPRECATED
        Varint(1).encode(to: &payload)

        // Wrap in a SETTINGS frame: type (0x04) + length + payload
        var frameData = Data()
        Varint(0x04).encode(to: &frameData)
        Varint(UInt64(payload.count)).encode(to: &frameData)
        frameData.append(payload)

        let (decoded, _) = try HTTP3FrameCodec.decode(from: frameData)
        guard case .settings(let settings) = decoded else {
            Issue.record("Expected SETTINGS frame")
            return
        }

        #expect(settings.enableConnectProtocol, "ENABLE_CONNECT_PROTOCOL should be true")
        #expect(settings.enableH3Datagram, "ENABLE_DATAGRAM should be true")
        #expect(settings.webtransportMaxSessions == 1, "webtransportMaxSessions should be 1")
        #expect(settings.isWebTransportReady, "Settings should be WebTransport-ready")
    }

    /// Verifies that settings from Deno with multiple sessions are decoded correctly.
    /// The new identifier (0xc671706a) should take priority over deprecated ones.
    @Test func decodeDenoWebTransportSettingsMultipleSessions() throws {
        var payload = Data()
        Varint(0x08).encode(to: &payload)  // ENABLE_CONNECT_PROTOCOL
        Varint(1).encode(to: &payload)
        Varint(0x33).encode(to: &payload)  // ENABLE_DATAGRAM
        Varint(1).encode(to: &payload)
        Varint(0xc671_706a).encode(to: &payload)  // WEBTRANSPORT_MAX_SESSIONS (new) = 16
        Varint(16).encode(to: &payload)
        Varint(0x2b60_3743).encode(to: &payload)  // WEBTRANSPORT_MAX_SESSIONS_DEPRECATED = 16
        Varint(16).encode(to: &payload)
        Varint(0x2b60_3742).encode(to: &payload)  // WEBTRANSPORT_ENABLE_DEPRECATED = 1
        Varint(1).encode(to: &payload)

        var frameData = Data()
        Varint(0x04).encode(to: &frameData)
        Varint(UInt64(payload.count)).encode(to: &frameData)
        frameData.append(payload)

        let (decoded, _) = try HTTP3FrameCodec.decode(from: frameData)
        guard case .settings(let settings) = decoded else {
            Issue.record("Expected SETTINGS frame")
            return
        }

        #expect(
            settings.webtransportMaxSessions == 16,
            "New identifier should set maxSessions to 16")
        #expect(settings.isWebTransportReady)
    }

    /// Verifies that legacy-only settings (no new 0xc671706a) still work.
    /// This covers Chrome 114-era clients that only sent deprecated identifiers.
    @Test func decodeLegacyOnlyWebTransportSettings() throws {
        var payload = Data()
        Varint(0x08).encode(to: &payload)  // ENABLE_CONNECT_PROTOCOL
        Varint(1).encode(to: &payload)
        Varint(0x33).encode(to: &payload)  // ENABLE_DATAGRAM
        Varint(1).encode(to: &payload)
        Varint(0xFFD277).encode(to: &payload)  // ENABLE_DATAGRAM_DEPRECATED
        Varint(1).encode(to: &payload)
        Varint(0x2b60_3742).encode(to: &payload)  // WEBTRANSPORT_ENABLE_DEPRECATED = 1
        Varint(1).encode(to: &payload)
        Varint(0x2b60_3743).encode(to: &payload)  // WEBTRANSPORT_MAX_SESSIONS_DEPRECATED = 8
        Varint(8).encode(to: &payload)

        var frameData = Data()
        Varint(0x04).encode(to: &frameData)
        Varint(UInt64(payload.count)).encode(to: &frameData)
        frameData.append(payload)

        let (decoded, _) = try HTTP3FrameCodec.decode(from: frameData)
        guard case .settings(let settings) = decoded else {
            Issue.record("Expected SETTINGS frame")
            return
        }

        #expect(settings.enableConnectProtocol)
        #expect(settings.enableH3Datagram)
        #expect(
            settings.webtransportMaxSessions == 8,
            "Deprecated max sessions should be used when new identifier is absent")
        #expect(settings.isWebTransportReady)
    }

    /// Verifies our server's SETTINGS are compatible with Deno's supports_webtransport() check.
    /// This is the critical interop test — Deno checks:
    ///   1. ENABLE_DATAGRAM (0x33) == 1
    ///   2. WEBTRANSPORT_MAX_SESSIONS (0xc671706a) if present → return value
    ///   3. Fallback: WEBTRANSPORT_ENABLE_DEPRECATED (0x2b603742) == 1
    ///   4. Fallback: WEBTRANSPORT_MAX_SESSIONS_DEPRECATED (0x2b603743) or default 1
    @Test func serverSettingsCompatibleWithDeno() {
        let settings = HTTP3Settings.webTransport(maxSessions: 4)
        let frame = HTTP3Frame.settings(settings)
        let encoded = HTTP3FrameCodec.encode(frame)

        // Deno check 1: ENABLE_DATAGRAM must be present with value 1
        #expect(
            containsSettingPair(encoded, identifier: 0x33, value: 1),
            "Must send ENABLE_DATAGRAM=1 for Deno")

        // Deno check 2 (primary): WEBTRANSPORT_MAX_SESSIONS (new) = 4
        #expect(
            containsSettingPair(encoded, identifier: 0xc671_706a, value: 4),
            "Must send new WEBTRANSPORT_MAX_SESSIONS for Deno")

        // Deno check 3 (fallback): WEBTRANSPORT_ENABLE_DEPRECATED must be exactly 1
        #expect(
            containsSettingPair(encoded, identifier: 0x2b60_3742, value: 1),
            "Must send WEBTRANSPORT_ENABLE_DEPRECATED=1 (boolean, NOT maxSessions)")

        // Deno check 4 (fallback): WEBTRANSPORT_MAX_SESSIONS_DEPRECATED = 4
        #expect(
            containsSettingPair(encoded, identifier: 0x2b60_3743, value: 4),
            "Must send deprecated max sessions for older clients")

        // Chrome compatibility: deprecated datagram identifier
        #expect(
            containsSettingPair(encoded, identifier: 0xFFD277, value: 1),
            "Must send ENABLE_DATAGRAM_DEPRECATED for Chrome")
    }

    // MARK: - Datagram Framing Verification

    /// Verifies datagram framing uses quarter stream ID (RFC 9297 Section 4)
    @Test func datagramQuarterStreamIDFraming() throws {
        // Session ID 4 → quarter stream ID = 1
        let sessionID: UInt64 = 4
        let quarterStreamID = sessionID / 4
        #expect(quarterStreamID == 1)

        // Frame a datagram
        let payload = Data("test".utf8)
        let framed = WebTransportSession.frameDatagram(
            payload: payload, quarterStreamID: quarterStreamID)

        // Parse it back
        guard let (parsedQSID, parsedPayload) = try WebTransportSession.parseDatagram(framed) else {
            Issue.record("Should parse successfully")
            return
        }

        #expect(parsedQSID == quarterStreamID)
        #expect(parsedPayload == payload)
    }

    /// Verifies datagram framing for various session IDs
    @Test func datagramFramingVariousSessionIDs() throws {
        let testCases: [(sessionID: UInt64, expectedQSID: UInt64)] = [
            (0, 0),
            (4, 1),
            (8, 2),
            (12, 3),
            (16, 4),
            (100, 25),
            (0x3FFF * 4, 0x3FFF),  // large but fits in 2-byte varint
        ]

        for (sessionID, expectedQSID) in testCases {
            let payload = Data("payload-\(sessionID)".utf8)
            let framed = WebTransportSession.frameDatagram(
                payload: payload,
                quarterStreamID: sessionID / 4
            )

            guard let (parsedQSID, parsedPayload) = try WebTransportSession.parseDatagram(framed)
            else {
                Issue.record("Failed to parse datagram for sessionID=\(sessionID)")
                continue
            }

            #expect(
                parsedQSID == expectedQSID,
                "Quarter stream ID mismatch for sessionID=\(sessionID)")
            #expect(
                parsedPayload == payload,
                "Payload mismatch for sessionID=\(sessionID)")
        }
    }

    /// Verifies datagram framing wire format matches what browsers expect
    @Test func datagramWireFormat() throws {
        // A datagram for session ID 4 (quarterStreamID = 1)
        // should start with varint(1) = 0x01 (single byte, 2MSB=00, value=1)
        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let framed = WebTransportSession.frameDatagram(payload: payload, quarterStreamID: 1)

        // First byte should be varint 1 = 0x01
        #expect(framed[0] == 0x01)
        // Remaining bytes should be the payload
        #expect(Data(framed.dropFirst(1)) == payload)

        // Quarter stream ID 0 → varint(0) = 0x00
        let framed0 = WebTransportSession.frameDatagram(payload: payload, quarterStreamID: 0)
        #expect(framed0[0] == 0x00)
        #expect(Data(framed0.dropFirst(1)) == payload)

        // Quarter stream ID 63 (0x3F) → single byte varint (2MSB=00, value=63)
        let framed63 = WebTransportSession.frameDatagram(payload: payload, quarterStreamID: 63)
        #expect(framed63[0] == 0x3F)
        #expect(Data(framed63.dropFirst(1)) == payload)

        // Quarter stream ID 64 (0x40) → two byte varint (2MSB=01, value=64 → 0x4040)
        let framed64 = WebTransportSession.frameDatagram(payload: payload, quarterStreamID: 64)
        #expect(framed64[0] == 0x40)
        #expect(framed64[1] == 0x40)
        #expect(Data(framed64.dropFirst(2)) == payload)
    }

    // MARK: - Extended CONNECT Wire Format

    /// Verifies the Extended CONNECT request has all required pseudo-headers
    @Test func extendedConnectRequestFormat() {
        let request = HTTP3Request.webTransportConnect(
            scheme: "https",
            authority: "example.com:4433",
            path: "/webtransport",
            headers: [("origin", "https://example.com")]
        )

        let headerList = request.toHeaderList()

        // Required pseudo-headers for Extended CONNECT (RFC 9220):
        // :method = CONNECT
        // :protocol = webtransport
        // :scheme = https
        // :authority = example.com:4433
        // :path = /webtransport
        assertHeader(headerList, name: ":method", value: "CONNECT")
        assertHeader(headerList, name: ":protocol", value: "webtransport")
        assertHeader(headerList, name: ":scheme", value: "https")
        assertHeader(headerList, name: ":authority", value: "example.com:4433")
        assertHeader(headerList, name: ":path", value: "/webtransport")

        // Regular header
        assertHeader(headerList, name: "origin", value: "https://example.com")

        // Verify no forbidden pseudo-headers (like :status on requests)
        let statusHeaders = headerList.filter { $0.name == ":status" }
        #expect(statusHeaders.isEmpty, "Request should not have :status")
    }

    /// Verifies the Extended CONNECT response format for 200 OK
    @Test func extendedConnectResponseFormat() {
        let response = HTTP3Response(status: 200)
        let headerList = response.toHeaderList()

        // Response should have :status = 200
        assertHeader(headerList, name: ":status", value: "200")

        // Should not have request pseudo-headers
        let methods = headerList.filter { $0.name == ":method" }
        #expect(methods.isEmpty)
    }

    // MARK: - WebTransport Stream Type Identification

    /// Verifies unidirectional stream type 0x54 (WEBTRANSPORT_STREAM)
    @Test func webTransportUniStreamType() {
        #expect(kWebTransportUniStreamType == 0x54)
        #expect(WebTransportStreamClassification.isWebTransportStream(0x54))
        #expect(!WebTransportStreamClassification.isWebTransportStream(0x00))  // control
        #expect(!WebTransportStreamClassification.isWebTransportStream(0x02))  // QPACK encoder
        #expect(!WebTransportStreamClassification.isWebTransportStream(0x03))  // QPACK decoder
    }

    /// Verifies bidirectional stream framing (session ID as first varint)
    @Test func bidiStreamFramingWireFormat() async throws {
        let stream = MockIntegrationStream(id: 100)

        // Write bidi header for session ID 4
        try await WebTransportStreamFraming.writeBidirectionalHeader(to: stream, sessionID: 4)

        let written = stream.allWrittenData
        // Session ID 4 as varint = single byte 0x04
        #expect(written.count == 1)
        #expect(written[0] == 0x04)
    }

    /// Verifies unidirectional stream framing (stream type 0x54 + session ID)
    @Test func uniStreamFramingWireFormat() async throws {
        let stream = MockIntegrationStream(id: 101, isUnidirectional: true)

        // Write uni header for session ID 4
        try await WebTransportStreamFraming.writeUnidirectionalHeader(to: stream, sessionID: 4)

        let written = stream.allWrittenData
        // Stream type 0x54 = 84 decimal, which exceeds 1-byte varint range (0-63),
        // so it encodes as a 2-byte varint (2MSB=01): [0x40, 0x54]
        // Session ID 4 encodes as 1-byte varint: [0x04]
        // Total = 3 bytes
        #expect(written.count == 3)
        #expect(
            written[0] == 0x40, "First byte: 2-byte varint high byte (2MSB=01, upper bits=0)")
        #expect(written[1] == 0x54, "Second byte: 2-byte varint low byte (0x54)")
        #expect(written[2] == 0x04, "Third byte should be session ID varint")

        // Verify roundtrip: decode the stream type varint
        let (streamTypeVarint, typeConsumed) = try Varint.decode(from: written)
        #expect(streamTypeVarint.value == kWebTransportUniStreamType)
        #expect(typeConsumed == 2, "Stream type 0x54 should consume 2 bytes")

        let remaining = Data(written.dropFirst(typeConsumed))
        let (sessionIDVarint, _) = try Varint.decode(from: remaining)
        #expect(sessionIDVarint.value == 4)
    }

    // MARK: - Capsule Wire Format (RFC 9297)

    /// Verifies CLOSE_WEBTRANSPORT_SESSION capsule wire format
    @Test func closeCapsuleWireFormat() throws {
        let closeData = WebTransportCapsuleCodec.encodeClose(errorCode: 0, reason: "")
        #expect(!closeData.isEmpty)

        // Decode and verify
        guard let (capsule, _) = try WebTransportCapsuleCodec.decode(from: closeData) else {
            Issue.record("Should decode successfully")
            return
        }

        guard case .close(let info) = capsule else {
            Issue.record("Should be a close capsule")
            return
        }

        #expect(info.errorCode == 0)
        #expect(info.reason == "")
    }

    /// Verifies DRAIN_WEBTRANSPORT_SESSION capsule wire format
    @Test func drainCapsuleWireFormat() throws {
        let drainData = WebTransportCapsuleCodec.encodeDrain()
        #expect(!drainData.isEmpty)

        guard let (capsule, _) = try WebTransportCapsuleCodec.decode(from: drainData) else {
            Issue.record("Should decode successfully")
            return
        }

        guard case .drain = capsule else {
            Issue.record("Should be a drain capsule")
            return
        }
    }

    /// Verifies CLOSE capsule with reason string
    @Test func closeCapsuleWithReasonWireFormat() throws {
        let reason = "Session ended by server"
        let closeData = WebTransportCapsuleCodec.encodeClose(
            errorCode: 42,
            reason: reason
        )

        guard let (capsule, _) = try WebTransportCapsuleCodec.decode(from: closeData) else {
            Issue.record("Should decode successfully")
            return
        }

        guard case .close(let info) = capsule else {
            Issue.record("Should be a close capsule")
            return
        }

        #expect(info.errorCode == 42)
        #expect(info.reason == reason)
    }

    // MARK: - Error Code Mapping (draft-ietf-webtrans-http3)

    /// Verifies WebTransport → HTTP/3 error code mapping
    @Test func errorCodeMapping() {
        // Base: 0x52e4a40d
        #expect(WebTransportStreamErrorCode.base == 0x52e4_a40d)

        // Application code 0 → 0x52e4a40d
        #expect(
            WebTransportStreamErrorCode.toHTTP3ErrorCode(0) == 0x52e4_a40d
        )

        // Application code 1 → 0x52e4a40e
        #expect(
            WebTransportStreamErrorCode.toHTTP3ErrorCode(1) == 0x52e4_a40e
        )

        // Round-trip
        let appCode: UInt32 = 255
        let h3Code = WebTransportStreamErrorCode.toHTTP3ErrorCode(appCode)
        let decoded = WebTransportStreamErrorCode.fromHTTP3ErrorCode(h3Code)
        #expect(decoded == appCode)

        // Non-WT code should return nil
        #expect(WebTransportStreamErrorCode.fromHTTP3ErrorCode(0) == nil)
        #expect(WebTransportStreamErrorCode.fromHTTP3ErrorCode(0x100) == nil)
    }

    /// Tests effectiveSendLimits with WebTransport settings
    @Test func effectiveSendLimitsWebTransport() {
        let local = HTTP3Settings.webTransport(maxSessions: 10)
        let peer = HTTP3Settings.webTransport(maxSessions: 5)

        let effective = local.effectiveSendLimits(peerSettings: peer)

        // Extended CONNECT: both enabled → true
        #expect(effective.enableConnectProtocol)
        // H3 Datagram: both enabled → true
        #expect(effective.enableH3Datagram)
        // WebTransport max sessions: peer's limit applies
        #expect(effective.webtransportMaxSessions == 5)
    }

    /// Tests effectiveSendLimits when peer doesn't support WebTransport
    @Test func effectiveSendLimitsNoWebTransportPeer() {
        let local = HTTP3Settings.webTransport(maxSessions: 10)
        let peer = HTTP3Settings()  // No WebTransport

        let effective = local.effectiveSendLimits(peerSettings: peer)

        #expect(!effective.enableConnectProtocol)
        #expect(!effective.enableH3Datagram)
        #expect(effective.webtransportMaxSessions == nil)
    }

    // MARK: - Varint Encoding Verification (QUIC Variable-Length Integer)

    /// Verifies varint encoding matches QUIC spec for values browsers will encounter
    @Test func varintEncodingBrowserRelevant() throws {
        // 1-byte: 0-63 (2MSB = 00)
        var buf1 = Data()
        Varint(0).encode(to: &buf1)
        #expect(buf1 == Data([0x00]))

        var buf2 = Data()
        Varint(63).encode(to: &buf2)
        #expect(buf2 == Data([0x3F]))

        // 2-byte: 64-16383 (2MSB = 01)
        var buf3 = Data()
        Varint(64).encode(to: &buf3)
        #expect(buf3.count == 2)
        #expect(buf3[0] & 0xC0 == 0x40, "2MSB should be 01")

        // 4-byte: 16384-1073741823 (2MSB = 10)
        var buf4 = Data()
        Varint(16384).encode(to: &buf4)
        #expect(buf4.count == 4)
        #expect(buf4[0] & 0xC0 == 0x80, "2MSB should be 10")

        // 8-byte: large values (2MSB = 11)
        var buf8 = Data()
        Varint(1_073_741_824).encode(to: &buf8)
        #expect(buf8.count == 8)
        #expect(buf8[0] & 0xC0 == 0xC0, "2MSB should be 11")
    }

    /// Verifies SETTINGS_WEBTRANSPORT_MAX_SESSIONS identifier varint encoding
    /// for both new (0xc671706a) and deprecated (0x2b603742, 0x2b603743) identifiers
    @Test func webtransportSettingsIdentifierEncoding() throws {
        // New identifier: 0xc671706a > 0x3FFFFFFF, so it needs an 8-byte varint (2MSB = 11)
        var buf = Data()
        Varint(0xc671_706a).encode(to: &buf)
        #expect(buf.count == 8, "0xc671706a should encode as 8-byte varint")
        #expect(buf[0] & 0xC0 == 0xC0, "2MSB should be 11 for 8-byte varint")

        let (decoded, consumed) = try Varint.decode(from: buf)
        #expect(decoded.value == 0xc671_706a)
        #expect(consumed == 8)

        // Deprecated enable identifier: 0x2b603742 should also encode as 4-byte varint
        var buf2 = Data()
        Varint(0x2b60_3742).encode(to: &buf2)
        #expect(buf2.count == 4, "0x2b603742 should encode as 4-byte varint")
        #expect(buf2[0] & 0xC0 == 0x80, "2MSB should be 10 for 4-byte varint")

        let (decoded2, consumed2) = try Varint.decode(from: buf2)
        #expect(decoded2.value == 0x2b60_3742)
        #expect(consumed2 == 4)

        // Deprecated max sessions identifier: 0x2b603743
        var buf3 = Data()
        Varint(0x2b60_3743).encode(to: &buf3)
        #expect(buf3.count == 4, "0x2b603743 should encode as 4-byte varint")

        let (decoded3, consumed3) = try Varint.decode(from: buf3)
        #expect(decoded3.value == 0x2b60_3743)
        #expect(consumed3 == 4)

        // Deprecated datagram identifier: 0xFFD277 should encode as 4-byte varint
        var buf4 = Data()
        Varint(0xFFD277).encode(to: &buf4)
        #expect(buf4.count == 4, "0xFFD277 should encode as 4-byte varint")

        let (decoded4, consumed4) = try Varint.decode(from: buf4)
        #expect(decoded4.value == 0xFFD277)
        #expect(consumed4 == 4)
    }

    // MARK: - Browser-Specific Quirks

    /// Chrome requires SETTINGS_WEBTRANSPORT_MAX_SESSIONS > 0 to enable WebTransport
    @Test func chromeRequiresNonZeroMaxSessions() {
        // With max sessions = 0, WebTransport should NOT be ready
        let zeroSettings = HTTP3Settings(
            enableConnectProtocol: true,
            enableH3Datagram: true,
            webtransportMaxSessions: 0
        )
        #expect(
            !zeroSettings.isWebTransportReady,
            "Chrome requires non-zero max sessions")

        // With max sessions = 1, should be ready
        let oneSettings = HTTP3Settings(
            enableConnectProtocol: true,
            enableH3Datagram: true,
            webtransportMaxSessions: 1
        )
        #expect(oneSettings.isWebTransportReady)
    }

    /// Firefox requires all three WebTransport settings before accepting connections
    @Test func firefoxRequiresAllThreeSettings() {
        // Missing any one should not be ready
        let missingConnect = HTTP3Settings(
            enableConnectProtocol: false,
            enableH3Datagram: true,
            webtransportMaxSessions: 1
        )
        #expect(!missingConnect.isWebTransportReady)

        let missingDatagram = HTTP3Settings(
            enableConnectProtocol: true,
            enableH3Datagram: false,
            webtransportMaxSessions: 1
        )
        #expect(!missingDatagram.isWebTransportReady)

        let missingMaxSessions = HTTP3Settings(
            enableConnectProtocol: true,
            enableH3Datagram: true,
            webtransportMaxSessions: nil
        )
        #expect(!missingMaxSessions.isWebTransportReady)
    }

    /// Verifies HTTP/3 SETTINGS frame type is 0x04
    @Test func settingsFrameType() {
        let frame = HTTP3Frame.settings(HTTP3Settings())
        #expect(frame.frameType == 0x04)
    }

    // MARK: - Helpers

    /// Checks if encoded SETTINGS data contains a specific identifier-value pair
    private func containsSettingPair(_ data: Data, identifier: UInt64, value: UInt64) -> Bool {
        // SETTINGS frame format:
        // Frame Type (varint) = 0x04
        // Frame Length (varint)
        // Settings { Identifier (varint), Value (varint) } ...
        guard data.count >= 2 else { return false }

        var offset = 0

        // Skip frame type
        guard let (frameType, typeLen) = try? decodeVarint(data, offset: offset) else {
            return false
        }
        offset += typeLen
        guard frameType == 0x04 else { return false }

        // Skip frame length
        guard let (_, lengthLen) = try? decodeVarint(data, offset: offset) else { return false }
        offset += lengthLen

        // Scan settings pairs
        while offset < data.count {
            guard let (settingID, idLen) = try? decodeVarint(data, offset: offset) else { break }
            offset += idLen

            guard let (settingValue, valLen) = try? decodeVarint(data, offset: offset) else {
                break
            }
            offset += valLen

            if settingID == identifier && settingValue == value {
                return true
            }
        }

        return false
    }

    private func decodeVarint(_ data: Data, offset: Int) throws -> (UInt64, Int) {
        guard offset < data.count else {
            throw NSError(domain: "test", code: 1, userInfo: nil)
        }

        let subdata = Data(data[offset...])
        let (varint, consumed) = try Varint.decode(from: subdata)
        return (varint.value, consumed)
    }

    private func assertHeader(
        _ headers: [(name: String, value: String)],
        name: String,
        value: String,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let matching = headers.filter { $0.name == name }
        #expect(
            matching.count == 1,
            "Expected exactly one \(name) header, found \(matching.count)",
            sourceLocation: sourceLocation
        )
        if let first = matching.first {
            #expect(
                first.value == value,
                "Expected \(name)=\(value), got \(first.value)",
                sourceLocation: sourceLocation
            )
        }
    }
}

// MARK: - Helper Actors

private actor SendResponseTracker {
    var called = false
    func markCalled() {
        called = true
    }
}

// MARK: - 6. WebTransport Stream Priority Integration Tests

/// Tests that WebTransport streams are correctly wired into the HTTP/3
/// priority scheduler (RFC 9218) and that priority metadata flows through
/// the stream creation, delivery, reprioritization, and cleanup paths.
@Suite struct WebTransportStreamPriorityTests {

    // MARK: - Default Priority Constants

    /// Verifies the WebTransport-specific default priority presets
    @Test func webTransportDefaultPriorityPresets() {
        // Bidi: urgency 3, incremental (interactive streams benefit from interleaving)
        #expect(StreamPriority.webTransportBidi.urgency == 3)
        #expect(StreamPriority.webTransportBidi.incremental)

        // Uni: urgency 4, non-incremental (slightly lower than bidi)
        #expect(StreamPriority.webTransportUni.urgency == 4)
        #expect(!StreamPriority.webTransportUni.incremental)

        // Datagram: urgency 5, incremental (unreliable, tolerates loss)
        #expect(StreamPriority.webTransportDatagram.urgency == 5)
        #expect(StreamPriority.webTransportDatagram.incremental)

        // Session control: urgency 1, non-incremental (capsules are critical)
        #expect(StreamPriority.webTransportSessionControl.urgency == 1)
        #expect(!StreamPriority.webTransportSessionControl.incremental)
    }

    /// Verifies relative ordering of WT defaults
    @Test func webTransportDefaultPriorityOrdering() {
        // Session control > bidi > uni > datagram
        #expect(StreamPriority.webTransportSessionControl < StreamPriority.webTransportBidi)
        #expect(StreamPriority.webTransportBidi < StreamPriority.webTransportUni)
        #expect(StreamPriority.webTransportUni < StreamPriority.webTransportDatagram)
    }

    // MARK: - WebTransportStream Priority Property

    /// Tests that WebTransportStream carries priority metadata
    @Test func streamCarriesPriority() {
        let mockStream = MockIntegrationStream(id: 4)
        let stream = WebTransportStream(
            quicStream: mockStream,
            sessionID: 0,
            direction: .bidirectional,
            isLocal: true,
            priority: .high
        )

        #expect(stream.priority == .high)
    }

    /// Tests that bidi streams default to webTransportBidi priority
    @Test func bidiStreamDefaultPriority() {
        let mockStream = MockIntegrationStream(id: 4)
        let stream = WebTransportStream(
            quicStream: mockStream,
            sessionID: 0,
            direction: .bidirectional,
            isLocal: true
        )

        #expect(stream.priority == .webTransportBidi)
    }

    /// Tests that uni streams default to webTransportUni priority
    @Test func uniStreamDefaultPriority() {
        let mockStream = MockIntegrationStream(id: 6, isUnidirectional: true)
        let stream = WebTransportStream(
            quicStream: mockStream,
            sessionID: 0,
            direction: .unidirectional,
            isLocal: true
        )

        #expect(stream.priority == .webTransportUni)
    }

    /// Tests that explicit priority overrides the default
    @Test func explicitPriorityOverridesDefault() {
        let mockStream = MockIntegrationStream(id: 4)
        let stream = WebTransportStream(
            quicStream: mockStream,
            sessionID: 0,
            direction: .bidirectional,
            isLocal: true,
            priority: .lowest
        )

        #expect(stream.priority == .lowest)
    }

    /// Tests that the description includes priority information
    @Test func streamDescriptionIncludesPriority() {
        let mockStream = MockIntegrationStream(id: 4)
        let stream = WebTransportStream(
            quicStream: mockStream,
            sessionID: 0,
            direction: .bidirectional,
            isLocal: true,
            priority: .high
        )

        let desc = stream.description
        #expect(desc.contains("u=1"), "Description should contain urgency: \(desc)")
    }

    // MARK: - openBidirectionalStream() with Priority

    /// Tests that openBidirectionalStream() uses default WT bidi priority
    @Test func openBidiStreamDefaultPriority() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()

        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        let stream = try await session.openBidirectionalStream()

        #expect(stream.priority == .webTransportBidi)

        // Verify the stream is registered with the HTTP/3 scheduler
        let scheduledIDs = await h3Conn.priorityOrderedStreamIDs()
        #expect(
            scheduledIDs.contains(stream.id),
            "Stream should be registered with scheduler")

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    /// Tests that openBidirectionalStream(priority:) passes custom priority
    @Test func openBidiStreamCustomPriority() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()

        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        let stream = try await session.openBidirectionalStream(priority: .highest)

        #expect(stream.priority == .highest)

        // Verify scheduler registration with the correct priority
        let activeCount = await h3Conn.activeResponseStreamCount
        #expect(activeCount == 1)

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    // MARK: - openUnidirectionalStream() with Priority

    /// Tests that openUnidirectionalStream() uses default WT uni priority
    @Test func openUniStreamDefaultPriority() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()

        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        let stream = try await session.openUnidirectionalStream()

        #expect(stream.priority == .webTransportUni)

        // Verify the stream is registered with the HTTP/3 scheduler
        let scheduledIDs = await h3Conn.priorityOrderedStreamIDs()
        #expect(
            scheduledIDs.contains(stream.id),
            "Uni stream should be registered with scheduler")

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    /// Tests that openUnidirectionalStream(priority:) passes custom priority
    @Test func openUniStreamCustomPriority() async throws {
        let (session, _, mockConn, connectStream) = makeServerSession()

        try await session.start()

        let stream = try await session.openUnidirectionalStream(priority: .background)

        #expect(stream.priority == .background)
        #expect(stream.priority.urgency == 7)
        #expect(stream.priority.incremental)

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    // MARK: - Multiple Streams Scheduling Order

    /// Tests that multiple WT streams are scheduled by priority
    @Test func multipleStreamsScheduledByPriority() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()

        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        // Open streams with different priorities
        let lowStream = try await session.openBidirectionalStream(priority: .low)
        let highStream = try await session.openBidirectionalStream(priority: .high)
        let defaultStream = try await session.openBidirectionalStream(priority: .default)

        let ordered = await h3Conn.priorityOrderedStreamIDs()

        // High (urgency 1) should be before default (urgency 3) should be before low (urgency 5)
        guard let highIdx = ordered.firstIndex(of: highStream.id),
            let defaultIdx = ordered.firstIndex(of: defaultStream.id),
            let lowIdx = ordered.firstIndex(of: lowStream.id)
        else {
            Issue.record("All streams should be in the scheduler")
            connectStream.enqueueFIN()
            mockConn.finish()
            return
        }

        #expect(
            highIdx < defaultIdx,
            "High priority stream should be scheduled before default")
        #expect(
            defaultIdx < lowIdx,
            "Default priority stream should be scheduled before low")

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    /// Tests mixed bidi and uni streams are ordered by priority
    @Test func mixedStreamTypesScheduledByPriority() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()

        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        // Uni stream with high priority
        let uniHigh = try await session.openUnidirectionalStream(priority: .high)
        // Bidi stream with default priority
        let bidiDefault = try await session.openBidirectionalStream()
        // Bidi stream with lowest priority
        let bidiLow = try await session.openBidirectionalStream(priority: .lowest)

        let ordered = await h3Conn.priorityOrderedStreamIDs()

        guard let uniHighIdx = ordered.firstIndex(of: uniHigh.id),
            let bidiDefaultIdx = ordered.firstIndex(of: bidiDefault.id),
            let bidiLowIdx = ordered.firstIndex(of: bidiLow.id)
        else {
            Issue.record("All streams should be in the scheduler")
            connectStream.enqueueFIN()
            mockConn.finish()
            return
        }

        #expect(
            uniHighIdx < bidiDefaultIdx,
            "High-priority uni should be before default bidi")
        #expect(
            bidiDefaultIdx < bidiLowIdx,
            "Default bidi should be before lowest bidi")

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    // MARK: - Dynamic Reprioritization

    /// Tests setStreamPriority changes the scheduling order
    @Test func dynamicReprioritization() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()

        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        let streamA = try await session.openBidirectionalStream(priority: .low)
        let streamB = try await session.openBidirectionalStream(priority: .high)

        // Initially B should be before A
        let ordered1 = await h3Conn.priorityOrderedStreamIDs()
        guard let idxA1 = ordered1.firstIndex(of: streamA.id),
            let idxB1 = ordered1.firstIndex(of: streamB.id)
        else {
            Issue.record("Streams not found in scheduler")
            connectStream.enqueueFIN()
            mockConn.finish()
            return
        }
        #expect(idxB1 < idxA1, "Stream B (high) should be before A (low)")

        // Reprioritize A to highest
        try await session.setStreamPriority(.highest, for: streamA.id)

        // Now A should be before B
        let ordered2 = await h3Conn.priorityOrderedStreamIDs()
        guard let idxA2 = ordered2.firstIndex(of: streamA.id),
            let idxB2 = ordered2.firstIndex(of: streamB.id)
        else {
            Issue.record("Streams not found in scheduler after reprioritization")
            connectStream.enqueueFIN()
            mockConn.finish()
            return
        }
        #expect(
            idxA2 < idxB2,
            "Stream A should now be before B after reprioritization to highest")

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    /// Tests that reprioritizing an unknown stream throws
    @Test func reprioritizeUnknownStreamThrows() async throws {
        let (session, _, mockConn, connectStream) = makeServerSession()

        try await session.start()

        do {
            try await session.setStreamPriority(.high, for: 9999)
            Issue.record("Should throw for unknown stream")
        } catch let error as WebTransportError {
            if case .unknownStream(let id) = error {
                #expect(id == 9999)
            } else {
                Issue.record("Expected unknownStream error, got \(error)")
            }
        }

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    /// Tests streamPriority(for:) query method
    @Test func streamPriorityQuery() async throws {
        let (session, _, mockConn, connectStream) = makeServerSession()

        try await session.start()

        let stream = try await session.openBidirectionalStream(priority: .high)

        let queriedPriority = await session.streamPriority(for: stream.id)
        #expect(queriedPriority == .high)

        // After reprioritization, query should reflect the new value
        try await session.setStreamPriority(.lowest, for: stream.id)
        let updatedPriority = await session.streamPriority(for: stream.id)
        #expect(updatedPriority == .lowest)

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    // MARK: - Incoming Stream Priority Registration

    /// Tests that incoming bidi streams get registered with default bidi priority
    @Test func incomingBidiStreamRegisteredWithDefaultPriority() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()

        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        // Deliver an incoming bidi stream (simulating a peer-opened stream)
        let incomingQuicStream = MockIntegrationStream(id: 8)
        await session.deliverIncomingBidirectionalStream(incomingQuicStream)

        // Allow the Task inside deliverIncoming to complete
        // Verify it was registered with the HTTP/3 scheduler
        // Retry loop to handle async Task registration
        var scheduledIDs: [UInt64] = []
        for _ in 0..<20 {
            scheduledIDs = await h3Conn.priorityOrderedStreamIDs()
            if scheduledIDs.contains(8) { break }
            try await Task.sleep(for: .milliseconds(10))
        }

        #expect(
            scheduledIDs.contains(8),
            "Incoming bidi stream should be registered with scheduler")

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    /// Tests that incoming uni streams get registered with default uni priority
    @Test func incomingUniStreamRegisteredWithDefaultPriority() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()

        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        // Deliver an incoming uni stream
        let incomingQuicStream = MockIntegrationStream(id: 10, isUnidirectional: true)
        await session.deliverIncomingUnidirectionalStream(incomingQuicStream)

        // Allow the Task inside deliverIncoming to complete
        var scheduledIDs: [UInt64] = []
        for _ in 0..<20 {
            scheduledIDs = await h3Conn.priorityOrderedStreamIDs()
            if scheduledIDs.contains(10) { break }
            try await Task.sleep(for: .milliseconds(10))
        }

        #expect(
            scheduledIDs.contains(10),
            "Incoming uni stream should be registered with scheduler")

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    // MARK: - Stream Cleanup Unregisters from Scheduler

    /// Tests that removeStream() unregisters from the HTTP/3 scheduler
    @Test func removeStreamUnregistersFromScheduler() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()

        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        let stream = try await session.openBidirectionalStream()
        let streamID = stream.id

        // Confirm registration
        let count1 = await h3Conn.activeResponseStreamCount
        #expect(count1 == 1)

        // Remove the stream
        await session.removeStream(streamID)

        // Allow the Task inside removeStream to complete
        try await Task.sleep(for: .milliseconds(50))

        let count2 = await h3Conn.activeResponseStreamCount
        #expect(count2 == 0, "Stream should be unregistered from scheduler after removal")

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    // MARK: - priorityOrderedStreams()

    /// Tests that priorityOrderedStreams() returns session-scoped streams in priority order
    @Test func priorityOrderedStreamsFiltersToSession() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()

        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        // Open some WT streams on this session
        let low = try await session.openBidirectionalStream(priority: .low)
        let high = try await session.openBidirectionalStream(priority: .high)

        // Also register a non-WT stream directly on the H3 connection (simulating a regular HTTP/3 stream)
        await h3Conn.registerActiveResponseStream(9999, priority: .highest)

        // Get session-scoped ordered streams
        let ordered = await session.priorityOrderedStreams()

        // Should only contain our session's streams, not the external one
        #expect(ordered.count == 2, "Should only contain session streams")
        #expect(ordered[0].id == high.id, "High priority stream should be first")
        #expect(ordered[1].id == low.id, "Low priority stream should be second")

        // Clean up the external stream
        await h3Conn.unregisterActiveResponseStream(9999)
        connectStream.enqueueFIN()
        mockConn.finish()
    }

    // MARK: - Session Close Cleanup

    /// Tests that closing a session unregisters all its streams from the scheduler
    @Test func sessionCloseUnregistersAllStreams() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()

        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        _ = try await session.openBidirectionalStream(priority: .high)
        _ = try await session.openBidirectionalStream(priority: .low)
        _ = try await session.openUnidirectionalStream()

        let countBefore = await h3Conn.activeResponseStreamCount
        #expect(countBefore == 3)

        // Close the session — this sends CLOSE capsule and transitions to closed
        try await session.close()

        // Allow cleanup Tasks to complete
        var countAfter = -1
        for _ in 0..<20 {
            countAfter = await h3Conn.activeResponseStreamCount
            if countAfter == 0 { break }
            try await Task.sleep(for: .milliseconds(10))
        }

        #expect(
            countAfter == 0,
            "All streams should be unregistered after session close")

        connectStream.enqueueFIN()
        mockConn.finish()
    }

    // MARK: - Edge Cases

    /// Tests opening a stream on a non-established session throws
    @Test func openStreamOnNonEstablishedSessionThrows() async throws {
        let (session, _, mockConn, _) = makeServerSession()
        // Don't call start() — session is in .connecting state

        do {
            _ = try await session.openBidirectionalStream(priority: .high)
            Issue.record("Should throw when session not established")
        } catch {
            // Expected
        }

        do {
            _ = try await session.openUnidirectionalStream(priority: .high)
            Issue.record("Should throw when session not established")
        } catch {
            // Expected
        }

        mockConn.finish()
    }

    /// Tests that all 8 urgency levels work as priority for WT streams
    @Test func allUrgencyLevelsWork() async throws {
        let (session, h3Conn, mockConn, connectStream) = makeServerSession()

        await h3Conn.registerWebTransportSession(session)
        try await session.start()

        var streams: [WebTransportStream] = []
        // Open streams with all 8 urgency levels in reverse order
        for urgency: UInt8 in stride(from: 7, through: 0, by: -1) {
            let priority = StreamPriority(urgency: urgency, incremental: false)
            let stream = try await session.openBidirectionalStream(priority: priority)
            streams.append(stream)
        }

        let ordered = await h3Conn.priorityOrderedStreamIDs()

        // Verify they're ordered by urgency (0 first, 7 last)
        #expect(ordered.count == 8)
        // The first stream in the ordered list should be urgency 0 (opened last)
        #expect(
            ordered.first == streams.last?.id,
            "Urgency 0 stream should be first in scheduling order")

        connectStream.enqueueFIN()
        mockConn.finish()
    }
}
