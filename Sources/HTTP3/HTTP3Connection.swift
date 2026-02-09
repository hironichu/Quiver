import Logging

/// HTTP/3 Connection Manager (RFC 9114, RFC 9218)
///
/// Manages the HTTP/3-specific aspects of a QUIC connection:
///
/// 1. **Control stream** — Opens one unidirectional stream in each direction,
///    exchanges SETTINGS frames
/// 2. **QPACK streams** — Opens encoder/decoder unidirectional streams
/// 3. **Request streams** — Bidirectional streams for HTTP request/response
/// 4. **Stream type identification** — Reads stream type byte from incoming
///    unidirectional streams
/// 5. **GOAWAY** — Graceful shutdown coordination
///
/// ## Connection Establishment Flow
///
/// ```
/// Client                                     Server
///   |                                          |
///   |  === QUIC connection established ===     |
///   |  === ALPN: "h3" negotiated ===           |
///   |                                          |
///   |  Open uni stream: Control (type=0x00)    |
///   |  Send SETTINGS frame                     |
///   |----------------------------------------->|
///   |                                          |
///   |  Open uni stream: QPACK Encoder (0x02)   |
///   |----------------------------------------->|
///   |                                          |
///   |  Open uni stream: QPACK Decoder (0x03)   |
///   |----------------------------------------->|
///   |                                          |
///   |  (Server also opens same 3 uni streams)  |
///   |<-----------------------------------------|
///   |                                          |
///   |  === HTTP/3 connection ready ===         |
///   |                                          |
/// ```
///
/// ## Thread Safety
///
/// `HTTP3Connection` is an `actor`, ensuring all mutable state is
/// accessed serially. This is consistent with Swift 6 concurrency
/// requirements and the project's design principles.

import Foundation
import QUIC
import QUICCore
import QUICStream
import QPACK

// MARK: - HTTP/3 Connection

/// HTTP/3 connection wrapping a QUIC connection (RFC 9114 Section 3)
///
/// Manages the HTTP/3 layer on top of a QUIC connection, including
/// control stream setup, SETTINGS exchange, request multiplexing,
/// and graceful shutdown via GOAWAY.
///
/// ## Usage
///
/// ```swift
/// // Client-side
/// let h3conn = HTTP3Connection(
///     quicConnection: quicConn,
///     role: .client,
///     settings: HTTP3Settings()
/// )
/// try await h3conn.initialize()
/// let response = try await h3conn.sendRequest(request)
///
/// // Server-side
/// let h3conn = HTTP3Connection(
///     quicConnection: quicConn,
///     role: .server,
///     settings: HTTP3Settings()
/// )
/// try await h3conn.initialize()
/// for await context in h3conn.incomingRequests {
///     try await context.respond(response)
/// }
/// ```
/// Context for an incoming Extended CONNECT request (RFC 9220).
///
/// Wraps an Extended CONNECT request with the underlying QUIC stream,
/// allowing the server to accept (200) or reject the request.
/// When accepted, the CONNECT stream remains open for the session lifetime
/// (e.g., for WebTransport session use).
///
/// ## Usage
///
/// ```swift
/// for await context in connection.incomingExtendedConnect {
///     if context.request.isWebTransportConnect {
///         // Accept the WebTransport session
///         try await context.accept()
///         // The stream is now open for WebTransport session use
///         let sessionStream = context.stream
///     } else {
///         // Reject unknown protocols
///         try await context.reject(status: 501)
///     }
/// }
/// ```
public struct ExtendedConnectContext: Sendable {
    /// The received Extended CONNECT request
    public let request: HTTP3Request

    /// The QUIC stream ID this request arrived on (the CONNECT stream)
    public let streamID: UInt64

    /// The underlying QUIC stream. After acceptance, this stream remains
    /// open and serves as the session's control channel.
    public let stream: any QUICStreamProtocol

    /// The HTTP/3 connection that owns this stream.
    ///
    /// This reference enables higher-level code (e.g. `WebTransportServer`)
    /// to create sessions on the correct connection without a fragile
    /// stream→connection lookup. Because `HTTP3Connection` is an actor,
    /// the reference is `Sendable`-safe.
    public let connection: HTTP3Connection

    /// Internal closure to send headers on the stream
    internal let _sendResponse: @Sendable (HTTP3Response) async throws -> Void

    /// Creates an Extended CONNECT context.
    ///
    /// - Parameters:
    ///   - request: The Extended CONNECT request
    ///   - streamID: The QUIC stream ID
    ///   - stream: The underlying QUIC stream
    ///   - connection: The HTTP/3 connection that received this request
    ///   - sendResponse: Closure to send a response (without closing the stream)
    public init(
        request: HTTP3Request,
        streamID: UInt64,
        stream: any QUICStreamProtocol,
        connection: HTTP3Connection,
        sendResponse: @escaping @Sendable (HTTP3Response) async throws -> Void
    ) {
        self.request = request
        self.streamID = streamID
        self.stream = stream
        self.connection = connection
        self._sendResponse = sendResponse
    }

    /// Accepts the Extended CONNECT request by sending a 200 response.
    ///
    /// After acceptance, the CONNECT stream stays open. The caller can
    /// use `stream` for the session lifetime (e.g., WebTransport).
    ///
    /// - Parameter headers: Additional response headers (default: empty)
    /// - Throws: If sending the response fails
    public func accept(headers: [(String, String)] = []) async throws {
        let response = HTTP3Response(
            status: 200,
            headers: headers
        )
        try await _sendResponse(response)
    }

    /// Rejects the Extended CONNECT request with an error status.
    ///
    /// After rejection, the CONNECT stream is closed.
    ///
    /// - Parameters:
    ///   - status: HTTP status code (e.g., 400, 403, 501)
    ///   - headers: Additional response headers (default: empty)
    ///   - body: Optional response body (default: empty)
    /// - Throws: If sending the response fails
    public func reject(
        status: Int,
        headers: [(String, String)] = [],
        body: Data = Data()
    ) async throws {
        let response = HTTP3Response(
            status: status,
            headers: headers,
            body: body
        )
        try await _sendResponse(response)
        // Close the stream after rejection
        try await stream.closeWrite()
    }
}

public actor HTTP3Connection {
    private static let logger = QuiverLogging.logger(label: "http3.connection")

    // MARK: - Types

    /// The role of this endpoint in the HTTP/3 connection
    public enum Role: Sendable {
        /// Client role — initiates requests
        case client
        /// Server role — responds to requests
        case server
    }

    /// Connection states
    enum State: Sendable, Hashable {
        /// Connection not yet initialized
        case idle
        /// Initialization in progress (control streams being opened)
        case initializing
        /// Connection is ready for requests
        case ready
        /// GOAWAY received/sent — no new requests
        case goingAway(lastStreamID: UInt64)
        /// Connection is closed
        case closed
    }

    // MARK: - Properties

    /// The underlying QUIC connection
    let quicConnection: any QUICConnectionProtocol

    /// Our role (client or server)
    let role: Role

    /// Local HTTP/3 settings
    let localSettings: HTTP3Settings

    /// Peer's HTTP/3 settings (set after SETTINGS received)
    var peerSettings: HTTP3Settings?

    /// Connection state
    var state: State = .idle

    /// QPACK encoder (for outgoing headers)
    let qpackEncoder: QPACKEncoder

    /// QPACK decoder (for incoming headers)
    let qpackDecoder: QPACKDecoder

    // MARK: - Streams

    /// Our local control stream
    var localControlStream: (any QUICStreamProtocol)?

    /// Peer's control stream
    var peerControlStream: (any QUICStreamProtocol)?

    /// Our local QPACK encoder stream
    var localQPACKEncoderStream: (any QUICStreamProtocol)?

    /// Our local QPACK decoder stream
    var localQPACKDecoderStream: (any QUICStreamProtocol)?

    /// Peer's QPACK encoder stream
    var peerQPACKEncoderStream: (any QUICStreamProtocol)?

    /// Peer's QPACK decoder stream
    var peerQPACKDecoderStream: (any QUICStreamProtocol)?

    /// GOAWAY stream ID (last stream/push ID to process)
    private var goawayStreamID: UInt64?

    // MARK: - WebTransport Session Registry

    /// Active WebTransport sessions, keyed by session ID (= CONNECT stream ID).
    private var webTransportSessions: [UInt64: WebTransportSession] = [:]

    /// Continuation for delivering newly created WebTransport sessions.
    private var incomingWebTransportSessionContinuation: AsyncStream<WebTransportSession>.Continuation?

    /// Stream of incoming WebTransport sessions (server-side).
    ///
    /// When an Extended CONNECT with `:protocol = webtransport` is accepted
    /// and a `WebTransportSession` is created, it is delivered here.
    ///
    /// ## Usage
    ///
    /// ```swift
    /// for await session in connection.incomingWebTransportSessions {
    ///     Task { await handleSession(session) }
    /// }
    /// ```
    public private(set) var incomingWebTransportSessions: AsyncStream<WebTransportSession>

    /// Task for the datagram routing loop (routes QUIC DATAGRAMs to WT sessions).
    private var datagramRoutingTask: Task<Void, Never>?

    /// The next client-initiated bidirectional stream ID to use
    /// Client bidi streams: 0, 4, 8, 12, ...
    /// Server bidi streams: 1, 5, 9, 13, ...
    private var nextStreamID: UInt64

    /// Whether the peer's control stream has been received
    private var peerControlStreamReceived: Bool = false

    /// Whether the peer's QPACK encoder stream has been received
    private var peerQPACKEncoderStreamReceived: Bool = false

    /// Whether the peer's QPACK decoder stream has been received
    private var peerQPACKDecoderStreamReceived: Bool = false

    // MARK: - Priority Tracking (RFC 9218)

    /// Stream priorities received via PRIORITY_UPDATE frames.
    ///
    /// Maps stream IDs to their dynamically-updated priorities.
    /// These override the initial priority from the Priority header.
    private var streamPriorities: [UInt64: StreamPriority] = [:]

    /// Pending PRIORITY_UPDATE frames for streams not yet created.
    ///
    /// Per RFC 9218 Section 7, a client can send PRIORITY_UPDATE for
    /// a stream ID before that stream is opened. The server stores
    /// these and applies them when the stream is created.
    private var pendingPriorityUpdates: [UInt64: StreamPriority] = [:]

    // MARK: - Priority Scheduling (RFC 9218)

    /// Stream scheduler for priority-ordered data sending.
    ///
    /// Implements RFC 9218 Extensible Priority Scheme scheduling:
    /// - Urgency levels 0-7 (lower = higher priority)
    /// - Incremental vs non-incremental delivery
    /// - Round-robin within same urgency level
    private var streamScheduler: StreamScheduler = StreamScheduler()

    /// Active response streams awaiting data send, keyed by stream ID.
    ///
    /// When a server has multiple concurrent responses to send, the
    /// scheduler determines the order based on priority.
    private var activeResponseStreams: [UInt64: StreamPriority] = [:]

    // MARK: - Incoming Request Handling

    /// Continuation for the incoming requests stream
    private var incomingRequestsContinuation: AsyncStream<HTTP3RequestContext>.Continuation?

    /// The async stream of incoming requests (server-side)
    public private(set) var incomingRequests: AsyncStream<HTTP3RequestContext>

    // MARK: - Incoming Extended CONNECT Handling (RFC 9220)

    /// Continuation for the incoming Extended CONNECT requests stream
    private var incomingExtendedConnectContinuation: AsyncStream<ExtendedConnectContext>.Continuation?

    /// The async stream of incoming Extended CONNECT requests (server-side).
    ///
    /// Extended CONNECT requests (those with a `:protocol` pseudo-header)
    /// are routed here instead of to `incomingRequests`. This allows
    /// separate handling of WebTransport and other tunneled protocols.
    ///
    /// ## Usage
    ///
    /// ```swift
    /// for await context in connection.incomingExtendedConnect {
    ///     if context.request.isWebTransportConnect {
    ///         try await context.accept()
    ///         // Use context.stream for WebTransport session
    ///     } else {
    ///         try await context.reject(status: 501)
    ///     }
    /// }
    /// ```
    public private(set) var incomingExtendedConnect: AsyncStream<ExtendedConnectContext>

    // MARK: - Initialization

    /// Creates an HTTP/3 connection manager.
    ///
    /// - Parameters:
    ///   - quicConnection: The underlying QUIC connection
    ///   - role: The role of this endpoint (client or server)
    ///   - settings: Local HTTP/3 settings (default: literal-only QPACK)
    public init(
        quicConnection: any QUICConnectionProtocol,
        role: Role,
        settings: HTTP3Settings = HTTP3Settings()
    ) {
        self.quicConnection = quicConnection
        self.role = role
        self.localSettings = settings
        self.qpackEncoder = QPACKEncoder()
        self.qpackDecoder = QPACKDecoder()

        // Client bidi streams start at 0, server at 1
        self.nextStreamID = (role == .client) ? 0 : 1

        // Create the incoming requests stream
        var continuation: AsyncStream<HTTP3RequestContext>.Continuation!
        self.incomingRequests = AsyncStream { cont in
            continuation = cont
        }
        self.incomingRequestsContinuation = continuation

        // Create the incoming Extended CONNECT stream
        var extConnectContinuation: AsyncStream<ExtendedConnectContext>.Continuation!
        self.incomingExtendedConnect = AsyncStream { cont in
            extConnectContinuation = cont
        }
        self.incomingExtendedConnectContinuation = extConnectContinuation

        // Create the incoming WebTransport sessions stream
        var wtSessionContinuation: AsyncStream<WebTransportSession>.Continuation!
        self.incomingWebTransportSessions = AsyncStream { cont in
            wtSessionContinuation = cont
        }
        self.incomingWebTransportSessionContinuation = wtSessionContinuation
    }

    deinit {
        incomingRequestsContinuation?.finish()
        incomingExtendedConnectContinuation?.finish()
        incomingWebTransportSessionContinuation?.finish()
        datagramRoutingTask?.cancel()
    }

    // MARK: - Connection Lifecycle

    /// Initializes the HTTP/3 connection.
    ///
    /// Opens the control stream (with SETTINGS), QPACK encoder and decoder
    /// streams, and starts processing incoming streams in the background.
    ///
    /// - Throws: `HTTP3Error` if initialization fails
    public func initialize() async throws {
        guard state == .idle else {
            throw HTTP3Error(code: .internalError, reason: "Connection already initialized")
        }

        state = .initializing

        // 0. Wait for QUIC handshake to complete before opening streams.
        //    Peer transport parameters (including stream limits) are only
        //    available after the handshake finishes.  Without this wait,
        //    openUniStream() will fail with streamLimitReached because the
        //    peer's max_streams values are still 0.
        let handshakeDeadline = ContinuousClock.now.advanced(by: .seconds(30))
        while !quicConnection.isEstablished {
            if ContinuousClock.now >= handshakeDeadline {
                state = .closed
                throw HTTP3Error(
                    code: .internalError,
                    reason: "QUIC handshake did not complete within timeout"
                )
            }
            try await Task.sleep(for: .milliseconds(10))
        }

        // 1. Open control stream and send SETTINGS
        try await openControlStream()

        // 2. Open QPACK encoder and decoder streams (required even in literal-only mode)
        try await openQPACKStreams()

        // 3. Start background task to process incoming streams
        let connection = self.quicConnection
        Task { [weak self] in
            await self?.processIncomingStreams(from: connection)
        }
    }

    /// Waits until the connection transitions to the ready state.
    ///
    /// The connection is ready once peer SETTINGS have been received.
    /// This typically happens during the initial stream exchange.
    ///
    /// - Parameter timeout: Maximum time to wait (default: 10 seconds)
    /// - Throws: `HTTP3Error` if the timeout expires or connection closes
    public func waitForReady(timeout: Duration = .seconds(10)) async throws {
        let deadline = ContinuousClock.now + timeout

        while ContinuousClock.now < deadline {
            if state == .ready || peerSettings != nil {
                state = .ready
                return
            }
            if case .closed = state {
                throw HTTP3Error(code: .internalError, reason: "Connection closed before ready")
            }
            try await Task.sleep(for: .milliseconds(10))
        }

        throw HTTP3Error(code: .missingSettings, reason: "Timed out waiting for peer SETTINGS")
    }

    /// Sends a GOAWAY frame to initiate graceful shutdown.
    ///
    /// For a client, `lastStreamID` is the last push ID to accept.
    /// For a server, `lastStreamID` is the last client-initiated
    /// stream ID that was or might be processed.
    ///
    /// - Parameter lastStreamID: The last stream/push ID to process
    /// - Throws: `HTTP3Error` if the GOAWAY frame cannot be sent
    public func goaway(lastStreamID: UInt64) async throws {
        guard let controlStream = localControlStream else {
            throw HTTP3Error(code: .closedCriticalStream, reason: "Control stream not open")
        }

        let frame = HTTP3Frame.goaway(streamID: lastStreamID)
        let encoded = HTTP3FrameCodec.encode(frame)
        try await controlStream.write(encoded)

        state = .goingAway(lastStreamID: lastStreamID)
    }

    /// Closes the HTTP/3 connection.
    ///
    /// Sends a GOAWAY if not already sent, then closes the underlying
    /// QUIC connection.
    ///
    /// - Parameter error: Optional HTTP/3 error code (default: no error)
    public func close(error: HTTP3ErrorCode = .noError) async {
        // Send GOAWAY if we haven't already
        if case .ready = state {
            let lastID: UInt64 = (role == .server) ? nextStreamID : 0
            try? await goaway(lastStreamID: lastID)
        }

        state = .closed
        incomingRequestsContinuation?.finish()
        incomingExtendedConnectContinuation?.finish()
        incomingWebTransportSessionContinuation?.finish()
        datagramRoutingTask?.cancel()
        datagramRoutingTask = nil

        // Close all active WebTransport sessions
        for (_, session) in webTransportSessions {
            await session.abort(applicationErrorCode: 0)
        }
        webTransportSessions.removeAll()

        // Close the QUIC connection
        await quicConnection.close(applicationError: error.rawValue, reason: error.reason)
    }

    // MARK: - Request/Response (Client)

    /// Sends an HTTP/3 request and waits for the response.
    ///
    /// Opens a new bidirectional QUIC stream, sends the HEADERS and
    /// optional DATA frames, closes the write side, and reads the
    /// response frames.
    ///
    /// - Parameter request: The HTTP/3 request to send
    /// - Returns: The HTTP/3 response
    /// - Throws: `HTTP3Error` if the request fails
    public func sendRequest(_ request: HTTP3Request) async throws -> HTTP3Response {
        guard state == .ready || state == .initializing else {
            throw HTTP3Error(code: .internalError, reason: "Connection not ready (state: \(state))")
        }

        // Check GOAWAY — don't send new requests past the goaway point
        if let goawayID = goawayStreamID, nextStreamID > goawayID {
            throw HTTP3Error(code: .requestRejected, reason: "Stream ID exceeds GOAWAY limit")
        }

        // Open a new bidirectional stream
        let stream = try await quicConnection.openStream()

        // Track the stream ID and advance to the next one
        // Client bidi streams: 0, 4, 8, 12, ... (increment by 4)
        // Server bidi streams: 1, 5, 9, 13, ... (increment by 4)
        nextStreamID += 4

        // Encode headers using QPACK
        let headerList = request.toHeaderList()
        let encodedHeaders = qpackEncoder.encode(headerList)

        // Send HEADERS frame
        let headersFrame = HTTP3Frame.headers(encodedHeaders)
        let headersData = HTTP3FrameCodec.encode(headersFrame)
        try await stream.write(headersData)

        // Send DATA frame if there's a body
        if let body = request.body, !body.isEmpty {
            let dataFrame = HTTP3Frame.data(body)
            let dataData = HTTP3FrameCodec.encode(dataFrame)
            try await stream.write(dataData)
        }

        // Send trailers (if any) — RFC 9114 §4.1
        if let trailers = request.trailers, !trailers.isEmpty {
            let encodedTrailers = qpackEncoder.encode(trailers)
            let trailersFrame = HTTP3Frame.headers(encodedTrailers)
            let trailersData = HTTP3FrameCodec.encode(trailersFrame)
            try await stream.write(trailersData)
        }

        // Close the write side (FIN)
        try await stream.closeWrite()

        // Read response
        return try await readResponse(from: stream)
    }

    // MARK: - Extended CONNECT (RFC 9220)

    /// Sends an Extended CONNECT request and returns the response along
    /// with the open stream.
    ///
    /// Unlike `sendRequest()`, this method does NOT close the write side
    /// of the stream after sending headers. If the server responds with
    /// 200, the stream remains open for the session lifetime (e.g.,
    /// WebTransport bidirectional data exchange).
    ///
    /// Per RFC 9220 §3, Extended CONNECT requires:
    /// - The peer must have sent `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`
    /// - The request must include `:protocol`, `:scheme`, `:authority`, `:path`
    ///
    /// - Parameter request: An Extended CONNECT request (must have `connectProtocol` set)
    /// - Returns: A tuple of the HTTP/3 response and the open QUIC stream.
    ///   If the response is 200, the stream is ready for session use.
    ///   If the response is an error, the stream has been closed.
    /// - Throws: `HTTP3Error` if the request fails or preconditions aren't met
    ///
    /// ## Usage
    ///
    /// ```swift
    /// let request = HTTP3Request.webTransportConnect(authority: "example.com", path: "/wt")
    /// let (response, stream) = try await connection.sendExtendedConnect(request)
    /// if response.isSuccess {
    ///     // stream is open — use for WebTransport session
    /// }
    /// ```
    public func sendExtendedConnect(_ request: HTTP3Request) async throws -> (response: HTTP3Response, stream: any QUICStreamProtocol) {
        guard request.isExtendedConnect else {
            throw HTTP3Error(
                code: .internalError,
                reason: "sendExtendedConnect requires a request with connectProtocol set"
            )
        }

        guard state == .ready || state == .initializing else {
            throw HTTP3Error(code: .internalError, reason: "Connection not ready (state: \(state))")
        }

        // Verify peer supports Extended CONNECT
        if let peer = peerSettings, !peer.enableConnectProtocol {
            throw HTTP3Error(
                code: .settingsError,
                reason: "Peer has not enabled SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220 §3)"
            )
        }

        // Check GOAWAY
        if let goawayID = goawayStreamID, nextStreamID > goawayID {
            throw HTTP3Error(code: .requestRejected, reason: "Stream ID exceeds GOAWAY limit")
        }

        // Open a new bidirectional stream
        let stream = try await quicConnection.openStream()
        nextStreamID += 4

        // Encode and send headers
        let headerList = request.toHeaderList()
        let encodedHeaders = qpackEncoder.encode(headerList)
        let headersFrame = HTTP3Frame.headers(encodedHeaders)
        let headersData = HTTP3FrameCodec.encode(headersFrame)
        try await stream.write(headersData)

        // NOTE: We do NOT close the write side here.
        // The stream stays open for the Extended CONNECT session lifetime.

        // Read ONLY the response headers — do NOT wait for body/FIN.
        // Extended CONNECT keeps the stream open for the session lifetime
        // (capsules, WebTransport data, etc.), so readResponse() would
        // block forever waiting for FIN and eventually hit idle timeout.
        let response = try await readExtendedConnectResponse(from: stream)

        // If the server rejected, close the stream
        if !response.isSuccess {
            try? await stream.closeWrite()
        }

        return (response, stream)
    }

    // MARK: - Response Reading (Client)

    /// Reads the response HEADERS frame from an Extended CONNECT stream.
    ///
    /// Unlike `readResponse()`, this method returns as soon as the first
    /// HEADERS frame is decoded — it does NOT wait for DATA frames, trailers,
    /// or FIN. Extended CONNECT streams (RFC 9220) stay open for the session
    /// lifetime (e.g. WebTransport), so waiting for FIN would block forever
    /// and eventually hit the idle timeout.
    ///
    /// Any data beyond the HEADERS frame is left for the caller to read
    /// (e.g. capsules on the CONNECT stream).
    private func readExtendedConnectResponse(from stream: any QUICStreamProtocol) async throws -> HTTP3Response {
        var buffer = Data()

        while true {
            let data: Data
            do {
                data = try await stream.read()
            } catch {
                // Stream ended or error before we got headers
                throw HTTP3Error.messageError("Extended CONNECT stream closed before response HEADERS received")
            }

            if data.isEmpty {
                throw HTTP3Error.messageError("Extended CONNECT stream FIN before response HEADERS received")
            }

            buffer.append(data)

            // Try to decode frames from what we have so far
            let (frames, _) = try decodeFramesFromBuffer(&buffer)

            for frame in frames {
                if HTTP3ReservedFrameType.isReserved(frame.frameType) {
                    throw HTTP3Error.frameUnexpected(
                        "Reserved frame type 0x\(String(frame.frameType, radix: 16)) (HTTP/2 only)"
                    )
                }

                switch frame {
                case .headers(let headerBlock):
                    let headers = try qpackDecoder.decode(headerBlock)
                    let response = try HTTP3Response.fromHeaderList(headers)
                    return response

                case .unknown:
                    // Ignore unknown frames (forward compatibility)
                    continue

                default:
                    throw HTTP3Error.frameUnexpected(
                        "Expected HEADERS frame for Extended CONNECT response, got frame type 0x\(String(frame.frameType, radix: 16))"
                    )
                }
            }
            // If no complete HEADERS frame decoded yet, loop and read more data
        }
    }

    /// Reads an HTTP/3 response from a request stream with buffered framing.
    ///
    /// Accumulates data across multiple reads and parses complete HTTP/3
    /// frames from the buffer, tolerating fragmentation at frame boundaries.
    private func readResponse(from stream: any QUICStreamProtocol) async throws -> HTTP3Response {
        var responseHeaders: [(name: String, value: String)]?
        var responseTrailers: [(String, String)]?
        var bodyData = Data()
        var headersReceived = false
        var buffer = Data()

        // Read frames from the stream with buffering
        while true {
            let data: Data
            do {
                data = try await stream.read()
            } catch {
                // Stream ended (FIN received) or error
                break
            }

            if data.isEmpty {
                // FIN received
                break
            }

            buffer.append(data)

            // Decode as many complete frames as possible from the buffer
            let (frames, _) = try decodeFramesFromBuffer(&buffer)

            for frame in frames {
                // Check for reserved HTTP/2 frame types (RFC 9114 Section 7.2.8)
                if HTTP3ReservedFrameType.isReserved(frame.frameType) {
                    throw HTTP3Error.frameUnexpected(
                        "Reserved frame type 0x\(String(frame.frameType, radix: 16)) (HTTP/2 only)"
                    )
                }

                switch frame {
                case .headers(let headerBlock):
                    if headersReceived {
                        // Trailing HEADERS frame (RFC 9114 §4.1)
                        let decoded = try qpackDecoder.decode(headerBlock)
                        responseTrailers = try validateTrailers(decoded)
                        continue
                    }
                    responseHeaders = try qpackDecoder.decode(headerBlock)
                    headersReceived = true

                case .data(let payload):
                    guard headersReceived else {
                        throw HTTP3Error.frameUnexpected("DATA frame before HEADERS")
                    }
                    bodyData.append(payload)

                case .unknown:
                    // Ignore unknown frames (forward compatibility)
                    continue

                default:
                    // Other frame types on request streams are errors
                    if !frame.isAllowedOnRequestStream {
                        throw HTTP3Error.frameUnexpected(
                            "Frame type 0x\(String(frame.frameType, radix: 16)) not allowed on request stream"
                        )
                    }
                }
            }
        }

        guard let headers = responseHeaders else {
            throw HTTP3Error.messageError("No HEADERS frame received in response")
        }

        var response = try HTTP3Response.fromHeaderList(headers)
        response.body = bodyData
        response.trailers = responseTrailers
        return response
    }

    // MARK: - Control Stream Setup

    /// Opens our local control stream and sends the initial SETTINGS frame.
    private func openControlStream() async throws {
        let stream = try await quicConnection.openUniStream()
        localControlStream = stream

        // Write stream type (Control = 0x00)
        let streamTypeData = HTTP3StreamType.control.encode()
        try await stream.write(streamTypeData)

        // Write SETTINGS frame
        let settingsFrame = HTTP3Frame.settings(localSettings)
        let settingsData = HTTP3FrameCodec.encode(settingsFrame)
        try await stream.write(settingsData)
    }

    /// Opens QPACK encoder and decoder unidirectional streams.
    ///
    /// These streams are required even in literal-only mode (RFC 9204 Section 4.2).
    /// In literal-only mode, no instructions are sent on these streams.
    private func openQPACKStreams() async throws {
        // Open QPACK encoder stream
        let encoderStream = try await quicConnection.openUniStream()
        localQPACKEncoderStream = encoderStream
        let encoderTypeData = HTTP3StreamType.qpackEncoder.encode()
        try await encoderStream.write(encoderTypeData)

        // Open QPACK decoder stream
        let decoderStream = try await quicConnection.openUniStream()
        localQPACKDecoderStream = decoderStream
        let decoderTypeData = HTTP3StreamType.qpackDecoder.encode()
        try await decoderStream.write(decoderTypeData)
    }

    // MARK: - Incoming Stream Processing

    /// Processes incoming QUIC streams (both bidirectional and unidirectional).
    ///
    /// Bidirectional streams are request streams. Unidirectional streams
    /// are classified by their stream type byte and routed accordingly.
    private func processIncomingStreams(from connection: any QUICConnectionProtocol) async {
        Self.logger.debug("processIncomingStreams started (role=\(role))")
        for await stream in connection.incomingStreams {
            Self.logger.trace("Received incoming stream id=\(stream.id), isUni=\(stream.isUnidirectional) (role=\(role))")
            if stream.isUnidirectional {
                Task { [weak self] in
                    Self.logger.trace("handleIncomingUniStream task starting for stream \(stream.id)")
                    await self?.handleIncomingUniStream(stream)
                    Self.logger.trace("handleIncomingUniStream task finished for stream \(stream.id)")
                }
            } else {
                // Bidirectional stream — could be HTTP/3 request or WebTransport bidi
                Task { [weak self] in
                    Self.logger.trace("handleIncomingBidiStream task starting for stream \(stream.id)")
                    await self?.handleIncomingBidiStream(stream)
                    Self.logger.trace("handleIncomingBidiStream task finished for stream \(stream.id)")
                }
            }
        }
        Self.logger.debug("processIncomingStreams ended (role=\(role))")
    }

    // MARK: - Unidirectional Stream Handling

    /// Handles an incoming unidirectional stream by reading its type byte
    /// and routing it to the appropriate handler.
    ///
    /// The stream type is sent as the first varint on the stream. Any
    /// remaining bytes after the type varint are forwarded to the handler
    /// as initial buffered data to avoid data loss.
    ///
    /// WebTransport unidirectional streams use stream type 0x54. When
    /// detected, the session ID varint is read and the stream is routed
    /// to the corresponding `WebTransportSession`.
    private func handleIncomingUniStream(_ stream: any QUICStreamProtocol) async {
        do {
            // Read the stream type (first varint on the stream)
            // We read a small amount — the varint is typically 1 byte,
            // but the read may also contain subsequent frame data.
            Self.logger.trace("handleIncomingUniStream: reading type from stream \(stream.id)")
            let typeData = try await stream.read()
            Self.logger.trace("handleIncomingUniStream: got \(typeData.count) bytes from stream \(stream.id): \(typeData.map { String(format: "%02x", $0) }.joined())")
            guard !typeData.isEmpty else {
                Self.logger.trace("handleIncomingUniStream: empty data from stream \(stream.id), returning")
                return
            }

            guard let (streamTypeValue, consumed) = try HTTP3StreamType.decode(from: typeData) else {
                Self.logger.warning("handleIncomingUniStream: failed to decode stream type from stream \(stream.id)")
                return
            }

            // Extract any remaining data after the stream type varint.
            // This data belongs to the first frame on the stream and
            // must NOT be discarded.
            let remainingData: Data
            if consumed < typeData.count {
                remainingData = Data(typeData.dropFirst(consumed))
            } else {
                remainingData = Data()
            }

            // Check for WebTransport unidirectional stream (type 0x54)
            if WebTransportStreamClassification.isWebTransportStream(streamTypeValue) {
                Self.logger.debug("handleIncomingUniStream: stream \(stream.id) is WebTransport uni stream (type 0x54)")
                await routeWebTransportUniStream(stream, initialData: remainingData)
                return
            }

            let classification = HTTP3StreamClassification.classify(streamTypeValue)
            Self.logger.trace("handleIncomingUniStream: stream \(stream.id) classified as \(classification), remainingData=\(remainingData.count) bytes")

            switch classification {
            case .known(let streamType):
                switch streamType {
                case .control:
                    Self.logger.debug("handleIncomingUniStream: stream \(stream.id) is CONTROL stream, calling handleIncomingControlStream")
                    try await handleIncomingControlStream(stream, remainingData: remainingData)
                case .qpackEncoder:
                    await handleIncomingQPACKEncoderStream(stream)
                case .qpackDecoder:
                    await handleIncomingQPACKDecoderStream(stream)
                case .push:
                    if role == .server {
                        // Servers don't receive push streams
                        await stream.reset(
                            errorCode: HTTP3ErrorCode.streamCreationError.rawValue
                        )
                    }
                    // Client-side push handling not implemented
                }

            case .grease:
                // GREASE streams must be silently ignored
                // Drain and discard the stream
                _ = try? await stream.read()

            case .unknown:
                // Unknown stream types must be silently ignored
                _ = try? await stream.read()
            }
        } catch {
            // Stream read error — log and ignore
        }
    }

    /// Handles the peer's incoming control stream.
    ///
    /// Validates that only one control stream exists, reads the SETTINGS
    /// frame (with buffering to tolerate fragmentation), and then continues
    /// reading control frames (GOAWAY, etc.).
    ///
    /// - Parameters:
    ///   - stream: The QUIC stream for the peer's control stream
    ///   - remainingData: Any data read after the stream type varint
    ///     (may contain part or all of the first SETTINGS frame)
    private func handleIncomingControlStream(
        _ stream: any QUICStreamProtocol,
        remainingData: Data
    ) async throws {
        Self.logger.debug("handleIncomingControlStream: stream \(stream.id), remainingData=\(remainingData.count) bytes: \(remainingData.map { String(format: "%02x", $0) }.joined())")
        // Only one control stream per peer
        guard !peerControlStreamReceived else {
            throw HTTP3Error(
                code: .streamCreationError,
                reason: "Duplicate peer control stream"
            )
        }

        peerControlStreamReceived = true
        peerControlStream = stream

        // Start a buffer with any leftover data from the stream type read
        var buffer = remainingData

        // Read the first frame — MUST be SETTINGS (RFC 9114 Section 6.2.1)
        // The SETTINGS frame may arrive across multiple reads, so we buffer
        // until a complete frame is available.
        Self.logger.debug("handleIncomingControlStream: reading SETTINGS frame (buffer=\(buffer.count) bytes)")
        let settingsFrame = try await readNextFrame(from: stream, buffer: &buffer)
        Self.logger.trace("handleIncomingControlStream: got frame: \(settingsFrame)")

        guard case .settings(let settings) = settingsFrame else {
            Self.logger.warning("handleIncomingControlStream: first frame is NOT settings: \(settingsFrame)")
            throw HTTP3Error.missingSettings
        }

        Self.logger.info("handleIncomingControlStream: received peer SETTINGS: \(settings)")
        peerSettings = settings

        // Transition to ready state
        if state == .initializing {
            state = .ready
            Self.logger.debug("handleIncomingControlStream: state -> ready")
        }

        // Continue reading control frames
        await readControlFrames(from: stream, initialBuffer: buffer)
    }

    /// Reads and processes control frames from the peer's control stream.
    ///
    /// This runs for the lifetime of the connection, processing GOAWAY
    /// and other control frames as they arrive. Uses buffered reading
    /// to tolerate frame fragmentation across QUIC stream reads.
    ///
    /// - Parameters:
    ///   - stream: The peer's control stream
    ///   - initialBuffer: Any unconsumed bytes from previous reads
    private func readControlFrames(
        from stream: any QUICStreamProtocol,
        initialBuffer: Data = Data()
    ) async {
        var buffer = initialBuffer

        while true {
            // First, try to decode frames already in the buffer
            do {
                let (frames, _) = try decodeFramesFromBuffer(&buffer)

                for frame in frames {
                    // Check for reserved HTTP/2 frame types
                    if HTTP3ReservedFrameType.isReserved(frame.frameType) {
                        await close(error: .frameUnexpected)
                        return
                    }

                    switch frame {
                    case .goaway(let streamID):
                        goawayStreamID = streamID
                        state = .goingAway(lastStreamID: streamID)

                    case .settings:
                        // Duplicate SETTINGS is a connection error
                        await close(error: .frameUnexpected)
                        return

                    case .maxPushID:
                        // Only valid if we're a server
                        if role != .server {
                            await close(error: .frameUnexpected)
                            return
                        }

                    case .priorityUpdateRequest(let streamID, let priority):
                        // RFC 9218: Dynamic reprioritization of request streams
                        // Only valid from a client (received by server)
                        if role == .server {
                            handlePriorityUpdate(streamID: streamID, priority: priority)
                        } else {
                            // Clients shouldn't receive request PRIORITY_UPDATE
                            await close(error: .frameUnexpected)
                            return
                        }

                    case .priorityUpdatePush(let pushID, let priority):
                        // RFC 9218: Dynamic reprioritization of push streams
                        // Only valid from a client (received by server)
                        if role == .server {
                            handlePriorityUpdate(streamID: pushID, priority: priority)
                        } else {
                            // Clients shouldn't receive push PRIORITY_UPDATE
                            await close(error: .frameUnexpected)
                            return
                        }

                    case .cancelPush:
                        // Push cancellation — not implemented yet
                        break

                    case .data, .headers, .pushPromise:
                        // These frames are NOT allowed on control streams
                        await close(error: .frameUnexpected)
                        return

                    case .unknown:
                        // Unknown frames on control stream are allowed
                        break
                    }
                }
            } catch {
                // Malformed frame on control stream
                await close(error: .frameError)
                return
            }

            // Read more data from the stream
            do {
                let data = try await stream.read()
                if data.isEmpty {
                    // Control stream closed — this is a connection error
                    await close(error: .closedCriticalStream)
                    return
                }
                buffer.append(data)
            } catch {
                // Error reading from control stream
                await close(error: .closedCriticalStream)
                return
            }
        }
    }

    // MARK: - QPACK Stream Handling

    /// Handles the peer's incoming QPACK encoder stream.
    ///
    /// In literal-only mode, no instructions are expected. The stream
    /// is drained and discarded.
    private func handleIncomingQPACKEncoderStream(_ stream: any QUICStreamProtocol) async {
        guard !peerQPACKEncoderStreamReceived else {
            // Duplicate — connection error
            await close(error: .streamCreationError)
            return
        }

        peerQPACKEncoderStreamReceived = true
        peerQPACKEncoderStream = stream

        // In literal-only mode, drain the stream
        do {
            while true {
                let data = try await stream.read()
                if data.isEmpty { break }
                // In full QPACK mode, we'd process encoder instructions here
            }
        } catch {
            // Stream closed or error — for critical streams this is an error
            // but in literal-only mode we tolerate it
        }
    }

    /// Handles the peer's incoming QPACK decoder stream.
    ///
    /// In literal-only mode, no instructions are expected. The stream
    /// is drained and discarded.
    private func handleIncomingQPACKDecoderStream(_ stream: any QUICStreamProtocol) async {
        guard !peerQPACKDecoderStreamReceived else {
            // Duplicate — connection error
            await close(error: .streamCreationError)
            return
        }

        peerQPACKDecoderStreamReceived = true
        peerQPACKDecoderStream = stream

        // In literal-only mode, drain the stream
        do {
            while true {
                let data = try await stream.read()
                if data.isEmpty { break }
                // In full QPACK mode, we'd process decoder instructions here
            }
        } catch {
            // Stream closed or error
        }
    }

    // MARK: - Request Stream Handling (Server)

    /// Handles an incoming bidirectional (request) stream from a client.
    ///
    /// Reads HEADERS and DATA frames using buffered framing to tolerate
    /// fragmentation, constructs the HTTP/3 request, and delivers it
    /// to the incoming requests stream.
    // MARK: - Incoming Bidirectional Stream Routing

    /// Routes an incoming bidirectional stream to either WebTransport or
    /// HTTP/3 request handling.
    ///
    /// Per draft-ietf-webtrans-http3, a WebTransport bidirectional stream
    /// starts with a session ID varint. An HTTP/3 request stream starts
    /// with a HEADERS frame (type 0x01). We disambiguate by peeking at
    /// the first varint and checking if it matches a known active
    /// WebTransport session ID.
    private func handleIncomingBidiStream(_ stream: any QUICStreamProtocol) async {
        // If no WebTransport sessions are active, fast-path to HTTP/3 request handling
        guard !webTransportSessions.isEmpty else {
            await handleIncomingRequestStream(stream)
            return
        }

        // Read the first chunk of data from the stream
        let firstData: Data
        do {
            firstData = try await stream.read()
        } catch {
            return
        }
        guard !firstData.isEmpty else {
            return
        }

        // Try to decode the first varint — this is either a WT session ID
        // or an HTTP/3 frame type
        do {
            let (varint, consumed) = try Varint.decode(from: firstData)
            let candidateSessionID = varint.value

            // Check if this matches a known WebTransport session
            if let session = webTransportSessions[candidateSessionID] {
                Self.logger.debug("handleIncomingBidiStream: stream \(stream.id) matched WebTransport session \(candidateSessionID)")
                let remaining: Data
                if consumed < firstData.count {
                    remaining = Data(firstData.dropFirst(consumed))
                } else {
                    remaining = Data()
                }
                await session.deliverIncomingBidirectionalStream(stream, initialData: remaining)
                return
            }
        } catch {
            // Varint decode failed — treat as HTTP/3 request stream
        }

        // Not a WebTransport stream — handle as HTTP/3 request stream
        // with the already-read data as a prefix buffer
        await handleIncomingRequestStreamWithBuffer(stream, initialBuffer: firstData)
    }

    /// Handles an incoming HTTP/3 request stream with pre-read buffer data.
    ///
    /// This variant is called when `handleIncomingBidiStream` has already
    /// read the first chunk of data (to check for WebTransport session ID)
    /// and determined the stream is an HTTP/3 request stream.
    private func handleIncomingRequestStreamWithBuffer(
        _ stream: any QUICStreamProtocol,
        initialBuffer: Data
    ) async {
        do {
            var requestHeaders: [(name: String, value: String)]?
            var requestTrailers: [(String, String)]?
            var bodyData = Data()
            var headersReceived = false
            var buffer = initialBuffer
            var isExtendedConnect = false

            // Process any frames already in the initial buffer
            let (initialFrames, _) = try decodeFramesFromBuffer(&buffer)

            for frame in initialFrames {
                if HTTP3ReservedFrameType.isReserved(frame.frameType) {
                    throw HTTP3Error.frameUnexpected(
                        "Reserved frame type 0x\(String(frame.frameType, radix: 16)) (HTTP/2 only)"
                    )
                }

                switch frame {
                case .headers(let headerBlock):
                    if headersReceived {
                        let decoded = try qpackDecoder.decode(headerBlock)
                        requestTrailers = try validateTrailers(decoded)
                        continue
                    }
                    let decoded = try qpackDecoder.decode(headerBlock)
                    requestHeaders = decoded
                    headersReceived = true

                    if let headers = requestHeaders {
                        let hasProtocol = headers.contains(where: { $0.name == ":protocol" })
                        let isConnect = headers.contains(where: { $0.name == ":method" && $0.value == "CONNECT" })
                        if hasProtocol && isConnect {
                            isExtendedConnect = true
                        }
                    }

                    if isExtendedConnect {
                        break
                    }

                case .data(let payload):
                    guard headersReceived else {
                        throw HTTP3Error.frameUnexpected("DATA frame before HEADERS")
                    }
                    bodyData.append(payload)

                case .unknown:
                    continue

                default:
                    if !frame.isAllowedOnRequestStream {
                        throw HTTP3Error.frameUnexpected(
                            "Frame type 0x\(String(frame.frameType, radix: 16)) on request stream"
                        )
                    }
                }
            }

            // If we got the headers and it's Extended CONNECT, route it now
            if isExtendedConnect, let headers = requestHeaders {
                var request = try HTTP3Request.fromHeaderList(headers)
                request.body = bodyData.isEmpty ? nil : bodyData
                request.trailers = requestTrailers
                await routeExtendedConnectRequest(request, stream: stream)
                return
            }

            // If we got the full request from the initial buffer (unlikely but possible)
            // or need to continue reading
            if !isExtendedConnect {
                // Continue with regular request stream reading loop
                while true {
                    let data: Data
                    do {
                        data = try await stream.read()
                    } catch {
                        break
                    }

                    if data.isEmpty {
                        break
                    }

                    buffer.append(data)

                    let (frames, _) = try decodeFramesFromBuffer(&buffer)

                    for frame in frames {
                        if HTTP3ReservedFrameType.isReserved(frame.frameType) {
                            throw HTTP3Error.frameUnexpected(
                                "Reserved frame type 0x\(String(frame.frameType, radix: 16)) (HTTP/2 only)"
                            )
                        }

                        switch frame {
                        case .headers(let headerBlock):
                            if headersReceived {
                                let decoded = try qpackDecoder.decode(headerBlock)
                                requestTrailers = try validateTrailers(decoded)
                                continue
                            }
                            let decoded = try qpackDecoder.decode(headerBlock)
                            requestHeaders = decoded
                            headersReceived = true

                            if let headers = requestHeaders {
                                let hasProtocol = headers.contains(where: { $0.name == ":protocol" })
                                let isConnect = headers.contains(where: { $0.name == ":method" && $0.value == "CONNECT" })
                                if hasProtocol && isConnect {
                                    isExtendedConnect = true
                                }
                            }

                            if isExtendedConnect {
                                break
                            }

                        case .data(let payload):
                            guard headersReceived else {
                                throw HTTP3Error.frameUnexpected("DATA frame before HEADERS")
                            }
                            bodyData.append(payload)

                        case .unknown:
                            continue

                        default:
                            if !frame.isAllowedOnRequestStream {
                                throw HTTP3Error.frameUnexpected(
                                    "Frame type 0x\(String(frame.frameType, radix: 16)) on request stream"
                                )
                            }
                        }
                    }

                    if isExtendedConnect {
                        break
                    }
                }
            }

            guard let headers = requestHeaders else {
                await stream.reset(errorCode: HTTP3ErrorCode.requestIncomplete.rawValue)
                return
            }

            var request = try HTTP3Request.fromHeaderList(headers)
            request.body = bodyData.isEmpty ? nil : bodyData
            request.trailers = requestTrailers

            if request.isExtendedConnect {
                await routeExtendedConnectRequest(request, stream: stream)
                return
            }

            // Regular request handling (same as handleIncomingRequestStream)
            let priorityHeaderValue = headers.first(where: { $0.name.lowercased() == "priority" })?.value
            let initialPriority = StreamPriority.fromHeader(priorityHeaderValue)
            let effectivePriority: StreamPriority
            if let pendingPriority = pendingPriorityUpdates.removeValue(forKey: stream.id) {
                effectivePriority = pendingPriority
            } else if let dynamicPriority = streamPriorities[stream.id] {
                effectivePriority = dynamicPriority
            } else {
                effectivePriority = initialPriority
            }
            streamPriorities[stream.id] = effectivePriority

            let respondClosure: @Sendable (HTTP3Response) async throws -> Void = { [weak self] response in
                guard let self = self else { return }
                await self.sendResponse(response, on: stream)
            }

            let context = HTTP3RequestContext(
                request: request,
                streamID: stream.id,
                respond: respondClosure
            )
            incomingRequestsContinuation?.yield(context)

        } catch {
            await stream.reset(errorCode: HTTP3ErrorCode.messageError.rawValue)
        }
    }

    /// Routes an Extended CONNECT request to the appropriate handler.
    private func routeExtendedConnectRequest(
        _ request: HTTP3Request,
        stream: any QUICStreamProtocol
    ) async {
        guard localSettings.enableConnectProtocol else {
            Self.logger.warning(
                "Received Extended CONNECT but SETTINGS_ENABLE_CONNECT_PROTOCOL is not enabled"
            )
            await stream.reset(errorCode: HTTP3ErrorCode.settingsError.rawValue)
            return
        }

        let sendResponseClosure: @Sendable (HTTP3Response) async throws -> Void = { [weak self] response in
            guard let self = self else { return }
            await self.sendResponseHeadersOnly(response, on: stream)
        }

        let context = ExtendedConnectContext(
            request: request,
            streamID: stream.id,
            stream: stream,
            connection: self,
            sendResponse: sendResponseClosure
        )

        incomingExtendedConnectContinuation?.yield(context)
    }

    private func handleIncomingRequestStream(_ stream: any QUICStreamProtocol) async {
        do {
            // Read frames from the request stream with buffering
            var requestHeaders: [(name: String, value: String)]?
            var requestTrailers: [(String, String)]?
            var bodyData = Data()
            var headersReceived = false
            var buffer = Data()
            var isExtendedConnect = false

            // Accumulate data until FIN
            while true {
                let data: Data
                do {
                    data = try await stream.read()
                } catch {
                    break
                }

                if data.isEmpty {
                    break
                }

                buffer.append(data)

                // Decode as many complete frames as possible from the buffer
                let (frames, _) = try decodeFramesFromBuffer(&buffer)

                for frame in frames {
                    // Check for reserved HTTP/2 frame types (RFC 9114 Section 7.2.8)
                    if HTTP3ReservedFrameType.isReserved(frame.frameType) {
                        throw HTTP3Error.frameUnexpected(
                            "Reserved frame type 0x\(String(frame.frameType, radix: 16)) (HTTP/2 only)"
                        )
                    }

                    switch frame {
                    case .headers(let headerBlock):
                        if headersReceived {
                            // Trailing HEADERS frame (RFC 9114 §4.1)
                            let decoded = try qpackDecoder.decode(headerBlock)
                            requestTrailers = try validateTrailers(decoded)
                            continue
                        }
                        let decoded = try qpackDecoder.decode(headerBlock)
                        requestHeaders = decoded
                        headersReceived = true

                        // Check if this is an Extended CONNECT — if so, route
                        // immediately after HEADERS without waiting for FIN.
                        // Extended CONNECT streams stay open (no FIN expected).
                        if let headers = requestHeaders {
                            let hasProtocol = headers.contains(where: { $0.name == ":protocol" })
                            let isConnect = headers.contains(where: { $0.name == ":method" && $0.value == "CONNECT" })
                            if hasProtocol && isConnect {
                                isExtendedConnect = true
                            }
                        }

                        // If Extended CONNECT, break out of frame loop to route immediately
                        if isExtendedConnect {
                            break
                        }

                    case .data(let payload):
                        guard headersReceived else {
                            throw HTTP3Error.frameUnexpected("DATA frame before HEADERS")
                        }
                        bodyData.append(payload)

                    case .unknown:
                        // Ignore unknown frames
                        continue

                    default:
                        if !frame.isAllowedOnRequestStream {
                            throw HTTP3Error.frameUnexpected(
                                "Frame type 0x\(String(frame.frameType, radix: 16)) on request stream"
                            )
                        }
                    }
                }

                // If Extended CONNECT detected, stop reading more data
                if isExtendedConnect {
                    break
                }
            }

            guard let headers = requestHeaders else {
                // No HEADERS frame received — incomplete request
                await stream.reset(errorCode: HTTP3ErrorCode.requestIncomplete.rawValue)
                return
            }

            // Construct the request
            var request = try HTTP3Request.fromHeaderList(headers)
            request.body = bodyData.isEmpty ? nil : bodyData
            request.trailers = requestTrailers

            // --- Extended CONNECT handling (RFC 9220) ---
            if request.isExtendedConnect {
                // Verify that we advertised SETTINGS_ENABLE_CONNECT_PROTOCOL
                guard localSettings.enableConnectProtocol else {
                    Self.logger.warning(
                        "Received Extended CONNECT but SETTINGS_ENABLE_CONNECT_PROTOCOL is not enabled"
                    )
                    await stream.reset(errorCode: HTTP3ErrorCode.settingsError.rawValue)
                    return
                }

                // Create a response sender that does NOT close the stream
                let sendResponseClosure: @Sendable (HTTP3Response) async throws -> Void = { [weak self] response in
                    guard let self = self else { return }
                    await self.sendResponseHeadersOnly(response, on: stream)
                }

                let context = ExtendedConnectContext(
                    request: request,
                    streamID: stream.id,
                    stream: stream,
                    connection: self,
                    sendResponse: sendResponseClosure
                )

                // Deliver to the Extended CONNECT stream
                incomingExtendedConnectContinuation?.yield(context)
                return
            }

            // --- Regular request handling ---

            // Extract Priority header (RFC 9218 Section 5.1)
            let priorityHeaderValue = headers.first(where: { $0.name.lowercased() == "priority" })?.value
            let initialPriority = StreamPriority.fromHeader(priorityHeaderValue)

            // Check for pending PRIORITY_UPDATE (may have arrived before the stream)
            let effectivePriority: StreamPriority
            if let pendingPriority = pendingPriorityUpdates.removeValue(forKey: stream.id) {
                // PRIORITY_UPDATE overrides the header
                effectivePriority = pendingPriority
            } else if let dynamicPriority = streamPriorities[stream.id] {
                // Already received a PRIORITY_UPDATE for this stream
                effectivePriority = dynamicPriority
            } else {
                effectivePriority = initialPriority
            }

            // Track the stream priority
            streamPriorities[stream.id] = effectivePriority

            // Create the response handler
            let respondClosure: @Sendable (HTTP3Response) async throws -> Void = { [weak self] response in
                guard let self = self else { return }
                await self.sendResponse(response, on: stream)
            }

            let context = HTTP3RequestContext(
                request: request,
                streamID: stream.id,
                respond: respondClosure
            )

            // Deliver to the incoming requests stream
            incomingRequestsContinuation?.yield(context)

        } catch {
            // Error processing request — reset the stream
            await stream.reset(errorCode: HTTP3ErrorCode.messageError.rawValue)
        }
    }

    // MARK: - Priority Management (RFC 9218)

    /// Handles a PRIORITY_UPDATE frame received on the control stream.
    ///
    /// Updates the priority for the specified stream. If the stream
    /// hasn't been created yet, the priority is stored as pending.
    ///
    /// - Parameters:
    ///   - streamID: The stream ID being reprioritized
    ///   - priority: The new priority
    // MARK: - WebTransport Session Management

    /// Registers a WebTransport session in the connection's session registry.
    ///
    /// Once registered, incoming bidirectional and unidirectional streams
    /// with a matching session ID will be routed to the session automatically.
    /// Datagrams with a matching quarter stream ID will also be routed.
    ///
    /// - Parameter session: The WebTransport session to register
    public func registerWebTransportSession(_ session: WebTransportSession) {
        let sessionID = session.sessionID
        webTransportSessions[sessionID] = session

        Self.logger.info(
            "Registered WebTransport session",
            metadata: [
                "sessionID": "\(sessionID)",
                "activeSessions": "\(webTransportSessions.count)",
            ]
        )

        // Start datagram routing if this is the first session and settings support it
        if webTransportSessions.count == 1 && datagramRoutingTask == nil {
            startDatagramRouting()
        }

        // Deliver to the incoming sessions stream
        incomingWebTransportSessionContinuation?.yield(session)
    }

    /// Attempts to register a WebTransport session, enforcing the per-connection
    /// session quota from `localSettings.webtransportMaxSessions`.
    ///
    /// Unlike `registerWebTransportSession`, this method checks the quota
    /// before registering and returns `false` if the limit is reached.
    ///
    /// - Parameter session: The session to register
    /// - Returns: `true` if registered successfully, `false` if quota exceeded
    @discardableResult
    public func tryRegisterWebTransportSession(_ session: WebTransportSession) -> Bool {
        let maxSessions = localSettings.webtransportMaxSessions ?? 0
        if maxSessions > 0 && webTransportSessions.count >= Int(maxSessions) {
            Self.logger.warning(
                "WebTransport session quota exceeded",
                metadata: [
                    "sessionID": "\(session.sessionID)",
                    "activeSessions": "\(webTransportSessions.count)",
                    "limit": "\(maxSessions)",
                ]
            )
            return false
        }

        registerWebTransportSession(session)
        return true
    }

    /// Unregisters a WebTransport session from the connection's session registry.
    ///
    /// After unregistration, streams and datagrams for this session ID
    /// will no longer be routed to it. The session should already be
    /// closed or closing when this is called.
    ///
    /// - Parameter sessionID: The session ID to unregister
    @discardableResult
    public func unregisterWebTransportSession(_ sessionID: UInt64) -> WebTransportSession? {
        let session = webTransportSessions.removeValue(forKey: sessionID)

        if session != nil {
            Self.logger.info(
                "Unregistered WebTransport session",
                metadata: [
                    "sessionID": "\(sessionID)",
                    "activeSessions": "\(webTransportSessions.count)",
                ]
            )
        }

        // Stop datagram routing if no more sessions
        if webTransportSessions.isEmpty {
            datagramRoutingTask?.cancel()
            datagramRoutingTask = nil
        }

        return session
    }

    /// Returns the WebTransport session for the given session ID, if any.
    ///
    /// - Parameter sessionID: The session ID to look up
    /// - Returns: The session, or `nil` if no session is registered with that ID
    public func webTransportSession(for sessionID: UInt64) -> WebTransportSession? {
        webTransportSessions[sessionID]
    }

    /// The number of active WebTransport sessions on this connection.
    public var activeWebTransportSessionCount: Int {
        webTransportSessions.count
    }

    /// Creates a new WebTransport session from a server-side accepted
    /// Extended CONNECT context.
    ///
    /// This convenience method:
    /// 1. Creates a `WebTransportSession` from the accepted context
    /// 2. Registers it in the session registry
    /// 3. Starts the session (transitions to `.established`)
    ///
    /// - Parameters:
    ///   - context: The accepted Extended CONNECT context
    ///   - role: The role of this endpoint (default: `.server`)
    /// - Returns: The started `WebTransportSession`
    /// - Throws: `WebTransportError` if the session cannot be created or started
    public func createWebTransportSession(
        from context: ExtendedConnectContext,
        role: WebTransportSession.Role = .server
    ) async throws -> WebTransportSession {
        let session = WebTransportSession(
            connectStream: context.stream,
            connection: self,
            role: role
        )

        // Enforce per-connection session quota
        guard tryRegisterWebTransportSession(session) else {
            throw WebTransportError.maxSessionsExceeded(
                limit: localSettings.webtransportMaxSessions ?? 0
            )
        }

        try await session.start()

        return session
    }

    /// Creates a new client-side WebTransport session after a successful
    /// Extended CONNECT.
    ///
    /// - Parameters:
    ///   - connectStream: The QUIC stream from the Extended CONNECT
    ///   - response: The HTTP/3 response (should be 200)
    /// - Returns: The started `WebTransportSession`
    /// - Throws: `WebTransportError` if the response is not 200 or setup fails
    public func createClientWebTransportSession(
        connectStream: any QUICStreamProtocol,
        response: HTTP3Response
    ) async throws -> WebTransportSession {
        guard response.isSuccess else {
            throw WebTransportError.sessionRejected(
                status: response.status,
                reason: response.statusText
            )
        }

        let session = WebTransportSession(
            connectStream: connectStream,
            connection: self,
            role: .client
        )

        // Enforce per-connection session quota (client side)
        guard tryRegisterWebTransportSession(session) else {
            throw WebTransportError.maxSessionsExceeded(
                limit: localSettings.webtransportMaxSessions ?? 0
            )
        }

        try await session.start()

        return session
    }

    /// Finds the HTTP3Connection that owns a given QUIC stream ID.
    ///
    /// This is a convenience method for the `serve()` codepath where
    /// the WebTransportServer needs to find the correct HTTP3Connection
    /// for a given stream (e.g., from the Extended CONNECT handler).
    ///
    /// Since `ExtendedConnectContext` already carries a `connection` reference,
    /// this method is primarily useful for external lookup scenarios.
    ///
    /// - Parameter streamID: The QUIC stream ID to look up
    /// - Returns: `true` if this connection owns the stream
    public func ownsStream(_ streamID: UInt64) -> Bool {
        // Check if the stream matches our QUIC connection's stream ID space.
        // Client-initiated bidi streams are even (0, 4, 8, ...),
        // Server-initiated bidi streams are 1, 5, 9, ...
        // The connection owns any stream routed through it.
        webTransportSessions.keys.contains(streamID) ||
        localControlStream?.id == streamID
    }

    // MARK: - WebTransport Stream Routing

    /// Routes an incoming WebTransport unidirectional stream to the
    /// appropriate session.
    ///
    /// The stream type (0x54) has already been consumed. This method
    /// reads the session ID varint and delivers the stream to the
    /// matching session.
    private func routeWebTransportUniStream(
        _ stream: any QUICStreamProtocol,
        initialData: Data
    ) async {
        // We need the session ID varint from the initial data.
        // If the initial data is empty, read more from the stream.
        var data = initialData
        if data.isEmpty {
            do {
                let moreData = try await stream.read()
                guard !moreData.isEmpty else {
                    Self.logger.warning("WebTransport uni stream \(stream.id): empty after stream type")
                    return
                }
                data = moreData
            } catch {
                Self.logger.warning("WebTransport uni stream \(stream.id): read error: \(error)")
                return
            }
        }

        do {
            guard let (sessionID, remaining) = try WebTransportStreamFraming.readUnidirectionalSessionID(from: data) else {
                Self.logger.warning("WebTransport uni stream \(stream.id): insufficient data for session ID")
                await stream.reset(errorCode: WebTransportStreamErrorCode.toHTTP3ErrorCode(0))
                return
            }

            guard let session = webTransportSessions[sessionID] else {
                Self.logger.warning("WebTransport uni stream \(stream.id): unknown session ID \(sessionID)")
                await stream.reset(errorCode: WebTransportStreamErrorCode.toHTTP3ErrorCode(0))
                return
            }

            await session.deliverIncomingUnidirectionalStream(stream, initialData: remaining)

        } catch {
            Self.logger.warning("WebTransport uni stream \(stream.id): session ID decode error: \(error)")
            await stream.reset(errorCode: WebTransportStreamErrorCode.toHTTP3ErrorCode(0))
        }
    }

    // MARK: - WebTransport Datagram Routing

    /// Starts the background task that routes incoming QUIC DATAGRAMs
    /// to WebTransport sessions based on the quarter stream ID prefix.
    private func startDatagramRouting() {
        guard datagramRoutingTask == nil else { return }

        let connection = self.quicConnection
        datagramRoutingTask = Task { [weak self] in
            for await datagramPayload in connection.incomingDatagrams {
                guard let self = self else { break }

                do {
                    guard let (quarterStreamID, appPayload) = try WebTransportSession.parseDatagram(datagramPayload) else {
                        continue
                    }

                    // Convert quarter stream ID back to session ID
                    let sessionID = quarterStreamID * 4

                    if let session = await self.webTransportSession(for: sessionID) {
                        await session.deliverDatagram(appPayload)
                    } else {
                        Self.logger.trace(
                            "Datagram for unknown session",
                            metadata: [
                                "quarterStreamID": "\(quarterStreamID)",
                                "sessionID": "\(sessionID)",
                            ]
                        )
                    }
                } catch {
                    Self.logger.trace("Datagram parse error: \(error)")
                }
            }
        }
    }

    // MARK: - Priority Tracking (RFC 9218)

    func handlePriorityUpdate(streamID: UInt64, priority: StreamPriority) {
        // Check if the stream is already active (has an existing priority entry
        // that was set when the request stream was first processed).
        // If the stream is not yet known, store the update as pending so it
        // can be applied when the stream is created.
        let isExistingStream = streamPriorities.keys.contains(streamID)

        streamPriorities[streamID] = priority

        if !isExistingStream {
            pendingPriorityUpdates[streamID] = priority
        }

        // Update the active response stream priority if it exists
        if activeResponseStreams.keys.contains(streamID) {
            activeResponseStreams[streamID] = priority
        }
    }

    /// Sends a PRIORITY_UPDATE frame for a request stream.
    ///
    /// RFC 9218 Section 7.1: PRIORITY_UPDATE frames are sent on the
    /// control stream to dynamically change the priority of a stream.
    ///
    /// - Parameters:
    ///   - streamID: The stream ID to reprioritize
    ///   - priority: The new priority
    /// - Throws: `HTTP3Error` if the control stream is not available
    public func sendPriorityUpdate(streamID: UInt64, priority: StreamPriority) async throws {
        guard let controlStream = localControlStream else {
            throw HTTP3Error(code: .closedCriticalStream, reason: "Control stream not open")
        }

        let frame = HTTP3Frame.priorityUpdateRequest(streamID: streamID, priority: priority)
        let encoded = HTTP3FrameCodec.encode(frame)
        try await controlStream.write(encoded)

        // Track locally
        streamPriorities[streamID] = priority
    }

    /// Returns the effective priority for a stream.
    ///
    /// Checks dynamic priorities (from PRIORITY_UPDATE) first,
    /// then falls back to the default priority.
    ///
    /// - Parameter streamID: The stream ID to query
    /// - Returns: The effective priority, or `.default` if not tracked
    public func priority(for streamID: UInt64) -> StreamPriority {
        streamPriorities[streamID] ?? .default
    }

    /// Cleans up priority tracking for a closed stream.
    ///
    /// - Parameter streamID: The stream ID to clean up
    private func cleanupStreamPriority(_ streamID: UInt64) {
        streamPriorities.removeValue(forKey: streamID)
        pendingPriorityUpdates.removeValue(forKey: streamID)
        activeResponseStreams.removeValue(forKey: streamID)
        streamScheduler.resetCursors()
    }

    // MARK: - Priority Scheduling (RFC 9218)

    /// Registers a stream as an active response stream with the given priority.
    ///
    /// Call this when beginning to send a response. The stream will be
    /// included in priority-ordered scheduling until it is cleaned up.
    ///
    /// - Parameters:
    ///   - streamID: The stream ID to register
    ///   - priority: The stream's effective priority
    public func registerActiveResponseStream(_ streamID: UInt64, priority: StreamPriority) {
        activeResponseStreams[streamID] = priority
    }

    /// Unregisters a stream from active response scheduling.
    ///
    /// Call this when the response has been fully sent.
    ///
    /// - Parameter streamID: The stream ID to unregister
    public func unregisterActiveResponseStream(_ streamID: UInt64) {
        activeResponseStreams.removeValue(forKey: streamID)
    }

    /// Returns stream IDs sorted by priority for scheduling data sends.
    ///
    /// Implements RFC 9218 scheduling:
    /// - Lower urgency values are served first (urgency 0 = highest priority)
    /// - Within the same urgency level, non-incremental streams are served
    ///   one at a time (sequential), while incremental streams are interleaved
    /// - Round-robin rotation ensures fairness within urgency groups
    ///
    /// ## Usage
    ///
    /// ```swift
    /// let orderedStreams = connection.priorityOrderedStreamIDs()
    /// for streamID in orderedStreams {
    ///     // Send data on this stream
    /// }
    /// ```
    ///
    /// - Returns: Array of stream IDs in priority-scheduled order
    public func priorityOrderedStreamIDs() -> [UInt64] {
        guard !activeResponseStreams.isEmpty else { return [] }

        // Build a list sorted by priority, then by stream ID for determinism
        var grouped: [UInt8: [(streamID: UInt64, priority: StreamPriority)]] = [:]
        for (streamID, priority) in activeResponseStreams {
            grouped[priority.urgency, default: []].append((streamID, priority))
        }

        // Sort each group by stream ID for deterministic ordering
        for (urgency, group) in grouped {
            grouped[urgency] = group.sorted { $0.streamID < $1.streamID }
        }

        var result: [UInt64] = []

        // Process urgency levels in order (0 = highest priority first)
        for urgency in UInt8(0)...7 {
            guard let group = grouped[urgency], !group.isEmpty else {
                continue
            }

            // Separate incremental and non-incremental
            let nonIncremental = group.filter { !$0.priority.incremental }
            let incremental = group.filter { $0.priority.incremental }

            if !nonIncremental.isEmpty {
                // Non-incremental: serve the active one first (cursor-based)
                let cursor = streamScheduler.cursorPositions[urgency] ?? 0
                let validCursor = cursor % nonIncremental.count
                result.append(nonIncremental[validCursor].streamID)

                // Then interleave incremental streams
                for entry in incremental {
                    result.append(entry.streamID)
                }

                // Then remaining non-incremental
                for (i, entry) in nonIncremental.enumerated() where i != validCursor {
                    result.append(entry.streamID)
                }
            } else {
                // Only incremental — round-robin all
                for entry in incremental {
                    result.append(entry.streamID)
                }
            }
        }

        return result
    }

    /// Advances the scheduler cursor for a given urgency level after
    /// data has been sent on a stream at that urgency.
    ///
    /// This ensures fair round-robin scheduling across streams at the
    /// same urgency level.
    ///
    /// - Parameter streamID: The stream that just sent data
    public func advanceSchedulerCursor(for streamID: UInt64) {
        guard let priority = activeResponseStreams[streamID] else { return }
        let urgency = priority.urgency

        // Count streams at this urgency level
        let groupSize = activeResponseStreams.values.filter { $0.urgency == urgency }.count
        guard groupSize > 0 else { return }

        if priority.incremental {
            streamScheduler.advanceIncrementalCursor(for: urgency, groupSize: groupSize)
        } else {
            streamScheduler.advanceCursor(for: urgency, groupSize: groupSize)
        }
    }

    /// The number of active response streams being tracked for scheduling.
    public var activeResponseStreamCount: Int {
        activeResponseStreams.count
    }

    /// Returns all tracked stream priorities (for debugging / testing).
    public var allStreamPriorities: [UInt64: StreamPriority] {
        streamPriorities
    }

    /// Returns all pending priority updates (for debugging / testing).
    public var allPendingPriorityUpdates: [UInt64: StreamPriority] {
        pendingPriorityUpdates
    }

    // MARK: - Response Sending (Server)

    /// Sends an HTTP/3 response on a request stream.
    ///
    /// Encodes the response headers with QPACK, sends a HEADERS frame,
    /// then sends a DATA frame with the body, and closes the stream.
    ///
    /// - Parameters:
    ///   - response: The HTTP/3 response to send
    ///   - stream: The QUIC stream to send on
    private func sendResponse(_ response: HTTP3Response, on stream: any QUICStreamProtocol) async {
        do {
            // Encode response headers using QPACK
            let headerList = response.toHeaderList()
            let encodedHeaders = qpackEncoder.encode(headerList)

            // Send HEADERS frame
            let headersFrame = HTTP3Frame.headers(encodedHeaders)
            let headersData = HTTP3FrameCodec.encode(headersFrame)
            try await stream.write(headersData)

            // Send DATA frame if there's a body
            if !response.body.isEmpty {
                let dataFrame = HTTP3Frame.data(response.body)
                let dataData = HTTP3FrameCodec.encode(dataFrame)
                try await stream.write(dataData)
            }

            // Send trailers (if any) — RFC 9114 §4.1
            if let trailers = response.trailers, !trailers.isEmpty {
                let encodedTrailers = qpackEncoder.encode(trailers)
                let trailersFrame = HTTP3Frame.headers(encodedTrailers)
                let trailersData = HTTP3FrameCodec.encode(trailersFrame)
                try await stream.write(trailersData)
            }

            // Close the write side (FIN)
            try await stream.closeWrite()

        } catch {
            // Error sending response — reset the stream
            await stream.reset(errorCode: HTTP3ErrorCode.internalError.rawValue)
        }
    }

    /// Sends response headers only on a stream, WITHOUT closing the write side.
    ///
    /// Used for Extended CONNECT (RFC 9220) responses where the stream must
    /// remain open after the response headers are sent (e.g., for WebTransport
    /// session lifetime). Also sends the body if present, but does NOT send FIN.
    ///
    /// - Parameters:
    ///   - response: The HTTP/3 response to send
    ///   - stream: The QUIC stream to send on
    private func sendResponseHeadersOnly(_ response: HTTP3Response, on stream: any QUICStreamProtocol) async {
        do {
            // Encode response headers using QPACK
            let headerList = response.toHeaderList()
            let encodedHeaders = qpackEncoder.encode(headerList)

            // Send HEADERS frame
            let headersFrame = HTTP3Frame.headers(encodedHeaders)
            let headersData = HTTP3FrameCodec.encode(headersFrame)
            try await stream.write(headersData)

            // Send DATA frame if there's a body
            if !response.body.isEmpty {
                let dataFrame = HTTP3Frame.data(response.body)
                let dataData = HTTP3FrameCodec.encode(dataFrame)
                try await stream.write(dataData)
            }

            // NOTE: Do NOT close the write side. The stream stays open
            // for the Extended CONNECT session (e.g., WebTransport).

        } catch {
            // Error sending response — reset the stream
            await stream.reset(errorCode: HTTP3ErrorCode.internalError.rawValue)
        }
    }

    // MARK: - Connection Info

    /// Whether the connection is ready for requests
    public var isReady: Bool {
        state == .ready
    }

    /// Whether the connection is in the process of shutting down
    public var isGoingAway: Bool {
        if case .goingAway = state { return true }
        return false
    }

    /// Whether the connection is closed
    public var isClosed: Bool {
        state == .closed
    }

    /// The remote address of the underlying QUIC connection
    public var remoteAddress: SocketAddress {
        quicConnection.remoteAddress
    }

    /// The local address of the underlying QUIC connection
    public var localAddress: SocketAddress? {
        quicConnection.localAddress
    }

    /// A summary of the connection's current state
    public var debugDescription: String {
        var parts = [String]()
        parts.append("role=\(role)")
        parts.append("state=\(state)")
        if let peer = peerSettings {
            parts.append("peerSettings=\(peer)")
        }
        parts.append("localSettings=\(localSettings)")
        return "HTTP3Connection(\(parts.joined(separator: ", ")))"
    }

    // MARK: - Buffered Frame Helpers

    /// Reads the next complete HTTP/3 frame from a stream, buffering across
    /// multiple reads if necessary.
    ///
    /// This is used for the first SETTINGS frame on the control stream where
    /// we need exactly one complete frame and must tolerate fragmentation.
    ///
    /// - Parameters:
    ///   - stream: The QUIC stream to read from
    ///   - buffer: A mutable buffer that accumulates unconsumed bytes.
    ///     On entry it may contain leftover data from a previous read;
    ///     on exit it contains any bytes remaining after the decoded frame.
    /// - Returns: The decoded HTTP/3 frame
    /// - Throws: `HTTP3Error` if the stream ends before a complete frame
    ///   is available, or if the frame is malformed
    private func readNextFrame(
        from stream: any QUICStreamProtocol,
        buffer: inout Data
    ) async throws -> HTTP3Frame {
        // Try to decode from what we already have
        while true {
            if !buffer.isEmpty {
                do {
                    var offset = 0
                    let frame = try HTTP3FrameCodec.decode(from: buffer, offset: &offset)
                    // Successfully decoded — remove consumed bytes from buffer
                    buffer = Data(buffer.dropFirst(offset))
                    return frame
                } catch HTTP3FrameCodecError.insufficientData {
                    // Need more data — fall through to read
                } catch {
                    // Malformed frame
                    throw error
                }
            }

            // Read more data from the stream
            let data = try await stream.read()
            if data.isEmpty {
                throw HTTP3Error.missingSettings
            }
            buffer.append(data)
        }
    }

    /// Decodes as many complete HTTP/3 frames as possible from the buffer,
    /// removing consumed bytes.
    ///
    /// Uses `HTTP3FrameCodec.decodeAll` which stops at the first incomplete
    /// frame boundary. The unconsumed bytes remain in the buffer for the
    /// next read cycle.
    ///
    /// - Parameter buffer: A mutable buffer of accumulated stream data.
    ///   Consumed bytes are removed; unconsumed bytes remain.
    /// - Returns: A tuple of (decoded frames, bytes consumed)
    /// - Throws: `HTTP3FrameCodecError` for malformed frames (not for
    ///   insufficient data at the boundary — that's handled internally)
    private func decodeFramesFromBuffer(_ buffer: inout Data) throws -> ([HTTP3Frame], Int) {
        guard !buffer.isEmpty else { return ([], 0) }

        let (frames, consumed) = try HTTP3FrameCodec.decodeAll(from: buffer)

        if consumed > 0 {
            buffer = Data(buffer.dropFirst(consumed))
        }

        return (frames, consumed)
    }
}

// MARK: - Re-export QUIC types for consumers of the HTTP3 module

// Other files in the HTTP3 module (HTTP3Client, HTTP3Server, etc.) use
// QUICConnectionProtocol / QUICStreamProtocol without importing QUIC
// directly. This re-export makes those types available transitively.
@_exported import QUIC