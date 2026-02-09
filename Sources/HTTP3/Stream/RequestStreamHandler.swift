/// HTTP/3 Request Stream Handler (RFC 9114 Section 4)
///
/// Handles the lifecycle of a single HTTP/3 request/response exchange
/// on a bidirectional QUIC stream.
///
/// ## Client-Side Flow
///
/// 1. Send HEADERS frame (`:method`, `:scheme`, `:authority`, `:path` + headers)
/// 2. Optionally send DATA frame(s) (request body)
/// 3. Close write side (send FIN)
/// 4. Receive HEADERS frame (`:status` + response headers)
/// 5. Receive DATA frame(s) (response body)
/// 6. Stream completes when FIN received
///
/// ## Server-Side Flow
///
/// 1. Receive HEADERS frame (`:method`, `:scheme`, `:authority`, `:path` + headers)
/// 2. Receive DATA frame(s) (request body, if any)
/// 3. Stream FIN indicates end of request
/// 4. Send HEADERS frame (`:status` + response headers)
/// 5. Send DATA frame(s) (response body)
/// 6. Close write side (send FIN)
///
/// ## Wire Format
///
/// ```
/// Client                                   Server
///   |                                        |
///   |  HEADERS (method, path, headers)       |
///   |--------------------------------------->|
///   |  DATA (optional body chunks)           |
///   |--------------------------------------->|
///   |  (FIN if no more data)                 |
///   |                                        |
///   |  HEADERS (status, headers)             |
///   |<---------------------------------------|
///   |  DATA (response body chunks)           |
///   |<---------------------------------------|
///   |  (FIN)                                 |
///   |                                        |
/// ```

import Foundation
import QUICCore
import QUIC
import QPACK

// MARK: - Request Stream State

/// State of a request stream
///
/// Tracks the lifecycle of an HTTP/3 request/response exchange
/// on a single bidirectional stream.
public enum RequestStreamState: Sendable, Hashable, CustomStringConvertible {
    /// Stream just created, nothing sent or received yet
    case idle

    /// Client: HEADERS frame sent, waiting for response
    /// Server: HEADERS frame received, processing request
    case headersReceived

    /// DATA frames being sent or received
    case dataTransfer

    /// Response headers sent (server) or received (client)
    case responseHeadersSent

    /// The request/response exchange is complete
    case complete

    /// The stream encountered an error
    case error

    public var description: String {
        switch self {
        case .idle: return "idle"
        case .headersReceived: return "headersReceived"
        case .dataTransfer: return "dataTransfer"
        case .responseHeadersSent: return "responseHeadersSent"
        case .complete: return "complete"
        case .error: return "error"
        }
    }
}

// MARK: - Request Stream Handler

/// Handles a single HTTP/3 request/response exchange on a bidirectional stream.
///
/// This handler encapsulates the logic for sending and receiving HTTP/3
/// frames on a request stream, including HEADERS and DATA frames.
///
/// ## Usage (Client)
///
/// ```swift
/// let handler = RequestStreamHandler(stream: stream, encoder: encoder, decoder: decoder)
/// let response = try await handler.sendRequest(request)
/// ```
///
/// ## Usage (Server)
///
/// ```swift
/// let handler = RequestStreamHandler(stream: stream, encoder: encoder, decoder: decoder)
/// let request = try await handler.receiveRequest()
/// try await handler.sendResponse(response)
/// ```
public actor RequestStreamHandler {
    /// The underlying QUIC bidirectional stream
    private let stream: any QUICStreamProtocol

    /// QPACK encoder for outgoing headers
    private let encoder: QPACKEncoder

    /// QPACK decoder for incoming headers
    private let decoder: QPACKDecoder

    /// Maximum DATA frame payload size for chunked sends
    private let maxDataFrameSize: Int

    /// Current state of the request stream
    private var state: RequestStreamState = .idle

    /// Buffer for accumulating partial frame data from reads
    private var readBuffer: Data = Data()

    /// Creates a request stream handler.
    ///
    /// - Parameters:
    ///   - stream: The QUIC bidirectional stream to use
    ///   - encoder: The QPACK encoder for outgoing headers
    ///   - decoder: The QPACK decoder for incoming headers
    ///   - maxDataFrameSize: Maximum size of a single DATA frame payload (default: 16 KB)
    public init(
        stream: any QUICStreamProtocol,
        encoder: QPACKEncoder,
        decoder: QPACKDecoder,
        maxDataFrameSize: Int = 16384
    ) {
        self.stream = stream
        self.encoder = encoder
        self.decoder = decoder
        self.maxDataFrameSize = maxDataFrameSize
    }

    /// The QUIC stream ID
    public var streamID: UInt64 {
        stream.id
    }

    /// The current state
    public var currentState: RequestStreamState {
        state
    }

    // MARK: - Client-Side Operations

    /// Sends an HTTP/3 request and receives the response.
    ///
    /// This is the primary client-side API. It performs the full
    /// request/response exchange:
    ///
    /// 1. Sends HEADERS frame with request pseudo-headers and headers
    /// 2. Sends DATA frame(s) with request body (if present)
    /// 3. Closes the write side (sends FIN)
    /// 4. Receives response HEADERS frame
    /// 5. Receives response DATA frame(s)
    ///
    /// - Parameter request: The HTTP/3 request to send
    /// - Returns: The HTTP/3 response received from the server
    /// - Throws: `HTTP3Error` if the exchange fails
    public func sendRequest(_ request: HTTP3Request) async throws -> HTTP3Response {
        guard state == .idle else {
            throw HTTP3Error(code: .generalProtocolError, reason: "Request stream not in idle state")
        }

        // 1. Send request HEADERS
        try await sendHeaders(request.toHeaderList())
        state = .headersReceived

        // 2. Send request body (if any)
        if let body = request.body, !body.isEmpty {
            try await sendData(body)
        }

        // 3. Send trailers (if any) — RFC 9114 §4.1
        if let trailers = request.trailers, !trailers.isEmpty {
            try await sendHeaders(trailers)
        }

        // 4. Close write side to signal end of request
        try await stream.closeWrite()

        // 5. Receive response
        let response = try await receiveResponse()
        state = .complete

        return response
    }

    // MARK: - Server-Side Operations

    /// Receives an HTTP/3 request from the client.
    ///
    /// Reads and decodes the HEADERS frame and any DATA frames
    /// from the client until the stream FIN is received.
    ///
    /// - Returns: The decoded HTTP/3 request
    /// - Throws: `HTTP3Error` if the request is malformed or reading fails
    public func receiveRequest() async throws -> HTTP3Request {
        guard state == .idle else {
            throw HTTP3Error(code: .generalProtocolError, reason: "Request stream not in idle state")
        }

        // 1. Read HEADERS frame
        let headerFields = try await receiveHeaders()
        state = .headersReceived

        // 2. Parse pseudo-headers into a request
        var request = try HTTP3Request.fromHeaderList(headerFields)

        // 3. Read DATA frames (body) and optional trailers until FIN
        let (body, trailers) = try await receiveBody()
        if !body.isEmpty {
            request.body = body
        }
        request.trailers = trailers

        state = .dataTransfer
        return request
    }

    /// Sends an HTTP/3 response to the client.
    ///
    /// Sends a HEADERS frame with the response status and headers,
    /// followed by DATA frame(s) with the response body, then closes
    /// the write side.
    ///
    /// - Parameter response: The HTTP/3 response to send
    /// - Throws: `HTTP3Error` if sending fails
    public func sendResponse(_ response: HTTP3Response) async throws {
        guard state == .headersReceived || state == .dataTransfer else {
            throw HTTP3Error(
                code: .generalProtocolError,
                reason: "Cannot send response in state: \(state)"
            )
        }

        // 1. Send response HEADERS
        try await sendHeaders(response.toHeaderList())
        state = .responseHeadersSent

        // 2. Send response body
        if !response.body.isEmpty {
            try await sendData(response.body)
        }

        // 3. Send trailers (if any) — RFC 9114 §4.1
        if let trailers = response.trailers, !trailers.isEmpty {
            try await sendHeaders(trailers)
        }

        // 4. Close write side
        try await stream.closeWrite()
        state = .complete
    }

    // MARK: - Frame-Level Operations

    /// Sends a HEADERS frame with the given header fields.
    ///
    /// The headers are QPACK-encoded before being placed into the
    /// HEADERS frame payload.
    ///
    /// - Parameter headers: The header fields to send
    /// - Throws: If QPACK encoding or stream write fails
    private func sendHeaders(_ headers: [(name: String, value: String)]) async throws {
        let encodedHeaders = encoder.encode(headers)
        let frame = HTTP3Frame.headers(encodedHeaders)
        let frameData = HTTP3FrameCodec.encode(frame)
        try await stream.write(frameData)
    }

    /// Sends a DATA frame (or multiple DATA frames for large payloads).
    ///
    /// Large payloads are automatically chunked into multiple DATA frames
    /// to avoid excessive memory use and allow flow control to work smoothly.
    ///
    /// - Parameter data: The payload data to send
    /// - Throws: If stream write fails
    private func sendData(_ data: Data) async throws {
        if data.count <= maxDataFrameSize {
            // Single DATA frame
            let frame = HTTP3Frame.data(data)
            let frameData = HTTP3FrameCodec.encode(frame)
            try await stream.write(frameData)
        } else {
            // Chunk into multiple DATA frames
            var offset = 0
            while offset < data.count {
                let end = min(offset + maxDataFrameSize, data.count)
                let chunk = data[data.startIndex + offset ..< data.startIndex + end]
                let frame = HTTP3Frame.data(Data(chunk))
                let frameData = HTTP3FrameCodec.encode(frame)
                try await stream.write(frameData)
                offset = end
            }
        }
    }

    /// Receives and decodes a HEADERS frame from the stream.
    ///
    /// Reads data from the stream until a complete HEADERS frame is
    /// available, then QPACK-decodes the header block.
    ///
    /// - Returns: The decoded header fields
    /// - Throws: If reading, frame decoding, or QPACK decoding fails
    private func receiveHeaders() async throws -> [(name: String, value: String)] {
        let frame = try await readNextFrame()

        guard case .headers(let headerBlock) = frame else {
            throw HTTP3Error(
                code: .frameUnexpected,
                reason: "Expected HEADERS frame, got \(frame)"
            )
        }

        do {
            return try decoder.decode(headerBlock)
        } catch {
            throw HTTP3Error(
                code: .generalProtocolError,
                reason: "QPACK decoding failed: \(error)",
                underlyingError: error
            )
        }
    }

    /// Receives a response (HEADERS + DATA frames) from the stream.
    ///
    /// Used by the client to receive the server's response.
    ///
    /// - Returns: The decoded HTTP/3 response
    /// - Throws: If reading or decoding fails
    private func receiveResponse() async throws -> HTTP3Response {
        // 1. Read response HEADERS
        let headerFields = try await receiveHeaders()

        // 2. Parse into response
        var response = try HTTP3Response.fromHeaderList(headerFields)

        // 3. Read body DATA frames and optional trailers
        let (body, trailers) = try await receiveBody()
        response.body = body
        response.trailers = trailers

        return response
    }

    /// Receives all DATA frames until stream FIN, returning the assembled body.
    ///
    /// Continues reading frames from the stream until either:
    /// - A stream FIN is received (empty read)
    /// - An error occurs
    ///
    /// Unknown frame types on request streams are ignored per RFC 9114 Section 4.1.
    ///
    /// - Returns: The assembled body data (may be empty)
    /// - Throws: If reading fails or an unexpected frame type is received
    /// Receives all DATA frames until stream FIN, returning the assembled body
    /// and any trailing HEADERS (trailers).
    ///
    /// Per RFC 9114 Section 4.1, an HTTP message on a request stream is:
    ///   HEADERS (initial) + DATA* + HEADERS? (trailers)
    ///
    /// A trailing HEADERS frame is QPACK-decoded and validated to ensure
    /// no pseudo-header fields are present (RFC 9114 §4.1.2).
    ///
    /// - Returns: Tuple of (body data, optional trailers)
    private func receiveBody() async throws -> (body: Data, trailers: [(String, String)]?) {
        var body = Data()
        var trailers: [(String, String)]?

        while true {
            // Try to read the next frame; if stream is done, break
            guard let frame = try await readNextFrameOrNil() else {
                break
            }

            switch frame {
            case .data(let chunk):
                body.append(chunk)

            case .headers(let headerBlock):
                // Trailing HEADERS frame (RFC 9114 §4.1)
                let decoded = try decoder.decode(headerBlock)
                trailers = try validateTrailers(decoded)

            case .unknown:
                // Unknown frame types on request streams MUST be ignored
                continue

            default:
                // Other frame types (SETTINGS, GOAWAY, etc.) are not allowed on request streams
                throw HTTP3Error(
                    code: .frameUnexpected,
                    reason: "\(frame) not allowed on request stream"
                )
            }
        }

        return (body, trailers)
    }

    // MARK: - Frame Reading

    /// Reads the next complete HTTP/3 frame from the stream.
    ///
    /// Buffers partial reads and returns a complete frame once enough
    /// data has been accumulated.
    ///
    /// - Returns: The next decoded HTTP/3 frame
    /// - Throws: If reading from the stream fails, or if the stream ends
    ///   before a complete frame is available
    private func readNextFrame() async throws -> HTTP3Frame {
        guard let frame = try await readNextFrameOrNil() else {
            throw HTTP3Error(
                code: .requestIncomplete,
                reason: "Stream ended before a complete frame was received"
            )
        }
        return frame
    }

    /// Reads the next complete HTTP/3 frame, or returns nil if the stream has ended.
    ///
    /// This handles partial reads by buffering data until a complete frame
    /// is available. Returns nil when the stream FIN has been received and
    /// no more complete frames are in the buffer.
    ///
    /// - Returns: The next decoded frame, or nil if the stream has ended
    /// - Throws: If reading from the stream fails or frame decoding encounters
    ///   a malformed frame
    private func readNextFrameOrNil() async throws -> HTTP3Frame? {
        while true {
            // Try to decode a frame from the current buffer
            if !readBuffer.isEmpty {
                do {
                    var offset = 0
                    let frame = try HTTP3FrameCodec.decode(from: readBuffer, offset: &offset)

                    // Remove consumed bytes from buffer
                    readBuffer.removeSubrange(readBuffer.startIndex..<(readBuffer.startIndex + offset))
                    return frame
                } catch HTTP3FrameCodecError.insufficientData {
                    // Need more data — fall through to read from stream
                } catch {
                    // Genuine decoding error
                    state = .error
                    throw HTTP3Error(
                        code: .frameError,
                        reason: "Frame decoding error: \(error)",
                        underlyingError: error
                    )
                }
            }

            // Read more data from the stream
            do {
                let data = try await stream.read()

                if data.isEmpty {
                    // Stream FIN received
                    if readBuffer.isEmpty {
                        return nil
                    } else {
                        // Partial frame in buffer + FIN = incomplete frame
                        state = .error
                        throw HTTP3Error(
                            code: .frameError,
                            reason: "Stream ended with incomplete frame (\(readBuffer.count) buffered bytes)"
                        )
                    }
                }

                readBuffer.append(data)
            } catch {
                // Check if this is already an HTTP3Error (e.g., stream reset)
                if error is HTTP3Error {
                    throw error
                }
                // Wrap other errors
                state = .error
                throw HTTP3Error(
                    code: .internalError,
                    reason: "Stream read error: \(error)",
                    underlyingError: error
                )
            }
        }
    }

    // MARK: - Stream Reset

    /// Resets the stream with an error code.
    ///
    /// Used to abort an in-progress request/response exchange.
    ///
    /// - Parameter errorCode: The HTTP/3 error code (default: H3_REQUEST_CANCELLED)
    public func reset(errorCode: UInt64 = HTTP3ErrorCode.requestCancelled.rawValue) async {
        state = .error
        await stream.reset(errorCode: errorCode)
    }

    /// Stops reading from the stream with an error code.
    ///
    /// Signals to the peer that no more data will be read.
    ///
    /// - Parameter errorCode: The HTTP/3 error code (default: H3_REQUEST_CANCELLED)
    public func stopReading(errorCode: UInt64 = HTTP3ErrorCode.requestCancelled.rawValue) async throws {
        try await stream.stopSending(errorCode: errorCode)
    }
}

// MARK: - Convenience Extensions

extension RequestStreamHandler {
    /// Sends a simple text response (server-side convenience).
    ///
    /// - Parameters:
    ///   - status: The HTTP status code
    ///   - contentType: The content type (default: "text/plain")
    ///   - body: The response body as a string
    /// - Throws: If sending fails
    public func sendTextResponse(
        status: Int = 200,
        contentType: String = "text/plain",
        body: String
    ) async throws {
        let bodyData = Data(body.utf8)
        let response = HTTP3Response(
            status: status,
            headers: [
                ("content-type", contentType),
                ("content-length", String(bodyData.count)),
            ],
            body: bodyData
        )
        try await sendResponse(response)
    }

    /// Sends a JSON response (server-side convenience).
    ///
    /// - Parameters:
    ///   - status: The HTTP status code
    ///   - body: The response body as JSON data
    /// - Throws: If sending fails
    public func sendJSONResponse(
        status: Int = 200,
        body: Data
    ) async throws {
        let response = HTTP3Response(
            status: status,
            headers: [
                ("content-type", "application/json"),
                ("content-length", String(body.count)),
            ],
            body: body
        )
        try await sendResponse(response)
    }
}

// MARK: - Request Stream Error

/// Errors specific to request stream handling
public enum RequestStreamError: Error, Sendable, CustomStringConvertible {
    /// The stream is not in the expected state for the operation
    case invalidState(current: RequestStreamState, expected: String)

    /// The received frame sequence is invalid
    case invalidFrameSequence(String)

    /// The request headers are malformed
    case malformedRequest(String)

    /// The response headers are malformed
    case malformedResponse(String)

    /// The stream was reset by the peer
    case streamReset(errorCode: UInt64)

    public var description: String {
        switch self {
        case .invalidState(let current, let expected):
            return "Invalid stream state: \(current) (expected: \(expected))"
        case .invalidFrameSequence(let reason):
            return "Invalid frame sequence: \(reason)"
        case .malformedRequest(let reason):
            return "Malformed request: \(reason)"
        case .malformedResponse(let reason):
            return "Malformed response: \(reason)"
        case .streamReset(let errorCode):
            return "Stream reset with error code: 0x\(String(errorCode, radix: 16))"
        }
    }
}