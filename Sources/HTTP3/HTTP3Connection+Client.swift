/// HTTP3Connection — Client Operations
///
/// Extension containing client-side request/response logic:
/// - `sendRequest` — sends an HTTP/3 request and reads the response
/// - `sendExtendedConnect` — sends an Extended CONNECT (RFC 9220) request
/// - `readResponse` — reads a full HTTP/3 response (HEADERS + DATA + trailers)
/// - `readExtendedConnectResponse` — reads only the response HEADERS (no FIN wait)

import Foundation
import QUIC
import QUICCore
import QPACK

// MARK: - Client Request/Response

extension HTTP3Connection {

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
    func readExtendedConnectResponse(from stream: any QUICStreamProtocol) async throws -> HTTP3Response {
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
    func readResponse(from stream: any QUICStreamProtocol) async throws -> HTTP3Response {
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
}