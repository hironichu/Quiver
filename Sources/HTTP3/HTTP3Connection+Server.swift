/// HTTP3Connection — Server Operations
///
/// Extension containing server-side request handling and response sending:
/// - `handleIncomingRequestStream` — reads and dispatches HTTP/3 requests
/// - `handleIncomingRequestStreamWithBuffer` — same, with pre-read buffer
/// - `routeExtendedConnectRequest` — routes Extended CONNECT to handler
/// - `sendResponse` — sends a full HTTP/3 response (HEADERS + DATA + FIN)
/// - `sendResponseHeadersOnly` — sends response headers without FIN (Extended CONNECT)

import Foundation
import QUIC
import QUICCore
import QUICStream
import QPACK

// MARK: - Server Request Handling & Response Sending

extension HTTP3Connection {

    // MARK: - Request Stream Handling (Server)

    /// Handles an incoming HTTP/3 request stream with pre-read buffer data.
    ///
    /// This variant is called when `handleIncomingBidiStream` has already
    /// read the first chunk of data (to check for WebTransport session ID)
    /// and determined the stream is an HTTP/3 request stream.
    func handleIncomingRequestStreamWithBuffer(
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
    func routeExtendedConnectRequest(
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

    /// Handles an incoming HTTP/3 request stream (no pre-read buffer).
    func handleIncomingRequestStream(_ stream: any QUICStreamProtocol) async {
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

    // MARK: - Response Sending (Server)

    /// Sends an HTTP/3 response on a request stream.
    ///
    /// Encodes the response headers with QPACK, sends a HEADERS frame,
    /// then sends a DATA frame with the body, and closes the stream.
    ///
    /// - Parameters:
    ///   - response: The HTTP/3 response to send
    ///   - stream: The QUIC stream to send on
    func sendResponse(_ response: HTTP3Response, on stream: any QUICStreamProtocol) async {
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
    func sendResponseHeadersOnly(_ response: HTTP3Response, on stream: any QUICStreamProtocol) async {
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
}