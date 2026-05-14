#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import HTTP3
import Logging
import NIOCore
import NIOHTTP1
import Vapor

/// Bridges Quiver HTTP/3 requests into a Vapor application responder.
///
/// The adapter is intentionally isolated from the `HTTP3` target so it can be
/// moved into a standalone package later without changing Quiver's core API.
public struct QuiverVaporAdapter: Sendable {
    public struct Configuration: Sendable, Hashable {
        /// Maximum request body size buffered before constructing a Vapor request.
        public var maxRequestBodySize: Int

        /// Maximum response body size collected from Vapor before writing HTTP/3.
        public var maxResponseBodySize: Int

        /// Logger label used for requests created by the adapter.
        public var requestLoggerLabel: String

        public init(
            maxRequestBodySize: Int = 16 * 1024 * 1024,
            maxResponseBodySize: Int = 16 * 1024 * 1024,
            requestLoggerLabel: String = "quiver.vapor.request"
        ) {
            self.maxRequestBodySize = maxRequestBodySize
            self.maxResponseBodySize = maxResponseBodySize
            self.requestLoggerLabel = requestLoggerLabel
        }
    }

    public enum AdapterError: Error, Sendable, CustomStringConvertible {
        case requestBodyTooLarge(size: Int, max: Int)
        case responseBodyTooLarge(size: Int, max: Int)

        public var description: String {
            switch self {
            case .requestBodyTooLarge(let size, let max):
                return "Request body too large: \(size) bytes exceeds \(max) bytes"
            case .responseBodyTooLarge(let size, let max):
                return "Response body too large: \(size) bytes exceeds \(max) bytes"
            }
        }
    }

    private static let hopByHopHeaders: Set<String> = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]

    private let application: Vapor.Application
    private let configuration: Configuration

    public init(
        application: Vapor.Application,
        configuration: Configuration = Configuration()
    ) {
        self.application = application
        self.configuration = configuration
    }

    /// Handles one Quiver HTTP/3 request by dispatching it to Vapor's responder.
    public func handle(_ context: HTTP3RequestContext) async throws {
        do {
            let vaporRequest = try await makeVaporRequest(from: context)
            let vaporResponse = try await application.responder.respond(to: vaporRequest).get()
            try await send(vaporResponse, to: context, on: vaporRequest.eventLoop)
        } catch AdapterError.requestBodyTooLarge {
            try await context.respond(
                status: 413,
                headers: [("content-type", "text/plain; charset=utf-8")],
                Data("Payload Too Large".utf8)
            )
        } catch AdapterError.responseBodyTooLarge {
            try await context.respond(
                status: 502,
                headers: [("content-type", "text/plain; charset=utf-8")],
                Data("Bad Gateway".utf8)
            )
        }
    }

    private func makeVaporRequest(from context: HTTP3RequestContext) async throws -> Vapor.Request {
        let eventLoop = application.eventLoopGroup.next()
        let body = try await collectRequestBody(context.body)
        var headers = makeVaporHeaders(from: context.request.headers)

        if !context.request.authority.isEmpty, !headers.contains(name: .host) {
            headers.add(name: .host, value: context.request.authority)
        }
        if body.readableBytes > 0, !headers.contains(name: .contentLength) {
            headers.add(name: .contentLength, value: String(body.readableBytes))
        }

        return Vapor.Request(
            application: application,
            method: Vapor.HTTPMethod(rawValue: context.request.method.rawValue),
            url: Vapor.URI(string: context.request.path),
            version: HTTPVersion(major: 3, minor: 0),
            headersNoUpdate: headers,
            collectedBody: body.readableBytes == 0 ? nil : body,
            remoteAddress: nil,
            logger: Logger(label: configuration.requestLoggerLabel),
            byteBufferAllocator: ByteBufferAllocator(),
            on: eventLoop
        )
    }

    private func collectRequestBody(_ body: consuming HTTP3Body) async throws -> ByteBuffer {
        var buffer = ByteBufferAllocator().buffer(capacity: 0)
        var size = 0

        for await chunk in body.stream() {
            size += chunk.count
            guard size <= configuration.maxRequestBodySize else {
                throw AdapterError.requestBodyTooLarge(size: size, max: configuration.maxRequestBodySize)
            }
            buffer.writeBytes(chunk)
        }

        return buffer
    }

    private func send(
        _ response: Vapor.Response,
        to context: HTTP3RequestContext,
        on eventLoop: EventLoop
    ) async throws {
        guard var bodyBuffer = try await response.body.collect(on: eventLoop).get() else {
            try await context.respond(
                status: Int(response.status.code),
                headers: makeHTTP3Headers(from: response.headers),
                Data()
            )
            return
        }

        guard bodyBuffer.readableBytes <= configuration.maxResponseBodySize else {
            throw AdapterError.responseBodyTooLarge(
                size: bodyBuffer.readableBytes,
                max: configuration.maxResponseBodySize
            )
        }

        let body = bodyBuffer.readData(length: bodyBuffer.readableBytes) ?? Data()
        try await context.respond(
            status: Int(response.status.code),
            headers: makeHTTP3Headers(from: response.headers),
            body
        )
    }

    private func makeVaporHeaders(from headers: [(String, String)]) -> HTTPHeaders {
        var vaporHeaders = HTTPHeaders()
        for (name, value) in headers {
            let lowercased = name.lowercased()
            guard !lowercased.hasPrefix(":"), !Self.hopByHopHeaders.contains(lowercased) else {
                continue
            }
            vaporHeaders.add(name: name, value: value)
        }
        return vaporHeaders
    }

    private func makeHTTP3Headers(from headers: HTTPHeaders) -> [(String, String)] {
        var http3Headers: [(String, String)] = []
        http3Headers.reserveCapacity(headers.count)

        for header in headers {
            let lowercased = header.name.lowercased()
            guard !lowercased.hasPrefix(":"), !Self.hopByHopHeaders.contains(lowercased) else {
                continue
            }
            http3Headers.append((lowercased, header.value))
        }

        return http3Headers
    }
}

extension QuiverVaporAdapter {
    /// Installs this adapter as the request handler for a Quiver HTTP/3 server.
    public func install(on server: HTTP3Server) async {
        await server.onRequest { context in
            try await handle(context)
        }
    }
}
