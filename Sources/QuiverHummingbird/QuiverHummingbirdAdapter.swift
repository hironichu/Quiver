#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import HTTP3
import HTTPTypes
import Hummingbird
import Logging
import NIOCore
import NIOEmbedded

private let quiverHummingbirdHopByHopHeaders: Set<String> = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
]

/// Bridges Quiver HTTP/3 requests into a Hummingbird responder.
///
/// This target intentionally sits outside `HTTP3`, depending only on public
/// Quiver and Hummingbird APIs so it can be split into its own package later.
public struct QuiverHummingbirdAdapter<Responder: HTTPResponder>: Sendable {
    public struct Configuration: Sendable, Hashable {
        /// Logger label used for requests created by the adapter.
        public var requestLoggerLabel: String

        public init(requestLoggerLabel: String = "quiver.hummingbird.request") {
            self.requestLoggerLabel = requestLoggerLabel
        }
    }

    public enum AdapterError: Error, Sendable, CustomStringConvertible {
        case invalidMethod(String)

        public var description: String {
            switch self {
            case .invalidMethod(let method):
                return "Invalid HTTP method for Hummingbird request: \(method)"
            }
        }
    }

    private let responder: Responder
    private let configuration: Configuration
    private let makeContext: @Sendable (Logger) -> Responder.Context

    public init(
        responder: Responder,
        configuration: Configuration = Configuration(),
        makeContext: @escaping @Sendable (Logger) -> Responder.Context
    ) {
        self.responder = responder
        self.configuration = configuration
        self.makeContext = makeContext
    }

    /// Creates an adapter for a Hummingbird application.
    ///
    /// Quiver owns the HTTP/3 transport, so the adapter constructs a lightweight
    /// in-memory channel only to satisfy Hummingbird request-context sources.
    public init(
        application: Hummingbird.Application<Responder>,
        configuration: Configuration = Configuration()
    ) where Responder.Context: InitializableFromSource<ApplicationRequestContextSource> {
        self.responder = application.responder
        self.configuration = configuration
        self.makeContext = { logger in
            Responder.Context(
                source: ApplicationRequestContextSource(
                    channel: EmbeddedChannel(),
                    logger: logger
                )
            )
        }
    }

    /// Handles one Quiver HTTP/3 request by dispatching it to Hummingbird's responder.
    public func handle(_ context: HTTP3RequestContext) async throws {
        let request = try makeHummingbirdRequest(from: context)
        let logger = Logger(label: configuration.requestLoggerLabel)
        let hummingbirdContext = makeContext(logger)
        let response = try await responder.respond(to: request, context: hummingbirdContext)
        try await send(response, to: context)
    }

    private func makeHummingbirdRequest(from context: HTTP3RequestContext) throws -> Hummingbird.Request {
        guard let method = HTTPRequest.Method(context.request.method.rawValue) else {
            throw AdapterError.invalidMethod(context.request.method.rawValue)
        }

        let headers = makeHTTPFields(from: context.request.headers)
        let body = RequestBody(asyncSequence: HTTP3ByteBufferSequence(stream: context.body.stream()))
        let head = HTTPRequest(
            method: method,
            scheme: context.request.scheme.isEmpty ? "https" : context.request.scheme,
            authority: context.request.authority.isEmpty ? nil : context.request.authority,
            path: context.request.path,
            headerFields: headers
        )

        return Hummingbird.Request(head: head, body: body)
    }

    private func send(_ response: Hummingbird.Response, to context: HTTP3RequestContext) async throws {
        let headers = makeHTTP3Headers(from: response.headers)
        try await context.respond(
            status: response.status.code,
            headers: headers
        ) { writer in
            let responseWriter = HTTP3ResponseBodyWriter(writer: writer)
            try await response.body.write(responseWriter)
        }
    }

    private func makeHTTPFields(from headers: [(String, String)]) -> HTTPFields {
        var fields = HTTPFields()
        for (name, value) in headers {
            let lowercased = name.lowercased()
            guard !lowercased.hasPrefix(":"), !quiverHummingbirdHopByHopHeaders.contains(lowercased) else {
                continue
            }
            guard let fieldName = HTTPField.Name(name) else {
                continue
            }
            fields.append(HTTPField(name: fieldName, value: value))
        }
        return fields
    }

    private func makeHTTP3Headers(from headers: HTTPFields) -> [(String, String)] {
        var http3Headers: [(String, String)] = []
        http3Headers.reserveCapacity(headers.count)

        for header in headers {
            let name = header.name.rawName.lowercased()
            guard !name.hasPrefix(":"), !quiverHummingbirdHopByHopHeaders.contains(name) else {
                continue
            }
            http3Headers.append((name, header.value))
        }

        return http3Headers
    }
}

extension QuiverHummingbirdAdapter {
    /// Installs this adapter as the request handler for a Quiver HTTP/3 server.
    public func install(on server: HTTP3Server) async {
        await server.onRequest { context in
            try await handle(context)
        }
    }
}

private struct HTTP3ByteBufferSequence: AsyncSequence, Sendable {
    typealias Element = ByteBuffer

    let stream: AsyncStream<Data>

    func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(iterator: stream.makeAsyncIterator())
    }

    struct AsyncIterator: AsyncIteratorProtocol {
        var iterator: AsyncStream<Data>.Iterator

        mutating func next() async -> ByteBuffer? {
            guard let data = await iterator.next() else {
                return nil
            }
            return ByteBuffer(bytes: data)
        }
    }
}

private struct HTTP3ResponseBodyWriter: ResponseBodyWriter {
    let writer: HTTP3BodyWriter

    mutating func write(_ buffer: ByteBuffer) async throws {
        try await writer.write(Data(buffer.readableBytesView))
    }

    consuming func finish(_ trailingHeaders: HTTPFields?) async throws {
        _ = trailingHeaders
    }
}
