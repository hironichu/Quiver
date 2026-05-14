#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import HTTPTypes
import Hummingbird
import NIOCore
import QuiverHummingbird
import XCTest

@testable import HTTP3

final class QuiverHummingbirdAdapterTests: XCTestCase {
    func testDispatchesRequestToHummingbirdResponder() async throws {
        let responder = CallbackResponder<BasicRequestContext> { request, _ in
            XCTAssertEqual(request.uri.path, "/hello")
            return Response(
                status: .ok,
                body: .init(byteBuffer: ByteBuffer(string: "Hello from Hummingbird"))
            )
        }
        let app = Hummingbird.Application(responder: responder)
        let adapter = QuiverHummingbirdAdapter(application: app)
        let recorder = ResponseRecorder()
        let context = makeContext(path: "/hello", recorder: recorder)

        try await adapter.handle(context)

        let response = await recorder.response
        XCTAssertEqual(response?.status, 200)
        XCTAssertEqual(String(data: response?.body ?? Data(), encoding: .utf8), "Hello from Hummingbird")
    }

    func testStreamsRequestBodyThroughHummingbirdResponse() async throws {
        let responder = CallbackResponder<BasicRequestContext> { request, _ in
            Response(status: .ok, body: .init(asyncSequence: request.body))
        }
        let app = Hummingbird.Application(responder: responder)
        let adapter = QuiverHummingbirdAdapter(application: app)
        let recorder = ResponseRecorder()
        let context = makeContext(
            method: .post,
            path: "/echo",
            bodyChunks: [Data("hello ".utf8), Data("stream".utf8)],
            recorder: recorder
        )

        try await adapter.handle(context)

        let response = await recorder.response
        XCTAssertEqual(response?.status, 200)
        XCTAssertEqual(String(data: response?.body ?? Data(), encoding: .utf8), "hello stream")
    }

    func testForwardsRequestHeaders() async throws {
        let responder = CallbackResponder<BasicRequestContext> { request, _ in
            let value = request.headers[HTTPField.Name("x-quiver-test")!] ?? "missing"
            return Response(status: .ok, body: .init(byteBuffer: ByteBuffer(string: value)))
        }
        let app = Hummingbird.Application(responder: responder)
        let adapter = QuiverHummingbirdAdapter(application: app)
        let recorder = ResponseRecorder()
        let context = makeContext(
            path: "/headers",
            headers: [("x-quiver-test", "present")],
            recorder: recorder
        )

        try await adapter.handle(context)

        let response = await recorder.response
        XCTAssertEqual(response?.status, 200)
        XCTAssertEqual(String(data: response?.body ?? Data(), encoding: .utf8), "present")
    }

    func testStripsHopByHopResponseHeaders() async throws {
        let responder = CallbackResponder<BasicRequestContext> { _, _ in
            var headers = HTTPFields()
            headers[.connection] = "close"
            headers[.transferEncoding] = "chunked"
            headers[HTTPField.Name("x-adapter-test")!] = "kept"
            return Response(status: .ok, headers: headers, body: .init(byteBuffer: ByteBuffer(string: "ok")))
        }
        let app = Hummingbird.Application(responder: responder)
        let adapter = QuiverHummingbirdAdapter(application: app)
        let recorder = ResponseRecorder()
        let context = makeContext(path: "/headers", recorder: recorder)

        try await adapter.handle(context)

        let headers = await recorder.response?.headers ?? []
        XCTAssertNil(headers.first { $0.0 == "connection" })
        XCTAssertNil(headers.first { $0.0 == "transfer-encoding" })
        XCTAssertEqual(headers.first { $0.0 == "x-adapter-test" }?.1, "kept")
    }

    private func makeContext(
        method: HTTP3.HTTPMethod = .get,
        path: String,
        headers: [(String, String)] = [],
        bodyChunks: [Data] = [],
        recorder: ResponseRecorder
    ) -> HTTP3RequestContext {
        let bodyStream = AsyncStream<Data> { continuation in
            for chunk in bodyChunks {
                continuation.yield(chunk)
            }
            continuation.finish()
        }

        return HTTP3RequestContext(
            request: HTTP3Request(
                method: method,
                authority: "localhost",
                path: path,
                headers: headers
            ),
            streamID: 0,
            bodyStream: bodyStream,
            respond: { status, headers, body, trailers in
                await recorder.record(status: status, headers: headers, body: body, trailers: trailers)
            },
            respondStreaming: { status, headers, trailers, writer in
                await recorder.record(status: status, headers: headers, body: Data(), trailers: trailers)
                let bodyWriter = HTTP3BodyWriter(_write: { data in
                    await recorder.append(data)
                })
                try await writer(bodyWriter)
            }
        )
    }
}

private actor ResponseRecorder {
    private(set) var response: RecordedResponse?

    func record(
        status: Int,
        headers: [(String, String)],
        body: Data,
        trailers: [(String, String)]?
    ) {
        response = RecordedResponse(status: status, headers: headers, body: body, trailers: trailers)
    }

    func append(_ data: Data) {
        guard var response else {
            return
        }
        response.body.append(data)
        self.response = response
    }
}

private struct RecordedResponse: Sendable {
    let status: Int
    let headers: [(String, String)]
    var body: Data
    let trailers: [(String, String)]?
}
