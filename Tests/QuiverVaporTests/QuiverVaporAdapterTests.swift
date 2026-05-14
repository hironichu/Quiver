#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import HTTP3
import NIOCore
import QuiverVapor
import Vapor
import XCTest

final class QuiverVaporAdapterTests: XCTestCase {
    func testDispatchesRequestToVaporRoute() async throws {
        let app = try await Application.make(.testing)

        app.get("hello") { _ in
            "Hello from Vapor"
        }

        let adapter = QuiverVaporAdapter(application: app)
        let recorder = ResponseRecorder()
        let context = makeContext(path: "/hello", recorder: recorder)

        try await adapter.handle(context)

        let response = await recorder.response
        XCTAssertEqual(response?.status, 200)
        XCTAssertEqual(String(data: response?.body ?? Data(), encoding: .utf8), "Hello from Vapor")
        XCTAssertEqual(response?.headers.first { $0.0 == "content-type" }?.1, "text/plain; charset=utf-8")
        try await app.asyncShutdown()
    }

    func testForwardsRequestBodyAndHeaders() async throws {
        let app = try await Application.make(.testing)

        app.post("echo") { request -> String in
            let header = request.headers.first(name: "x-quiver-test") ?? "missing"
            return "\(header):\(request.body.string ?? "")"
        }

        let adapter = QuiverVaporAdapter(application: app)
        let recorder = ResponseRecorder()
        let context = makeContext(
            method: .post,
            path: "/echo",
            headers: [("x-quiver-test", "present")],
            body: Data("payload".utf8),
            recorder: recorder
        )

        try await adapter.handle(context)

        let response = await recorder.response
        XCTAssertEqual(response?.status, 200)
        XCTAssertEqual(String(data: response?.body ?? Data(), encoding: .utf8), "present:payload")
        try await app.asyncShutdown()
    }

    func testStripsHopByHopResponseHeaders() async throws {
        let app = try await Application.make(.testing)

        app.get("headers") { _ -> Response in
            var headers = HTTPHeaders()
            headers.add(name: "connection", value: "close")
            headers.add(name: "transfer-encoding", value: "chunked")
            headers.add(name: "x-adapter-test", value: "kept")
            return Response(status: .ok, headers: headers, body: .init(string: "ok"))
        }

        let adapter = QuiverVaporAdapter(application: app)
        let recorder = ResponseRecorder()
        let context = makeContext(path: "/headers", recorder: recorder)

        try await adapter.handle(context)

        let headers = await recorder.response?.headers ?? []
        XCTAssertNil(headers.first { $0.0 == "connection" })
        XCTAssertNil(headers.first { $0.0 == "transfer-encoding" })
        XCTAssertEqual(headers.first { $0.0 == "x-adapter-test" }?.1, "kept")
        try await app.asyncShutdown()
    }

    func testRejectsOversizedRequestBody() async throws {
        let app = try await Application.make(.testing)

        app.post("echo") { request -> String in
            request.body.string ?? ""
        }

        let adapter = QuiverVaporAdapter(
            application: app,
            configuration: .init(maxRequestBodySize: 3)
        )
        let recorder = ResponseRecorder()
        let context = makeContext(
            method: .post,
            path: "/echo",
            body: Data("toolarge".utf8),
            recorder: recorder
        )

        try await adapter.handle(context)

        let response = await recorder.response
        XCTAssertEqual(response?.status, 413)
        XCTAssertEqual(String(data: response?.body ?? Data(), encoding: .utf8), "Payload Too Large")
        try await app.asyncShutdown()
    }

    private func makeContext(
        method: HTTP3.HTTPMethod = .get,
        path: String,
        headers: [(String, String)] = [],
        body: Data = Data(),
        recorder: ResponseRecorder
    ) -> HTTP3RequestContext {
        let bodyStream = AsyncStream<Data> { continuation in
            if !body.isEmpty {
                continuation.yield(body)
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
                _ = writer
                await recorder.record(
                    status: status,
                    headers: headers,
                    body: Data(),
                    trailers: trailers
                )
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
}

private struct RecordedResponse: Sendable {
    let status: Int
    let headers: [(String, String)]
    let body: Data
    let trailers: [(String, String)]?
}

