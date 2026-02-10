# HTTP/3 Streaming API Reference

## Overview

Quiver's HTTP/3 layer treats **all bodies as streams by default**. There is no
distinction between "streaming" and "buffered" at the API level -- the consumer
decides how to read the body (`.data()`, `.text()`, `.json()`, or raw iteration).

This design mirrors the JavaScript `fetch()` / `Response` API:
- `response.body` is always a `ReadableStream`
- `.json()`, `.text()`, `.arrayBuffer()` are convenience consumers

---

## Core Type: `HTTP3Body`

File: `Sources/HTTP3/HTTP3Body.swift`

`HTTP3Body` wraps an `AsyncStream<Data>` and provides typed convenience consumers.
Each consumer **consumes the stream exactly once**. A second call throws
`HTTP3BodyError.alreadyConsumed`.

```swift

public struct HTTP3Body: ~Copyable, Sendable {

    private let _stream: AsyncStream<Data>
    public init(stream: AsyncStream<Data>) {
        self._stream = stream
    }

    public init(data: Data = Data()) {

    }


    public consuming func data(maxBytes: Int = 104_857_600) async throws -> Data {
    }

    public consuming func text(maxBytes: Int = 104_857_600) async throws -> String {
    }

    public consuming func json<T: Decodable>(_ type: T.Type, maxBytes: Int = 104_857_600) async throws -> T {
        let rawData = try await data(maxBytes: maxBytes)
        return try JSONDecoder().decode(T.self, from: rawData)
    }

    public consuming func stream() -> AsyncStream<Data> {

    }
}
```

## Server-Side API

### `context.body` -- Request body (always a stream)

File: `Sources/HTTP3/HTTP3Types.swift` -- `HTTP3RequestContext`

```swift
public struct HTTP3RequestContext: Sendable {
    /// The received HTTP/3 request (headers only; body NOT pre-read).
    public let request: HTTP3Request

    /// The QUIC stream ID this request arrived on.
    public let streamID: UInt64

    /// The request body. Always present (empty body = zero-yield stream).
    /// Consume with .data(), .text(), .json(), or .stream().
    public let body: HTTP3Body

    // -- Response methods (see below) --
}
```

Usage:
```swift
// Read full body as Data (capped at 10 MB)
let data = try await context.body.data(maxBytes: 10_485_760)

// Read as String
let text = try await context.body.text()

// Decode JSON
let payload = try await context.body.json(MyPayload.self)

// Stream chunks manually
for await chunk in context.body.stream() {
    process(chunk)
}
```

### `context.respond(status:headers:_ body:)` -- Send response with Data body

```swift
public func respond(
    status: Int,
    headers: [(String, String)] = [],
    _ body: Data = Data()
) async throws
```

Sends HEADERS + single DATA frame + FIN in one shot.
Pass `Data()` (or omit) for an empty body (e.g. 204).

```swift
try await context.respond(status: 200, headers: [("content-type", "text/plain")], Data("OK".utf8))
try await context.respond(status: 204)
```

### `context.respond(status:headers:trailers:_ writer:)` -- Send response with streaming body

```swift
public func respond(
    status: Int,
    headers: [(String, String)] = [],
    trailers: [(String, String)]? = nil,
    _ writer: @escaping @Sendable (HTTP3BodyWriter) async throws -> Void
) async throws
```

Sends HEADERS immediately, then streams DATA frames via the writer closure.
FIN is sent when the closure returns. Optional trailing headers before FIN.

```swift
try await context.respond(status: 200, headers: [("content-type", "application/octet-stream")]) { writer in
    for chunk in generateChunks() {
        try await writer.write(chunk)
    }
}
```

### `HTTP3BodyWriter`

File: `Sources/HTTP3/HTTP3Types.swift`

```swift
public struct HTTP3BodyWriter: Sendable {
    /// Write a chunk as an HTTP/3 DATA frame.
    /// Empty data is a no-op. Suspends if QUIC send window is full.
    public func write(_ data: Data) async throws
}
```

---

## Client-Side API

File: `Sources/HTTP3/HTTP3Client.swift`

All client methods return `HTTP3Response` with a **stream-backed** `body: HTTP3Body`.
The caller decides how to consume it.

### `HTTP3Response`

File: `Sources/HTTP3/HTTP3Types.swift`

```swift
public struct HTTP3Response: Sendable {
    public var status: Int
    public var headers: [(String, String)]
    public var body: HTTP3Body
    public var trailers: [(String, String)]?

    /// Convenience init wrapping Data (used internally and in tests).
    public init(
        status: Int,
        headers: [(String, String)] = [],
        body: Data = Data(),
        trailers: [(String, String)]? = nil
    )
}
```

Note: `HTTP3Response` is no longer `Hashable` or `Equatable` because `HTTP3Body`
is a reference type with stream semantics. Status/header checks remain trivial.

### `client.get(_ url:headers:)` -- GET request, streaming response

```swift
public func get(
    _ url: String,
    headers: [(String, String)] = []
) async throws -> HTTP3Response
```

Response body is always a stream. Consume however you want:

```swift
let response = try await client.get("https://example.com/data")
let data = try await response.body.data()

// OR stream chunks
let response = try await client.get("https://example.com/large-file")
for await chunk in response.body.stream() {
    fileHandle.write(chunk)
}
```

### `client.post(_ url:body:headers:)` -- POST with Data body

```swift
public func post(
    _ url: String,
    body: Data,
    headers: [(String, String)] = []
) async throws -> HTTP3Response
```

Sends the entire `Data` body in one shot. Response body is a stream.

### `client.post(_ url:headers:_ writer:)` -- POST with streaming upload body

```swift
public func post(
    _ url: String,
    headers: [(String, String)] = [],
    _ writer: @escaping @Sendable (HTTP3BodyWriter) async throws -> Void
) async throws -> HTTP3Response
```

Streams the request body via the writer closure. Response is returned
after the upload completes (half-duplex).

```swift
let response = try await client.post("https://example.com/upload", headers: [
    ("content-type", "application/octet-stream")
]) { writer in
    for chunk in fileChunks {
        try await writer.write(chunk)
    }
}
let status = response.status
```

### `client.put(_ url:body:headers:)` -- PUT with Data body

```swift
public func put(
    _ url: String,
    body: Data,
    headers: [(String, String)] = []
) async throws -> HTTP3Response
```

### `client.delete(_ url:headers:)` -- DELETE

```swift
public func delete(
    _ url: String,
    headers: [(String, String)] = []
) async throws -> HTTP3Response
```

### `client.request(_ request:)` -- Generic method

```swift
public func request(_ request: HTTP3Request) async throws -> HTTP3Response
```

Low-level method for arbitrary HTTP methods. Uses buffered body from
`request.body` if present. Response body is stream-backed.

---

## Full-Duplex: `client.open(method:url:headers:)` (Planned)

For bidirectional streaming (write request body while reading response body
concurrently on the same HTTP/3 stream):

```swift
public func open(
    method: String = "POST",
    url: String,
    headers: [(String, String)] = []
) async throws -> HTTP3Exchange
```

Returns:
```swift
public struct HTTP3Exchange: Sendable {
    /// Writer for the request body. Call .finish() to send FIN.
    public let writer: HTTP3BodyWriter

    /// The response. Available once the server sends HEADERS.
    /// Body is a stream that can be read concurrently with writing.
    public var response: HTTP3Response { get async throws }
}
```

Usage:
```swift
let exchange = try await client.open(method: "POST", url: "/bidi-rpc", headers: [...])

// Write and read concurrently
async let upload: Void = {
    try await exchange.writer.write(chunk1)
    try await exchange.writer.write(chunk2)
    try await exchange.writer.finish()
}()

let response = try await exchange.response
for await chunk in response.body.stream() {
    process(chunk)
}
try await upload
```

This maps directly to a single HTTP/3 bidirectional QUIC stream where both
sides send frames independently. Useful for gRPC-style bidirectional streaming.

**Status**: API defined, implementation deferred.

---

## Browser `fetch()` Interop

### How `context.respond(status:headers:_ writer:)` works with browser `fetch()`

When the server uses the streaming `respond()` overload and a browser calls
`fetch()` against that endpoint, the response is consumed as a stream via the
`ReadableStream` API. The browser does NOT buffer the entire response.

#### Wire-level sequence

1. Server sends HTTP/3 HEADERS frame (status + response headers) immediately.
2. Server sends HTTP/3 DATA frames as the writer closure yields chunks.
3. Server sends FIN (end-of-stream flag) when the writer closure returns.

#### Browser-side consumption

```javascript
const response = await fetch('https://your-server/stream-endpoint');
// response.status and response.headers available now (from HEADERS frame)

const reader = response.body.getReader();
while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  // value: Uint8Array -- arrives as each DATA frame lands
  console.log('Received chunk:', value.length, 'bytes');
}
```

Each `reader.read()` resolves when the browser receives DATA frames from the
HTTP/3 connection. Chunks arrive incrementally as they are sent.

### This is NOT SSE

The streaming `respond()` produces a standard HTTP response with a streamed
body. It is not Server-Sent Events unless you explicitly format it as such.

---

## Comparison: Streaming respond vs SSE vs WebSocket

| Aspect | `respond()` streaming + fetch | SSE (`EventSource`) | WebSocket |
|---|---|---|---|
| Transport | HTTP/3 DATA frames, FIN at end | HTTP chunked, text-based | Upgrade to WS, bidirectional |
| Browser API | `fetch()` -> `response.body.getReader()` | `EventSource` or fetch + reader | `WebSocket` API |
| Content-Type | Any | Must be `text/event-stream` | N/A |
| Data format | Raw bytes (any) | Text: `event:` / `data:` lines | Binary or text frames |
| Direction | Server -> Client (single response) | Server -> Client (long-lived) | Bidirectional |
| Auto-reconnect | No | Yes (built into EventSource) | No |
| Binary support | Yes (native) | No (must base64) | Yes |
| Connection lifetime | Ends when writer finishes (FIN) | Stays open indefinitely | Stays open indefinitely |
| Backpressure | QUIC flow control (native) | TCP flow control | TCP flow control |

### When to use which

- **Streaming `respond()`**: File downloads, binary data, large JSON, video/audio. Transfer has a defined end.
- **SSE**: Real-time event notifications (chat, live scores, log tailing). Auto-reconnect and text framing useful.
- **WebSocket**: Bidirectional communication (games, collaborative editing, RPC).

---

## Layering SSE on Top of Streaming `respond()`

Set the appropriate Content-Type and format output as SSE text:

```swift
try await context.respond(status: 200, headers: [
    ("content-type", "text/event-stream"),
    ("cache-control", "no-cache")
]) { writer in
    for await event in someAsyncSequence {
        let sseText = "event: update\ndata: \(event.json)\n\n"
        try await writer.write(Data(sseText.utf8))
    }
}
```

Browser-side, consumable with either `EventSource` or `fetch()` + `getReader()`.

---

## Chunk Size Behavior

`for await chunk in body.stream()` yields chunks whose size is determined by:
- QUIC packet size and congestion window
- How the peer batches `writer.write()` calls
- Network conditions

A single `writer.write(1MB)` on the sender may arrive as multiple ~100KB chunks.
This is expected behavior for byte streams -- chunks are **arbitrary byte slices,
not semantic message boundaries**.

The convenience consumers (`.data()`, `.text()`, `.json()`) handle this
transparently by accumulating all chunks internally.

---

## Implementation Details

### Source Locations

| Component | File | Symbol |
|---|---|---|
| Body type | `Sources/HTTP3/HTTP3Body.swift` | `HTTP3Body` |
| Body error | `Sources/HTTP3/HTTP3Body.swift` | `HTTP3BodyError` |
| Body writer | `Sources/HTTP3/HTTP3Types.swift` | `HTTP3BodyWriter` |
| Request context | `Sources/HTTP3/HTTP3Types.swift` | `HTTP3RequestContext` |
| Response type | `Sources/HTTP3/HTTP3Types.swift` | `HTTP3Response` |
| Client | `Sources/HTTP3/HTTP3Client.swift` | `HTTP3Client` |
| Connection (client) | `Sources/HTTP3/HTTP3Connection+Client.swift` | `sendRequest()`, `readResponseStreaming()` |
| Connection (server) | `Sources/HTTP3/HTTP3Connection+Server.swift` | `dispatchRegularRequest()`, `sendResponse()`, `sendResponseStreaming()` |

### Wire Protocol

- **HEADERS frame**: Sent once at the start (status + headers via QPACK).
- **DATA frames**: Sent incrementally by `writer.write()`. Size depends on QUIC flow control.
- **FIN**: Set on final frame when writer closure returns or `Data` body is fully sent.

### Backpressure

- `writer.write()` is async and suspends when the QUIC stream send window is full.
- The send window refills as the peer ACKs received data.
- On the receiver side, `.stream()` consumption rate controls ACK flow, which governs the sender's window.
- `.data()` / `.text()` / `.json()` read as fast as possible (no artificial throttle).

---

## API Migration Summary

| Old API | New API | Notes |
|---|---|---|
| `context.bodyStream` | `context.body` | `HTTP3Body`, not raw `AsyncStream` |
| `context.collectBody(maxBytes:)` | `context.body.data(maxBytes:)` | Method on body, not on context |
| N/A | `context.body.text(maxBytes:)` | New convenience |
| N/A | `context.body.json(_:maxBytes:)` | New convenience |
| N/A | `context.body.stream()` | Replaces direct `bodyStream` access |
| `context.respond(HTTP3Response(...))` | `context.respond(status:headers:body)` | No HTTP3Response construction |
| `context.respondStreaming(...)` | `context.respond(status:headers:_ writer:)` | Same name, writer overload |
| `client.postStreaming(url:bodyWriter:)` | `client.post(url:headers:_ writer:)` | Method = HTTP verb, overload = body type |
| `client.getStreaming(url:)` | `client.get(url:)` | Response body is always a stream |
| `HTTP3Response.body: Data` | `HTTP3Response.body: HTTP3Body` | Stream-backed by default |
| `HTTP3Response: Hashable` | Removed | Body is reference type with stream semantics |

---

## Related Documentation

- [PLAN_MTU_PACKET_SPLITTING.md](PLAN_MTU_PACKET_SPLITTING.md) -- MTU handling and packet batching
- [RFC9114-HTTP3.md](RFC9114-HTTP3.md) -- HTTP/3 protocol reference
- [WEBTRANSPORT_PLAN.md](WEBTRANSPORT_PLAN.md) -- WebTransport streaming (datagrams + streams)
- [SWIFT_OPTIMIZATION_ANALYSIS.md](SWIFT_OPTIMIZATION_ANALYSIS.md) -- Performance analysis and syscall optimization
