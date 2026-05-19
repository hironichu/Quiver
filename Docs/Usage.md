# Quiver Usage Guide

This guide shows where to start. Package-specific READMEs and DocC catalogs contain the deeper API references.

## Install The Aggregate Package

```swift
dependencies: [
    .package(url: "https://github.com/hironichu/quiver.git", branch: "main")
]
```

```swift
.target(
    name: "MyApp",
    dependencies: [
        .product(name: "Quiver", package: "quiver")
    ]
)
```

The aggregate product re-exports modules according to enabled SwiftPM package traits. The default trait set enables the complete stack.

Enable the experimental runtime-backed QUIC transport path by selecting `QuiverRuntimeSupport`. That root trait forwards `quiver-quic`'s `quiverRuntime` package trait and also enables `QUICSupport`.

```bash
swift build --target Quiver --traits QuiverRuntimeSupport
```

## Use A Dedicated Package

For libraries, prefer the narrowest package you need:

```swift
dependencies: [
    .package(url: "https://github.com/hironichu/quiver-quic.git", branch: "main")
]
```

```swift
.target(
    name: "TransportLibrary",
    dependencies: [
        .product(name: "QUIC", package: "quiver-quic")
    ]
)
```

## QUIC

```swift
import QUIC

let endpoint = QUICEndpoint(role: .client)
let connection = try await endpoint.connect(
    to: SocketAddress(ipAddress: "127.0.0.1", port: 4433)
)

let stream = try await connection.openStream()
try await stream.write(Data("ping".utf8))
try await stream.closeWrite()

if let response = try await stream.read() {
    print(String(decoding: response, as: UTF8.self))
}

await connection.shutdown()
```

Use `openStream(priority:)` when the stream should enter QUIC scheduling with a non-default priority.

## HTTP/3

```swift
import HTTP3

let options = HTTP3ServerOptions(
    host: "0.0.0.0",
    port: 4433,
    certificatePath: "/path/to/cert.pem",
    privateKeyPath: "/path/to/key.pem"
)

let server = HTTP3Server(options: options)

await server.onRequest { context in
    try await context.respond(
        status: 200,
        headers: [("content-type", "text/plain")],
        Data("Hello from Quiver".utf8)
    )
}

try await server.listen()
```

For client code:

```swift
import HTTP3

let client = HTTP3Client()
let response = try await client.get("https://localhost:4433/")
print(response.status)
```

## WebTransport

```swift
import WebTransport

let session = try await WebTransport.connect(
    url: "https://localhost:4433/echo",
    options: .insecure()
)

let stream = try await session.openBidirectionalStream()
try await stream.write(Data("hello".utf8))
let response = try await stream.read()
try await session.sendDatagram(Data("ping".utf8))
```

Server-side WebTransport APIs are implemented by `quiver-http3` and re-exported by `quiver-webtransport`.

## Authentication

```swift
import QuiverAuth
```

Use `QuiverAuth` for HTTP/3 request extraction, auth policies, JWT issuing, and OIDC helpers. See [QuiverAuth.md](QuiverAuth.md) for the dedicated authentication notes.

## Framework Adapters

```swift
import QuiverVapor
import QuiverHummingbird
```

The adapters are kept in `quiver-adapters` so framework-specific dependencies do not enter lower protocol packages.

## Media Over QUIC

```swift
import MOQCore
import MOQClient
import MOQRelay
```

Use `quiver-moq` directly when building MOQ clients or relays. The root aggregate can re-export MOQ products through the `MOQSupport` trait.

## Examples

The root repository keeps runnable examples:

```bash
swift run QUICEchoServer
swift run HTTP3Demo
swift run WebTransportDemo
```

See [../Examples/EXAMPLES.md](../Examples/EXAMPLES.md) for the example guide.
