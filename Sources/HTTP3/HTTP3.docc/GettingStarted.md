# Getting Started with HTTP3

Build an HTTP/3 server or client using the `HTTP3` module.

## Overview

This is a starter article for the HTTP/3 catalog.

Use it to document:

- Required runtime and certificate setup
- Minimal server bootstrap
- Minimal client request flow
- Core request/response types
- Common startup failures and fixes

## Prerequisites

- Swift toolchain compatible with this package
- A project dependency on Quiver with the `HTTP3` product
- TLS certificates suitable for your local/dev environment

## Add the Dependency

```/dev/null/Package.swift#L1-13
dependencies: [
    .package(url: "https://github.com/hironichu/quiver.git", branch: "main")
],
targets: [
    .target(
        name: "MyApp",
        dependencies: [
            .product(name: "HTTP3", package: "Quiver")
        ]
    )
]
```

## Minimal Server Skeleton

```/dev/null/Server.swift#L1-13
import Foundation
import HTTP3

let server = HTTP3Server()

server.route("GET", "/") { _, _ in
    HTTP3Response(status: 200, body: Data("ok".utf8))
}

try await server.listen(host: "0.0.0.0", port: 4433)
```

## Minimal Client Skeleton

```/dev/null/Client.swift#L1-9
import Foundation
import HTTP3

let client = HTTP3Client()
let response = try await client.get("https://localhost:4433/")
print(response.status)
print(String(data: response.body, encoding: .utf8) ?? "")
```

## Next Steps

- <doc:ServerGuide>
- <doc:ClientGuide>
- <doc:WebTransportGuide>
- <doc:Architecture>
- <doc:Troubleshooting>