# Client Guide

@Metadata {
  @TitleHeading("HTTP3")
}

Build client-side HTTP/3 workflows using ``HTTP3Client`` and related request/response APIs.

## Overview

This placeholder article documents how to:

- create and configure an ``HTTP3Client``
- send requests and handle responses
- manage connection reuse behavior
- integrate error handling and retries

## Basic Usage

```/dev/null/ClientGuide.swift#L1-11
import HTTP3

let client = HTTP3Client()
let response = try await client.get("https://localhost:4433/health")

print("Status: \(response.status)")
if let text = String(data: response.body, encoding: .utf8) {
    print(text)
}
```

## Request Patterns

Typical client patterns to document here:

- single-shot GET/POST calls
- custom headers
- payload upload
- streaming response consumption
- cancellation and timeout strategy

## Configuration

Document and link all supported configuration points for:

- transport and connection behavior
- TLS/certificate policy
- request-level defaults
- concurrency limits

## Error Handling

Capture expected error categories:

- connection/setup failures
- protocol/frame violations
- response validation failures
- transient network conditions

Include recommended retry/backoff behavior and observability guidance.

## Diagnostics

Add examples for:

- enabling structured logging
- collecting per-request timing
- surfacing protocol-level errors
- mapping failures into app error domains

## Next Steps

- <doc:ServerGuide>
- <doc:WebTransportGuide>
- <doc:Troubleshooting>
- ``HTTP3Client``
- ``HTTP3Request``
- ``HTTP3Response``
