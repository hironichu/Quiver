# WebTransport Guide

@Metadata {
  @TitleHeading("HTTP3")
}

Use this guide as the implementation map for WebTransport over HTTP/3 in Quiver.

## Overview

`HTTP3` provides WebTransport primitives for establishing sessions over Extended CONNECT, creating streams, and exchanging datagrams.

This article is a placeholder and should be expanded with concrete examples and API-level references from:

- ``WebTransport``
- ``WebTransportServer``
- ``WebTransportSession``
- ``WebTransportStream``
- ``WebTransportOptions``
- ``WebTransportServerOptions``
- ``WebTransportError``
- ``ExtendedConnectContext``

## Prerequisites

- QUIC + HTTP/3 transport available
- TLS configured for your endpoint
- HTTP/3 route/middleware setup for CONNECT handling
- WebTransport settings enabled where required

## Session Establishment

High-level flow:

1. Client opens HTTP/3 connection.
2. Client sends Extended CONNECT request for WebTransport.
3. Server validates request and accepts with `200`.
4. Session is created and control stream stays active.

Implementation focus points:

- Request validation (`:method`, `:protocol`, `:path`, `:authority`)
- Session ID / stream ownership
- Connection-to-session lifecycle binding
- Rejection handling (`4xx/5xx`) with deterministic errors

## Stream Operations

After session establishment:

- Open bidirectional streams for request/response-like exchanges.
- Open unidirectional streams for one-way media/data pipelines.
- Read/write with flow-control awareness.
- Close streams with explicit shutdown semantics.

Checklist:

- Backpressure propagation
- Partial reads/writes
- Cancellation behavior
- Stream close ordering (write close vs full close)

## Datagram Operations

Use datagrams for low-latency, lossy delivery where ordering/reliability is not required.

Checklist:

- Capability negotiation (datagram support)
- Size boundaries and MTU considerations
- Drop tolerance at app layer
- Fallback path when datagrams are unavailable

## Error Handling

Document and normalize errors from:

- CONNECT rejection / invalid response
- Session state violations
- Stream state violations
- Datagram unsupported/invalid operations
- Underlying transport failures

Recommended structure:

- map low-level failures to `WebTransportError`
- include actionable context in logs
- separate protocol errors from runtime I/O errors

## Security Notes

- Validate authority/path before session acceptance.
- Enforce origin/policy checks at middleware boundary.
- Bound memory use for inbound payloads.
- Apply timeout/idle policies for session cleanup.

## Observability

Add structured logs and metrics for:

- CONNECT accepted/rejected counts
- active sessions
- stream open/close rates
- datagram send/drop counters
- protocol error categories

## Related Articles

- <doc:GettingStarted>
- <doc:ServerGuide>
- <doc:ClientGuide>
- <doc:Architecture>
- <doc:Troubleshooting>