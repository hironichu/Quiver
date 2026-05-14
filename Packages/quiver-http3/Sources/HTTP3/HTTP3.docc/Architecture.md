# HTTP3 Architecture

## Overview

This article is a placeholder for the `HTTP3` module architecture.

`HTTP3` is layered over `QUIC` and integrates `QPACK` for header compression.  
The module provides server/client APIs, connection and stream orchestration, frame codecs, and WebTransport support.

## Layer Model

1. **Application API Layer**
   - `HTTP3Server`
   - `HTTP3Client`
   - Request/response routing and handlers

2. **Connection and Stream Layer**
   - `HTTP3Connection`
   - Request stream lifecycle
   - Control stream management
   - Extended CONNECT handling

3. **Protocol Framing Layer**
   - `HTTP3Frame`
   - `HTTP3FrameCodec`
   - `HTTP3Settings`
   - Validation of frame placement and protocol rules

4. **Compression Layer**
   - QPACK encoder/decoder integration
   - Header block encode/decode pipeline

5. **Transport Layer**
   - QUIC stream and datagram transport
   - Reliability, flow control, and congestion handled by lower layers

## Key Responsibilities

- Enforce HTTP/3 stream-type and frame-type constraints.
- Encode/decode frames and apply settings negotiation.
- Bridge request/response semantics to QUIC streams.
- Support Extended CONNECT for WebTransport sessions.
- Preserve forward compatibility for unknown frame types where required by spec.

## Concurrency Model

- Uses Swift concurrency (`async/await`) for I/O and connection tasks.
- Long-lived connection/session processing should run in isolated tasks.
- Shared mutable state should be actor-isolated where applicable.

## Error and Diagnostics Model

- Protocol violations should map to explicit `HTTP3Error` values.
- Transport and session failures should propagate with contextual error messages.
- Future version of this article should include:
  - error-classification matrix
  - recoverable vs terminal failure paths
  - recommended logging fields

## Integration Points

- With `QUIC`: stream lifecycle, connection shutdown, transport backpressure.
- With `QPACK`: request/response header field section encoding/decoding.
- With WebTransport: session bootstrap via Extended CONNECT and stream/datagram APIs.

## Planned Expansion

This placeholder should be expanded with:

- sequence diagrams for:
  - client request lifecycle
  - server response lifecycle
  - WebTransport session establishment
- protocol state transition notes
- performance and memory considerations
- RFC section mapping for implemented features

## See Also

- <doc:GettingStarted>
- <doc:ServerGuide>
- <doc:ClientGuide>
- <doc:WebTransportGuide>
- <doc:Troubleshooting>