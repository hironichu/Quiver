# ``HTTP3``

A Swift HTTP/3 implementation built on QUIC, including core request/response APIs, frame handling, and WebTransport integration points.

## Overview

Use ``HTTP3`` to build HTTP/3 servers and clients with Swift concurrency.  
This module provides:

- HTTP/3 connection and stream handling
- Request/response abstractions
- Frame and settings primitives
- Extended CONNECT support
- WebTransport server/client building blocks

## Topics

### Essentials

- ``HTTP3Server``
- ``HTTP3Client``
- ``HTTP3Connection``
- ``HTTP3Request``
- ``HTTP3Response``

### Configuration

- ``HTTP3Settings``
- <doc:ClientGuide>

### Frames and Protocol Types

- ``HTTP3Frame``
- ``HTTP3FrameType``
- ``HTTP3FrameCodec``
- ``HTTP3Error``

### Extended CONNECT and WebTransport

- ``ExtendedConnectContext``
- ``WebTransport``
- ``WebTransportServer``
- ``WebTransportSession``
- ``WebTransportStream``
- ``WebTransportOptions``
- ``WebTransportServerOptions``
- ``WebTransportError``

### Articles

- <doc:GettingStarted>
- <doc:ServerGuide>
- <doc:ClientGuide>
- <doc:WebTransportGuide>
- <doc:Architecture>
- <doc:Troubleshooting>

## See Also

- [QUIC module](https://github.com/hironichu/quiver)
- [QPACK module](https://github.com/hironichu/quiver)
- [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)