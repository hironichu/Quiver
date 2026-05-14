# Quiver Architecture

Quiver is organized as a layered protocol stack. Lower layers are usable on their own, and higher layers depend on them through explicit Swift package products.

## Stack Overview

```text
Application code
├── Framework adapters: Vapor, Hummingbird
├── Auth: guards, policies, JWT, OIDC helpers
├── MOQ: client, relay, track and object models
├── WebTransport: sessions, streams, datagrams, capsules
├── HTTP/3: requests, responses, settings, streams, Extended CONNECT
├── QPACK: header compression
├── QUIC public API: endpoints, managed connections, managed streams
├── QUIC connection: packet processing, connection state, migration, datagrams
├── QUIC stream: stream state, flow control, priorities, buffering
├── QUIC recovery: ACKs, RTT, loss detection, congestion control
├── QUIC crypto: TLS 1.3, AEAD, key schedule, certificates, session tickets
├── QUIC core: frames, packets, varints, transport parameters, errors
└── UDP transport: NIO and platform socket integration
```

## Ownership Boundaries

### `quiver-quic`

Owns QUIC protocol behavior and the lower transport stack:

- `QUICCore` contains protocol model types and frame/packet codecs.
- `QUICCrypto` contains TLS 1.3 integration, QUIC key material, header protection, AEAD, certificate validation, and session ticket types.
- `QUICStream` contains stream state machines, flow control, priority scheduling, and buffering.
- `QUICRecovery` contains ACK management, RTT estimation, loss detection, and congestion control.
- `QUICTransport` and `NIOUDPTransport` contain UDP integration.
- `QUICConnection` contains connection-state internals.
- `QUIC` exposes the public endpoint and managed connection API.

### `quiver-http3`

Owns HTTP/3 and QPACK:

- `QPACK` is independent header compression support.
- `HTTP3` contains client/server APIs, settings, frame codec, stream routing, priority handling, and Extended CONNECT.
- WebTransport server/session implementation lives here because it is part of HTTP/3 connection state and routing.

### `quiver-webtransport`

Provides a dedicated WebTransport package identity. It intentionally remains thin and re-exports HTTP/3-hosted WebTransport APIs.

### `quiver-auth`

Contains authentication middleware and helpers that operate on HTTP/3 request models. OIDC and JWT support live here rather than in HTTP/3.

### `quiver-adapters`

Contains framework integration surfaces. Adapter code should translate framework requests/responses to Quiver types without owning protocol behavior.

### `quiver-moq`

Contains Media over QUIC models and client/relay building blocks. It depends on QUIC core and stream types, but not on HTTP/3 unless a future feature explicitly requires it.

## Design Principles

- Keep protocol layers independent where possible.
- Put package-specific documentation in the package repository that owns the behavior.
- Keep the root `quiver` package as an aggregate and examples workspace.
- Use local path dependencies for development and GitHub URLs for package consumption.
- Prefer explicit products over large all-in-one imports in reusable libraries.

## Compliance

Detailed protocol compliance notes live in [../RFC_COMPLIANCE.md](../RFC_COMPLIANCE.md) and [RFC9114-HTTP3.md](RFC9114-HTTP3.md).
