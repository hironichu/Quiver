# ByteBuffer End-to-End Migration — Scope & Plan

Status: **Deferred**
Last updated: 2025-02-10

## Problem

Every incoming UDP datagram is copied from NIO `ByteBuffer` to Foundation `Data`
at the receive boundary. The reverse copy happens on the send path. For a
connection processing thousands of packets per second, these copies are
measurable overhead.

## Current Conversion Boundaries

### Inbound (ByteBuffer -> Data)

| Location | Operation |
|---|---|
| `Sources/QUIC/QUICEndpoint+IOLoop.swift` L152 | `Data(buffer: packet.buffer)` — primary copy point |
| `Sources/QUICTransport/UDPSocket.swift` L81-83 | `IncomingPacket.data` computed property |
| `Sources/NIOUDPTransport/UDPTransport.swift` L41-43 | `IncomingDatagram.data` computed property |

### Outbound (Data -> ByteBuffer)

| Location | Operation |
|---|---|
| `Sources/NIOUDPTransport/NIOUDPTransport.swift` L313-323 | `sendBatch` converts `[Data]` to `[ByteBuffer]` |
| `Sources/NIOUDPTransport/AddressHelpers.swift` L155-167 | `ByteBuffer.from(_:allocator:)` helper |

### Conversion Helpers

| Location | Role |
|---|---|
| `Sources/NIOUDPTransport/AddressHelpers.swift` L140-152 | `Data.init(buffer: ByteBuffer)` |
| `Sources/NIOUDPTransport/AddressHelpers.swift` L155-167 | `ByteBuffer.from(_:allocator:)` |

## Downstream Data Flow (modules consuming Foundation `Data`)

Once converted to `Data`, the value flows through the entire stack:

```
QUICEndpoint+IOLoop.swift          Data(buffer:) copy
        |
        v
PacketProcessor                    decrypt/encrypt, header protection
        |
        v
FrameCodec / DataReader            frame decode (varint, fields)
        |
        v
QUICConnectionHandler              frame dispatch
        |
        +--------> CryptoStreamManager / CryptoBuffer    (CRYPTO frames)
        |                  |
        |                  v
        |           TLS13Provider                        (handshake bytes)
        |
        +--------> StreamManager / DataBuffer            (STREAM frames)
        |
        +--------> AckManager                            (ACK frames)
        |
        v
AEAD (seal / open)                 nonce + encrypt/decrypt
        |
        v
[Data] outbound packets            returned up to endpoint
        |
        v
NIOUDPTransport                    ByteBuffer.from() copy back
```

## Affected Source Files (non-exhaustive)

### Core pipeline (must change)

- `Sources/QUIC/QUICEndpoint+IOLoop.swift`
- `Sources/QUIC/ManagedConnection.swift`
- `Sources/QUIC/PacketProcessor.swift` (internal only — not public API)
- `Sources/QUICCrypto/AEAD.swift`
- `Sources/QUICCrypto/CryptoStream/CryptoStreamManager.swift`
- `Sources/QUICCrypto/CryptoStream/CryptoBuffer.swift`
- `Sources/QUICCore/Frame/FrameCodec.swift`
- `Sources/QUICCore/DataReader.swift`
- `Sources/QUICCore/Packet/*.swift` (header parsing)
- `Sources/QUICStream/DataBuffer.swift`
- `Sources/QUICStream/DataStream.swift`
- `Sources/QUICStream/StreamManager.swift`

### TLS boundary (high risk)

- `Sources/QUICCrypto/TLS/TLS13Handler.swift`
- `Sources/QUICCrypto/TLS/TLS13Provider.swift` (protocol — public API change)
- Any TLS backend implementations

### Transport layer (already ByteBuffer-native)

- `Sources/NIOUDPTransport/NIOUDPTransport.swift` — already uses ByteBuffer
- `Sources/NIOUDPTransport/UDPTransport.swift` — `IncomingDatagram.buffer` already ByteBuffer
- `Sources/QUICTransport/UDPSocket.swift` — `IncomingPacket.buffer` already ByteBuffer

### HTTP/3 layer (secondary)

- `Sources/HTTP3/HTTP3FrameCodec.swift`
- `Sources/HTTP3/HTTP3Connection.swift`
- `Sources/HTTP3/WebTransportCapsule.swift`
- `Sources/HTTP3/WebTransportSession.swift`

## Estimated Scope

| Area | Files | Risk | Effort |
|---|---|---|---|
| Transport boundary removal | 3 | Low | 1 day |
| PacketProcessor + AEAD | 4 | Medium | 2-3 days |
| FrameCodec + DataReader | 5 | Medium | 2-3 days |
| Stream buffers | 4 | Medium | 1-2 days |
| CryptoStream + TLS | 4 | High | 3-5 days |
| HTTP/3 layer | 6 | Medium | 2-3 days |
| Test updates | all | Low | 2-3 days |
| **Total** | **~30** | **High** | **13-20 days** |

## Migration Strategy

### Option A: Progressive (Recommended)

Introduce a `QUICBuffer` type alias that starts as `Data` and later switches to
`ByteBuffer`. Add a compatibility shim so both can coexist during migration.

1. **Phase 0**: Define `typealias QUICBuffer = Data` and a `QUICBufferReader`
   wrapper around `DataReader`. Replace direct `Data` usage in internal APIs
   with `QUICBuffer`. No behavioral change.

2. **Phase 1**: Migrate `PacketProcessor` and `AEAD` to accept `QUICBuffer`.
   These are internal, non-public types. Remove the inbound copy in
   `QUICEndpoint+IOLoop.swift` by passing `ByteBuffer` directly.

3. **Phase 2**: Migrate `FrameCodec`, `DataReader`, stream buffers. These are
   `@testable`-accessible but have public protocol conformances.

4. **Phase 3**: Migrate TLS boundary. This is the highest-risk change because
   `TLS13Provider` is a public protocol. May require a major version bump or
   a parallel protocol with default implementation.

5. **Phase 4**: Migrate HTTP/3 layer. This is downstream and can follow once
   the core pipeline is done.

6. **Phase 5**: Remove `QUICBuffer` alias, finalize on `ByteBuffer` everywhere.
   Remove conversion helpers.

### Option B: Big Bang

Switch everything in one branch. Faster if done by a single developer with full
context, but high risk of regressions and impossible to review incrementally.

Not recommended.

## Prerequisites

- All current optimization work (this sweep) must be merged and stable.
- Benchmark baselines must be recorded before starting migration.
- The `DataReader` type should be evaluated for replacement with NIO's
  `ByteBuffer` read APIs (`readInteger`, `readSlice`, etc.) which are
  already zero-copy.

## Decision Criteria for Starting

Start this migration when:

1. Profiling shows the `Data(buffer:)` copy is a measurable bottleneck
   (> 5% of per-packet CPU time), OR
2. A major API-level overhaul is planned that already requires breaking changes, OR
3. The codebase needs to integrate with NIO channel handlers that expect
   `ByteBuffer` end-to-end (e.g., QUIC-as-NIO-protocol-handler).

## Notes

- The NIO `ByteBuffer` is CoW like `Data`, but uses NIO's allocator which
  pools memory. This is an additional win beyond removing the copy.
- `ByteBuffer` slicing is zero-copy (`getSlice` / `readSlice`), which would
  replace many `Data(slice)` / `dropFirst` patterns that currently copy.
- CryptoKit APIs (`AES.GCM`, `ChaChaPoly`) accept `ContiguousBytes`, which
  `ByteBuffer.readableBytesView` conforms to. No extra copy needed for
  encryption/decryption.