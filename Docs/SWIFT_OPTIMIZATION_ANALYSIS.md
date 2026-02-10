# Quiver — Swift Optimization & Restructuring Analysis

> **Purpose**: This document is a technical brief for an AI agent (or human engineer) who will execute the refactoring. Every finding includes file paths, line numbers, rationale, impact, and concrete instructions.
>
> **Generated from**: Full source analysis of `Sources/` (9 modules, ~80 files, ~20 000+ LOC)
>
> **Swift version**: 6.2 · **Platforms**: macOS 15+, iOS 18+, tvOS 18+, watchOS 11+, visionOS 2+

---

## Table of Contents

1. [Project Architecture Overview](#1-project-architecture-overview)
2. [File Splitting — Oversized Files](#2-file-splitting--oversized-files)
3. [Protocol-Oriented Improvements](#3-protocol-oriented-improvements)
4. [Extension Usage Improvements](#4-extension-usage-improvements)
5. [Swift Language Feature Adoption](#5-swift-language-feature-adoption)
6. [Type System Strengthening](#6-type-system-strengthening)
7. [Potential Bugs & Correctness Issues](#7-potential-bugs--correctness-issues)
8. [Performance Micro-Optimizations](#8-performance-micro-optimizations)
9. [Naming, Deprecation & Cleanup](#9-naming-deprecation--cleanup)
10. [Cross-Module Visibility (`package` access)](#10-cross-module-visibility-package-access)
11. [Summary Priority Matrix](#11-summary-priority-matrix)

---

## 1. Project Architecture Overview

### Module Dependency Graph

```text
HTTP3
 ├── QUIC
 │    ├── QUICCore
 │    ├── QUICCrypto     → QUICCore
 │    ├── QUICConnection → QUICCore, QUICCrypto, QUICStream, QUICRecovery
 │    ├── QUICStream     → QUICCore
 │    ├── QUICRecovery   → QUICCore
 │    └── QUICTransport  → QUICCore
 ├── QPACK (standalone)
 └── QUICCore
```

### File Count per Module

| Module | Files | Approx LOC | Largest file |
|--------|-------|-----------|-------------|
| QUICCore | 12 (incl. subdirs) | ~3 200 | `FrameCodec.swift` (752) |
| QUICCrypto | 24 (incl. TLS tree) | ~5 500 | `TLS13Handler.swift` (1 437) |
| QUICConnection | 5 | ~2 100 | `QUICConnectionHandler.swift` (1 120) |
| QUICStream | 7 | ~2 800 | `StreamManager.swift` (736) |
| QUICRecovery | 10 | ~2 400 | `LossDetector.swift` (539) |
| QUICTransport | 3 | ~600 | `Pacing.swift` (260) |
| QUIC | 9 | ~5 500 | `ManagedConnection.swift` (2 026+) |
| QPACK | 6 | ~1 800 | `HuffmanCodec.swift` (~700) |
| HTTP3 | 12 (incl. subdirs) | ~4 500 | `HTTP3Connection.swift` (2 309) |

---

## 2. File Splitting — Oversized Files

Files over ~500 LOC hurt readability and make diffs painful. Swift's extension-in-separate-file model is the idiomatic way to split.

### 2.1 `Sources/QUIC/ManagedConnection.swift` — **2 026+ lines** ⚠️ CRITICAL

**Current structure** (by line range):

| Lines | Concern |
|-------|---------|
| L18-38 | `HandshakeState` enum |
| L50-197 | `ManagedConnection` class init, properties |
| L203-756 | Packet processing, TLS output handling, handshake |
| L760-1146 | Timer, frame processing, header building, notifications |
| L1150-1422 | `extension ManagedConnection: QUICConnectionProtocol` |
| L1426-1524 | `extension ManagedConnection` — Stream read/write/finish/reset |
| L1528-1608 | `extension ManagedConnection` — Send signaling |
| L1612-1930 | `extension ManagedConnection` — TLS, path validation, CID management |
| L1933-1942 | `MigrationError` enum |
| L1946-2009 | `ManagedConnectionState` struct |
| L2014-2026 | `ManagedConnectionError` enum |

**Recommended split**:

| New file | Move what | Lines |
|----------|-----------|-------|
| `ManagedConnection+Protocol.swift` | `extension ManagedConnection: QUICConnectionProtocol` (streams, datagrams, close, shutdown, `incomingStreams`, `sessionTickets`) | L1150-1422 |
| `ManagedConnection+StreamOps.swift` | Stream read/write/finish/reset helpers | L1426-1524 |
| `ManagedConnection+SendSignal.swift` | `hasPendingStreamData`, `sendSignal`, `signalNeedsSend` | L1528-1608 |
| `ManagedConnection+Migration.swift` | Path validation, address change, CID management, `MigrationError` | L1612-1942 |
| `ManagedConnection+TLS.swift` | `underlyingTLSProvider`, `is0RTTAccepted`, `waitForHandshake`, `retryWithVersion` | L1612-1756 (subset) |
| `ManagedConnectionState.swift` | `ManagedConnectionState`, `HandshakeState`, `ManagedConnectionError` | L18-38 + L1946-2026 |

**Why**: Every extension block is already logically isolated with `// MARK:` comments. They can be lifted verbatim into separate files. The `class` declaration and its `init` stay in the original file.

---

### 2.2 `Sources/HTTP3/HTTP3Connection.swift` — **2 309 lines** ⚠️ CRITICAL

**Current structure**:

| Lines | Concern |
|-------|---------|
| L105-187 | `ExtendedConnectContext` |
| L189-414 | `HTTP3Connection` actor, init, deinit |
| L424-593 | `initialize()`, `waitForReady()`, `goaway()`, `close()`, `sendRequest()` |
| L624-816 | Extended CONNECT, response reading |
| L821-1237 | Control stream, QPACK streams, incoming stream dispatch |
| L1244-1461 | Incoming request handling, Extended CONNECT routing |
| L1463-1633 | `handleIncomingRequestStream` |
| L1654-1815 | WebTransport session management |
| L1828-2117 | Stream ownership, datagram routing, priority scheduling |
| L2129-2238 | Response sending, state queries |
| L2256-2309 | Frame reading helpers |

**Recommended split**:

| New file | Concern |
|----------|---------|
| `HTTP3Connection+Client.swift` | `sendRequest`, `sendExtendedConnect`, `readResponse`, `readExtendedConnectResponse` |
| `HTTP3Connection+Server.swift` | `handleIncomingRequestStream`, `handleIncomingRequestStreamWithBuffer`, `routeExtendedConnectRequest`, `sendResponse`, `sendResponseHeadersOnly` |
| `HTTP3Connection+Streams.swift` | Control stream setup, QPACK stream setup, `processIncomingStreams`, `handleIncomingUniStream`, `handleIncomingBidiStream`, incoming control/QPACK handlers |
| `HTTP3Connection+WebTransport.swift` | Session register/unregister, `createWebTransportSession`, `ownsStream`, `routeWebTransportUniStream`, `startDatagramRouting` |
| `HTTP3Connection+Priority.swift` | `handlePriorityUpdate`, `sendPriorityUpdate`, `priority(for:)`, `cleanupStreamPriority`, scheduling helpers |
| `ExtendedConnectContext.swift` | `ExtendedConnectContext` struct (L105-187) |

---

### 2.3 `Sources/QUIC/QUICEndpoint.swift` — **1 238 lines**

**Recommended split**:

| New file | Concern | Lines |
|----------|---------|-------|
| `QUICEndpoint+Server.swift` | `listen`, `serve` overloads, `handleNewConnection`, `handleVersionNegotiationPacket` | L216-816 |
| `QUICEndpoint+Client.swift` | `dial`, `connect`, `connectWith0RTT`, `connectWithSession` | L332-593 |
| `QUICEndpoint+IOLoop.swift` | `run`, `runPacketLoop`, `packetReceiveLoop`, `outboundSendLoop`, `timerProcessingLoop` | L894-1172 |
| `QUICEndpointError.swift` | `QUICEndpointError` enum | L1220-1238 |

---

### 2.4 `Sources/QUICConnection/QUICConnectionHandler.swift` — **1 120 lines**

**Recommended split**:

| New file | Concern | Lines |
|----------|---------|-------|
| `QUICConnectionHandler+Frames.swift` | `processFrames`, `processAckFrame`, `processCryptoFrame`, `processConnectionClose`, `processHandshakeDone` | L218-441 |
| `QUICConnectionHandler+Crypto.swift` | `deriveInitialKeys`, `installKeys`, `cryptoContext`, `discardLevel` | L155-181, L493-570, L1019-1024 |
| `QUICConnectionHandler+Streams.swift` | All stream operation forwarding (`openStream`, `writeToStream`, etc.) | L751-826 |
| `QUICConnectionHandler+Migration.swift` | Path validation, CID, stateless reset forwarding | L949-1015 |
| `FrameProcessingResult.swift` | `FrameProcessingResult`, `OutboundPacket`, `TimerAction`, `ConnectionCloseError` structs | L1030-1120 |

---

### 2.5 `Sources/QUICCrypto/TLS/TLS13Handler.swift` — **1 437 lines**

The file already contains two classes: `TLS13Handler` and `ServerStateMachine`.

| New file | Concern |
|----------|---------|
| `ServerStateMachine.swift` | Move `class ServerStateMachine` (L603-1405) and `CipherSuite` extension (L1409-1437) to their own file |

This is a clean cut — `ServerStateMachine` is a self-contained class.

---

### 2.6 `Sources/QUICStream/StreamScheduler.swift` — **673 lines**

| New file | Concern | Lines |
|----------|---------|-------|
| `PriorityHeaderParser.swift` | `enum PriorityHeaderParser` | L37-108 |
| `PriorityUpdate.swift` | `struct PriorityUpdate`, `PriorityUpdateClassification`, `PriorityUpdateError` | L145-325 |
| Keep in `StreamScheduler.swift` | `SchedulingStrategy`, `StreamScheduler`, `StreamPriority` extensions for H3 presets | L347-673 |

---

## 3. Protocol-Oriented Improvements

### 3.1 Congestion Controller — Factory / Pluggable Design

**File**: `Sources/QUICRecovery/CongestionController.swift`
**File**: `Sources/QUICRecovery/NewRenoCongestionController.swift`
**File**: `Sources/QUICConnection/QUICConnectionHandler.swift` L50

**Current state**: `QUICConnectionHandler` hard-codes `NewRenoCongestionController`:

```swift
// QUICConnectionHandler.swift L50
let congestionController: NewRenoCongestionController
```

**Problem**: The `CongestionController` protocol exists but there's no way for users to inject an alternative (CUBIC, BBR). The handler instantiates `NewRenoCongestionController` directly in its `init`.

**Recommendation**:
1. Change the stored property type to `any CongestionController`.
2. Add a `CongestionControllerFactory` protocol or a closure parameter to `QUICConnectionHandler.init`.
3. Expose a `congestionAlgorithm` setting in `QUICConfiguration`.

```swift
// Proposed protocol
public protocol CongestionControllerFactory: Sendable {
    func makeCongestionController(maxDatagramSize: Int) -> any CongestionController
}

// Default implementation
public struct NewRenoFactory: CongestionControllerFactory {
    public func makeCongestionController(maxDatagramSize: Int) -> any CongestionController {
        NewRenoCongestionController(maxDatagramSize: maxDatagramSize)
    }
}
```

**Impact**: Medium — Enables future CUBIC/BBR implementations without modifying connection handler internals.

---

### 3.2 Missing Protocol for `StreamScheduler`

**File**: `Sources/QUICStream/StreamScheduler.swift` L375

**Current state**: `StreamScheduler` is a concrete struct. The scheduling algorithm is hardcoded.

**Recommendation**: Extract a `StreamScheduling` protocol:

```swift
public protocol StreamScheduling: Sendable {
    mutating func scheduleStreams(
        _ streams: [UInt64: DataStream]
    ) -> [(streamID: UInt64, stream: DataStream)]
}
```

This allows plugging in alternative scheduling strategies (FIFO, weighted fair queuing, deadline-based).

**Impact**: Low — Mostly a future-proofing concern but aligns with the existing `SchedulingStrategy` enum (L347-356) which is defined but underutilized.

---

### 3.3 `ReceiveBuffer` Protocol for `DataBuffer`

**File**: `Sources/QUICStream/DataBuffer.swift`

**Current state**: `DataBuffer` is a concrete struct with no protocol abstraction.

**Recommendation**: Define a `ReceiveBuffer` protocol:

```swift
public protocol ReceiveBuffer: Sendable {
    mutating func insert(offset: UInt64, data: Data, fin: Bool) throws
    mutating func readContiguous() -> Data?
    var isComplete: Bool { get }
    var contiguousBytesAvailable: Int { get }
}
```

**Why**: Makes `DataStream` testable with mock buffers and enables alternative implementations (e.g., ring buffer for large streams).

---

### 3.4 `FrameEncoder` / `FrameDecoder` Protocol Adoption

**File**: `Sources/QUICCore/Frame/FrameCodec.swift` L25-50

**Current state**: `FrameEncoder` and `FrameDecoder` protocols are defined but `StandardFrameCodec` is the only consumer, and the rest of the codebase references `StandardFrameCodec` directly (e.g., `PacketEncoder.frameCodec: StandardFrameCodec` at `PacketCodec.swift` L99).

**Recommendation**: Change references to use the protocol type:

```swift
// PacketCodec.swift L99 — change from:
let frameCodec: StandardFrameCodec
// to:
let frameCodec: any FrameEncoder & FrameDecoder
```

Or, better, use a generic constraint:

```swift
struct PacketEncoder<Codec: FrameEncoder & FrameDecoder & Sendable>: Sendable {
    let frameCodec: Codec
}
```

**Impact**: Low — Improves testability and protocol-oriented design consistency.

---

## 4. Extension Usage Improvements

### 4.1 `Frame` Enum — Separate Encoding/Decoding from Definition

**File**: `Sources/QUICCore/Frame/Frame.swift`

**Current state**: The `Frame` enum (L80-176) includes `frameType`, `isAckEliciting`, and `isValid(at:)` all in one file. Meanwhile, `FrameSize.swift` and `FrameCodec.swift` contain related logic.

**Recommendation**: Reorganize with extensions:

| File | Content |
|------|---------|
| `Frame.swift` | `Frame` enum cases only + `FrameType` enum |
| `Frame+Validation.swift` | `isValid(at:)`, `isAckEliciting` |
| `Frame+QLOG.swift` | Already exists as `QLOGHelpers.swift` — rename for consistency |
| `Frame+Size.swift` | Already exists as `FrameSize.swift` — OK |

This is a minor readability improvement. The `Frame` enum is currently ~180 lines which is manageable, but the validation logic (L161-176) could move.

---

### 4.2 `ConnectionID` — Consolidate Extensions

**File**: `Sources/QUICCore/Packet/ConnectionID.swift`

**Current state**: Already well-structured with MARK sections for Encoding/Decoding, CustomStringConvertible, etc.

**Status**: ✅ Good — no action needed. This is a model for how other types should be organized.

---

### 4.3 `QUICVersion` — Extract Wire Constants

**File**: `Sources/QUICCore/Packet/Version.swift`

**Current state**: `initialSalt`, `retryIntegrityKey`, and `retryIntegrityNonce` are computed properties that create `Data` literals on every call.

**Recommendation**: Store these as `static let` constants to avoid repeated allocation:

```swift
extension QUICVersion {
    // V1 constants
    private static let v1InitialSalt = Data([0x38, 0x76, ...])
    
    public var initialSalt: Data? {
        switch self {
        case .v1: return Self.v1InitialSalt
        case .v2: return Self.v2InitialSalt
        default: return nil
        }
    }
}
```

**Impact**: Low — These are not hot-path but avoiding repeated `Data` allocation is good hygiene.

---

## 5. Swift Language Feature Adoption

### 5.1 Typed Throws (Swift 6.0+)

**Where**: Throughout the codebase — many functions throw specific error types but declare `throws` generically.

**Examples**:

| File | Function | Known error type |
|------|----------|-----------------|
| `ConnectionID.swift` L25 | `init(bytes:)` | `ConnectionIDError` |
| `Varint.swift` L105 | `decode(from:)` | `Varint.DecodeError` |
| `DataReader.swift` L137 | `readVarint()` | `Varint.DecodeError` |
| `SafeConversions.swift` L28 | `toInt(_:)` | `ConversionError` |
| `DataBuffer.swift` L57 | `insert(offset:data:fin:)` | `DataBufferError` |
| `FrameCodec.swift` L73 | `encode(_:)` | `FrameCodecError` |

**Recommendation**: Adopt `throws(ErrorType)` syntax:

```swift
// Before
public init(bytes: Data) throws { ... }
// After
public init(bytes: Data) throws(ConnectionIDError) { ... }
```

**Impact**: Medium — Improves API documentation, enables exhaustive catch patterns, eliminates unnecessary error type erasure. Must be done gradually as it changes the API surface.

**Caveat**: Typed throws propagate — a function calling `throws(A)` and `throws(B)` must either wrap or use `throws(any Error)`. Evaluate on a case-by-case basis; start with leaf functions.

---

### 5.2 `@frozen` for Performance-Critical Enums

**Where**: Enums that are exhaustively switched in hot paths and will never gain new cases.

| File | Type | Rationale |
|------|------|-----------|
| `PacketHeader.swift` L52-57 | `EncryptionLevel` | 4 fixed cases per RFC; switched on every packet |
| `Frame.swift` L11-39 | `FrameType` | Fixed by RFC 9000; switched on every frame decode |
| `PacketHeader.swift` L12-49 | `PacketType` | Fixed by RFC |
| `Version.swift` | `QUICVersion` | Not an enum (struct with rawValue) — N/A |
| `ConnectionState.swift` L17-25 | `ConnectionStatus` | Small, stable set |
| `StreamState.swift` L75-83 | `SendState` | RFC-defined state machine |
| `StreamState.swift` L86-93 | `RecvState` | RFC-defined state machine |

**How**: Add `@frozen` before `public enum`:

```swift
@frozen
public enum EncryptionLevel: Int, Sendable, Hashable, CaseIterable {
    case initial = 0
    case handshake = 1
    case zeroRTT = 2
    case application = 3
}
```

**Impact**: Medium — Enables the compiler to use a more efficient switch lowering (no default case needed in the binary, no resilience overhead). Since these enums are in library targets consumed by the same package, the benefit is in downstream consumers and benchmarks.

**Caveat**: `@frozen` is a permanent ABI contract. Only apply to enums that are truly closed.

---

### 5.3 `borrowing` / `consuming` Parameter Ownership

**Where**: Functions that accept `Data` parameters and either read-only inspect them or take ownership.

**Key candidates**:

| File | Function | Ownership | Rationale |
|------|----------|-----------|-----------|
| `DataReader.swift` L18 | `init(_ data: Data)` | `consuming` | Reader takes ownership of data; prevents caller from mutating |
| `ConnectionID.swift` L25 | `init(bytes: Data)` | `borrowing` | Only reads + copies if valid |
| `FrameCodec.swift` L429 | `decodeFrames(from data: Data)` | `borrowing` | Reader created internally |
| `ManagedStream.swift` L113 | `write(_ data: Data)` | `consuming` | Data is forwarded to stream, no need for caller copy |
| `CoalescedPacketBuilder.swift` L38 | `addPacket(_ packet: Data)` | `consuming` | Appends to internal array |

**Impact**: Low-Medium — Primarily documentation value in Swift 6. The compiler can already infer ownership for `Sendable` types, but explicit annotations prevent accidental copies and serve as API contracts.

---

### 5.4 `~Copyable` for Move-Only Semantics

> **STATUS: CLOSED — WON'T FIX**
>
> **Reason**: Zero performance gain. ~45 call sites across 7 modules would need updating. Source-breaking change for downstream consumers. The bug class it prevents (accidental reader forking) does not exist in this codebase — every usage follows the safe `var reader = DataReader(data)` + `inout` pattern. Adding `consuming` to `DataReader.init` (done in P3) already captures the most meaningful ownership optimization. Revisit if Swift stabilizes noncopyable generics further or if reader-forking bugs appear.

**Where**: Types that should not be accidentally duplicated.

**Candidate**: `DataReader`

**File**: `Sources/QUICCore/DataReader.swift` L11

**Rationale**: A `DataReader` has mutable cursor state (`position`). Copying a reader creates a hidden fork of parsing state that can lead to subtle bugs (re-parsing the same bytes). Making it `~Copyable` would force callers to pass by `inout` reference.

```swift
public struct DataReader: ~Copyable, Sendable {
    // ...
}
```

**Impact**: Low — Requires updating all call sites from `var reader = DataReader(data)` (already correct) to ensure no accidental copies. The main benefit is catching bugs at compile time.

**Caveat**: `~Copyable` types have restrictions (can't be stored in arrays, dictionaries, etc.). Since `DataReader` is only used as a local variable, this is fine. But verify no code stores readers in collections.

---

### 5.5 `package` Access Level (Swift 5.9+)

See [Section 10](#10-cross-module-visibility-package-access) for detailed analysis.

---

### 5.6 `@inlinable` Consistency

**Current state**: Some functions have `@inlinable` (e.g., `Varint.encode(to:)`, `DataReader.readByte()`, `FrameSize.streamFrame(...)`) but many similar functions do not.

**Missing `@inlinable` in hot paths**:

| File | Function | Lines |
|------|----------|-------|
| `Varint.swift` | `init(_ value: UInt64)` | L22 |
| `DataReader.swift` | `readUInt16()`, `readUInt32()`, `readUInt64()` | L107-130 |
| `DataWriter.swift` | `writeUInt8()`, `writeUInt16()`, `writeUInt32()`, `writeUInt64()` | L240-270 |
| `Frame.swift` | `var frameType: FrameType` | L139 |
| `Frame.swift` | `var isAckEliciting: Bool` | L155 |
| `FrameSize.swift` | `ackFrame(_:)` | L81 (static, not inlinable) |

**Rule**: Any function that is a thin wrapper, a property computed from stored state, or involves only bitwise/arithmetic operations in a performance-critical path should be `@inlinable`. Pair with `@usableFromInline` for stored properties that `@inlinable` methods access.

---

### 5.7 Result Builder for Packet Construction (Exploratory)

> **STATUS: CLOSED — WON'T FIX**
>
> **Reason**: The `CoalescedPacketBuilder` API is internal-only (package-scoped) and already clean. A `@resultBuilder` cannot naturally model the conditional fit-checking (`addPacket` returns `Bool` to indicate whether the packet fit) without `buildOptional`/`buildEither`, which adds complexity. The builder would also need to integrate with encryption/sealing in `QUICCrypto`, adding a cross-module coupling concern. Zero performance benefit; marginal readability benefit for an internal API.

**Where**: `CoalescedPacketBuilder`, `PacketEncoder`

**Concept**: A `@resultBuilder` for building coalesced packets:

```swift
let datagram = CoalescedPacket(maxSize: 1200) {
    InitialPacket(header: ..., frames: [...])
    HandshakePacket(header: ..., frames: [...])
}
```

**Impact**: Low — This is a readability improvement for the high-level API, not a correctness or performance concern. Consider only if the API is user-facing.

---

## 6. Type System Strengthening

### 6.1 `StreamID` Newtype Wrapper

**Current state**: Stream IDs are `UInt64` everywhere. The `StreamID` enum in `StreamState.swift` (L11-63) provides static helper methods but is not a type wrapper.

**Problem**: Nothing prevents passing a packet number where a stream ID is expected, or vice versa.

**Recommendation**: Create a `StreamID` struct:

```swift
public struct StreamIdentifier: RawRepresentable, Hashable, Sendable, Comparable {
    public let rawValue: UInt64
    public init(rawValue: UInt64) { self.rawValue = rawValue }
    
    public var isBidirectional: Bool { (rawValue & 0x02) == 0 }
    public var isClientInitiated: Bool { (rawValue & 0x01) == 0 }
    // ... move methods from StreamID enum ...
}
```

**Affected files**: `StreamFrame`, `DataStream`, `StreamManager`, `FlowController`, `StreamScheduler`, `ManagedStream`, `QUICConnectionHandler`, `HTTP3Connection`.

**Impact**: High effort, high safety — This is a large refactor but catches type confusion bugs at compile time. Consider introducing via a `typealias StreamID = UInt64` first, then migrating to a struct later.

---

### 6.2 `PacketNumber` Newtype

**Current state**: Packet numbers are `UInt64` throughout (`SentPacket.id`, `LossDetector.largestAckedPacket`, `AckManager.largestReceived`, `ConnectionState.nextPacketNumber`, etc.).

**Same approach as 6.1**: Start with `typealias PacketNumber = UInt64`, then optionally migrate to a struct.

---

### 6.3 `ECNCounts` Name Collision ⚠️

**File 1**: `Sources/QUICCore/Frame/FrameTypes.swift` L56-63

```swift
public struct ECNCounts: Sendable, Hashable {
    public let ect0Count: UInt64
    public let ect1Count: UInt64
    public let ecnCECount: UInt64
}
```

**File 2**: `Sources/QUICTransport/ECN.swift` L42-73

```swift
public struct ECNCounts: Sendable, Equatable {
    public var ect0Count: UInt64 = 0
    public var ect1Count: UInt64 = 0
    public var ceCount: UInt64 = 0
}
```

**Problem**: Two distinct types with the same name in different modules. One is `Hashable` with `let` fields and `ecnCECount`, the other is `Equatable` with `var` fields and `ceCount`. Importing both modules in the same file requires disambiguation.

**Recommendation**:
- Rename `QUICTransport.ECNCounts` to `ECNTracker` or `ECNCountState` to avoid ambiguity.
- Alternatively, unify into a single type in `QUICCore` and have `QUICTransport` import it.
- The `QUICCore` version is the wire format (used in `AckFrame`). The `QUICTransport` version is the mutable tracking state. They serve different purposes — rename the transport one.

**Impact**: Medium — Prevents future compilation errors when both modules are imported.

---

## 7. Potential Bugs & Correctness Issues

### 7.1 `StreamFrame.frameTypeByte` Ignores `hasLength` ⚠️ BUG

**File**: `Sources/QUICCore/Frame/FrameTypes.swift` L104-110

```swift
public var frameTypeByte: UInt8 {
    var byte: UInt8 = 0x08
    if offset > 0 { byte |= 0x04 }  // OFF bit
    if true { byte |= 0x02 }         // LEN bit (always include length)
    if fin { byte |= 0x01 }          // FIN bit
    return byte
}
```

**Bug**: The `if true` on the LEN bit means `hasLength` is completely ignored. The comment says "always include length" but the `hasLength` field exists on `StreamFrame` and is used elsewhere (e.g., `FrameSize.streamFrame()` at `FrameSize.swift` L27-37 checks `hasLength`).

**The encoding in `FrameCodec.swift` L260-294 (`encodeStreamFrame`) constructs its own type byte and does respect `hasLength`:**

```swift
// FrameCodec.swift L265-270
var typeByte: UInt8 = 0x08
if stream.offset > 0 { typeByte |= 0x04 }
if stream.hasLength { typeByte |= 0x02 }
if stream.fin { typeByte |= 0x01 }
```

**So the `frameTypeByte` computed property is inconsistent with the actual encoder.** If anyone uses `frameTypeByte` directly (rather than the codec), they'll always set the LEN bit.

**Fix**:

```swift
public var frameTypeByte: UInt8 {
    var byte: UInt8 = 0x08
    if offset > 0 { byte |= 0x04 }
    if hasLength { byte |= 0x02 }
    if fin { byte |= 0x01 }
    return byte
}
```

**Impact**: High — Incorrect frame type byte could cause interop failures with other QUIC implementations. Verify if `frameTypeByte` is used anywhere outside of `FrameCodec`.

---

### 7.2 `constantTimeContains` Uses `Bool` Accumulator

**File**: `Sources/QUICConnection/StatelessReset.swift` L332-342

```swift
private func constantTimeContains(_ token: Data, in tokens: Set<Data>) -> Bool {
    var found = false
    for existingToken in tokens {
        if constantTimeCompare(token, existingToken) {
            found = true
            // Don't break early to maintain constant time
        }
    }
    return found
}
```

**Problem**: The Swift compiler may optimize away the loop iterations after `found = true` since `found` is a `Bool` and the loop body has no observable side effects after the first match. This defeats the constant-time intent.

**Fix**: Use a `UInt8` accumulator and bitwise OR:

```swift
private func constantTimeContains(_ token: Data, in tokens: Set<Data>) -> Bool {
    var result: UInt8 = 0
    for existingToken in tokens {
        result |= constantTimeCompareUInt8(token, existingToken)
    }
    return result != 0
}

@inline(never)
private func constantTimeCompareUInt8(_ a: Data, _ b: Data) -> UInt8 {
    guard a.count == b.count else { return 0 }
    var diff: UInt8 = 0
    for (x, y) in zip(a, b) {
        diff |= x ^ y
    }
    return diff == 0 ? 1 : 0
}
```

**Impact**: High (security) — Timing side-channel in stateless reset detection could be exploited.

---

### 7.3 `Duration` Extension Operators Are Global

**File**: `Sources/QUICRecovery/RTTEstimator.swift` L116-139

```swift
extension Duration {
    static func / (lhs: Duration, rhs: Int) -> Duration { ... }
    static func * (lhs: Duration, rhs: Int) -> Duration { ... }
    static func abs(_ duration: Duration) -> Duration { ... }
}
```

**Problem**: These operators extend `Duration` globally. Any consumer of the `QUICRecovery` module gets these operators, which may conflict with:
- Other libraries defining the same operators
- Future Swift standard library additions

**Recommendation**:
- Make these `internal` (not `public`) — they're only used within `QUICRecovery`.
- Or, move the arithmetic to `FastDuration` (which already exists for this purpose in `FastDuration.swift`).

**Impact**: Medium — Potential source of ambiguity errors in downstream code.

---

### 7.4 `TimerWheel.addTimer` Unnecessary Tuple Binding

**File**: `Sources/QUIC/TimerManager.swift` L238

```swift
let (currentTickValue, _) = (currentTick.withLock { $0 }, ())
```

**Problem**: This creates a tuple `(Int, Void)` to extract the mutex value. It's confusing and the `Void` element is discarded.

**Fix**:

```swift
let currentTickValue = currentTick.withLock { $0 }
```

**Impact**: Low — Readability only.

---

### 7.5 `ManagedStream` is `@unchecked Sendable`

**File**: `Sources/QUIC/ManagedStream.swift` L12

```swift
public final class ManagedStream: @unchecked Sendable {
```

**Concern**: The class uses a `Mutex<ManagedStreamState>` for its mutable state and has `let` properties otherwise. The `weak var connection: ManagedConnection?` (L24) is the reason for `@unchecked` — weak references are not inherently `Sendable`.

**Assessment**: The `@unchecked` is justified here because:
- `connection` is only read inside `state.withLock` or at the start of async methods
- `ManagedConnection` itself is `Sendable`

**Recommendation**: Add a comment explaining why `@unchecked` is safe:

```swift
/// @unchecked because `connection` is a weak reference to a Sendable type.
/// All mutable state is protected by `state: Mutex<ManagedStreamState>`.
public final class ManagedStream: @unchecked Sendable {
```

---

### 7.6 `ConnectionRouter.extractSourceConnectionID` Duplicates Logic

**File**: `Sources/QUIC/ConnectionRouter.swift` L218-248

This private method manually parses the long header to extract SCID. The same logic exists in `PacketProcessor.extractHeaderInfo` and `PacketProcessor.extractLongHeaderInfo`.

**Recommendation**: Remove `extractSourceConnectionID` and use `packetProcessor.extractHeaderInfo(from:).scid` instead. The method is only called from `route()` which already calls `extractHeaderInfo`.

**Impact**: Low — Dead code elimination.

---

### 7.7 Race Condition Window in `QUICEndpoint.connect`

**File**: `Sources/QUIC/QUICEndpoint.swift` — `connect(to:)` method

**Concern**: The method creates a `ManagedConnection`, registers it with the router, then starts the handshake. Between registration and the first packet being sent, the connection is in a partially initialized state. If an incoming packet arrives for this connection's DCID during that window, it could be routed before `start()` completes.

**Assessment**: This is likely safe because `QUICEndpoint` is an `actor` — the `connect` method is isolated. But verify that `processIncomingPacket` cannot be called concurrently with `connect` on the same actor. Since both are actor-isolated, they can't interleave. ✅ Safe.

---

## 8. Performance Micro-Optimizations

### 8.1 `Data` Allocations in `QUICVersion` Computed Properties

**File**: `Sources/QUICCore/Packet/Version.swift` L49-97

Each call to `initialSalt`, `retryIntegrityKey`, `retryIntegrityNonce` creates a new `Data` from a byte array literal.

**Fix**: Store as `static let`:

```swift
private static let v1Salt = Data([0x38, 0x76, 0x2c, ...])

public var initialSalt: Data? {
    switch self {
    case .v1: return Self.v1Salt
    case .v2: return Self.v2Salt
    default: return nil
    }
}
```

**Impact**: Low — These are called during connection setup (once per connection), not per-packet.

---

### 8.2 `hex` String Formatting in `ConnectionID.description`

> **STATUS: CLOSED — WON'T FIX**
>
> **Reason**: Only affects logging/debug paths. The intermediate array allocation from `map { }.joined()` is negligible. Connection IDs are at most 20 bytes (40 hex chars). Not worth the code churn.

**File**: `Sources/QUICCore/Packet/ConnectionID.swift` L159-163

```swift
let hex = bytes.map { String(format: "%02x", $0) }.joined()
```

This allocates an intermediate array of strings. For debug/logging paths this is fine, but if called frequently:

**Alternative** (no intermediate array):

```swift
var hex = ""
hex.reserveCapacity(bytes.count * 2)
for byte in bytes {
    hex.append(String(format: "%02x", byte))
}
```

Or use a pre-computed hex table. Same pattern exists in `QLOGHelpers.swift` for `qlogHex`.

**Impact**: Very low — Only affects logging/debug paths.

---

### 8.3 `DataBuffer.mergeSegments` Could Avoid Re-allocation

> **STATUS: CLOSED — WON'T FIX**
>
> **Reason**: The current implementation already uses delta tracking (not full recalculation) and `reserveCapacity`. Segments are typically 1–3 in normal QUIC operation. An in-place merge would save one allocation per `insert` call but adds complexity for near-zero practical gain.

**File**: `Sources/QUICStream/DataBuffer.swift` L155-181

The merge creates a new `merged` array every time. For buffers with many segments, consider an in-place merge:

**Current**: O(n) allocation per merge call.
**Alternative**: Process segments in-place using a write cursor index.

**Impact**: Low — Merge is called after every `insert`, but the number of segments is typically small (1-3 in normal operation).

---

### 8.4 `AckManager.buildAckRanges` — Avoid `stride(from:through:by:)`

> **STATUS: CLOSED — WON'T FIX**
>
> **Reason**: The current implementation is correct and already well-optimized with pre-allocated capacity. The difference between `stride` and `reversed()` is negligible. Not worth touching working recovery code.

**File**: `Sources/QUICRecovery/AckManager.swift` L240-270

The function iterates in reverse using `stride`. This is fine, but could use `reversed()` iterator:

```swift
for range in packetRanges.reversed() { ... }
```

The current implementation is correct and already well-optimized with pre-allocated capacity.

**Impact**: Negligible.

---

### 8.5 `FlowController` Uses Dictionaries for Per-Stream Limits

> **STATUS: CLOSED — WON'T FIX**
>
> **Reason**: Dictionary is the correct data structure for the general case (100+ concurrent streams). A sorted array of tuples would be slower at scale and add code complexity. The current implementation is idiomatic and correct.

**File**: `Sources/QUICStream/FlowController.swift` L79-82

```swift
var streamRecvLimits: [UInt64: UInt64]
var streamBytesReceived: [UInt64: UInt64]
```

For a small number of streams, a sorted array of tuples might be faster than dictionary hashing. But for the general case (100+ streams), dictionaries are fine.

**Impact**: Negligible — Dictionary is the right choice for the general case.

---

## 9. Naming, Deprecation & Cleanup

### 9.1 Remove Deprecated Legacy TLS Fields — ✅ Done

**File**: `Sources/QUIC/QUICConfiguration.swift`

Three fields were marked `@available(*, deprecated)` and documented as "not consumed by
`TLS13Handler`". Zero call sites read these fields from `QUICConfiguration` (the actively
used equivalents live on `TLSConfiguration`). All three properties and their initialization
in `init()` have been **deleted**:

- `certificatePath: String?`
- `privateKeyPath: String?`
- `verifyPeer: Bool`

The `// MARK:` section was renamed from "TLS (Legacy — prefer TLSConfiguration)" to
"TLS Provider" since only the still-used `tlsProviderFactory` remains. The `init()` doc
comment was updated to remove references to the deleted fields.

**Status**: Removed. Build clean, 876/876 tests pass.

---

### 9.2 Deprecated Methods in `ConnectionRouter`

**File**: `Sources/QUIC/ConnectionRouter.swift` L183-188, L198-201

Two methods are marked `@available(*, deprecated)`:

```swift
@available(*, deprecated, message: "Use retireConnectionID(_:for:) instead for proper tracking")
public func unregister(connectionIDs: [ConnectionID]) { ... }

@available(*, deprecated, message: "Use retireConnectionID(_:for:) instead for proper tracking")
public func retireConnectionID(_ connectionID: ConnectionID) { ... }
```

**Recommendation**: Search for call sites. If none exist, remove them. If they exist, migrate and then remove.

---

### 9.3 `Varint.decode(from reader:)` Deprecated but Not Marked Consistently

**File**: `Sources/QUICCore/Varint.swift` L161-167

```swift
@available(*, deprecated, message: "Use DataReader.readVarint() or readVarintValue() for better performance")
@inlinable
public static func decode(from reader: inout DataReader) throws -> Varint {
```

**Status**: ✅ Properly deprecated. Grep for call sites and migrate them.

---

### 9.4 `QUICSecurityMode.testing` Only Available in DEBUG

**File**: `Sources/QUIC/QUICConfiguration.swift` L232-243

```swift
#if DEBUG
@available(*, message: "Testing mode disables TLS encryption. Never use in production.")
public static func testing() -> QUICConfiguration { ... }
#endif
```

**Issue**: The `@available(*, message:)` is not a deprecation — it's a diagnostic message. But `QUICSecurityMode.testing` itself (L41) has no `#if DEBUG` guard. So the enum case is always available, but the factory method is not.

**Recommendation**: Either:
1. Guard the enum case itself with `#if DEBUG`, or
2. Make both unconditional but rely on the `@available` message.

Current inconsistency means users can write `.testing` without the factory in release builds.

---

### 9.5 Inconsistent Error Naming

> **STATUS: CLOSED — WON'T FIX**
>
> **Reason**: The existing naming is functional and each error type is unambiguous within its module. Renaming would be high churn (every `catch` site, test, and import) for purely cosmetic benefit. The `{Feature}Error` convention is already dominant. `QUICError` vs `QUICEndpointError` serve different scopes and don't collide.

| Module | Error type | Convention |
|--------|-----------|------------|
| QUICCore | `QUICError` | Module-prefixed |
| QUICCore | `ConversionError` | Unprefixed |
| QUICCore | `PacketCodecError` | Feature-prefixed |
| QUICCore | `FrameCodecError` | Feature-prefixed |
| QUICStream | `StreamError` | Feature-prefixed |
| QUICStream | `StreamManagerError` | Feature-prefixed |
| QUICRecovery | (none — uses QUICCore errors) | — |
| HTTP3 | `HTTP3Error`, `HTTP3ErrorCode` | Module-prefixed |
| QUIC | `QUICEndpointError` | Module-prefixed |
| QUIC | `ManagedConnectionError` | Feature-prefixed |
| QUIC | `ManagedStreamError` | Feature-prefixed |

**Recommendation**: Standardize on `{Feature}Error` pattern. `ConversionError` is fine. Main inconsistency is `QUICError` vs `QUICEndpointError` — consider if they should be merged or renamed.

---

## 10. Cross-Module Visibility (`package` access)

Swift 5.9 introduced `package` access — visible within the same Swift package but not to external consumers. This is ideal for Quiver's internal module boundaries.

### Current `public` APIs That Should Be `package`

Many types are `public` only because they need to be shared between Quiver's modules, not because they're part of the user-facing API.

| Type | Module | Used by | Should be |
|------|--------|---------|-----------|
| `CryptoContext` | QUICCrypto | QUIC, QUICConnection | `package` |
| `KeyMaterial` | QUICCrypto | QUIC, QUICConnection | `package` |
| `KeysAvailableInfo` | QUICCrypto | QUIC | `package` |
| `CryptoStreamManager` | QUICCrypto | QUICConnection | `package` |
| `PacketEncoder` | QUICCore | QUIC | `package` |
| `PacketDecoder` | QUICCore | QUIC | `package` |
| `StandardFrameCodec` | QUICCore | QUIC, QUICConnection | `package` |
| `DataWriter` | QUICCore | QUICCrypto, QUICConnection | `package` |
| `ProtocolLimits` | QUICCore | All modules | `public` (keep) |
| `SafeConversions` | QUICCore | All modules | `public` (keep) |
| `FlowController` | QUICStream | QUICConnection | `package` |
| `LossDetector` | QUICRecovery | QUICConnection | `package` |
| `PacketNumberSpaceManager` | QUICRecovery | QUICConnection | `package` |
| `RTTEstimator` | QUICRecovery | QUICConnection | `package` |
| `ConnectionState` | QUICConnection | QUIC | `package` |
| `QUICConnectionHandler` | QUICConnection | QUIC | `package` |

**Rule of thumb**: If a type is not documented in the README or intended for end-user consumption, it should be `package` not `public`.

**Impact**: High for API hygiene — prevents users from depending on internal types. Zero runtime impact.

---

### Current `internal` Types That Should Be `package`

Some types are `internal` but need cross-module access, forcing them to be `public`:

| Type | Current | Why public | Should be |
|------|---------|-----------|-----------|
| `ConnectionID.init(uncheckedBytes:)` | `internal` | Only used within QUICCore | Keep `internal` ✅ |
| `DataStreamInternalState` | `internal` to QUICStream | Not exposed | Keep `internal` ✅ |

These are already correctly scoped.

---

## 11. Summary Priority Matrix

| # | Category | Effort | Impact | Priority | Status |
|---|----------|--------|--------|----------|--------|
| 7.1 | **BUG**: `StreamFrame.frameTypeByte` ignores `hasLength` | 🟢 Low | 🔴 High | **P0** | ✅ Done |
| 7.2 | **BUG**: Constant-time comparison uses `Bool` | 🟢 Low | 🔴 High (security) | **P0** | ✅ Done |
| 7.3 | Global `Duration` operators | 🟢 Low | 🟡 Medium | **P1** | ✅ Done |
| 6.3 | `ECNCounts` name collision | 🟢 Low | 🟡 Medium | **P1** | ✅ Done |
| 2.1 | Split `ManagedConnection.swift` | 🟡 Medium | 🟡 Medium | **P1** | ✅ Done |
| 2.2 | Split `HTTP3Connection.swift` | 🟡 Medium | 🟡 Medium | **P1** | ✅ Done |
| 2.3 | Split `QUICEndpoint.swift` | 🟡 Medium | 🟡 Medium | **P1** | ✅ Done |
| 2.4 | Split `QUICConnectionHandler.swift` | 🟡 Medium | 🟡 Medium | **P1** | ✅ Done |
| 2.5 | Split `TLS13Handler.swift` | 🟢 Low | 🟡 Medium | **P1** | ✅ Done |
| 10 | `package` access level audit | 🟡 Medium | 🟡 Medium | **P1** | ✅ Done |
| 9.1 | Proper `@available(*, deprecated)` | 🟢 Low | 🟢 Low | **P2** | ✅ Done |
| 5.2 | `@frozen` enums | 🟢 Low | 🟡 Medium | **P2** | ✅ Done |
| 5.6 | `@inlinable` consistency | 🟢 Low | 🟢 Low | **P2** | ✅ Done |
| 3.1 | Pluggable congestion controller | 🟡 Medium | 🟡 Medium | **P2** | ✅ Done |
| 5.1 | Typed throws | 🔴 High | 🟡 Medium | **P3** | ✅ Done (leaf functions) |
| 5.3 | `borrowing`/`consuming` | 🟡 Medium | 🟢 Low | **P3** | ✅ Done |
| 5.4 | `~Copyable` for `DataReader` | 🟡 Medium | 🟢 Low | **P3** | ⛔ Closed |
| 6.1 | `StreamID` newtype | 🔴 High | 🟡 Medium | **P3** | ✅ Foundation done |
| 3.2 | `StreamScheduling` protocol | 🟢 Low | 🟢 Low | **P3** | ✅ Done |
| 3.3 | `ReceiveBuffer` protocol | 🟢 Low | 🟢 Low | **P3** | ✅ Done |
| 8.1 | Static `Data` constants for version salts | 🟢 Low | 🟢 Low | **P3** | ✅ Done |
| 5.7 | Result builder for packets | 🟡 Medium | 🟢 Low | **P3** | ⛔ Closed |
| 8.2 | `hex` string formatting | 🟢 Low | 🟢 Very Low | — | ⛔ Closed |
| 8.3 | `DataBuffer.mergeSegments` realloc | 🟢 Low | 🟢 Low | — | ⛔ Closed |
| 8.4 | `AckManager.buildAckRanges` stride | 🟢 Low | 🟢 Negligible | — | ⛔ Closed |
| 8.5 | `FlowController` dictionaries | 🟢 Low | 🟢 Negligible | — | ⛔ Closed |
| 9.5 | Inconsistent error naming | 🟡 Medium | 🟢 Low | — | ⛔ Closed |

---

## 12. Remaining Work Plan

The following items were identified in the analysis body (Sections 3–9) but not included in the original priority matrix. They represent the complete set of remaining actionable work.

### Phase R1 — Dead Code & Deprecation Cleanup (🟢 Trivial) — ✅ Done

> **Goal**: Remove dead code and resolve deprecation inconsistencies.
> **Effort**: ~30 minutes. **Risk**: None — pure deletion and annotation.

| Step | Item | File(s) | Action | Status |
|------|------|---------|--------|--------|
| R1.1 | **9.3** Remove `Varint.decode(from reader:)` | `Sources/QUICCore/Varint.swift` | Zero call sites confirmed. Deleted the deprecated static method entirely. | ✅ Done |
| R1.2 | **9.2** Remove deprecated `ConnectionRouter` methods | `Sources/QUIC/ConnectionRouter.swift` | Zero call sites confirmed for both `unregister(connectionIDs:)` and `retireConnectionID(_:)`. Deleted both methods. Also removed dead `extractSourceConnectionID(from:)` private helper (R2.2). | ✅ Done |
| R1.3 | **9.4** Align `QUICSecurityMode.testing` DEBUG guard | `Sources/QUIC/QUICConfiguration.swift` | Wrapped the `.testing` enum case in `#if DEBUG` (option a). Updated `QUICEndpoint.swift` switch arms to use `#if DEBUG` around `case .testing:` to match. | ✅ Done |

### Phase R2 — Protocol Adoption & Testability (🟢 Low effort) — ✅ Done

> **Goal**: Use existing protocols instead of concrete types; improve testability.
> **Effort**: ~1 hour. **Risk**: Low — internal/package-scoped changes only.

| Step | Item | File(s) | Action | Status |
|------|------|---------|--------|--------|
| R2.1 | **3.4** Genericize `PacketEncoder`/`PacketDecoder` | `Sources/QUICCore/Packet/PacketCodec.swift` | Made both structs generic over `<Codec: FrameEncoder & FrameDecoder & Sendable>` (option b — zero-cost at runtime). Added constrained convenience `init()` for `Codec == StandardFrameCodec` so all existing callers work unchanged. Extracted `PacketConstants` non-generic enum for `defaultMTU`, `aeadTagSize`, `initialPacketMinSize` to avoid generic-parameter inference issues in call sites. | ✅ Done |
| R2.2 | **7.6** Deduplicate `ConnectionRouter.extractSourceConnectionID` | `Sources/QUIC/ConnectionRouter.swift` | Method was dead code (zero call sites — the only reference was its own definition). Deleted entirely as part of R1.2 cleanup. | ✅ Done |

### Phase R3 — Extension & File Organization (🟢 Low effort) — ✅ No action needed

> **Goal**: Improve code organization without changing behavior.
> **Effort**: ~30 minutes. **Risk**: None — file moves and extension reorganization.

| Step | Item | File(s) | Action | Status |
|------|------|---------|--------|--------|
| R3.1 | **4.1** Separate `Frame` encoding/decoding from definition | `Sources/QUICCore/Frame/Frame.swift` | Reviewed: `Frame.swift` is ~200 lines containing only the enum cases and basic computed properties (`frameType`, `isAckEliciting`, `isValid(at:)`). Encoding/decoding already lives in `FrameCodec.swift`. No split needed. | ✅ Already clean |
| R3.2 | **4.2** Consolidate `ConnectionID` extensions | `Sources/QUICCore/Packet/ConnectionID.swift` | Reviewed: already well-structured with MARK sections (Definition → Encoding/Decoding → CustomStringConvertible → Utilities). No changes needed. | ✅ Already clean |
| R3.3 | **4.3** `QUICVersion` wire constants organization | `Sources/QUICCore/Packet/Version.swift` | Reviewed: static `Data` constants are already stored as `private static let` with clear MARKs. Encoding/decoding extension is small (~15 lines) — not worth splitting into a separate file. | ✅ Already clean |

### Phase R4 — Correctness & Safety (🟡 Medium effort) — ✅ Done

> **Goal**: Address remaining correctness concerns and `@unchecked Sendable` usage.
> **Effort**: ~2 hours. **Risk**: Medium — requires careful analysis of concurrency invariants.

| Step | Item | File(s) | Action | Status |
|------|------|---------|--------|--------|
| R4.1 | **7.5** Audit `ManagedStream` `@unchecked Sendable` | `Sources/QUIC/ManagedStream.swift` | Audited: `@unchecked` is justified — the sole reason is `weak var connection: ManagedConnection?` (weak refs aren't inherently `Sendable`). All mutable state is in `Mutex<ManagedStreamState>`, all other properties are `let`. Added detailed doc comment explaining the safety reasoning. Moving `connection` into the Mutex would unnecessarily complicate every method call for no safety gain. | ✅ Done |
| R4.2 | **7.7** Investigate race window in `QUICEndpoint.connect` | `Sources/QUIC/QUICEndpoint+Client.swift` | Investigated: **No race exists.** `QUICEndpoint` is an `actor`, so `connect(to:)` and the packet-receive path are actor-isolated and cannot interleave. Router registration happens *before* the first Initial packet is sent, so by the time any response arrives, the connection is fully registered. Added a `## Concurrency Safety` doc comment on `connect(to:)` documenting this finding. | ✅ Done (safe) |
| R4.3 | **7.4** Simplify `TimerWheel.addTimer` tuple binding | `Sources/QUIC/TimerManager.swift` | The original tuple binding issue was already fixed in a prior pass. Simplified the remaining verbose `delay.components.seconds * 1000 + …` one-liner by extracting a `private static func milliseconds(from:) -> Int` helper. `addTimer` now reads `let delayMs = Self.milliseconds(from: delay)` / `let tickMs = Self.milliseconds(from: tickDuration)`. | ✅ Done |

### Phase R5 — Type System Foundation (🔴 High effort) — ✅ Foundation done

> **Goal**: Lay groundwork for stronger compile-time type safety.
> **Effort**: ~3 hours for typealias; full migration is a separate project. **Risk**: Low for typealias, high for full migration.

| Step | Item | File(s) | Action | Status |
|------|------|---------|--------|--------|
| R5.1 | **6.2** `PacketNumber` newtype — foundation | `Sources/QUICCore/Packet/PacketNumber.swift` | Created `PacketNumber` struct wrapping `UInt64` with `RawRepresentable`, `Hashable`, `Sendable`, `Comparable`, `ExpressibleByIntegerLiteral`, `Codable`. Includes helpers: `next()`, `distance(to:)`, `advanced(by:)`, `encodedLength(largestAcked:)`, `until(_:)`, `through(_:)`. Call-site migration deferred (affects `SentPacket`, `LossDetector`, `AckManager`, `ConnectionState`, etc.). | ✅ Done |
| R5.2 | **6.1** `StreamIdentifier` call-site migration (incremental) | `Sources/QUICStream/StreamManager.swift` | Added `StreamIdentifier`-based convenience overloads to `StreamManager`: `openTypedStream`, `hasStream(streamIdentifier:)`, `read(streamIdentifier:)`, `write(streamIdentifier:data:)`, `finish(streamIdentifier:)`, `closeStream(streamIdentifier:)`, `setPriority(_:forStream:)`, `priority(forStream:)`, `getOrCreateStream(streamIdentifier:)`, `activeStreamIdentifiers`. Internal storage remains `UInt64`-keyed for compatibility. Further migration to `FlowController`, `DataStream`, and cross-module boundaries deferred to future PRs. | ✅ Foundation done |

### Execution Order

```
R1 (trivial cleanup) → R2 (protocol adoption) → R3 (file org) → R4 (correctness) → R5 (type system)
```

R1–R3 can be done in a single PR. R4 should be a separate PR with careful review. R5 is best split across multiple PRs (one per type migration).

> **Status**: All phases R1–R5 completed. 876/876 tests pass. Build clean (zero errors, zero new warnings).
> Remaining long-tail work: `PacketNumber` call-site migration, `StreamIdentifier` call-site migration beyond `StreamManager`.

---

## Appendix A: File Inventory

Complete list of source files analyzed:

```
Sources/
├── HTTP3/
│   ├── Frame/
│   │   ├── HTTP3Frame.swift
│   │   └── HTTP3FrameCodec.swift
│   ├── Stream/
│   │   ├── HTTP3StreamType.swift
│   │   └── RequestStreamHandler.swift
│   ├── WebTransport/
│   │   ├── WebTransportCapsule.swift
│   │   ├── WebTransportClient.swift
│   │   ├── WebTransportError.swift
│   │   ├── WebTransportServer.swift
│   │   ├── WebTransportSession.swift
│   │   └── WebTransportStream.swift
│   ├── HTTP3Client.swift
│   ├── HTTP3Connection.swift          ← 2309 lines
│   ├── HTTP3Error.swift
│   ├── HTTP3Server.swift
│   ├── HTTP3Settings.swift
│   └── HTTP3Types.swift
├── QPACK/
│   ├── HuffmanCodec.swift
│   ├── QPACKDecoder.swift
│   ├── QPACKEncoder.swift
│   ├── QPACKInteger.swift
│   ├── QPACKString.swift
│   └── StaticTable.swift
├── QUIC/
│   ├── ConnectionRouter.swift
│   ├── ManagedConnection.swift        ← 2026+ lines
│   ├── ManagedStream.swift
│   ├── PacketProcessor.swift
│   ├── QUICConfiguration.swift
│   ├── QUICConnection.swift
│   ├── QUICEndpoint.swift             ← 1238 lines
│   ├── TimerManager.swift
│   └── VersionNegotiator.swift
├── QUICConnection/
│   ├── ConnectionState.swift
│   ├── IdleTimeoutManager.swift
│   ├── PathValidation.swift
│   ├── QUICConnectionHandler.swift    ← 1120 lines
│   └── StatelessReset.swift
├── QUICCore/
│   ├── Frame/
│   │   ├── Frame.swift
│   │   ├── FrameCodec.swift
│   │   ├── FrameSize.swift
│   │   └── FrameTypes.swift
│   ├── Packet/
│   │   ├── CoalescedPackets.swift
│   │   ├── ConnectionID.swift
│   │   ├── PacketCodec.swift
│   │   ├── PacketHeader.swift
│   │   └── Version.swift
│   ├── QLOG/
│   │   ├── QLOGEvent.swift
│   │   ├── QLOGHelpers.swift
│   │   └── QLOGLogger.swift
│   ├── DataReader.swift
│   ├── ProtocolLimits.swift
│   ├── QUICError.swift
│   ├── QuiverLogging.swift
│   ├── SafeConversions.swift
│   ├── TransportParameters.swift
│   └── Varint.swift
├── QUICCrypto/
│   ├── CryptoStream/
│   │   ├── CryptoBuffer.swift
│   │   ├── CryptoStream.swift
│   │   └── CryptoStreamManager.swift
│   ├── KeySchedule/
│   │   └── KeySchedule.swift
│   ├── TLS/
│   │   ├── Crypto/
│   │   │   ├── KeyExchange.swift
│   │   │   ├── PEMLoader.swift
│   │   │   └── Signature.swift
│   │   ├── Extensions/
│   │   │   ├── ALPN.swift
│   │   │   ├── EarlyData.swift
│   │   │   ├── KeyShare.swift
│   │   │   ├── PreSharedKey.swift
│   │   │   ├── PskKeyExchangeModes.swift
│   │   │   ├── ServerName.swift
│   │   │   ├── SignatureAlgorithms.swift
│   │   │   ├── SupportedGroups.swift
│   │   │   ├── SupportedVersions.swift
│   │   │   └── TLSExtension.swift
│   │   ├── KeySchedule/
│   │   │   ├── TLSKeySchedule.swift
│   │   │   └── TranscriptHash.swift
│   │   ├── Messages/
│   │   │   ├── Alert.swift
│   │   │   ├── Certificate.swift
│   │   │   ├── CertificateRequest.swift
│   │   │   ├── CertificateVerify.swift
│   │   │   ├── ClientHello.swift
│   │   │   ├── EncryptedExtensions.swift
│   │   │   ├── Finished.swift
│   │   │   ├── HandshakeMessage.swift
│   │   │   ├── NewSessionTicket.swift
│   │   │   └── ServerHello.swift
│   │   ├── Session/
│   │   │   ├── ClientSessionCache.swift
│   │   │   ├── ReplayProtection.swift
│   │   │   └── SessionTicketStore.swift
│   │   ├── StateMachine/
│   │   │   ├── ClientStateMachine.swift
│   │   │   └── HandshakeState.swift
│   │   ├── X509/
│   │   │   ├── ASN1/
│   │   │   ├── CertificateRevocation.swift
│   │   │   ├── PublicKeyExtractor.swift
│   │   │   ├── SystemTrustStore.swift
│   │   │   ├── X509Certificate.swift
│   │   │   ├── X509Error.swift
│   │   │   ├── X509Extensions.swift
│   │   │   └── X509Validator.swift
│   │   ├── MockTLSProvider.swift
│   │   ├── TLS13Handler.swift         ← 1437 lines
│   │   ├── TLS13Provider.swift
│   │   └── TLSOutput.swift
│   ├── TransportParameters/
│   │   ├── TransportParameterCodec.swift
│   │   └── TransportParameterID.swift
│   ├── AEAD.swift
│   ├── ChaCha20Block.swift
│   ├── CryptoState.swift
│   ├── CryptoStateKeyPhase.swift
│   ├── InitialSecrets.swift
│   ├── KeyUpdate.swift
│   └── RetryIntegrityTag.swift
├── QUICRecovery/
│   ├── AckManager.swift
│   ├── AntiAmplificationLimiter.swift
│   ├── CongestionController.swift
│   ├── FastDuration.swift
│   ├── LossDetectionConstants.swift
│   ├── LossDetector.swift
│   ├── NewRenoCongestionController.swift
│   ├── PacketNumberSpaceManager.swift
│   ├── RTTEstimator.swift
│   └── SentPacket.swift
└── QUICTransport/
    ├── ECN.swift
    ├── Pacing.swift
    └── UDPSocket.swift
```

---

## Appendix B: Grep Patterns for the Executing Agent

Use these to locate all instances before refactoring:

```bash
# Find all uses of StreamFrame.frameTypeByte (Bug 7.1)
grep -rn "frameTypeByte" Sources/

# Find all ECNCounts references (Collision 6.3)
grep -rn "ECNCounts" Sources/

# Find all Duration operator extensions (Issue 7.3)
grep -rn "extension Duration" Sources/

# Find all @unchecked Sendable (Audit 7.5)
grep -rn "@unchecked Sendable" Sources/

# Find all public types that should be package (Section 10)
grep -rn "^public " Sources/QUICCrypto/CryptoState.swift
grep -rn "^public " Sources/QUICCore/Frame/FrameCodec.swift

# Find all deprecated methods
grep -rn "@available.*deprecated" Sources/

# Find functions missing @inlinable in hot paths
grep -rn "public func " Sources/QUICCore/DataReader.swift | grep -v "@inlinable"

# Find hard-coded NewRenoCongestionController
grep -rn "NewRenoCongestionController" Sources/QUICConnection/

# Count lines per file (to validate split candidates)
find Sources -name "*.swift" -exec wc -l {} + | sort -rn | head -20
```

---

*End of analysis. Ready for execution.*