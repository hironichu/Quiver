# WebTransport Implementation Plan

> **Goal**: Full WebTransport support over HTTP/3, browser-compatible, both server and client.
>
> **RFCs**:
> - RFC 9220 — Bootstrapping WebTransport via HTTP/3 (Extended CONNECT)
> - RFC 9297 — HTTP Datagrams and the Capsule Protocol
> - RFC 9221 — QUIC Unreliable Datagram Extension
> - RFC 9114 — HTTP/3 (already implemented)
> - RFC 9000 — QUIC (already implemented)
> - draft-ietf-webtrans-http3 — WebTransport over HTTP/3

## Constraints

- **NO rewrites, NO reworks** — extend existing code only
- **Browser-compatible** — must work with Chrome, Firefox, Safari WebTransport API
- **Both server AND client**
- **Self-signed TLS AND valid TLS**
- **Phase by phase execution, stop at each checkpoint**

---

## Architecture Overview

```
┌───────────────────────────────────────────────────────────────┐
│  Application Layer                                            │
│  (WebTransportServer, WebTransportClient)                     │
├───────────────────────────────────────────────────────────────┤
│  WebTransport Session Layer                                   │
│  (WebTransportSession, session streams, datagrams)            │
├───────────────────────────────────────────────────────────────┤
│  Extended CONNECT (RFC 9220)                                  │
│  (:protocol pseudo-header, CONNECT handshake)                 │
├───────────────────────────────────────────────────────────────┤
│  HTTP/3 + Settings Extensions                                 │
│  (ENABLE_CONNECT_PROTOCOL, H3_DATAGRAM, WT_MAX_SESSIONS)      │
├───────────────────────────────────────────────────────────────┤
│  QUIC Datagram Extension (RFC 9221)                           │
│  (max_datagram_frame_size transport param, DATAGRAM frames)   │
├───────────────────────────────────────────────────────────────┤
│  Existing QUIC + HTTP/3 Stack                                 │
│  (QUICEndpoint, ManagedConnection, HTTP3Connection, etc.)     │
└───────────────────────────────────────────────────────────────┘
```

## Module Structure (New Files Only)

```
Sources/
├── QUICCore/
│   └── TransportParameters.swift          # MODIFY: add maxDatagramFrameSize field
│
├── QUICCrypto/
│   └── TransportParameters/
│       ├── TransportParameterID.swift     # MODIFY: add maxDatagramFrameSize case
│       └── TransportParameterCodec.swift  # MODIFY: encode/decode maxDatagramFrameSize
│
├── QUIC/
│   └── QUICConfiguration.swift            # MODIFY: add enableDatagrams option
│
├── HTTP3/
│   ├── HTTP3Settings.swift                # MODIFY: add WT-related settings
│   ├── Frame/
│   │   └── HTTP3FrameCodec.swift          # MODIFY: encode/decode new settings
│   └── Stream/
│       └── HTTP3StreamType.swift          # MODIFY: add webtransport stream type
│
├── WebTransport/                          # NEW MODULE
│   ├── WebTransportSession.swift          # Session management
│   ├── WebTransportStream.swift           # WT bidirectional/unidirectional streams
│   ├── WebTransportDatagram.swift         # Datagram send/receive per session
│   ├── WebTransportError.swift            # WT-specific errors
│   ├── WebTransportConfiguration.swift    # Options: unreliable, allowPooling, etc.
│   ├── WebTransportServer.swift           # Server-side API
│   ├── WebTransportClient.swift           # Client-side API
│   └── CapsuleProtocol.swift             # HTTP Capsule framing (RFC 9297)
│
Tests/
└── WebTransportTests/
    └── WebTransportTests.swift            # Server demo, Client demo, TLS tests
```

---

## Phase 1: QUIC Datagram Support (Transport Parameter)

**Status**: ✅ Complete

### What Exists
- `DatagramFrame` struct in `QUICCore/Frame/FrameTypes.swift` ✅
- `Frame.datagram(DatagramFrame)` case in `QUICCore/Frame/Frame.swift` ✅
- `FrameType.datagram` and `FrameType.datagramWithLength` in `QUICCore/Frame/Frame.swift` ✅
- DATAGRAM frame encode/decode in `QUICCore/Frame/FrameCodec.swift` ✅

### What Was Added
1. **`TransportParameters.maxDatagramFrameSize`** — new `UInt64?` field (RFC 9221 §3)
   - File: `Sources/QUICCore/TransportParameters.swift`
   - Transport parameter ID: `0x0020`
   - Default: `nil` (datagrams disabled)
   - When set: indicates willingness to receive DATAGRAM frames up to this size

2. **`TransportParameterID.maxDatagramFrameSize`** — new enum case
   - File: `Sources/QUICCrypto/TransportParameters/TransportParameterID.swift`
   - Value: `0x0020`

3. **Transport parameter encode/decode** — added to codec
   - File: `Sources/QUICCrypto/TransportParameters/TransportParameterCodec.swift`
   - Encode: if `maxDatagramFrameSize != nil`, encode as varint param
   - Decode: parse `0x0020` parameter, set field

4. **`QUICConfiguration.enableDatagrams`** — new `Bool` field (default: `false`)
   - File: `Sources/QUIC/QUICConfiguration.swift`
   - When true, set `maxDatagramFrameSize = 65535` in transport params

5. **Wired `maxDatagramFrameSize` into `TransportParameters.init(from: QUICConfiguration)`**
   - File: `Sources/QUIC/QUICConfiguration.swift`

### Acceptance Criteria
- [x] Existing tests pass (no breaking changes)
- [x] `TransportParameters` roundtrip encode/decode with `maxDatagramFrameSize`
- [x] `QUICConfiguration(enableDatagrams: true)` produces correct transport params

---

## Phase 2: HTTP/3 Settings for WebTransport

**Status**: ✅ Complete

### What Was Added

1. **New HTTP/3 Settings identifiers**:
   - `SETTINGS_ENABLE_CONNECT_PROTOCOL` = `0x08` (RFC 9220 §3)
   - `SETTINGS_H3_DATAGRAM` = `0x33` (RFC 9297 §2.1)
   - `SETTINGS_H3_DATAGRAM_DEPRECATED` = `0xFFD277` (still used by Chrome)
   - `SETTINGS_WEBTRANSPORT_MAX_SESSIONS` = `0xc671706a` (draft-ietf-webtrans-http3-07+)
   - `WEBTRANSPORT_ENABLE_DEPRECATED` = `0x2b603742` (boolean flag, must be 1)
   - `WEBTRANSPORT_MAX_SESSIONS_DEPRECATED` = `0x2b603743` (old max sessions)

2. **`HTTP3Settings` new fields**:
   - `enableConnectProtocol: Bool` (default: `false`)
   - `enableH3Datagram: Bool` (default: `false`)
   - `webtransportMaxSessions: UInt64?` (default: `nil`, meaning not advertised)
   - `isWebTransportReady: Bool` computed property (all three enabled)
   - `HTTP3Settings.webTransport(maxSessions:)` factory method

3. **`HTTP3SettingsIdentifier` new cases**:
   - `.enableConnectProtocol = 0x08`
   - `.h3Datagram = 0x33`
   - `.h3DatagramDeprecated = 0xFFD277`
   - `.webtransportMaxSessions = 0xc671706a` (NEW, draft-07+)
   - `.webtransportEnableDeprecated = 0x2b603742` (boolean enable flag)
   - `.webtransportMaxSessionsDeprecated = 0x2b603743` (old max sessions)

4. **Settings encode/decode** in `HTTP3FrameCodec`:
   - Encode the new settings when non-default
   - Decode and populate the new fields
   - MUST NOT error on unknown settings (already handled)

5. **Bugfix**: Removed `0x08` from `isHTTP2OnlySetting()` blocklist.
   `0x08` was incorrectly treated as reserved HTTP/2 setting
   (`SETTINGS_MAX_HEADER_LIST_SIZE`). Per RFC 9114 §11.2.2 only
   `0x02-0x05` are reserved; `0x08` is `SETTINGS_ENABLE_CONNECT_PROTOCOL`
   (RFC 9220).

### Acceptance Criteria
- [x] Settings roundtrip with all three new settings
- [x] Browsers see correct SETTINGS frame
- [x] Existing HTTP/3 tests still pass (113/113)

---

## Phase 3: Extended CONNECT Protocol (RFC 9220)

**Status**: 🔲 Not Started

### What Needs Adding

1. **`:protocol` pseudo-header support in `HTTP3Request`**:
   - New optional `protocol: String?` field
   - When set, method MUST be `CONNECT`
   - Added to header list encoding: `:protocol` header
   - Value for WebTransport: `"webtransport"`

2. **Server-side Extended CONNECT handling**:
   - Detect `:protocol` in incoming request headers
   - Validate: must have `:method=CONNECT`, `:protocol`, `:scheme`, `:authority`, `:path`
   - Route to WebTransport handler if `:protocol=webtransport`

3. **Client-side Extended CONNECT sending**:
   - Build CONNECT request with `:protocol=webtransport`
   - Include `:scheme=https`, `:authority`, `:path`
   - Handle 200 response (session established)

4. **Response handling**:
   - Server sends `200` status to accept
   - Server sends `4xx`/`5xx` to reject
   - The CONNECT stream stays open for the session lifetime

### Acceptance Criteria
- [ ] Extended CONNECT request encodes all required pseudo-headers
- [ ] Server correctly identifies and routes Extended CONNECT requests
- [ ] 200 response establishes the session; error codes reject it

---

## Phase 4: WebTransport Session + Streams + Datagrams

**Status**: 🔲 Not Started

### New Module: `WebTransport`

#### 4a. `WebTransportSession`
- Associated with a CONNECT stream (session ID = stream ID of CONNECT stream)
- Manages WT streams (bidi + uni) opened within the session
- Manages datagrams for this session
- Lifecycle: open → active → closing → closed
- Properties:
  - `sessionID: UInt64` (the CONNECT stream ID)
  - `url: String` (the path requested)
  - `incomingBidirectionalStreams: AsyncStream<WebTransportStream>`
  - `incomingUnidirectionalStreams: AsyncStream<WebTransportStream>`
  - `datagrams: WebTransportDatagramChannel`

#### 4b. `WebTransportStream`
- Wraps a QUIC stream within a WT session
- Stream types (RFC draft-ietf-webtrans-http3 §4):
  - **WT bidi stream**: HTTP/3 bidi stream, first varint = `0x41` + session ID
  - **WT uni stream**: HTTP/3 uni stream type `0x54`, then session ID
- Methods:
  - `read() async throws -> Data`
  - `write(_ data: Data) async throws`
  - `closeWrite() async throws`
  - `reset(errorCode:) async`

#### 4c. `WebTransportDatagram`
- QUIC DATAGRAM frame with session ID (quarter stream ID) prefix
- Per RFC 9297: datagram format = `Quarter Stream ID (varint) + Payload`
- Quarter Stream ID = session stream ID / 4
- API:
  - `sendDatagram(_ data: Data) async throws`
  - `incomingDatagrams: AsyncStream<Data>`

#### 4d. `WebTransportError`
- `sessionRejected(status: Int)`
- `sessionClosed(code: UInt32, reason: String)`
- `streamError(String)`
- `datagramTooLarge(maxSize: Int)`
- `notConnected`
- `protocolError(String)`

#### 4e. `WebTransportConfiguration`
- `unreliable: Bool` — enable datagram support (default: true)
- `allowPooling: Bool` — allow multiple sessions on one connection (default: false)
- `congestionControl: CongestionControlPreference` — `.default`, `.throughput`, `.lowLatency`
- `requireUnreliable: Bool` — fail if datagrams not supported (default: false)
- `maxDatagramSize: Int` — max datagram payload size
- `serverCertificateHashes: [Data]?` — for self-signed cert pinning (browser API)

#### 4f. `CapsuleProtocol` (RFC 9297)
- `CLOSE_WEBTRANSPORT_SESSION` capsule type (`0x2843`)
- Encode/decode close session capsule with error code + reason
- Used to gracefully close a WT session

### Stream Type Constants
- **WT bidirectional stream signal**: frame type `0x41` on HTTP/3 bidi stream
- **WT unidirectional stream type**: `0x54` on HTTP/3 uni stream

### Acceptance Criteria
- [ ] Session can be created from a CONNECT stream
- [ ] WT bidi streams open/close correctly with session ID framing
- [ ] WT uni streams open/close correctly with session ID framing
- [ ] Datagrams route to the correct session
- [ ] Session close propagates to all streams and datagrams

---

## Phase 5: WebTransport Server API

**Status**: 🔲 Not Started

### `WebTransportServer`
- Extends/wraps `HTTP3Server`
- Listens for incoming WebTransport sessions (Extended CONNECT requests)
- API:
  ```
  let server = WebTransportServer(configuration: wtConfig)
  server.onSession { session in
      // session.url, session.sessionID
      for await stream in session.incomingBidirectionalStreams {
          // handle stream
      }
      for await datagram in session.datagrams.incoming {
          // handle datagram
      }
  }
  try await server.serve(connectionSource: quicEndpoint.incomingConnections)
  ```
- Route by path (e.g., `/chat`, `/game`)
- Multiple concurrent sessions
- Graceful shutdown with CLOSE_WEBTRANSPORT_SESSION capsule

### Acceptance Criteria
- [ ] Server accepts WT sessions from browsers
- [ ] Server can receive/send streams within sessions
- [ ] Server can receive/send datagrams within sessions
- [ ] Multiple concurrent sessions work
- [ ] Graceful close sends proper capsule

---

## Phase 6: WebTransport Client API

**Status**: 🔲 Not Started

### `WebTransportClient`
- Wraps `HTTP3Client`
- Connects to a WebTransport server via Extended CONNECT
- API:
  ```
  let client = WebTransportClient(configuration: wtConfig)
  let session = try await client.connect(to: "https://example.com/chat")

  // Open streams
  let stream = try await session.openBidirectionalStream()
  try await stream.write(Data("hello".utf8))
  let response = try await stream.read()

  // Send datagrams
  try await session.sendDatagram(Data("ping".utf8))

  // Receive
  for await datagram in session.datagrams.incoming {
      print("Got datagram: \(datagram.count) bytes")
  }
  ```
- Options: `unreliable`, `allowPooling`, `congestionControl`
- Support `serverCertificateHashes` for self-signed certs (mirrors browser API)

### Acceptance Criteria
- [ ] Client connects to a WT server and establishes session
- [ ] Client can open bidi/uni streams
- [ ] Client can send/receive datagrams
- [ ] Options are properly negotiated
- [ ] Self-signed cert support works

---

## Phase 7: Tests

**Status**: 🔲 Not Started

### Test Structure
```
Tests/WebTransportTests/
├── WebTransportTests.swift              # Core unit tests
├── WebTransportServerDemoTest.swift     # Server demo / integration
├── WebTransportClientDemoTest.swift     # Client demo / integration
└── WebTransportTLSTests.swift           # Self-signed + valid TLS
```

### Server Demo Test
- Start a WebTransport server on localhost
- Accept sessions
- Echo streams (bidi echo)
- Echo datagrams
- Verify session open/close lifecycle

### Client Demo Test
- Connect to server
- Open bidi stream, send data, receive echo
- Send datagram, receive echo
- Close session gracefully

### TLS Tests
- Self-signed certificate: server + client connect successfully
- Valid TLS certificate: server + client connect successfully
- Certificate hash pinning works

### Browser Compatibility Checklist
- [ ] SETTINGS frame includes all required settings
- [ ] Extended CONNECT uses correct pseudo-headers
- [ ] DATAGRAM frames use correct quarter-stream-ID encoding
- [ ] WT stream framing matches spec (0x41 bidi, 0x54 uni)
- [ ] CLOSE_WEBTRANSPORT_SESSION capsule is correct
- [ ] Session ID is correctly derived from CONNECT stream ID
- [ ] H3_DATAGRAM setting value = 1 (not just present)
- [ ] SETTINGS_ENABLE_CONNECT_PROTOCOL value = 1

---

## Browser Compatibility Notes

### Required SETTINGS for Browser Clients
The server MUST advertise all three settings:
1. `SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08) = 1`
2. `SETTINGS_H3_DATAGRAM (0x33) = 1`  
3. `SETTINGS_WEBTRANSPORT_MAX_SESSIONS (0xc671706a) = 1` (or higher, draft-07+)
4. `WEBTRANSPORT_ENABLE_DEPRECATED (0x2b603742) = 1` (boolean, for Chrome/Deno compat)
5. `WEBTRANSPORT_MAX_SESSIONS_DEPRECATED (0x2b603743) = N` (for Chrome/Deno compat)
6. `SETTINGS_H3_DATAGRAM_DEPRECATED (0xFFD277) = 1` (for Chrome compat)

Without the core three (0x08, 0x33, 0xc671706a), modern clients will reject the
WebTransport connection. The deprecated identifiers are sent alongside for
backward compatibility with Deno (web-transport-rs) and older Chrome versions.

**Critical**: `0x2b603742` is a boolean enable flag (value MUST be 1).
Sending the max sessions count here instead of 1 will cause Deno to
reject WebTransport as unsupported.

### ALPN
- Must be `h3` (standard HTTP/3 ALPN)
- WebTransport does NOT use a separate ALPN

### Extended CONNECT Request (from browser)
```
:method = CONNECT
:protocol = webtransport
:scheme = https
:authority = example.com:443
:path = /endpoint
origin = https://example.com
```

### Extended CONNECT Response (from server)
```
:status = 200
sec-webtransport-http3-draft = draft02
```

### Datagram Encoding
- QUIC DATAGRAM frame payload:
  ```
  Quarter Stream ID (varint) | Payload
  ```
- Quarter Stream ID = CONNECT stream ID / 4

### WebTransport Stream Framing
- **Bidirectional**: On the QUIC bidi stream, first bytes:
  ```
  0x41 (WT stream signal, varint) | Session ID (varint) | data...
  ```
  Wait — actually per the latest draft:
  - WT bidi streams: The client opens a QUIC bidi stream and sends `WT_STREAM_BIDI (0x41)` frame type followed by session ID
  - WT uni streams: The client opens a QUIC uni stream with type `WT_STREAM_UNI (0x54)` followed by session ID

### Session Close
- Via CLOSE_WEBTRANSPORT_SESSION capsule on the CONNECT stream
- Capsule type: `0x2843`
- Payload: `error_code (u32) + reason_phrase_bytes`

---

## Execution Order

| Phase | Description | Dependencies | Est. Files Changed |
|-------|-------------|-------------|-------------------|
| 1 | QUIC Datagram transport param | None | 4 modified |
| 2 | HTTP/3 Settings extensions | Phase 1 | 3 modified |
| 3 | Extended CONNECT protocol | Phase 2 | 3 modified |
| 4 | WebTransport session layer | Phase 3 | 8 new files |
| 5 | WebTransport Server API | Phase 4 | 1 new file + Package.swift |
| 6 | WebTransport Client API | Phase 4 | 1 new file |
| 7 | Tests | Phase 5+6 | 4 new test files |

**Total**: ~8 new files, ~10 modified files, 1 new module (`WebTransport`)

---

## Current Progress

- [x] Phase 0: Survey and plan (this document)
- [x] Phase 1: QUIC Datagram Support
- [x] Phase 2: HTTP/3 Settings Extensions
- [ ] Phase 3: Extended CONNECT Protocol
- [ ] Phase 4: WebTransport Session Layer
- [ ] Phase 5: WebTransport Server API
- [ ] Phase 6: WebTransport Client API
- [ ] Phase 7: Tests