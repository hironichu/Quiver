## WebTransport Rewrite Plan

---

### Phase 1 -- New Types (Foundation)

**Goal**: Create all new types that the rest of the rewrite depends on. No deletions, no modifications to existing code.

**Files to CREATE:**

1. `quiver/Sources/HTTP3/WebTransport/WebTransportOptions.swift`
   - `WebTransportOptions` struct (client-side)
     - `caCertificates: [Data]?` -- optional, no default, no presumption
     - `verifyPeer: Bool` -- default `true`
     - `alpn: [String]` -- default `["h3", "webtransport"]` (spec ALPNs)
     - `headers: [(String, String)]` -- optional custom CONNECT headers, commented as unused placeholder
     - `datagramStrategy: DatagramSendingStrategy` -- default `.fifo`
     - `maxIdleTimeout: Duration` -- default 30s
     - `connectionReadyTimeout: Duration` -- default 10s
     - `connectTimeout: Duration` -- default 10s
     - `initialMaxStreamsBidi: UInt64` -- optional, default 100
     - `initialMaxStreamsUni: UInt64` -- optional, default 100
     - `maxSessions: UInt64` -- default 1
   - `static func insecure()` -- factory that sets `verifyPeer: false`, clearly named
   - `func buildQUICConfiguration() -> QUICConfiguration` -- internal, generates QUIC config with WT-mandatory settings (enableDatagrams, ALPN, flow control)
   - `func buildHTTP3Settings() -> HTTP3Settings` -- internal, generates H3 settings with `enableConnectProtocol: true`, `enableH3Datagram: true`, `webtransportMaxSessions`

2. `quiver/Sources/HTTP3/WebTransport/WebTransportOptionsAdvanced.swift`
   - `WebTransportOptionsAdvanced` struct (power-user path)
     - `quic: QUICConfiguration` -- full access
     - `http3Settings: HTTP3Settings` -- full access
     - `headers: [(String, String)]`
     - `connectionReadyTimeout: Duration`
     - `connectTimeout: Duration`
   - Enforces WT-mandatory settings in a `func validated() -> WebTransportOptionsAdvanced` that merges required flags on top of user values
   - Conforms to same internal protocol or has same `buildQUICConfiguration()` / `buildHTTP3Settings()` shape as `WebTransportOptions`

3. `quiver/Sources/HTTP3/WebTransport/WebTransportReply.swift`
   - `WebTransportReply` enum: `.accept`, `.reject(reason: String)`
   - `WebTransportMiddleware` typealias: `@Sendable (WebTransportRequestContext) async -> WebTransportReply`
   - `WebTransportRequestContext` struct: exposes `path: String`, `authority: String`, `headers: [(String, String)]`, `origin: String?`

4. `quiver/Sources/HTTP3/WebTransport/WebTransportServerOptions.swift`
   - `WebTransportServerOptions` struct
     - `certificatePath: String` or `certificateChain: [Data]`
     - `privateKeyPath: String` or `privateKey: Data`
     - `caCertificates: [Data]?`
     - `verifyPeer: Bool` -- default `true`
     - `alpn: [String]` -- default `["h3", "webtransport"]`
     - `maxSessions: UInt64` -- default 1
     - `maxConnections: Int` -- default 0 (unlimited)
     - `maxIdleTimeout: Duration` -- default 30s
     - `initialMaxStreamsBidi: UInt64` -- optional, default 100
     - `initialMaxStreamsUni: UInt64` -- optional, default 100
   - `func buildQUICConfiguration() -> QUICConfiguration` -- internal
   - `func buildHTTP3Settings() -> HTTP3Settings` -- internal

**Files MODIFIED**: None.
**Files DELETED**: None.

**Checkpoint**: Review all new types before any wiring.

---

### Phase 2 -- Client Rewrite

**Goal**: Replace `WebTransportClient` actor and `WebTransportConfiguration` with a single `WebTransport` entry point.

**File to CREATE:**

1. `quiver/Sources/HTTP3/WebTransport/WebTransport.swift`
   - Top-level namespace/factory: `public enum WebTransport`
   - `static func connect(url: String, options: WebTransportOptions) async throws -> WebTransportSession`
   - `static func connect(url: URL, options: WebTransportOptions) async throws -> WebTransportSession`
   - `static func connect(url: String, options: WebTransportOptionsAdvanced) async throws -> WebTransportSession`
   - One shared private implementation: `static func _connect(scheme:authority:path:quicConfig:h3Settings:headers:connectionReadyTimeout:connectTimeout:) async throws -> WebTransportSession`
     - Extracted from current `WebTransportClient.swift` L653-743
     - Single place for: create endpoint, dial, init H3, waitForReady, verify peer settings, send CONNECT, check response, create session
     - Peer validation logic (currently duplicated at L303-320 and L700-717) lives here once
     - URL parsing (currently duplicated at L398-422 and L567-596) lives here once
     - Settings merge (currently at L197-200 and L673-676) lives here once

**Files to DELETE:**

1. `quiver/Sources/HTTP3/WebTransport/WebTransportClient.swift` -- entire file (744 lines)
2. `quiver/Sources/HTTP3/WebTransport/WebTransportConfiguration.swift` -- entire file (100 lines)

**Checkpoint**: Client compiles and connects. Old client fully removed.

---

### Phase 3 -- Server Rewrite

**Goal**: Replace `WebTransportServer` with the new options + middleware architecture.

**File to OVERWRITE:**

1. `quiver/Sources/HTTP3/WebTransport/WebTransportServer.swift`
   - `public actor WebTransportServer`
   - Constructor: `init(host: String, port: UInt16, options: WebTransportServerOptions, middleware: WebTransportMiddleware? = nil)`
     - Also accept `init(host: SocketAddress, ...)` variant
   - `func register(path: String, middleware: WebTransportMiddleware? = nil)`
     - Stores in `private var routes: [String: WebTransportMiddleware?]`
   - Middleware resolution logic:
     - Request path matches a registered route with middleware -> run that middleware
     - Request path matches a registered route without middleware -> run global middleware if any, else accept
     - Request path matches NO registered route AND routes are registered -> reject 404
     - No routes registered + global middleware exists -> run global middleware on all paths
     - No routes registered + no global middleware -> accept all (open server)
   - On `.reject(reason:)`: respond with `403 Forbidden`, header `X-WT-Reject: <reason>`, close stream with reason
   - `func listen() async throws` -- starts the server
   - `func stop(gracePeriod: Duration = .seconds(5)) async`
   - `var incomingSessions: AsyncStream<WebTransportSession>`
   - Internally delegates to `HTTP3Server` as before, but request handler integrates middleware

**Files MODIFIED:**

1. `quiver/Sources/HTTP3/HTTP3Server.swift`
   - Rename existing `WebTransportOptions` at L98-130 to `HTTP3WebTransportOptions` (internal use only) to resolve name clash
   - Or: update `enableWebTransport()` to accept the new parameter shape directly
   - Minimal change -- just enough to avoid collision with the new `WebTransportOptions`

**Checkpoint**: Server compiles, middleware routing works, old server API replaced.

---

### Phase 4 -- Cleanup and Integration

**Goal**: Remove dead code, update all references, ensure everything compiles.

**Files to AUDIT and UPDATE:**

1. `quiver/Sources/HTTP3/WebTransport/WebTransportError.swift` -- no structural change expected, verify all error cases still referenced
2. `quiver/Sources/HTTP3/WebTransport/WebTransportSession.swift` -- no structural change, verify it works standalone without `WebTransportClient`
3. `quiver/Sources/HTTP3/WebTransport/WebTransportStream.swift` -- no change expected
4. `quiver/Sources/HTTP3/WebTransport/WebTransportCapsule.swift` -- no change expected
5. `quiver/Examples/WebTransportDemo/main.swift` -- update to use `WebTransport.connect()` and new server API
6. `quiver/Examples/HTTP3Demo/main.swift` -- update any WT references
7. All test files referencing `WebTransportClient` or `WebTransportConfiguration` -- update imports and call sites

**Files to DELETE (if not already):**

1. Confirm `WebTransportClient.swift` is gone
2. Confirm `WebTransportConfiguration.swift` is gone

**Checkpoint**: Full project compiles. `diagnostics()` clean. No references to deleted types remain.

---

### Phase 5 -- Validation

**Goal**: Verify correctness.

1. Run `grep` for any remaining references to:
   - `WebTransportClient`
   - `WebTransportConfiguration`
   - `WebTransportClient.Configuration`
2. Run `diagnostics` on the full project
3. Verify the final file list in `quiver/Sources/HTTP3/WebTransport/`:
   - `WebTransport.swift` (client entry point)
   - `WebTransportOptions.swift` (client options)
   - `WebTransportOptionsAdvanced.swift` (power-user options)
   - `WebTransportReply.swift` (middleware types)
   - `WebTransportServerOptions.swift` (server options)
   - `WebTransportServer.swift` (server)
   - `WebTransportSession.swift` (unchanged)
   - `WebTransportStream.swift` (unchanged)
   - `WebTransportCapsule.swift` (unchanged)
   - `WebTransportError.swift` (unchanged)

---

### Summary

| Phase | Action | Lines Added | Lines Removed | Risk |
|---|---|---|---|---|
| 1 | New types | ~300 | 0 | LOW |
| 2 | Client rewrite | ~200 | ~844 | MEDIUM |
| 3 | Server rewrite | ~250 | ~330 | MEDIUM |
| 4 | Cleanup | ~50 | ~50 | LOW |
| 5 | Validation | 0 | 0 | NONE |

Net result: **~-424 lines**, 3 config types eliminated, 0 duplication in connect flow, single middleware pattern for server.