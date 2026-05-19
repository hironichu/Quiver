# Quiver Package Map

Quiver is split into small Swift packages that can be used independently or through the root aggregate package.

## Repositories

| Repository | Role | Products |
| --- | --- | --- |
| `quiver` | Aggregate package and examples | `Quiver` |
| `quiver-quic` | QUIC transport stack | `QUIC`, `QUICCore`, `QUICCrypto`, `QUICStream`, `QUICRecovery`, `QUICTransport`, `NIOUDPTransport`, `QUICConnection`, `QuiverTestSupport` |
| `quiver-runtime` | Optional native runtime used by QUIC transport experiments | `QuiverRuntimeCore`, `QuiverRuntimeTesting` |
| `quiver-http3` | HTTP/3, QPACK, and WebTransport implementation | `HTTP3`, `QPACK` |
| `quiver-webtransport` | Thin WebTransport facade | `WebTransport` |
| `quiver-auth` | Authentication and OIDC helpers for HTTP/3 | `QuiverAuth` |
| `quiver-adapters` | Framework adapters | `QuiverVapor`, `QuiverHummingbird` |
| `quiver-moq` | Media over QUIC building blocks | `MOQCore`, `MOQRelay`, `MOQClient` |

## Dependency Direction

```text
quiver
├── quiver-quic ───────────> quiver-runtime (optional through `QuiverRuntimeSupport`)
├── quiver-http3 ───────────> quiver-quic
├── quiver-webtransport ────> quiver-http3
├── quiver-auth ────────────> quiver-http3, quiver-quic
├── quiver-adapters ────────> quiver-http3
└── quiver-moq ─────────────> quiver-quic
```

`quiver-http3` owns the WebTransport server/session implementation because HTTP/3 owns Extended CONNECT request handling, stream registration, and session routing. `quiver-webtransport` exists as a consumer-friendly package boundary that re-exports those APIs.

## Aggregate Product

The root `Quiver` product conditionally re-exports package products with SwiftPM package traits. The default trait set enables the whole stack.

| Trait | Re-exported Areas |
| --- | --- |
| `QUICSupport` | `QUIC`, `QUICCore`, `QUICCrypto`, `QUICStream`, `QUICRecovery`, `QUICTransport`, `NIOUDPTransport`, `QUICConnection` |
| `QuiverRuntimeSupport` | Enables `quiver-quic`'s `quiverRuntime` package trait, plus `QUICSupport` |
| `HTTP3Support` | `HTTP3`, `QPACK`, plus `QUICSupport` |
| `WebTransportSupport` | `WebTransport`, plus `HTTP3Support` |
| `AuthSupport` | `QuiverAuth`, plus `HTTP3Support` |
| `VaporSupport` | `QuiverVapor`, plus `HTTP3Support` |
| `HummingbirdSupport` | `QuiverHummingbird`, plus `HTTP3Support` |
| `MOQSupport` | `MOQCore`, `MOQRelay`, `MOQClient`, plus `QUICSupport` |

## Choosing A Package

Use the root `quiver` package when you want a single dependency for an application or experiment.

Use a dedicated package when you want a smaller dependency graph or are building a reusable library. For example:

- QUIC-only code should depend on `quiver-quic`.
- HTTP/3 or QPACK code should depend on `quiver-http3`.
- Browser-facing WebTransport applications can depend on `quiver-webtransport`.
- Vapor or Hummingbird applications can depend on `quiver-adapters`.
- Authentication middleware can depend on `quiver-auth`.
- Media over QUIC code can depend on `quiver-moq`.

## Local And Remote Resolution

Each package prefers local sibling checkouts when they are available and falls back to GitHub URLs when consumed remotely. The default local layout is:

```text
workspace/
├── quiver/
└── quiver-packages/
    ├── quiver-quic/
    ├── quiver-runtime/
    ├── quiver-http3/
    ├── quiver-webtransport/
    ├── quiver-auth/
    ├── quiver-adapters/
    └── quiver-moq/
```

Set `QUIVER_PACKAGES_PATH` to override the local package root.
