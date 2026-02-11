/// WebTransport Advanced Options (Power-User Path)
///
/// Provides direct access to the underlying `QUICConfiguration` and
/// `HTTP3Settings` for callers who need full control over transport
/// parameters while still ensuring WebTransport-mandatory settings
/// are present.
///
/// ## When to Use
///
/// Use `WebTransportOptionsAdvanced` when you need to:
/// - Set custom congestion control, MTU, or flow-control parameters
/// - Provide a pre-configured `QUICConfiguration` with a specific security mode
/// - Override QPACK settings or other HTTP/3 knobs
///
/// For most callers, `WebTransportOptions` is sufficient.
///
/// ## Mandatory Settings
///
/// Call `validated()` (or rely on `WebTransport.connect()` to call it)
/// to ensure WebTransport-required flags are merged on top of your values:
/// - `quic.enableDatagrams = true`
/// - `quic.alpn` contains `"h3"`
/// - `http3Settings.enableConnectProtocol = true`
/// - `http3Settings.enableH3Datagram = true`
/// - `http3Settings.webtransportMaxSessions >= 1`
///
/// ## Usage
///
/// ```swift
/// var quic = QUICConfiguration()
/// quic.securityMode = .production { MyTLSProvider() }
/// quic.maxIdleTimeout = .seconds(60)
///
/// let opts = WebTransportOptionsAdvanced(
///     quic: quic,
///     http3Settings: HTTP3Settings(maxTableCapacity: 4096)
/// )
///
/// let session = try await WebTransport.connect(
///     url: "https://example.com:4433/wt",
///     options: opts
/// )
/// ```

import Foundation
import QUIC
import QUICCore

// MARK: - WebTransport Advanced Options

/// Power-user configuration that exposes the full QUIC and HTTP/3 settings.
///
/// Unlike `WebTransportOptions`, this struct does not abstract away the
/// underlying transport configuration. The caller is responsible for
/// setting TLS, flow control, and other QUIC parameters directly on
/// the `quic` field.
///
/// WebTransport-mandatory flags are enforced by `validated()`, which
/// merges required settings on top of whatever the caller provided.
public struct WebTransportOptionsAdvanced: Sendable {

    // MARK: - QUIC (full access)

    /// The underlying QUIC transport configuration.
    ///
    /// Set TLS mode (`securityMode`), transport parameters, flow control,
    /// idle timeout, and all other QUIC-level knobs directly on this field.
    public var quic: QUICConfiguration

    // MARK: - HTTP/3 (full access)

    /// HTTP/3 settings for the connection.
    ///
    /// WebTransport-required settings (`enableConnectProtocol`,
    /// `enableH3Datagram`, `webtransportMaxSessions`) are enforced
    /// by `validated()`. You may set additional knobs (QPACK table
    /// capacity, max field section size, etc.) here.
    public var http3Settings: HTTP3Settings

    // MARK: - WebTransport-specific

    /// Additional HTTP headers to include in the Extended CONNECT request.
    ///
    /// Use for authentication tokens, origin headers, or other
    /// application-specific metadata. (Client-side only.)
    ///
    /// - Default: `[]`
    public var headers: [(String, String)]

    /// Timeout for the HTTP/3 SETTINGS exchange after QUIC handshake.
    ///
    /// If the peer does not send SETTINGS within this duration,
    /// the connection attempt proceeds with a warning (some
    /// implementations send SETTINGS lazily).
    ///
    /// - Default: 10 seconds
    public var connectionReadyTimeout: Duration

    /// Timeout for the Extended CONNECT request/response handshake.
    ///
    /// If the server does not respond to the CONNECT request
    /// within this duration, the session establishment fails.
    ///
    /// - Default: 10 seconds
    public var connectTimeout: Duration

    // MARK: - Initialization

    /// Creates advanced WebTransport options with explicit QUIC and HTTP/3 access.
    ///
    /// - Parameters:
    ///   - quic: Full QUIC configuration (TLS, transport params, etc.)
    ///   - http3Settings: HTTP/3 settings (default: literal-only QPACK)
    ///   - headers: Additional CONNECT headers (default: [])
    ///   - connectionReadyTimeout: SETTINGS exchange timeout (default: 10s)
    ///   - connectTimeout: Extended CONNECT timeout (default: 10s)
    public init(
        quic: QUICConfiguration,
        http3Settings: HTTP3Settings = HTTP3Settings(),
        headers: [(String, String)] = [],
        connectionReadyTimeout: Duration = .seconds(10),
        connectTimeout: Duration = .seconds(10)
    ) {
        self.quic = quic
        self.http3Settings = http3Settings
        self.headers = headers
        self.connectionReadyTimeout = connectionReadyTimeout
        self.connectTimeout = connectTimeout
    }

    // MARK: - Validation

    /// Returns a copy with WebTransport-mandatory settings enforced.
    ///
    /// Merges required flags on top of the caller's values without
    /// overwriting unrelated settings. Specifically:
    ///
    /// - QUIC:
    ///   - `enableDatagrams` is set to `true` (RFC 9221, required for WT datagrams)
    ///   - `alpn` is ensured to contain `"h3"` (RFC 9114 ALPN requirement)
    ///
    /// - HTTP/3:
    ///   - `enableConnectProtocol` is set to `true` (RFC 9220)
    ///   - `enableH3Datagram` is set to `true` (RFC 9297)
    ///   - `webtransportMaxSessions` is set to at least 1
    ///
    /// This method is idempotent: calling it multiple times yields
    /// the same result.
    ///
    /// - Returns: A validated copy with mandatory settings applied.
    public func validated() -> WebTransportOptionsAdvanced {
        var result = self

        // --- QUIC mandatory settings ---
        result.quic.enableDatagrams = true
        if !result.quic.alpn.contains("h3") {
            result.quic.alpn.append("h3")
        }

        // --- HTTP/3 mandatory settings ---
        result.http3Settings.enableConnectProtocol = true
        result.http3Settings.enableH3Datagram = true
        if (result.http3Settings.webtransportMaxSessions ?? 0) < 1 {
            result.http3Settings.webtransportMaxSessions = max(
                result.http3Settings.webtransportMaxSessions ?? 1,
                1
            )
        }

        return result
    }

    // MARK: - Build Helpers (internal, same shape as WebTransportOptions)

    /// Returns the QUIC configuration with WebTransport-mandatory transport
    /// settings applied.
    ///
    /// Equivalent to `validated().quic`. The caller's `securityMode` and
    /// all other QUIC knobs are preserved.
    ///
    /// - Returns: A `QUICConfiguration` ready for WebTransport use.
    internal func buildQUICConfiguration() -> QUICConfiguration {
        return validated().quic
    }

    /// Returns HTTP/3 settings with WebTransport-mandatory flags applied.
    ///
    /// Equivalent to `validated().http3Settings`. The caller's QPACK
    /// and other HTTP/3 knobs are preserved.
    ///
    /// - Returns: An `HTTP3Settings` ready for WebTransport use.
    internal func buildHTTP3Settings() -> HTTP3Settings {
        return validated().http3Settings
    }
}