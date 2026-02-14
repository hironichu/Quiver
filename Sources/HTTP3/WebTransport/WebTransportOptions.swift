/// WebTransport Client Options
///
/// A simplified, user-facing configuration for WebTransport clients.
/// Abstracts away the underlying QUIC and HTTP/3 settings into
/// WebTransport-relevant knobs with safe defaults.
///
/// ## Usage
///
/// ```swift
/// // Minimal (production TLS, all defaults)
/// let session = try await WebTransport.connect(
///     url: "https://example.com:4433/wt",
///     options: WebTransportOptions()
/// )
///
/// // Development / self-signed certs
/// let session = try await WebTransport.connect(
///     url: "https://localhost:4433/wt",
///     options: .insecure()
/// )
///
/// // Custom CA bundle (DER)
/// var opts = WebTransportOptions()
/// opts.caCertificates = .der([myRootCertDER])
/// opts.maxIdleTimeout = .seconds(60)
///
/// // Custom CA bundle (PEM file path)
/// opts.caCertificates = .pem(path: "/path/to/roots.pem")
/// ```
///
/// For full control over QUIC and HTTP/3 parameters, use
/// `WebTransportOptionsAdvanced` instead.
///
/// ## References
///
/// - [draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)
/// - [RFC 9220: Bootstrapping WebSockets with HTTP/3](https://www.rfc-editor.org/rfc/rfc9220.html)

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import QUIC
import QUICCore

// MARK: - CA Certificate Source

/// Source of trusted CA certificates used for TLS peer verification.
///
/// This type does not parse certificates directly in the HTTP3 module.
/// Resolution (for example PEM file loading) is performed by the QUIC/TLS layer.
public enum CACertificateSource: Sendable {
    /// Use platform/system trust store.
    case system

    /// Use explicit DER-encoded root CA certificate blobs.
    case der([Data])

    /// Load PEM-encoded certificates from a file path.
    case pem(path: String)
}

// MARK: - WebTransport Client Options

/// Simplified client-side options for establishing a WebTransport session.
///
/// Provides safe defaults for common use cases. The `buildQUICConfiguration()`
/// and `buildHTTP3Settings()` methods translate these into the underlying
/// QUIC and HTTP/3 types needed by the connection machinery.
public struct WebTransportOptions: Sendable {

    // MARK: - TLS / Security

    /// Trusted CA certificate source for peer verification.
    ///
    /// - `.system`: use system/platform trust roots
    /// - `.der([Data])`: use explicit DER-encoded roots
    /// - `.pem(path:)`: resolve PEM file at TLS provider creation layer
    ///
    /// - Default: `.system`
    public var caCertificates: CACertificateSource

    /// Whether to verify the server's TLS certificate.
    ///
    /// Setting this to `false` disables certificate validation entirely.
    /// **Never disable in production.**
    ///
    /// - Default: `true`
    public var verifyPeer: Bool

    // MARK: - Protocol

    /// ALPN tokens advertised during the TLS handshake.
    ///
    /// The WebTransport spec requires `h3`; some implementations also
    /// accept `webtransport` as a secondary token.
    ///
    /// - Default: `["h3"]`
    public var alpn: [String]

    /// Additional HTTP headers to include in the Extended CONNECT request.
    ///
    /// Use this for authentication tokens, origin headers, or custom
    /// metadata. These are sent as-is; no validation is performed.
    ///
    /// - Note: Placeholder for future use. Currently passed through to
    ///   the CONNECT request builder but not processed by middleware.
    ///
    /// - Default: `[]`
    public var headers: [(String, String)]

    // MARK: - Datagrams

    /// Strategy for outbound QUIC DATAGRAM frames.
    ///
    /// Controls how datagrams are queued and prioritized at the QUIC layer.
    ///
    /// - Default: `.fifo`
    public var datagramStrategy: DatagramSendingStrategy

    // MARK: - Timeouts

    /// Maximum idle timeout for the QUIC connection.
    ///
    /// If no packets are exchanged within this duration, the connection
    /// is closed. Applies symmetrically (both sides must agree).
    ///
    /// - Default: 30 seconds
    public var maxIdleTimeout: Duration

    /// Timeout for the HTTP/3 SETTINGS exchange after QUIC handshake.
    ///
    /// If the peer does not send its SETTINGS frame within this duration,
    /// the connection attempt fails.
    ///
    /// - Default: 10 seconds
    public var connectionReadyTimeout: Duration

    /// Timeout for the Extended CONNECT request/response handshake.
    ///
    /// If the server does not respond to the CONNECT request within
    /// this duration, the session establishment fails.
    ///
    /// - Default: 10 seconds
    public var connectTimeout: Duration

    // MARK: - Flow Control

    /// Initial maximum number of peer-initiated bidirectional streams.
    ///
    /// Advertised as the `initial_max_streams_bidi` QUIC transport parameter.
    ///
    /// - Default: 100
    public var initialMaxStreamsBidi: UInt64

    /// Initial maximum number of peer-initiated unidirectional streams.
    ///
    /// Advertised as the `initial_max_streams_uni` QUIC transport parameter.
    ///
    /// - Default: 100
    public var initialMaxStreamsUni: UInt64

    // MARK: - Sessions

    /// Maximum number of concurrent WebTransport sessions.
    ///
    /// Advertised via `SETTINGS_WEBTRANSPORT_MAX_SESSIONS`. Browsers
    /// require this to be > 0.
    ///
    /// - Default: 1
    public var maxSessions: UInt64

    // MARK: - Initialization

    /// Creates client options with sensible defaults.
    ///
    /// - Parameters:
    ///   - caCertificates: Trusted CA source (default: `.system`)
    ///   - verifyPeer: Verify server certificate (default: true)
    ///   - alpn: ALPN tokens (default: ["h3"])
    ///   - headers: Extra CONNECT headers (default: [])
    ///   - datagramStrategy: Datagram queuing strategy (default: .fifo)
    ///   - maxIdleTimeout: QUIC idle timeout (default: 30s)
    ///   - connectionReadyTimeout: SETTINGS exchange timeout (default: 10s)
    ///   - connectTimeout: Extended CONNECT timeout (default: 10s)
    ///   - initialMaxStreamsBidi: Max peer bidi streams (default: 100)
    ///   - initialMaxStreamsUni: Max peer uni streams (default: 100)
    ///   - maxSessions: Max concurrent WT sessions (default: 1)
    public init(
        caCertificates: CACertificateSource = .system,
        verifyPeer: Bool = true,
        alpn: [String] = ["h3"],
        headers: [(String, String)] = [],
        datagramStrategy: DatagramSendingStrategy = .fifo,
        maxIdleTimeout: Duration = .seconds(30),
        connectionReadyTimeout: Duration = .seconds(10),
        connectTimeout: Duration = .seconds(10),
        initialMaxStreamsBidi: UInt64 = 100,
        initialMaxStreamsUni: UInt64 = 100,
        maxSessions: UInt64 = 1
    ) {
        self.caCertificates = caCertificates
        self.verifyPeer = verifyPeer
        self.alpn = alpn
        self.headers = headers
        self.datagramStrategy = datagramStrategy
        self.maxIdleTimeout = maxIdleTimeout
        self.connectionReadyTimeout = connectionReadyTimeout
        self.connectTimeout = connectTimeout
        self.initialMaxStreamsBidi = initialMaxStreamsBidi
        self.initialMaxStreamsUni = initialMaxStreamsUni
        self.maxSessions = maxSessions
    }

    /// Backward-compatible initializer for DER certificate arrays.
    ///
    /// - Parameters:
    ///   - caCertificatesDER: Trusted CA certs in DER format (nil => `.system`)
    ///   - verifyPeer: Verify server certificate (default: true)
    ///   - alpn: ALPN tokens (default: `["h3"]`)
    ///   - headers: Extra CONNECT headers (default: `[]`)
    ///   - datagramStrategy: Datagram queuing strategy (default: `.fifo`)
    ///   - maxIdleTimeout: QUIC idle timeout (default: 30s)
    ///   - connectionReadyTimeout: SETTINGS exchange timeout (default: 10s)
    ///   - connectTimeout: Extended CONNECT timeout (default: 10s)
    ///   - initialMaxStreamsBidi: Max peer bidi streams (default: 100)
    ///   - initialMaxStreamsUni: Max peer uni streams (default: 100)
    ///   - maxSessions: Max concurrent WT sessions (default: 1)
    public init(
        caCertificatesDER: [Data]?,
        verifyPeer: Bool = true,
        alpn: [String] = ["h3"],
        headers: [(String, String)] = [],
        datagramStrategy: DatagramSendingStrategy = .fifo,
        maxIdleTimeout: Duration = .seconds(30),
        connectionReadyTimeout: Duration = .seconds(10),
        connectTimeout: Duration = .seconds(10),
        initialMaxStreamsBidi: UInt64 = 100,
        initialMaxStreamsUni: UInt64 = 100,
        maxSessions: UInt64 = 1
    ) {
        self.init(
            caCertificates: caCertificatesDER.map { .der($0) } ?? .system,
            verifyPeer: verifyPeer,
            alpn: alpn,
            headers: headers,
            datagramStrategy: datagramStrategy,
            maxIdleTimeout: maxIdleTimeout,
            connectionReadyTimeout: connectionReadyTimeout,
            connectTimeout: connectTimeout,
            initialMaxStreamsBidi: initialMaxStreamsBidi,
            initialMaxStreamsUni: initialMaxStreamsUni,
            maxSessions: maxSessions
        )
    }

    // MARK: - Factory Methods

    /// Creates options with peer verification disabled.
    ///
    /// Intended **only** for local development and testing against
    /// servers with self-signed or untrusted certificates.
    ///
    /// - Returns: Options with `verifyPeer` set to `false`.
    public static func insecure() -> WebTransportOptions {
        var options = WebTransportOptions()
        options.verifyPeer = false
        return options
    }

    // MARK: - Internal Builders

    /// Generates a `QUICConfiguration` with WebTransport-mandatory transport settings.
    ///
    /// Sets:
    /// - `maxIdleTimeout` from `self`
    /// - `alpn` from `self`
    /// - `enableDatagrams = true` (required for WT datagrams)
    /// - `initialMaxStreamsBidi` / `initialMaxStreamsUni` from `self`
    ///
    /// **Does not set `securityMode`**. The caller (e.g. `WebTransport.connect()`)
    /// is responsible for configuring TLS using `verifyPeer` and `caCertificates`
    /// from this options struct. Certificate source resolution (notably `.pem(path:)`)
    /// is intentionally deferred to the QUIC/TLS layer, where crypto loaders exist.
    ///
    /// - Returns: A partially-configured `QUICConfiguration`.
    internal func buildQUICConfiguration() -> QUICConfiguration {
        var config = QUICConfiguration()

        // Transport parameters
        config.maxIdleTimeout = maxIdleTimeout
        config.alpn = alpn
        config.initialMaxStreamsBidi = initialMaxStreamsBidi
        config.initialMaxStreamsUni = initialMaxStreamsUni

        // WebTransport requires QUIC DATAGRAM support (RFC 9221)
        config.enableDatagrams = true
        config.maxDatagramFrameSize = 65535

        return config
    }

    /// Generates `HTTP3Settings` with WebTransport-mandatory flags enabled.
    ///
    /// Always sets:
    /// - `enableConnectProtocol = true` (RFC 9220)
    /// - `enableH3Datagram = true` (RFC 9297)
    /// - `webtransportMaxSessions` from `self.maxSessions`
    ///
    /// - Returns: HTTP/3 settings ready for WebTransport.
    internal func buildHTTP3Settings() -> HTTP3Settings {
        HTTP3Settings(
            enableConnectProtocol: true,
            enableH3Datagram: true,
            webtransportMaxSessions: maxSessions
        )
    }
}
