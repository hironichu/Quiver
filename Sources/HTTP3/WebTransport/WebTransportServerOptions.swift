/// WebTransport Server Options
///
/// Server-side configuration for WebTransport. Provides certificate paths,
/// TLS settings, and transport parameters. Builds the underlying
/// `QUICConfiguration` and `HTTP3Settings` internally so the caller
/// does not need to understand the QUIC/HTTP3 layering.
///
/// ## Usage
///
/// ```swift
/// let options = WebTransportServerOptions(
///     certificatePath: "/path/to/cert.pem",
///     privateKeyPath: "/path/to/key.pem"
/// )
/// let server = WebTransportServer(
///     host: "0.0.0.0", port: 4433, options: options
/// )
/// ```
///
/// ## References
///
/// - [draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)
/// - [RFC 9220: Bootstrapping WebSockets with HTTP/3](https://www.rfc-editor.org/rfc/rfc9220.html)

import FoundationEssentials
import QUIC
import QUICCore

// MARK: - WebTransport Server Options

/// Configuration for a WebTransport server.
///
/// Encapsulates certificate material, TLS verification policy, transport
/// parameters, and WebTransport-specific knobs. Two internal `build`
/// methods produce the `QUICConfiguration` and `HTTP3Settings` consumed
/// by the QUIC endpoint and HTTP/3 server respectively.
///
/// The struct intentionally does **not** expose raw `QUICConfiguration`
/// or `HTTP3Settings` — use `WebTransportOptionsAdvanced` (or the
/// underlying `HTTP3Server` directly) for full control.
public struct WebTransportServerOptions: Sendable {

    // MARK: - Certificate Material

    /// Path to the TLS certificate file (PEM format).
    ///
    /// Mutually exclusive with `certificateChain`. At least one of
    /// `certificatePath` or `certificateChain` must be provided.
    public var certificatePath: String?

    /// DER-encoded certificate chain.
    ///
    /// Mutually exclusive with `certificatePath`. At least one of
    /// `certificatePath` or `certificateChain` must be provided.
    public var certificateChain: [Data]?

    /// Path to the TLS private key file (PEM format).
    ///
    /// Mutually exclusive with `privateKey`. At least one of
    /// `privateKeyPath` or `privateKey` must be provided.
    public var privateKeyPath: String?

    /// DER-encoded private key.
    ///
    /// Mutually exclusive with `privateKeyPath`. At least one of
    /// `privateKeyPath` or `privateKey` must be provided.
    public var privateKey: Data?

    // MARK: - TLS Verification

    /// Trusted CA certificates for client verification (DER encoded).
    ///
    /// When non-nil and `verifyPeer` is `true`, the server will verify
    /// client certificates against these roots (mutual TLS).
    ///
    /// When `nil`, client certificate verification uses the system
    /// trust store (if `verifyPeer` is `true`).
    ///
    /// - Default: `nil` (system trust store / no client auth)
    public var caCertificates: [Data]?

    /// Whether to verify the peer (client) certificate.
    ///
    /// When `true`, the server requires clients to present a valid
    /// certificate (mutual TLS). When `false`, no client certificate
    /// is required.
    ///
    /// - Default: `false` (servers typically do not verify clients)
    public var verifyPeer: Bool

    // MARK: - ALPN

    /// Application-Layer Protocol Negotiation values.
    ///
    /// Advertised during the TLS handshake. The WebTransport spec
    /// requires `"h3"` and some implementations also advertise
    /// `"webtransport"`.
    ///
    /// - Default: `["h3", "webtransport"]`
    public var alpn: [String]

    // MARK: - WebTransport / Session Limits

    /// Maximum number of concurrent WebTransport sessions per connection.
    ///
    /// Advertised via `SETTINGS_WEBTRANSPORT_MAX_SESSIONS`.
    /// Browsers require this to be > 0 to establish WebTransport sessions.
    ///
    /// - Default: 1
    public var maxSessions: UInt64

    /// Maximum number of concurrent HTTP/3 connections accepted.
    ///
    /// 0 means unlimited.
    ///
    /// - Default: 0 (unlimited)
    public var maxConnections: Int

    // MARK: - Transport Parameters

    /// Maximum idle timeout for the QUIC connection.
    ///
    /// - Default: 30 seconds
    public var maxIdleTimeout: Duration

    /// Initial maximum number of bidirectional streams.
    ///
    /// - Default: 100
    public var initialMaxStreamsBidi: UInt64

    /// Initial maximum number of unidirectional streams.
    ///
    /// - Default: 100
    public var initialMaxStreamsUni: UInt64

    // MARK: - Initialization

    /// Creates server options with certificate file paths.
    ///
    /// - Parameters:
    ///   - certificatePath: Path to the PEM certificate file
    ///   - privateKeyPath: Path to the PEM private key file
    ///   - caCertificates: Trusted CA certs for client verification (default: nil)
    ///   - verifyPeer: Whether to verify client certs (default: false)
    ///   - alpn: ALPN values (default: ["h3", "webtransport"])
    ///   - maxSessions: Max concurrent WT sessions per connection (default: 1)
    ///   - maxConnections: Max concurrent connections, 0 = unlimited (default: 0)
    ///   - maxIdleTimeout: QUIC idle timeout (default: 30s)
    ///   - initialMaxStreamsBidi: Initial max bidi streams (default: 100)
    ///   - initialMaxStreamsUni: Initial max uni streams (default: 100)
    public init(
        certificatePath: String,
        privateKeyPath: String,
        caCertificates: [Data]? = nil,
        verifyPeer: Bool = false,
        alpn: [String] = ["h3", "webtransport"],
        maxSessions: UInt64 = 1,
        maxConnections: Int = 0,
        maxIdleTimeout: Duration = .seconds(30),
        initialMaxStreamsBidi: UInt64 = 100,
        initialMaxStreamsUni: UInt64 = 100
    ) {
        self.certificatePath = certificatePath
        self.certificateChain = nil
        self.privateKeyPath = privateKeyPath
        self.privateKey = nil
        self.caCertificates = caCertificates
        self.verifyPeer = verifyPeer
        self.alpn = alpn
        self.maxSessions = maxSessions
        self.maxConnections = maxConnections
        self.maxIdleTimeout = maxIdleTimeout
        self.initialMaxStreamsBidi = initialMaxStreamsBidi
        self.initialMaxStreamsUni = initialMaxStreamsUni
    }

    /// Creates server options with in-memory certificate material.
    ///
    /// - Parameters:
    ///   - certificateChain: DER-encoded certificate chain
    ///   - privateKey: DER-encoded private key
    ///   - caCertificates: Trusted CA certs for client verification (default: nil)
    ///   - verifyPeer: Whether to verify client certs (default: false)
    ///   - alpn: ALPN values (default: ["h3", "webtransport"])
    ///   - maxSessions: Max concurrent WT sessions per connection (default: 1)
    ///   - maxConnections: Max concurrent connections, 0 = unlimited (default: 0)
    ///   - maxIdleTimeout: QUIC idle timeout (default: 30s)
    ///   - initialMaxStreamsBidi: Initial max bidi streams (default: 100)
    ///   - initialMaxStreamsUni: Initial max uni streams (default: 100)
    public init(
        certificateChain: [Data],
        privateKey: Data,
        caCertificates: [Data]? = nil,
        verifyPeer: Bool = false,
        alpn: [String] = ["h3", "webtransport"],
        maxSessions: UInt64 = 1,
        maxConnections: Int = 0,
        maxIdleTimeout: Duration = .seconds(30),
        initialMaxStreamsBidi: UInt64 = 100,
        initialMaxStreamsUni: UInt64 = 100
    ) {
        self.certificatePath = nil
        self.certificateChain = certificateChain
        self.privateKeyPath = nil
        self.privateKey = privateKey
        self.caCertificates = caCertificates
        self.verifyPeer = verifyPeer
        self.alpn = alpn
        self.maxSessions = maxSessions
        self.maxConnections = maxConnections
        self.maxIdleTimeout = maxIdleTimeout
        self.initialMaxStreamsBidi = initialMaxStreamsBidi
        self.initialMaxStreamsUni = initialMaxStreamsUni
    }

    // MARK: - Build Methods

    /// Builds a `QUICConfiguration` with WebTransport-mandatory transport settings.
    ///
    /// Sets:
    /// - `enableDatagrams = true` (required for WT datagrams)
    /// - `alpn` from the options
    /// - `maxIdleTimeout`, `initialMaxStreamsBidi`, `initialMaxStreamsUni`
    ///
    /// **Note:** `securityMode` is NOT set here because the HTTP3 module
    /// does not have direct access to `QUICCrypto` types (`TLSConfiguration`,
    /// `TLS13Handler`). The caller (e.g. `WebTransportServer.listen()`) must
    /// configure `securityMode` on the returned config using the certificate
    /// and key material from this options struct.
    ///
    /// - Returns: A `QUICConfiguration` ready for transport-level use
    internal func buildQUICConfiguration() -> QUICConfiguration {
        var config = QUICConfiguration()

        // Transport parameters
        config.maxIdleTimeout = maxIdleTimeout
        config.initialMaxStreamsBidi = initialMaxStreamsBidi
        config.initialMaxStreamsUni = initialMaxStreamsUni

        // WebTransport requires QUIC datagrams (RFC 9221)
        config.enableDatagrams = true

        // ALPN
        config.alpn = alpn

        return config
    }

    /// Builds `HTTP3Settings` with WebTransport-mandatory flags enabled.
    ///
    /// Enables:
    /// - `enableConnectProtocol = true` (RFC 9220, Extended CONNECT)
    /// - `enableH3Datagram = true` (RFC 9297)
    /// - `webtransportMaxSessions` from the options
    ///
    /// - Returns: An `HTTP3Settings` ready for the HTTP/3 server
    internal func buildHTTP3Settings() -> HTTP3Settings {
        var settings = HTTP3Settings()
        settings.enableConnectProtocol = true
        settings.enableH3Datagram = true
        settings.webtransportMaxSessions = maxSessions
        return settings
    }

    // MARK: - Validation

    /// Validation errors for server options.
    public enum ValidationError: Error, Sendable, CustomStringConvertible {
        /// No certificate material provided.
        case noCertificate

        /// No private key material provided.
        case noPrivateKey

        /// Both file-path and in-memory certificate material provided.
        case ambiguousCertificate

        /// Both file-path and in-memory private key material provided.
        case ambiguousPrivateKey

        /// maxSessions must be > 0 for WebTransport to function.
        case maxSessionsZero

        public var description: String {
            switch self {
            case .noCertificate:
                return "No certificate provided (set certificatePath or certificateChain)"
            case .noPrivateKey:
                return "No private key provided (set privateKeyPath or privateKey)"
            case .ambiguousCertificate:
                return "Both certificatePath and certificateChain are set — use one or the other"
            case .ambiguousPrivateKey:
                return "Both privateKeyPath and privateKey are set — use one or the other"
            case .maxSessionsZero:
                return "maxSessions must be > 0 for WebTransport (browsers require non-zero)"
            }
        }
    }

    /// Validates the options for internal consistency.
    ///
    /// - Throws: `ValidationError` on the first violated constraint.
    public func validate() throws {
        // Certificate
        if certificatePath == nil && certificateChain == nil {
            throw ValidationError.noCertificate
        }
        if certificatePath != nil && certificateChain != nil {
            throw ValidationError.ambiguousCertificate
        }

        // Private key
        if privateKeyPath == nil && privateKey == nil {
            throw ValidationError.noPrivateKey
        }
        if privateKeyPath != nil && privateKey != nil {
            throw ValidationError.ambiguousPrivateKey
        }

        // Sessions
        if maxSessions == 0 {
            throw ValidationError.maxSessionsZero
        }
    }
}
