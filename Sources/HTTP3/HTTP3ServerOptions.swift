/// HTTP/3 Server Options
///
/// Server-side configuration for HTTP/3. Provides certificate paths,
/// TLS settings, and transport parameters. Builds the underlying
/// `QUICConfiguration` and `HTTP3Settings` internally so the caller
/// does not need to understand the QUIC/HTTP3/TLS layering.
///
/// ## Usage
///
/// ```swift
/// let options = HTTP3ServerOptions(
///     certificatePath: "/path/to/cert.pem",
///     privateKeyPath: "/path/to/key.pem"
/// )
/// let server = HTTP3Server(options: options)
///
/// await server.onRequest { context in
///     try await context.respond(status: 200, Data("Hello, HTTP/3!".utf8))
/// }
///
/// try await server.listen()
/// ```
///
/// ## Advanced TLS
///
/// For full control over TLS configuration, use the advanced
/// `HTTP3Server` initializer with a `QUICConfiguration` directly:
///
/// ```swift
/// let server = HTTP3Server(settings: settings)
/// try await server.listen(host: host, port: port, quicConfiguration: quicConfig)
/// ```
///
/// ## References
///
/// - [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
/// - [RFC 9001: Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001.html)

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import QUIC
import QUICCore
import QUICCrypto

// MARK: - HTTP/3 Server Options

/// Configuration for an HTTP/3 server.
///
/// Encapsulates certificate material, TLS verification policy, transport
/// parameters, and HTTP/3-specific settings. Internal `build` methods
/// produce the `QUICConfiguration`, `TLSConfiguration`, and
/// `HTTP3Settings` consumed by the QUIC endpoint and HTTP/3 server.
///
/// The struct intentionally hides raw `QUICConfiguration` and
/// `TLS13Handler` wiring from the caller. For full control, use the
/// advanced `HTTP3Server.listen(host:port:quicConfiguration:)` API.
public struct HTTP3ServerOptions: Sendable {

    // MARK: - Network Binding

    /// The host address to bind to (e.g. `"0.0.0.0"` or `"127.0.0.1"`).
    ///
    /// - Default: `"0.0.0.0"` (all interfaces)
    public var host: String

    /// The port number to listen on.
    ///
    /// - Default: `4433`
    public var port: UInt16

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

    /// Signing key for CertificateVerify (alternative to file/DER key).
    ///
    /// When set, takes precedence over `privateKeyPath` / `privateKey`
    /// for the TLS CertificateVerify signature.
    public var signingKey: SigningKey?

    // MARK: - TLS Verification

    /// Trusted CA certificates for peer verification (DER encoded).
    ///
    /// When non-nil and `verifyPeer` is `true`, the server will verify
    /// client certificates against these roots (mutual TLS).
    ///
    /// - Default: `nil`
    public var caCertificates: [Data]?

    /// Whether to verify the peer (client) certificate.
    ///
    /// When `true`, the server requires clients to present a valid
    /// certificate (mutual TLS). When `false`, no client certificate
    /// is required.
    ///
    /// - Default: `false`
    public var verifyPeer: Bool

    /// Whether to allow self-signed certificates.
    ///
    /// When `true`, self-signed certificates are accepted during
    /// peer verification. Useful for development environments.
    ///
    /// - Default: `false`
    public var allowSelfSigned: Bool

    /// Whether to load the platform system trust store.
    ///
    /// When `true`, the system trust store roots are added to the
    /// TLS trusted root set automatically.
    ///
    /// - Default: `false`
    public var useSystemTrustStore: Bool

    /// Replay protection configuration for 0-RTT data.
    ///
    /// When set, protects against replay attacks on early data.
    ///
    /// - Default: `nil` (no replay protection)
    public var replayProtection: ReplayProtection?

    // MARK: - ALPN

    /// Application-Layer Protocol Negotiation values.
    ///
    /// Advertised during the TLS handshake. HTTP/3 requires `"h3"`.
    ///
    /// - Default: `["h3"]`
    public var alpn: [String]

    // MARK: - Connection Limits

    /// Maximum number of concurrent HTTP/3 connections accepted.
    ///
    /// 0 means unlimited.
    ///
    /// - Default: `0` (unlimited)
    public var maxConnections: Int

    // MARK: - Transport Parameters

    /// Maximum idle timeout for the QUIC connection.
    ///
    /// - Default: 30 seconds
    public var maxIdleTimeout: Duration

    /// Initial maximum number of bidirectional streams.
    ///
    /// - Default: `100`
    public var initialMaxStreamsBidi: UInt64

    /// Initial maximum number of unidirectional streams.
    ///
    /// - Default: `100`
    public var initialMaxStreamsUni: UInt64

    /// Whether to enable QUIC datagrams (RFC 9221).
    ///
    /// Required for HTTP/3 datagrams (RFC 9297) and WebTransport.
    ///
    /// - Default: `false`
    public var enableDatagrams: Bool

    // MARK: - HTTP/3 Settings

    /// Whether to enable the Extended CONNECT protocol (RFC 9220).
    ///
    /// Required for WebTransport session establishment.
    ///
    /// - Default: `false`
    public var enableConnectProtocol: Bool

    /// Whether to enable HTTP/3 datagrams (RFC 9297).
    ///
    /// - Default: `false`
    public var enableH3Datagram: Bool

    /// Maximum number of concurrent WebTransport sessions.
    ///
    /// When non-nil, advertised via `SETTINGS_WEBTRANSPORT_MAX_SESSIONS`.
    ///
    /// - Default: `nil`
    public var webtransportMaxSessions: UInt64?

    /// Maximum size of the QPACK dynamic table in bytes.
    ///
    /// 0 means literal-only mode (simplest, no dynamic table).
    ///
    /// - Default: `0`
    public var qpackMaxTableCapacity: Int

    /// Maximum number of QPACK blocked streams.
    ///
    /// - Default: `0`
    public var qpackBlockedStreams: Int

    // MARK: - Security Mode

    /// Whether this is a development (self-signed) or production deployment.
    ///
    /// When `true`, uses `.development` security mode which relaxes
    /// certificate validation. When `false`, uses `.production`.
    ///
    /// - Default: `false`
    public var developmentMode: Bool

    // MARK: - Alt-Svc Gateway (HTTP/1.1 + HTTP/2 -> HTTP/3 Upgrade)

    /// Plain HTTP port for the Alt-Svc gateway (301 redirect to HTTPS).
    ///
    /// When non-nil, `listenAll()` starts a TCP listener on this port
    /// that redirects all requests to the HTTPS gateway port.
    ///
    /// - Default: `nil` (gateway disabled)
    public var gatewayHTTPPort: UInt16?

    /// HTTPS port for the Alt-Svc gateway.
    ///
    /// When non-nil, `listenAll()` starts a TLS-terminated TCP listener
    /// on this port that always includes `Alt-Svc: h3` and either
    /// dispatches requests to the shared application handler or serves
    /// an `HTTP/3 Required` page, depending on `gatewayHTTPSBehavior`.
    ///
    /// Requires `certificatePath` and `privateKeyPath` to be set (the
    /// same PEM files are reused for TCP TLS via NIOSSL).
    ///
    /// - Default: `nil` (gateway disabled)
    public var gatewayHTTPSPort: UInt16?

    /// `max-age` value (seconds) for the `Alt-Svc` header.
    ///
    /// Controls how long browsers cache the HTTP/3 alternative service
    /// advertisement before re-checking via TCP.
    ///
    /// - Default: `86400` (24 hours)
    public var altSvcMaxAge: UInt32

    /// Whether the gateway HTTPS listener should emit `Alt-Svc: h3`.
    ///
    /// When `false`, the HTTPS gateway remains enabled but does not
    /// advertise HTTP/3 alternatives to clients.
    ///
    /// - Default: `true`
    public var advertiseAltSvc: Bool

    /// HTTPS behavior for the Alt-Svc gateway.
    ///
    /// Controls whether the HTTPS listener serves application resources
    /// through the shared request handler, or returns the legacy
    /// `HTTP/3 Required` informational page.
    ///
    /// - Default: `.serveApplication`
    public var gatewayHTTPSBehavior: AltSvcGatewayConfiguration.HTTPSBehavior

    // MARK: - Initialization (File Paths)

    /// Creates server options with certificate file paths.
    ///
    /// - Parameters:
    ///   - host: Bind address (default: `"0.0.0.0"`)
    ///   - port: Port number (default: `4433`)
    ///   - certificatePath: Path to PEM certificate file
    ///   - privateKeyPath: Path to PEM private key file
    ///   - verifyPeer: Verify client certs / mTLS (default: `false`)
    ///   - allowSelfSigned: Accept self-signed certs (default: `false`)
    ///   - useSystemTrustStore: Load system CA roots (default: `false`)
    ///   - alpn: ALPN protocols (default: `["h3"]`)
    ///   - maxConnections: Max concurrent connections, 0 = unlimited (default: `0`)
    ///   - maxIdleTimeout: QUIC idle timeout (default: 30s)
    ///   - developmentMode: Use relaxed TLS validation (default: `false`)
    public init(
        host: String = "0.0.0.0",
        port: UInt16 = 4433,
        certificatePath: String,
        privateKeyPath: String,
        verifyPeer: Bool = false,
        allowSelfSigned: Bool = false,
        useSystemTrustStore: Bool = false,
        replayProtection: ReplayProtection? = nil,
        alpn: [String] = ["h3"],
        maxConnections: Int = 0,
        maxIdleTimeout: Duration = .seconds(30),
        initialMaxStreamsBidi: UInt64 = 100,
        initialMaxStreamsUni: UInt64 = 100,
        enableDatagrams: Bool = false,
        enableConnectProtocol: Bool = false,
        enableH3Datagram: Bool = false,
        webtransportMaxSessions: UInt64? = nil,
        qpackMaxTableCapacity: Int = 0,
        qpackBlockedStreams: Int = 0,
        developmentMode: Bool = false,
        gatewayHTTPPort: UInt16? = nil,
        gatewayHTTPSPort: UInt16? = nil,
        altSvcMaxAge: UInt32 = 86400,
        advertiseAltSvc: Bool = true,
        gatewayHTTPSBehavior: AltSvcGatewayConfiguration.HTTPSBehavior = .serveApplication
    ) {
        self.host = host
        self.port = port
        self.certificatePath = certificatePath
        self.certificateChain = nil
        self.privateKeyPath = privateKeyPath
        self.privateKey = nil
        self.signingKey = nil
        self.caCertificates = nil
        self.verifyPeer = verifyPeer
        self.allowSelfSigned = allowSelfSigned
        self.useSystemTrustStore = useSystemTrustStore
        self.replayProtection = replayProtection
        self.alpn = alpn
        self.maxConnections = maxConnections
        self.maxIdleTimeout = maxIdleTimeout
        self.initialMaxStreamsBidi = initialMaxStreamsBidi
        self.initialMaxStreamsUni = initialMaxStreamsUni
        self.enableDatagrams = enableDatagrams
        self.enableConnectProtocol = enableConnectProtocol
        self.enableH3Datagram = enableH3Datagram
        self.webtransportMaxSessions = webtransportMaxSessions
        self.qpackMaxTableCapacity = qpackMaxTableCapacity
        self.qpackBlockedStreams = qpackBlockedStreams
        self.developmentMode = developmentMode
        self.gatewayHTTPPort = gatewayHTTPPort
        self.gatewayHTTPSPort = gatewayHTTPSPort
        self.altSvcMaxAge = altSvcMaxAge
        self.advertiseAltSvc = advertiseAltSvc
        self.gatewayHTTPSBehavior = gatewayHTTPSBehavior
    }

    // MARK: - Initialization (In-Memory)

    /// Creates server options with in-memory certificate material.
    ///
    /// - Parameters:
    ///   - host: Bind address (default: `"0.0.0.0"`)
    ///   - port: Port number (default: `4433`)
    ///   - certificateChain: DER-encoded certificate chain
    ///   - privateKey: DER-encoded private key
    ///   - verifyPeer: Verify client certs / mTLS (default: `false`)
    ///   - allowSelfSigned: Accept self-signed certs (default: `false`)
    ///   - useSystemTrustStore: Load system CA roots (default: `false`)
    ///   - alpn: ALPN protocols (default: `["h3"]`)
    ///   - maxConnections: Max concurrent connections, 0 = unlimited (default: `0`)
    ///   - maxIdleTimeout: QUIC idle timeout (default: 30s)
    ///   - developmentMode: Use relaxed TLS validation (default: `false`)
    public init(
        host: String = "0.0.0.0",
        port: UInt16 = 4433,
        certificateChain: [Data],
        privateKey: Data,
        verifyPeer: Bool = false,
        allowSelfSigned: Bool = false,
        useSystemTrustStore: Bool = false,
        replayProtection: ReplayProtection? = nil,
        alpn: [String] = ["h3"],
        maxConnections: Int = 0,
        maxIdleTimeout: Duration = .seconds(30),
        initialMaxStreamsBidi: UInt64 = 100,
        initialMaxStreamsUni: UInt64 = 100,
        enableDatagrams: Bool = false,
        enableConnectProtocol: Bool = false,
        enableH3Datagram: Bool = false,
        webtransportMaxSessions: UInt64? = nil,
        qpackMaxTableCapacity: Int = 0,
        qpackBlockedStreams: Int = 0,
        developmentMode: Bool = false,
        gatewayHTTPPort: UInt16? = nil,
        gatewayHTTPSPort: UInt16? = nil,
        altSvcMaxAge: UInt32 = 86400,
        advertiseAltSvc: Bool = true,
        gatewayHTTPSBehavior: AltSvcGatewayConfiguration.HTTPSBehavior = .serveApplication
    ) {
        self.host = host
        self.port = port
        self.certificatePath = nil
        self.certificateChain = certificateChain
        self.privateKeyPath = nil
        self.privateKey = privateKey
        self.signingKey = nil
        self.caCertificates = nil
        self.verifyPeer = verifyPeer
        self.allowSelfSigned = allowSelfSigned
        self.useSystemTrustStore = useSystemTrustStore
        self.replayProtection = replayProtection
        self.alpn = alpn
        self.maxConnections = maxConnections
        self.maxIdleTimeout = maxIdleTimeout
        self.initialMaxStreamsBidi = initialMaxStreamsBidi
        self.initialMaxStreamsUni = initialMaxStreamsUni
        self.enableDatagrams = enableDatagrams
        self.enableConnectProtocol = enableConnectProtocol
        self.enableH3Datagram = enableH3Datagram
        self.webtransportMaxSessions = webtransportMaxSessions
        self.qpackMaxTableCapacity = qpackMaxTableCapacity
        self.qpackBlockedStreams = qpackBlockedStreams
        self.developmentMode = developmentMode
        self.gatewayHTTPPort = gatewayHTTPPort
        self.gatewayHTTPSPort = gatewayHTTPSPort
        self.altSvcMaxAge = altSvcMaxAge
        self.advertiseAltSvc = advertiseAltSvc
        self.gatewayHTTPSBehavior = gatewayHTTPSBehavior
    }

    // MARK: - Initialization (Signing Key)

    /// Creates server options with an inline signing key and certificate chain.
    ///
    /// - Parameters:
    ///   - host: Bind address (default: `"0.0.0.0"`)
    ///   - port: Port number (default: `4433`)
    ///   - signingKey: The signing key for TLS CertificateVerify
    ///   - certificateChain: DER-encoded certificate chain
    ///   - alpn: ALPN protocols (default: `["h3"]`)
    ///   - developmentMode: Use relaxed TLS validation (default: `false`)
    public init(
        host: String = "0.0.0.0",
        port: UInt16 = 4433,
        signingKey: SigningKey,
        certificateChain: [Data],
        verifyPeer: Bool = false,
        allowSelfSigned: Bool = false,
        useSystemTrustStore: Bool = false,
        replayProtection: ReplayProtection? = nil,
        alpn: [String] = ["h3"],
        maxConnections: Int = 0,
        maxIdleTimeout: Duration = .seconds(30),
        initialMaxStreamsBidi: UInt64 = 100,
        initialMaxStreamsUni: UInt64 = 100,
        enableDatagrams: Bool = false,
        enableConnectProtocol: Bool = false,
        enableH3Datagram: Bool = false,
        webtransportMaxSessions: UInt64? = nil,
        qpackMaxTableCapacity: Int = 0,
        qpackBlockedStreams: Int = 0,
        developmentMode: Bool = false,
        gatewayHTTPPort: UInt16? = nil,
        gatewayHTTPSPort: UInt16? = nil,
        altSvcMaxAge: UInt32 = 86400,
        advertiseAltSvc: Bool = true,
        gatewayHTTPSBehavior: AltSvcGatewayConfiguration.HTTPSBehavior = .serveApplication
    ) {
        self.host = host
        self.port = port
        self.certificatePath = nil
        self.certificateChain = certificateChain
        self.privateKeyPath = nil
        self.privateKey = nil
        self.signingKey = signingKey
        self.caCertificates = nil
        self.verifyPeer = verifyPeer
        self.allowSelfSigned = allowSelfSigned
        self.useSystemTrustStore = useSystemTrustStore
        self.replayProtection = replayProtection
        self.alpn = alpn
        self.maxConnections = maxConnections
        self.maxIdleTimeout = maxIdleTimeout
        self.initialMaxStreamsBidi = initialMaxStreamsBidi
        self.initialMaxStreamsUni = initialMaxStreamsUni
        self.enableDatagrams = enableDatagrams
        self.enableConnectProtocol = enableConnectProtocol
        self.enableH3Datagram = enableH3Datagram
        self.webtransportMaxSessions = webtransportMaxSessions
        self.qpackMaxTableCapacity = qpackMaxTableCapacity
        self.qpackBlockedStreams = qpackBlockedStreams
        self.developmentMode = developmentMode
        self.gatewayHTTPPort = gatewayHTTPPort
        self.gatewayHTTPSPort = gatewayHTTPSPort
        self.altSvcMaxAge = altSvcMaxAge
        self.advertiseAltSvc = advertiseAltSvc
        self.gatewayHTTPSBehavior = gatewayHTTPSBehavior
    }

    // MARK: - Build Methods

    /// Builds a `TLSConfiguration` from the options.
    ///
    /// Populates certificate material, verification flags, ALPN,
    /// replay protection, and optionally loads system trust roots.
    ///
    /// - Returns: A configured `TLSConfiguration`
    /// - Throws: If PEM loading fails or system trust store loading fails
    public func buildTLSConfiguration() throws -> TLSConfiguration {
        var tlsConfig: TLSConfiguration

        if let certPath = certificatePath, let keyPath = privateKeyPath {
            // File-path based setup: loads PEM and populates chain + signingKey
            tlsConfig = try TLSConfiguration.server(
                certificatePath: certPath,
                privateKeyPath: keyPath,
                alpnProtocols: alpn
            )
        } else if let chain = certificateChain, let sKey = signingKey {
            // In-memory signing key + chain
            tlsConfig = TLSConfiguration.server(
                signingKey: sKey,
                certificateChain: chain,
                alpnProtocols: alpn
            )
        } else {
            // In-memory DER key + chain: populate fields manually
            var config = TLSConfiguration()
            config.alpnProtocols = alpn
            config.certificateChain = certificateChain
            config.privateKey = privateKey
            tlsConfig = config
        }

        // Verification
        tlsConfig.verifyPeer = verifyPeer
        tlsConfig.allowSelfSigned = allowSelfSigned

        // CA certificates
        if let caCerts = caCertificates {
            tlsConfig.trustedCACertificates = caCerts
        }

        // System trust store
        if useSystemTrustStore {
            try tlsConfig.addSystemTrustStore()
        }

        // Replay protection
        if let replay = replayProtection {
            tlsConfig.replayProtection = replay
        }

        return tlsConfig
    }

    /// Builds a `QUICConfiguration` from the options.
    ///
    /// Sets transport parameters, ALPN, datagram support, and
    /// security mode with the provided `TLSConfiguration`.
    ///
    /// - Parameter tlsConfiguration: The TLS configuration (from `buildTLSConfiguration()`)
    /// - Returns: A `QUICConfiguration` ready for the QUIC endpoint
    public func buildQUICConfiguration(
        tlsConfiguration: TLSConfiguration
    ) -> QUICConfiguration {
        let tlsConfig = tlsConfiguration

        var config = QUICConfiguration()

        // Transport parameters
        config.maxIdleTimeout = maxIdleTimeout
        config.initialMaxStreamsBidi = initialMaxStreamsBidi
        config.initialMaxStreamsUni = initialMaxStreamsUni
        config.enableDatagrams = enableDatagrams
        config.alpn = alpn

        // Security mode: wire up TLS13Handler
        if developmentMode {
            config.securityMode = .development {
                TLS13Handler(configuration: tlsConfig)
            }
        } else {
            config.securityMode = .production {
                TLS13Handler(configuration: tlsConfig)
            }
        }

        return config
    }

    /// Builds `HTTP3Settings` from the options.
    ///
    /// - Returns: An `HTTP3Settings` with the configured values
    public func buildHTTP3Settings() -> HTTP3Settings {
        var settings = HTTP3Settings()
        settings.maxTableCapacity = UInt64(qpackMaxTableCapacity)
        settings.qpackBlockedStreams = UInt64(qpackBlockedStreams)
        settings.enableConnectProtocol = enableConnectProtocol
        settings.enableH3Datagram = enableH3Datagram
        settings.webtransportMaxSessions = webtransportMaxSessions
        return settings
    }

    /// Builds an `AltSvcGatewayConfiguration` from the options, if the
    /// gateway is enabled (at least one of `gatewayHTTPPort` or
    /// `gatewayHTTPSPort` is non-nil).
    ///
    /// - Returns: Configuration for the gateway, or `nil` when disabled.
    public func buildGatewayConfiguration() -> AltSvcGatewayConfiguration? {
        guard gatewayHTTPPort != nil || gatewayHTTPSPort != nil else {
            return nil
        }
        return AltSvcGatewayConfiguration(
            host: host,
            httpPort: gatewayHTTPPort,
            httpsPort: gatewayHTTPSPort,
            h3Port: port,
            altSvcMaxAge: altSvcMaxAge,
            advertiseAltSvc: advertiseAltSvc,
            httpsBehavior: gatewayHTTPSBehavior,
            certificatePath: certificatePath,
            privateKeyPath: privateKeyPath
        )
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

        /// The port number is 0.
        case invalidPort

        /// Gateway HTTPS port enabled but no PEM certificate path set.
        case gatewayMissingCertificatePath

        /// Gateway HTTPS port enabled but no PEM private key path set.
        case gatewayMissingPrivateKeyPath

        public var description: String {
            switch self {
            case .noCertificate:
                return "No certificate provided (set certificatePath or certificateChain)"
            case .noPrivateKey:
                return "No private key provided (set privateKeyPath, privateKey, or signingKey)"
            case .ambiguousCertificate:
                return "Both certificatePath and certificateChain are set — use one or the other"
            case .ambiguousPrivateKey:
                return "Both privateKeyPath and privateKey are set — use one or the other"
            case .invalidPort:
                return "Port must be non-zero"
            case .gatewayMissingCertificatePath:
                return "gatewayHTTPSPort is set but certificatePath is nil — NIOSSL requires PEM file paths"
            case .gatewayMissingPrivateKeyPath:
                return "gatewayHTTPSPort is set but privateKeyPath is nil — NIOSSL requires PEM file paths"
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

        // Private key (signingKey is an alternative)
        if privateKeyPath == nil && privateKey == nil && signingKey == nil {
            throw ValidationError.noPrivateKey
        }
        if privateKeyPath != nil && privateKey != nil {
            throw ValidationError.ambiguousPrivateKey
        }

        // Port
        if port == 0 {
            throw ValidationError.invalidPort
        }

        // Gateway: HTTPS listener requires PEM file paths (NIOSSL)
        if gatewayHTTPSPort != nil {
            if certificatePath == nil {
                throw ValidationError.gatewayMissingCertificatePath
            }
            if privateKeyPath == nil {
                throw ValidationError.gatewayMissingPrivateKeyPath
            }
        }
    }
}
