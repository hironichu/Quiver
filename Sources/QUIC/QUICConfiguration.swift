/// QUIC Configuration
///
/// Configuration options for QUIC connections.

import Foundation
import QUICCore
import QUICCrypto
import QUICRecovery

// MARK: - Security Mode

/// QUIC security mode for TLS provider configuration
///
/// This enum enforces explicit security configuration, preventing
/// accidental use of insecure defaults in production environments.
///
/// ## Usage
///
/// ```swift
/// // Production: TLS required
/// let config = QUICConfiguration.production {
///     MyTLSProvider()
/// }
///
/// // Development: TLS with self-signed certificates
/// let devConfig = QUICConfiguration.development {
///     MyTLSProvider(allowSelfSigned: true)
/// }
///
/// // Testing only: Mock TLS (explicit opt-in)
/// let testConfig = QUICConfiguration.testing()
/// ```
public enum QUICSecurityMode: Sendable {
    /// Production environment: TLS required with proper certificate validation
    case production(tlsProviderFactory: @Sendable () -> any TLS13Provider)

    /// Development environment: TLS required but self-signed certificates allowed
    case development(tlsProviderFactory: @Sendable () -> any TLS13Provider)

    /// Testing environment: Uses MockTLSProvider
    /// - Warning: Never use in production. This mode disables encryption.
    case testing
}

// MARK: - Security Errors

/// QUIC security-related errors
public enum QUICSecurityError: Error, Sendable {
    /// TLS provider is not configured. Set `securityMode` before connecting.
    case tlsProviderNotConfigured

    /// Certificate validation failed
    case certificateValidationFailed(reason: String)

    /// Security mode is not appropriate for the operation
    case inappropriateSecurityMode(String)
}

// MARK: - TLS Provider Factory

/// Factory for creating TLS 1.3 providers.
///
/// This allows custom TLS implementations (with custom X.509 certificate
/// extensions or validation logic) to be injected into QUIC connections.
///
/// ## Example
///
/// ```swift
/// var config = QUICConfiguration()
/// config.tlsProviderFactory = { isClient in
///     MyCustomTLSProvider(isClient: isClient)
/// }
/// ```
public typealias TLSProviderFactory = @Sendable (_ isClient: Bool) -> any TLS13Provider

// MARK: - QUIC Configuration

/// Configuration for a QUIC endpoint
public struct QUICConfiguration: Sendable {
    // MARK: - Connection Settings

    /// Maximum idle timeout (default: 30 seconds)
    public var maxIdleTimeout: Duration

    /// Maximum UDP payload size (default: 1200)
    public var maxUDPPayloadSize: Int

    // MARK: - Flow Control

    /// Initial maximum data the peer can send on the connection (default: 10 MB)
    public var initialMaxData: UInt64

    /// Initial max data for locally-initiated bidirectional streams (default: 1 MB)
    public var initialMaxStreamDataBidiLocal: UInt64

    /// Initial max data for remotely-initiated bidirectional streams (default: 1 MB)
    public var initialMaxStreamDataBidiRemote: UInt64

    /// Initial max data for unidirectional streams (default: 1 MB)
    public var initialMaxStreamDataUni: UInt64

    /// Initial max bidirectional streams (default: 100)
    public var initialMaxStreamsBidi: UInt64

    /// Initial max unidirectional streams (default: 100)
    public var initialMaxStreamsUni: UInt64

    // MARK: - Datagram Support (RFC 9221)

    /// Whether to enable QUIC DATAGRAM frame support (RFC 9221).
    ///
    /// When `true`, the `max_datagram_frame_size` transport parameter is
    /// advertised during the handshake, indicating willingness to receive
    /// DATAGRAM frames. Required for WebTransport datagram support.
    ///
    /// - Default: `false`
    public var enableDatagrams: Bool

    /// Maximum DATAGRAM frame payload size this endpoint will accept.
    ///
    /// Only meaningful when `enableDatagrams` is `true`. The value is
    /// advertised as the `max_datagram_frame_size` transport parameter
    /// (RFC 9221 §3). A value of 65535 is the typical maximum.
    ///
    /// - Default: `65535`
    public var maxDatagramFrameSize: UInt64

    // MARK: - ACK Delay

    /// Maximum ack delay in milliseconds (default: 25ms)
    public var maxAckDelay: Duration

    /// ACK delay exponent (default: 3)
    public var ackDelayExponent: UInt64

    // MARK: - Connection ID

    /// Preferred connection ID length (default: 8)
    public var connectionIDLength: Int

    // MARK: - Version

    /// QUIC version to use
    public var version: QUICVersion

    // MARK: - ALPN

    /// Application Layer Protocol Negotiation protocols.
    ///
    /// Used for QUIC transport parameter negotiation. For TLS-level ALPN
    /// configuration, use `TLSConfiguration.alpnProtocols` instead.
    public var alpn: [String]

    // MARK: - TLS (Legacy — prefer TLSConfiguration)

    /// Path to certificate file (for servers).
    ///
    /// - Warning: **Legacy field.** This field is **not consumed** by
    ///   `TLS13Handler` and exists only for backward compatibility.
    ///   Use `TLSConfiguration.certificatePath` or
    ///   `TLSConfiguration.server(certificatePath:privateKeyPath:)` instead.
    ///   This field will be removed in a future release.
    @available(*, deprecated, message: "Use TLSConfiguration.certificatePath or TLSConfiguration.server(certificatePath:privateKeyPath:) instead")
    public var certificatePath: String?

    /// Path to private key file (for servers).
    ///
    /// - Warning: **Legacy field.** This field is **not consumed** by
    ///   `TLS13Handler` and exists only for backward compatibility.
    ///   Use `TLSConfiguration.privateKeyPath` or
    ///   `TLSConfiguration.server(certificatePath:privateKeyPath:)` instead.
    ///   This field will be removed in a future release.
    @available(*, deprecated, message: "Use TLSConfiguration.privateKeyPath or TLSConfiguration.server(certificatePath:privateKeyPath:) instead")
    public var privateKeyPath: String?

    /// Whether to verify peer certificates (default: true).
    ///
    /// - Warning: **Legacy field.** This field is **not consumed** by
    ///   `TLS13Handler` and exists only for backward compatibility.
    ///   Use `TLSConfiguration.verifyPeer` instead.
    ///   This field will be removed in a future release.
    @available(*, deprecated, message: "Use TLSConfiguration.verifyPeer instead")
    public var verifyPeer: Bool

    /// Custom TLS provider factory (legacy).
    ///
    /// When set, this factory is used to create TLS providers for new connections
    /// instead of the default MockTLSProvider. This enables custom TLS
    /// implementations with application-specific certificate authentication.
    ///
    /// - Note: Prefer using `securityMode` for new code. This property is
    ///   maintained for backward compatibility.
    ///
    /// - Parameter isClient: `true` for client connections, `false` for server connections
    /// - Returns: A TLS 1.3 provider instance
    public var tlsProviderFactory: TLSProviderFactory?

    // MARK: - Security Mode

    /// Security mode for TLS configuration.
    ///
    /// This property enforces explicit security configuration to prevent
    /// accidental deployment with insecure defaults.
    ///
    /// - Important: If neither `securityMode` nor `tlsProviderFactory` is set,
    ///   connection attempts will fail with `QUICSecurityError.tlsProviderNotConfigured`.
    ///
    /// ## Example
    ///
    /// ```swift
    /// var config = QUICConfiguration()
    /// config.securityMode = .production { MyTLSProvider() }
    /// ```
    public var securityMode: QUICSecurityMode?

    // MARK: - Congestion Control

    /// Factory for creating congestion control algorithm instances.
    ///
    /// Defaults to `NewRenoFactory()` (RFC 9002 NewReno). Set this to inject
    /// a custom congestion control algorithm (e.g., CUBIC, BBR) for all
    /// connections created with this configuration.
    ///
    /// - Note: This property is `package` access because the `CongestionControllerFactory`
    ///   protocol and its dependency types (`CongestionController`, `RTTEstimator`,
    ///   `SentPacket`) are package-internal. When these types are promoted to `public`,
    ///   this property should be promoted as well.
    package var congestionControllerFactory: any CongestionControllerFactory

    // MARK: - Initialization

    /// Creates a default configuration.
    ///
    /// - Note: The legacy TLS fields (`certificatePath`, `privateKeyPath`,
    ///   `verifyPeer`) are initialized for backward compatibility but are **not**
    ///   consumed by the TLS stack. Use `TLSConfiguration` for all TLS settings,
    ///   and prefer `QUICConfiguration.production()` or `.development()` factory
    ///   methods for new code.
    public init() {
        self.maxIdleTimeout = .seconds(30)
        self.maxUDPPayloadSize = 1200
        self.initialMaxData = 10_000_000
        self.initialMaxStreamDataBidiLocal = 1_000_000
        self.initialMaxStreamDataBidiRemote = 1_000_000
        self.initialMaxStreamDataUni = 1_000_000
        self.initialMaxStreamsBidi = 100
        self.initialMaxStreamsUni = 100
        self.maxAckDelay = .milliseconds(25)
        self.ackDelayExponent = 3
        self.connectionIDLength = 8
        self.version = .v1
        self.alpn = ["h3"]
        self.enableDatagrams = false
        self.maxDatagramFrameSize = 65535
        self.certificatePath = nil
        self.privateKeyPath = nil
        self.verifyPeer = true
        self.tlsProviderFactory = nil
        self.securityMode = nil
        self.congestionControllerFactory = NewRenoFactory()
    }

    // MARK: - Security Mode Factory Methods

    /// Creates a production configuration with required TLS.
    ///
    /// Use this for production deployments where security is critical.
    /// The TLS provider factory must produce a properly configured
    /// TLS provider with valid certificates.
    ///
    /// - Parameter tlsProviderFactory: Factory that creates TLS providers
    /// - Returns: A configuration with production security mode
    ///
    /// ## Example
    ///
    /// ```swift
    /// let config = QUICConfiguration.production {
    ///     TLS13Provider(certificatePath: "/path/to/cert.pem")
    /// }
    /// ```
    public static func production(
        tlsProviderFactory: @escaping @Sendable () -> any TLS13Provider
    ) -> QUICConfiguration {
        var config = QUICConfiguration()
        config.securityMode = .production(tlsProviderFactory: tlsProviderFactory)
        return config
    }

    /// Creates a development configuration with TLS but relaxed validation.
    ///
    /// Use this for development and testing environments where
    /// self-signed certificates are acceptable.
    ///
    /// - Parameter tlsProviderFactory: Factory that creates TLS providers
    /// - Returns: A configuration with development security mode
    ///
    /// ## Example
    ///
    /// ```swift
    /// let config = QUICConfiguration.development {
    ///     TLS13Provider(allowSelfSigned: true)
    /// }
    /// ```
    public static func development(
        tlsProviderFactory: @escaping @Sendable () -> any TLS13Provider
    ) -> QUICConfiguration {
        var config = QUICConfiguration()
        config.securityMode = .development(tlsProviderFactory: tlsProviderFactory)
        return config
    }

    #if DEBUG
    /// Creates a testing configuration with MockTLSProvider.
    ///
    /// - Warning: **Never use in production.** This mode disables TLS encryption
    ///   and uses a mock provider that does not provide any security.
    ///
    /// - Returns: A configuration with testing security mode
    ///
    /// ## Example
    ///
    /// ```swift
    /// // Only in unit tests
    /// let config = QUICConfiguration.testing()
    /// ```
    ///
    /// - Note: This method is only available in DEBUG builds.
    @available(*, message: "Testing mode disables TLS encryption. Never use in production.")
    public static func testing() -> QUICConfiguration {
        var config = QUICConfiguration()
        config.securityMode = .testing
        return config
    }
    #endif
}

// MARK: - Transport Parameters Extension

extension TransportParameters {
    /// Creates transport parameters from a configuration (client-side)
    public init(from config: QUICConfiguration, sourceConnectionID: ConnectionID) {
        self.init()
        self.maxIdleTimeout = UInt64(config.maxIdleTimeout.components.seconds * 1000)
        self.maxUDPPayloadSize = UInt64(config.maxUDPPayloadSize)
        self.initialMaxData = config.initialMaxData
        self.initialMaxStreamDataBidiLocal = config.initialMaxStreamDataBidiLocal
        self.initialMaxStreamDataBidiRemote = config.initialMaxStreamDataBidiRemote
        self.initialMaxStreamDataUni = config.initialMaxStreamDataUni
        self.initialMaxStreamsBidi = config.initialMaxStreamsBidi
        self.initialMaxStreamsUni = config.initialMaxStreamsUni
        self.ackDelayExponent = config.ackDelayExponent
        self.maxAckDelay = UInt64(config.maxAckDelay.components.seconds * 1000 +
                                   config.maxAckDelay.components.attoseconds / 1_000_000_000_000_000)
        self.initialSourceConnectionID = sourceConnectionID

        // RFC 9221: Advertise max_datagram_frame_size when datagrams are enabled
        if config.enableDatagrams {
            self.maxDatagramFrameSize = config.maxDatagramFrameSize
        }
    }

    /// Creates transport parameters from a configuration (server-side)
    ///
    /// RFC 9000 Section 18.2: A server MUST include original_destination_connection_id
    /// transport parameter in its transport parameters.
    ///
    /// - Parameters:
    ///   - config: QUIC configuration
    ///   - sourceConnectionID: Server's source connection ID
    ///   - originalDestinationConnectionID: The DCID from the client's first Initial packet
    public init(
        from config: QUICConfiguration,
        sourceConnectionID: ConnectionID,
        originalDestinationConnectionID: ConnectionID
    ) {
        self.init(from: config, sourceConnectionID: sourceConnectionID)
        self.originalDestinationConnectionID = originalDestinationConnectionID
    }
}
