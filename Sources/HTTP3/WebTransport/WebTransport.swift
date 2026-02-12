/// WebTransport Client Entry Point
///
/// A single namespace for establishing WebTransport sessions over HTTP/3.
/// Replaces the former `WebTransportClient` actor and its three-tier API
/// with a flat set of `connect` overloads that return a ready-to-use
/// `WebTransportSession`.
///
/// ## Usage
///
/// ```swift
/// // Simple — defaults + insecure (dev/testing)
/// let session = try await WebTransport.connect(
///     url: "https://localhost:4433/echo",
///     options: .insecure()
/// )
///
/// // Production — custom CA (DER source)
/// var opts = WebTransportOptions()
/// opts.caCertificates = .der([myRootCertDER])
/// let session = try await WebTransport.connect(
///     url: "https://example.com:4433/wt",
///     options: opts
/// )
///
/// // Production — custom CA (PEM file source)
/// opts.caCertificates = .pem(path: "/path/to/roots.pem")
///
/// // Power-user — full QUIC/HTTP3 control
/// var quic = QUICConfiguration()
/// quic.securityMode = .production { MyTLSProvider() }
/// let advanced = WebTransportOptionsAdvanced(quic: quic)
/// let session = try await WebTransport.connect(
///     url: "https://example.com:4433/wt",
///     options: advanced
/// )
/// ```
///
/// ## Connect Flow (single implementation)
///
/// ```
/// 1. Parse URL → scheme, authority, path
/// 2. Build QUICConfiguration + HTTP3Settings from options
/// 3. QUICEndpoint(config).dial(address)       ← QUIC handshake
/// 4. HTTP3Connection.initialize()             ← control + QPACK streams, SETTINGS
/// 5. HTTP3Connection.waitForReady()           ← peer SETTINGS
/// 6. Verify peer supports WebTransport        ← SETTINGS check
/// 7. HTTP3Connection.sendExtendedConnect()    ← :protocol=webtransport
/// 8. Check 200 response                      ← session accepted
/// 9. HTTP3Connection.createClientWebTransportSession()
/// ```
///
/// ## References
///
/// - [draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)
/// - [RFC 9220: Bootstrapping WebSockets with HTTP/3](https://www.rfc-editor.org/rfc/rfc9220.html)
/// - [RFC 9297: HTTP Datagrams and the Capsule Protocol](https://www.rfc-editor.org/rfc/rfc9297.html)

import Foundation
import Logging
import QUIC
import QUICCore

// MARK: - WebTransport Namespace

/// Client-side entry point for establishing WebTransport sessions.
///
/// All `connect` overloads funnel into a single private `_connect`
/// implementation. No actor, no retained state — each call produces
/// an independent `WebTransportSession`.
public enum WebTransport {

    private static let logger = QuiverLogging.logger(label: "webtransport")

    // MARK: - connect(url: String, options: WebTransportOptions)

    /// Establishes a WebTransport session from a URL string.
    ///
    /// Parses the URL, creates a QUIC endpoint, dials the server,
    /// initializes HTTP/3, sends Extended CONNECT, and returns a
    /// ready-to-use session.
    ///
    /// - Parameters:
    ///   - url: The WebTransport URL (e.g. `"https://example.com:4433/wt"`)
    ///   - options: Client-side options (TLS, timeouts, streams, etc.)
    /// - Returns: An established `WebTransportSession`
    /// - Throws: `WebTransportError` if the URL is invalid, connection fails,
    ///   or the server rejects the session
    public static func connect(
        url: String,
        options: WebTransportOptions
    ) async throws -> WebTransportSession {
        let (scheme, authority, host, port, path) = try parseURL(url)

        var quicConfig = options.buildQUICConfiguration()

        // Pass TLS trust source intent to QUIC/TLS layer (resolved there)
        quicConfig.verifyPeer = options.verifyPeer
        switch options.caCertificates {
        case .system:
            quicConfig.useSystemTrustStore = true
            quicConfig.userTrustedCACertificatesDER = nil
            quicConfig.userTrustedCAsPEMPath = nil
        case .der(let certs):
            quicConfig.useSystemTrustStore = false
            quicConfig.userTrustedCACertificatesDER = certs
            quicConfig.userTrustedCAsPEMPath = nil
        case .pem(let path):
            quicConfig.useSystemTrustStore = false
            quicConfig.userTrustedCACertificatesDER = nil
            quicConfig.userTrustedCAsPEMPath = path
        }

        let h3Settings = options.buildHTTP3Settings()

        let endpoint = QUICEndpoint(configuration: quicConfig)
        let address = SocketAddress(ipAddress: host, port: port)
        let quicConnection = try await endpoint.dial(address: address)

        return try await _connect(
            scheme: scheme,
            authority: authority,
            path: path,
            quicConnection: quicConnection,
            h3Settings: h3Settings,
            headers: options.headers,
            connectionReadyTimeout: options.connectionReadyTimeout,
            connectTimeout: options.connectTimeout
        )
    }

    // MARK: - connect(url: URL, options: WebTransportOptions)

    /// Establishes a WebTransport session from a `URL` value.
    ///
    /// Convenience overload that accepts a `Foundation.URL` instead of
    /// a raw string. Delegates to the string-based overload.
    ///
    /// - Parameters:
    ///   - url: The WebTransport URL
    ///   - options: Client-side options
    /// - Returns: An established `WebTransportSession`
    /// - Throws: `WebTransportError` if the URL is invalid, connection fails,
    ///   or the server rejects the session
    public static func connect(
        url: URL,
        options: WebTransportOptions
    ) async throws -> WebTransportSession {
        return try await connect(url: url.absoluteString, options: options)
    }

    // MARK: - connect(url: String, options: WebTransportOptionsAdvanced)

    /// Establishes a WebTransport session using advanced options.
    ///
    /// The caller provides a fully-configured `QUICConfiguration` (including
    /// `securityMode`) and `HTTP3Settings`. WebTransport-mandatory flags
    /// are enforced via `validated()`.
    ///
    /// - Parameters:
    ///   - url: The WebTransport URL (e.g. `"https://example.com:4433/wt"`)
    ///   - options: Advanced options with full QUIC/HTTP3 access
    /// - Returns: An established `WebTransportSession`
    /// - Throws: `WebTransportError` if the URL is invalid, connection fails,
    ///   or the server rejects the session
    public static func connect(
        url: String,
        options: WebTransportOptionsAdvanced
    ) async throws -> WebTransportSession {
        let validated = options.validated()
        let (scheme, authority, host, port, path) = try parseURL(url)

        let endpoint = QUICEndpoint(configuration: validated.quic)
        let address = SocketAddress(ipAddress: host, port: port)
        let quicConnection = try await endpoint.dial(address: address)

        return try await _connect(
            scheme: scheme,
            authority: authority,
            path: path,
            quicConnection: quicConnection,
            h3Settings: validated.http3Settings,
            headers: validated.headers,
            connectionReadyTimeout: validated.connectionReadyTimeout,
            connectTimeout: validated.connectTimeout
        )
    }

    // MARK: - connect(url: URL, options: WebTransportOptionsAdvanced)

    /// Establishes a WebTransport session from a `URL` using advanced options.
    ///
    /// - Parameters:
    ///   - url: The WebTransport URL
    ///   - options: Advanced options with full QUIC/HTTP3 access
    /// - Returns: An established `WebTransportSession`
    /// - Throws: `WebTransportError` if the URL is invalid, connection fails,
    ///   or the server rejects the session
    public static func connect(
        url: URL,
        options: WebTransportOptionsAdvanced
    ) async throws -> WebTransportSession {
        return try await connect(url: url.absoluteString, options: options)
    }

    // MARK: - Private: URL Parsing

    /// Parses a URL string into its components for the connect flow.
    ///
    /// - Parameter url: The raw URL string
    /// - Returns: A tuple of (scheme, authority, host, port, path)
    /// - Throws: `WebTransportError.internalError` if the URL is malformed
    private static func parseURL(
        _ url: String
    ) throws -> (scheme: String, authority: String, host: String, port: UInt16, path: String) {
        guard let components = URLComponents(string: url) else {
            throw WebTransportError.internalError(
                "Invalid URL: \(url)",
                underlying: nil
            )
        }

        let host = components.host ?? "localhost"
        let port = components.port.map { UInt16($0) } ?? 443
        let scheme = components.scheme ?? "https"
        let path = components.path.isEmpty ? "/" : components.path

        let authority: String
        if let explicitPort = components.port {
            authority = "\(host):\(explicitPort)"
        } else {
            authority = host
        }

        return (scheme, authority, host, port, path)
    }

    // MARK: - Private: Shared Connect Implementation

    /// Single connect implementation shared by all public overloads.
    ///
    /// This is the **only** place where the following steps happen:
    /// 1. HTTP/3 connection initialization (control + QPACK streams, SETTINGS)
    /// 2. Wait for peer SETTINGS
    /// 3. Peer WebTransport capability verification
    /// 4. Extended CONNECT send + response check
    /// 5. Session creation
    ///
    /// No duplication — every `connect` overload funnels here.
    ///
    /// - Parameters:
    ///   - scheme: URI scheme (`"https"`)
    ///   - authority: The `:authority` pseudo-header value (e.g. `"example.com:4433"`)
    ///   - path: The `:path` pseudo-header value (e.g. `"/wt"`)
    ///   - quicConnection: An established QUIC connection (handshake complete)
    ///   - h3Settings: HTTP/3 settings with WT-mandatory flags already set
    ///   - headers: Additional HTTP headers for the Extended CONNECT request
    ///   - connectionReadyTimeout: Max time to wait for peer SETTINGS
    ///   - connectTimeout: Max time to wait for Extended CONNECT response (reserved for future use)
    /// - Returns: An established `WebTransportSession`
    /// - Throws: `WebTransportError` on any failure in the chain
    private static func _connect(
        scheme: String,
        authority: String,
        path: String,
        quicConnection: any QUICConnectionProtocol,
        h3Settings: HTTP3Settings,
        headers: [(String, String)],
        connectionReadyTimeout: Duration,
        connectTimeout: Duration
    ) async throws -> WebTransportSession {

        // --- Step 1: Create and initialize the HTTP/3 connection ---

        let h3 = HTTP3Connection(
            quicConnection: quicConnection,
            role: .client,
            settings: h3Settings
        )

        do {
            try await h3.initialize()
        } catch {
            throw WebTransportError.http3Error(
                "Failed to initialize HTTP/3 connection",
                underlying: error
            )
        }

        // --- Step 2: Wait for peer SETTINGS exchange ---

        do {
            try await h3.waitForReady(timeout: connectionReadyTimeout)
        } catch {
            // Some implementations send SETTINGS lazily — proceed anyway
            logger.warning("waitForReady timed out, proceeding: \(error)")
        }

        // --- Step 3: Verify peer supports WebTransport ---

        let peerSettings = await h3.peerSettings
        if let peer = peerSettings {
            if !peer.enableConnectProtocol {
                throw WebTransportError.peerDoesNotSupportWebTransport(
                    "Peer has not enabled SETTINGS_ENABLE_CONNECT_PROTOCOL"
                )
            }
            if !peer.enableH3Datagram {
                logger.warning(
                    "Peer has not enabled SETTINGS_H3_DATAGRAM — datagrams may not work"
                )
            }
            if let maxSessions = peer.webtransportMaxSessions, maxSessions == 0 {
                throw WebTransportError.maxSessionsExceeded(limit: 0)
            }
        }

        // --- Step 4: Build and send Extended CONNECT ---

        let request = HTTP3Request.webTransportConnect(
            scheme: scheme,
            authority: authority,
            path: path,
            headers: headers
        )

        logger.debug(
            "Sending WebTransport CONNECT",
            metadata: [
                "authority": "\(authority)",
                "path": "\(path)",
            ]
        )

        let (response, connectStream): (HTTP3ResponseHead, any QUICStreamProtocol)
        do {
            (response, connectStream) = try await h3.sendExtendedConnect(request)
        } catch {
            throw WebTransportError.http3Error(
                "Extended CONNECT failed",
                underlying: error
            )
        }

        guard response.isSuccess else {
            throw WebTransportError.sessionRejected(
                status: response.status,
                reason: response.statusText
            )
        }

        logger.info(
            "WebTransport session accepted",
            metadata: [
                "streamID": "\(connectStream.id)",
                "status": "\(response.status)",
                "authority": "\(authority)",
                "path": "\(path)",
            ]
        )

        // --- Step 5: Create the session ---

        do {
            return try await h3.createClientWebTransportSession(
                connectStream: connectStream,
                response: response,
                path: path,
                authority: authority
            )
        } catch {
            throw WebTransportError.internalError(
                "Failed to create WebTransport session",
                underlying: error
            )
        }
    }
}