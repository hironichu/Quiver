/// WebTransport Middleware Types
///
/// Defines the request/reply model for server-side WebTransport session acceptance.
///
/// ## Middleware Flow
///
/// ```
/// Client                           Server
///   |                                |
///   |  Extended CONNECT              |
///   |------------------------------->|
///   |                                |-- WebTransportRequestContext built
///   |                                |-- middleware(context) called
///   |                                |
///   |                                |<- .accept or .reject(reason:)
///   |                                |
///   |  200 OK  or  403 Forbidden     |
///   |<-------------------------------|
/// ```
///
/// ## Usage
///
/// ```swift
/// let server = WebTransportServer(
///     host: "0.0.0.0",
///     port: 4433,
///     options: serverOptions,
///     middleware: { context in
///         guard context.path == "/game" else {
///             return .reject(reason: "Unknown endpoint")
///         }
///         guard context.headers.contains(where: { $0.0 == "authorization" }) else {
///             return .reject(reason: "Missing auth")
///         }
///         return .accept
///     }
/// )
/// ```
///
/// ## References
///
/// - [draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)
/// - [RFC 9220: Bootstrapping WebSockets with HTTP/3](https://www.rfc-editor.org/rfc/rfc9220.html)

import FoundationEssentials

// MARK: - WebTransport Reply

/// The result of a middleware evaluation for an incoming WebTransport session request.
///
/// Returned by a `WebTransportMiddleware` closure to indicate whether the
/// server should accept or reject the Extended CONNECT request.
public enum WebTransportReply: Sendable, Hashable {
    /// Accept the WebTransport session.
    ///
    /// The server responds with `200 OK` and proceeds to establish the session.
    case accept

    /// Reject the WebTransport session with a reason.
    ///
    /// The server responds with `403 Forbidden` and includes an
    /// `X-WT-Reject: <reason>` header. The CONNECT stream is then closed.
    ///
    /// - Parameter reason: Human-readable rejection reason (for logging/debugging).
    case reject(reason: String)
}

// MARK: - CustomStringConvertible

extension WebTransportReply: CustomStringConvertible {
    public var description: String {
        switch self {
        case .accept:
            return "accept"
        case .reject(let reason):
            return "reject(\(reason))"
        }
    }
}

// MARK: - WebTransport Request Context

/// Context provided to middleware when evaluating an incoming WebTransport session request.
///
/// Contains the parsed fields from the Extended CONNECT request that the
/// middleware needs to make an accept/reject decision.
///
/// All fields are read-only. The context is constructed internally by the
/// server from the incoming HTTP/3 request headers.
public struct WebTransportRequestContext: Sendable {
    /// The `:path` pseudo-header from the Extended CONNECT request.
    ///
    /// Example: `"/game"`, `"/chat/room42"`
    public let path: String

    /// The `:authority` pseudo-header from the Extended CONNECT request.
    ///
    /// Example: `"example.com:4433"`
    public let authority: String

    /// All headers from the Extended CONNECT request as key-value pairs.
    ///
    /// Includes both pseudo-headers (`:method`, `:scheme`, `:path`,
    /// `:authority`, `:protocol`) and regular headers.
    /// Keys are lowercased per HTTP/3 convention.
    public let headers: [(String, String)]

    /// The `Origin` header value, if present.
    ///
    /// Used for CORS-style origin validation. `nil` if the client
    /// did not send an `Origin` header.
    public let origin: String?

    /// Creates a request context.
    ///
    /// - Parameters:
    ///   - path: The `:path` pseudo-header value
    ///   - authority: The `:authority` pseudo-header value
    ///   - headers: All request headers
    ///   - origin: The `Origin` header value, if present
    public init(
        path: String,
        authority: String,
        headers: [(String, String)],
        origin: String? = nil
    ) {
        self.path = path
        self.authority = authority
        self.headers = headers
        self.origin = origin
    }
}

// MARK: - CustomStringConvertible

extension WebTransportRequestContext: CustomStringConvertible {
    public var description: String {
        var parts = ["path=\(path)", "authority=\(authority)"]
        if let origin = origin {
            parts.append("origin=\(origin)")
        }
        parts.append("headers=\(headers.count)")
        return "WebTransportRequestContext(\(parts.joined(separator: ", ")))"
    }
}

// MARK: - WebTransport Middleware

/// A closure that evaluates incoming WebTransport session requests.
///
/// Called by the server for each Extended CONNECT request before the session
/// is established. The middleware receives a `WebTransportRequestContext`
/// containing the request details and returns a `WebTransportReply` indicating
/// whether to accept or reject the session.
///
/// ## Thread Safety
///
/// The closure must be `@Sendable` because it may be called concurrently
/// for multiple incoming requests.
///
/// ## Examples
///
/// Accept all requests:
/// ```swift
/// let openMiddleware: WebTransportMiddleware = { _ in .accept }
/// ```
///
/// Path-based routing:
/// ```swift
/// let routingMiddleware: WebTransportMiddleware = { context in
///     switch context.path {
///     case "/game", "/chat":
///         return .accept
///     default:
///         return .reject(reason: "Unknown path: \(context.path)")
///     }
/// }
/// ```
///
/// Origin validation:
/// ```swift
/// let originMiddleware: WebTransportMiddleware = { context in
///     guard let origin = context.origin,
///           origin == "https://example.com" else {
///         return .reject(reason: "Invalid origin")
///     }
///     return .accept
/// }
/// ```
public typealias WebTransportMiddleware = @Sendable (WebTransportRequestContext) async -> WebTransportReply

// MARK: - WebTransport Session Handler

/// A closure that handles an accepted WebTransport session for a registered route.
///
/// Called by the server after middleware (if any) returns `.accept`.
/// The handler receives a fully established `WebTransportSession` and
/// owns its lifecycle — streams, datagrams, and close.
///
/// Sessions dispatched to a handler are **not** yielded to
/// `WebTransportServer.incomingSessions`. Sessions on routes without
/// a handler (or with no routes registered) still appear there.
///
/// ## Thread Safety
///
/// The closure must be `@Sendable` because it may be called concurrently
/// for multiple accepted sessions.
///
/// ## Example
///
/// ```swift
/// server.register(path: "/echo") { session in
///     for await stream in await session.incomingBidirectionalStreams {
///         let data = try await stream.read()
///         try await stream.write(data)
///     }
/// }
/// ```
public typealias WebTransportSessionHandler = @Sendable (WebTransportSession) async -> Void
