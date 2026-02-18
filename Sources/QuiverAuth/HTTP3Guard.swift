import Foundation
import HTTP3
import Logging
import QUICCore

public struct HTTP3AuthGuard<SessionPayload: Codable & Sendable>: Sendable {
    private var logger: Logger {
        QuiverLogging.logger(label: "quiver.auth.guard")
    }

    public let policy: AuthPolicy
    public let namespace: String

    private let payloadBuilder: @Sendable (AuthPrincipal, AuthPolicy) -> SessionPayload?

    public var resolver: HTTP3Server.RequestSessionResolver {
        { context in
            logger.trace(
                "resolver invoked",
                metadata: [
                    "path": "\(context.request.path)",
                    "method": "\(context.request.method.rawValue)",
                    "namespace": "\(namespace)",
                ]
            )

            if policy.isOIDCCallbackRequest(context.request) {
                logger.trace(
                    "resolver skipped session attach (oidc callback)",
                    metadata: [
                        "path": "\(context.request.path)",
                        "namespace": "\(namespace)",
                    ]
                )
                return context.session
            }

            switch await policy.evaluate(context) {
            case .allow(let principal):
                let session = buildSession(for: principal, base: context.session)
                logger.debug(
                    "resolver attached auth session",
                    metadata: [
                        "path": "\(context.request.path)",
                        "namespace": "\(namespace)",
                        "subject": "\(principal.subject)",
                        "source": "\(principal.source)",
                    ]
                )
                return session
            case .deny(let status, let reason):
                logger.debug(
                    "resolver skipped session attach (denied)",
                    metadata: [
                        "path": "\(context.request.path)",
                        "status": "\(status)",
                        "reason": "\(reason)",
                    ]
                )
                return context.session
            }
        }
    }

    public init(
        policy: AuthPolicy,
        namespace: String? = nil,
        into _: SessionPayload.Type = SessionPayload.self
    ) {
        self.policy = policy
        self.namespace = namespace ?? "auth"
        self.payloadBuilder = { principal, policy in
            let values = policy.sessionValues(for: principal)
            let logger = QuiverLogging.logger(label: "quiver.auth.guard")

            do {
                let data = try JSONEncoder().encode(values)
                return try JSONDecoder().decode(SessionPayload.self, from: data)
            } catch {
                logger.warning(
                    "failed to decode typed auth session payload",
                    metadata: [
                        "namespace": "\(namespace ?? "auth")",
                        "payloadType": "\(String(describing: SessionPayload.self))",
                        "subject": "\(principal.subject)",
                        "keys": "\(values.keys.sorted().joined(separator: ","))",
                        "error": "\(error)",
                    ]
                )
                return nil
            }
        }
    }

    public init(
        policy: AuthPolicy,
        namespace: String? = nil,
        into _: SessionPayload.Type = SessionPayload.self,
        payloadBuilder: @escaping @Sendable (AuthPrincipal, AuthPolicy) -> SessionPayload?
    ) {
        self.policy = policy
        self.namespace = namespace ?? "auth"
        self.payloadBuilder = payloadBuilder
    }

    private func buildSession(for principal: AuthPrincipal, base: HTTP3Session) -> HTTP3Session {
        var session = policy.session(for: principal, base: base, namespace: namespace)
        if let typedPayload = payloadBuilder(principal, policy) {
            session = session.settingTyped(namespace: namespace, payload: typedPayload)
            logger.trace(
                "typed session payload attached",
                metadata: [
                    "namespace": "\(namespace)",
                    "subject": "\(principal.subject)",
                    "payloadType": "\(String(describing: SessionPayload.self))",
                ]
            )
        } else {
            logger.warning(
                "typed session payload builder returned nil",
                metadata: [
                    "namespace": "\(namespace)",
                    "subject": "\(principal.subject)",
                    "payloadType": "\(String(describing: SessionPayload.self))",
                ]
            )
        }
        return session
    }

    public func protect(
        _ handler: @escaping HTTP3Server.RequestHandler,
        scope: ProtectedScope = .all
    ) -> HTTP3Server.RequestHandler {
        return { context in
            if let callbackResponse = await policy.oidcCallbackResponse(for: context.request) {
                logger.debug(
                    "oidc callback handled by guard",
                    metadata: [
                        "path": "\(context.request.path)",
                        "status": "\(callbackResponse.status)",
                    ]
                )
                try await context.respond(
                    status: callbackResponse.status,
                    headers: callbackResponse.headers,
                    callbackResponse.body
                )
                return
            }

            if !scope.applies(to: context.request.path) {
                logger.trace(
                    "scope bypass",
                    metadata: ["path": "\(context.request.path)"]
                )
                try await handler(context)
                return
            }

            switch await policy.evaluate(context) {
            case .allow(let principal):
                logger.debug(
                    "request authorized",
                    metadata: [
                        "path": "\(context.request.path)",
                        "subject": "\(principal.subject)",
                        "source": "\(principal.source)",
                    ]
                )
                let session = buildSession(for: principal, base: context.session)
                try await handler(context.withSession(session))
            case .deny(let status, let reason):
                logger.debug(
                    "request denied",
                    metadata: [
                        "path": "\(context.request.path)",
                        "status": "\(status)",
                        "reason": "\(reason)",
                    ]
                )
                let policyHeaders = policy.denyResponseHeaders(
                    for: context.request,
                    status: status,
                    reason: reason
                )
                if status == 401,
                    let loginURL = await policy.loginRedirectURL(for: context.request)
                {
                    logger.debug(
                        "redirecting to oidc login",
                        metadata: [
                            "path": "\(context.request.path)",
                            "redirectHost": "\(loginURL.host ?? "unknown")",
                        ]
                    )
                    let headers = policyHeaders + [
                        ("location", loginURL.absoluteString),
                        ("cache-control", "no-store"),
                    ]
                    try await context.respond(
                        status: 302,
                        headers: headers,
                        Data()
                    )
                    return
                }

                if shouldReturnHTML(for: context.request) {
                    logger.trace(
                        "sending html deny response",
                        metadata: ["path": "\(context.request.path)"]
                    )
                    let headers = policyHeaders + [
                        ("content-type", "text/html; charset=utf-8"),
                        ("cache-control", "no-store"),
                    ]
                    try await context.respond(
                        status: status,
                        headers: headers,
                        Data(htmlErrorPage(status: status, reason: reason, retryURL: policy.uiRetryURL()).utf8)
                    )
                    return
                }

                logger.trace(
                    "sending json deny response",
                    metadata: ["path": "\(context.request.path)"]
                )
                let headers = policyHeaders + [
                    ("content-type", "application/json"),
                    ("cache-control", "no-store"),
                ]
                try await context.respond(
                    status: status,
                    headers: headers,
                    Data("{\"error\":\"unauthorized\",\"reason\":\"\(reason)\"}".utf8)
                )
            }
        }
    }

    private func shouldReturnHTML(for request: HTTP3Request) -> Bool {
        let accept = headerValue("accept", in: request)?.lowercased() ?? ""
        let contentType = headerValue("content-type", in: request)?.lowercased() ?? ""
        let requestedWith = headerValue("x-requested-with", in: request)?.lowercased() ?? ""
        let fetchMode = headerValue("sec-fetch-mode", in: request)?.lowercased() ?? ""

        if accept.contains("application/json") { return false }
        if contentType.contains("application/json") { return false }
        if requestedWith.contains("xmlhttprequest") { return false }
        if !fetchMode.isEmpty && fetchMode != "navigate" { return false }

        return accept.contains("text/html") || fetchMode == "navigate"
    }

    private func headerValue(_ name: String, in request: HTTP3Request) -> String? {
        request.headers.first { $0.0.caseInsensitiveCompare(name) == .orderedSame }?.1
    }

    private func htmlErrorPage(status: Int, reason: String, retryURL: String?) -> String {
        let title: String
        if status == 401 {
            title = "Authentication Required"
        } else if status == 403 {
            title = "Access Forbidden"
        } else {
            title = "Request Denied"
        }

        let safeTitle = escapeHTML(title)
        let safeReason = escapeHTML(reason)
        let retryHTML: String
        if let retryURL, !retryURL.isEmpty {
            retryHTML = "<p><a class=\"btn\" href=\"\(escapeHTML(retryURL))\">Try again</a></p>"
        } else {
            retryHTML = ""
        }

        return """
        <!doctype html>
        <html lang=\"en\">
            <head>
                <meta charset=\"utf-8\" />
                <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
                <title>\(safeTitle)</title>
                <style>
                    :root { color-scheme: light dark; }
                    body {
                        margin: 0;
                        font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif;
                        background: #f7f8fa;
                        color: #101828;
                        display: grid;
                        min-height: 100vh;
                        place-items: center;
                        padding: 16px;
                    }
                    .card {
                        width: min(460px, 100%);
                        background: #ffffff;
                        border: 1px solid #e4e7ec;
                        border-radius: 12px;
                        padding: 18px 20px;
                        box-shadow: 0 6px 20px rgba(16, 24, 40, 0.08);
                    }
                    h1 { margin: 0 0 8px 0; font-size: 18px; }
                    p { margin: 0 0 10px 0; color: #475467; font-size: 14px; }
                    code {
                        display: inline-block;
                        margin-top: 4px;
                        padding: 2px 6px;
                        border-radius: 6px;
                        background: #f2f4f7;
                        font-size: 12px;
                        color: #344054;
                    }
                    .btn {
                        display: inline-block;
                        margin-top: 8px;
                        text-decoration: none;
                        background: #175cd3;
                        color: #ffffff;
                        border-radius: 8px;
                        padding: 7px 12px;
                        font-size: 13px;
                    }
                </style>
            </head>
            <body>
                <main class=\"card\">
                    <h1>\(safeTitle)</h1>
                    <p>This page requires authorization before it can be displayed.</p>
                    <code>status=\(status) • reason=\(safeReason)</code>
                    \(retryHTML)
                </main>
            </body>
        </html>
        """
    }

    private func escapeHTML(_ value: String) -> String {
        value
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }

    public func protectExtendedConnect(
        _ handler: @escaping HTTP3Server.ExtendedConnectHandler,
        allowedProtocols: Set<String> = ["webtransport"]
    ) -> HTTP3Server.ExtendedConnectHandler {
        return { context in
            switch await policy.evaluate(context) {
            case .allow(let principal):
                if let proto = context.request.connectProtocol?.lowercased(), allowedProtocols.contains(proto)
                {
                    logger.debug(
                        "extended connect authorized",
                        metadata: [
                            "path": "\(context.request.path)",
                            "protocol": "\(proto)",
                            "subject": "\(principal.subject)",
                        ]
                    )
                    let session = buildSession(for: principal, base: context.session)
                    try await handler(context.withSession(session))
                } else {
                    logger.debug(
                        "extended connect rejected due to protocol",
                        metadata: [
                            "path": "\(context.request.path)",
                            "protocol": "\(context.request.connectProtocol ?? "nil")",
                        ]
                    )
                    try await context.reject(status: 501)
                }
            case .deny(let status, _):
                logger.debug(
                    "extended connect denied",
                    metadata: [
                        "path": "\(context.request.path)",
                        "status": "\(status)",
                    ]
                )
                try await context.reject(status: status)
            }
        }
    }
}

public extension HTTP3AuthGuard where SessionPayload == QuiverAuthSession {
    init(
        policy: AuthPolicy,
        namespace: String? = nil
    ) {
        self.init(
            policy: policy,
            namespace: namespace,
            into: QuiverAuthSession.self,
            payloadBuilder: { principal, policy in
                policy.defaultSessionPayload(for: principal)
            }
        )
    }
}
