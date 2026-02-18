import Foundation
import HTTP3

public struct HTTP3AuthGuard: Sendable {
    public let policy: AuthPolicy

    public init(policy: AuthPolicy) {
        self.policy = policy
    }

    public func protect(
        _ handler: @escaping HTTP3Server.RequestHandler,
        scope: ProtectedScope = .all
    ) -> HTTP3Server.RequestHandler {
        return { context in
            if let callbackResponse = await policy.oidcCallbackResponse(for: context.request) {
                try await context.respond(
                    status: callbackResponse.status,
                    headers: callbackResponse.headers,
                    callbackResponse.body
                )
                return
            }

            if !scope.applies(to: context.request.path) {
                try await handler(context)
                return
            }

            switch await policy.evaluate(context) {
            case .allow:
                try await handler(context)
            case .deny(let status, let reason):
                if status == 401,
                    let loginURL = await policy.loginRedirectURL(for: context.request)
                {
                    try await context.respond(
                        status: 302,
                        headers: [
                            ("location", loginURL.absoluteString),
                            ("cache-control", "no-store"),
                        ],
                        Data()
                    )
                    return
                }

                if shouldReturnHTML(for: context.request) {
                    try await context.respond(
                        status: status,
                        headers: [
                            ("content-type", "text/html; charset=utf-8"),
                            ("cache-control", "no-store"),
                        ],
                        Data(htmlErrorPage(status: status, reason: reason, retryURL: policy.uiRetryURL()).utf8)
                    )
                    return
                }

                try await context.respond(
                    status: status,
                    headers: [
                        ("content-type", "application/json"),
                        ("cache-control", "no-store"),
                    ],
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
            case .allow:
                if let proto = context.request.connectProtocol?.lowercased(), allowedProtocols.contains(proto) {
                    try await handler(context)
                } else {
                    try await context.reject(status: 501)
                }
            case .deny(let status, _):
                try await context.reject(status: status)
            }
        }
    }
}
