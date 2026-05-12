import Foundation
import HTTP3

/// Extracts authentication credentials from HTTP/3 requests.
public struct AuthExtractor: Sendable {
    /// Creates an extractor with QuiverAuth's default header and cookie parsing behavior.
    public init() {}

    /// Returns the first request header value whose name matches case-insensitively.
    public func header(_ name: String, in request: HTTP3Request) -> String? {
        request.headers.first(where: { $0.0.caseInsensitiveCompare(name) == .orderedSame })?.1
    }

    /// Parses the request `Cookie` header into `(name, value)` pairs.
    public func cookies(in request: HTTP3Request) -> [(String, String)] {
        guard let rawCookie = header("cookie", in: request), !rawCookie.isEmpty else {
            return []
        }

        var result: [(String, String)] = []
        for part in rawCookie.split(separator: ";") {
            let pair = part.trimmingCharacters(in: .whitespaces)
            guard let sep = pair.firstIndex(of: "=") else { continue }
            let name = String(pair[..<sep]).trimmingCharacters(in: .whitespaces)
            let value = String(pair[pair.index(after: sep)...]).trimmingCharacters(in: .whitespaces)
            if !name.isEmpty {
                result.append((name, value))
            }
        }
        return result
    }

    /// Extracts a bearer token from the first configured authorization header that contains one.
    public func extractBearerToken(from request: HTTP3Request, headers: [String]) -> String? {
        for headerName in headers {
            guard let raw = header(headerName, in: request), !raw.isEmpty else { continue }
            let prefix = "Bearer "
            guard raw.hasPrefix(prefix) else { continue }
            let token = String(raw.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
            if !token.isEmpty {
                return token
            }
        }
        return nil
    }

    /// Returns the first configured header that is present and non-empty.
    public func firstPresentHeader(in request: HTTP3Request, names: [String]) -> (String, String)? {
        for name in names {
            if let value = header(name, in: request), !value.isEmpty {
                return (name, value)
            }
        }
        return nil
    }

    /// Builds a credential snapshot for policy evaluation from a request and auth configuration.
    public func snapshot(request: HTTP3Request, configuration: AuthConfiguration) -> AuthCredentialSnapshot {
        let bearer = extractBearerToken(from: request, headers: configuration.bearerHeaderNames)
        let identity = firstPresentHeader(in: request, names: configuration.identityHeaderNames)
        let email = firstPresentHeader(in: request, names: configuration.emailHeaderNames)
        let parsedCookies = cookies(in: request)

        return AuthCredentialSnapshot(
            bearerToken: bearer,
            identityHeaderName: identity?.0,
            identityHeaderValue: identity?.1,
            emailHeaderValue: email?.1,
            cookies: parsedCookies
        )
    }
}
