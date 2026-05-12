# QuiverAuth

`QuiverAuth` adds authentication policy evaluation and middleware for HTTP/3, Extended CONNECT, and WebTransport handlers. It keeps the core model small: extract credentials, validate them with either application logic or OIDC/JWT, turn success into an `AuthPrincipal`, and attach typed auth data to `HTTP3Session`.

QuiverAuth supports:

- custom async validators for application-owned auth
- generic server-side sessions through `AuthSessionStore`
- typed session cookies with `Duration` lifetimes and `AuthCookieSameSite`
- OIDC/JWT validation with issuer, audience, temporal claims, subject, and signature checks
- browser OIDC authorization-code login with state, nonce, PKCE, callback handling, and logout helpers
- server-side OIDC sessions with opaque cookies, token refresh, and optional UserInfo claim hydration
- HS256 JWT issuing for application-owned tokens
- trusted forwarded identity for gateway deployments

## Core Types

| Type | Purpose |
| --- | --- |
| `AuthConfiguration` | Top-level policy configuration. |
| `AuthPolicy` | Evaluates requests and creates sessions, cookies, redirects, callback responses, and JWTs. |
| `HTTP3AuthGuard` | Wraps HTTP/3 handlers and attaches auth session data. |
| `AuthValidator` | Application-provided async validator. |
| `AuthSessionStore` | Application-provided generic session persistence. |
| `AuthCookieConfiguration` | Typed cookie attributes used for `Set-Cookie` headers. |
| `OIDCConfiguration` | OIDC/JWT validation and browser login configuration. |
| `AuthJWTIssuer` | HS256 JWT issuer for application-owned auth flows. |

`AuthPolicy` returns an `AuthDecision`. On success, it provides an `AuthPrincipal`. `HTTP3AuthGuard` stores that principal under the `auth` session namespace by default.

## Auth Modes

| Mode | Behavior |
| --- | --- |
| `.customOnly` | Generic sessions and custom validators only. |
| `.forwardOnly` | Trusted forwarded identity or cookie signals only. |
| `.oidcOnly` | OIDC/JWT only. |
| `.composite` | Generic sessions, custom validators, OIDC/JWT, then forwarded identity/cookie auth. |

Prefer the narrowest mode that matches your application. Use `.composite` only when multiple authentication paths are intentional.

## Custom Application Auth

Use `AuthValidator` when your application owns authentication. A validator receives an `AuthValidationContext` containing the request, extracted bearer token, parsed cookies, forwarded identity headers, and gateway marker.

```swift
let databaseValidator = AuthValidator(name: "database") { context in
    guard let token = context.snapshot.bearerToken else {
        return nil
    }

    guard let user = try? await users.findSessionToken(token) else {
        return .deny(status: 401, reason: "invalid token")
    }

    return .allow(
        AuthPrincipal(
            subject: user.id,
            email: user.email,
            source: "database",
            claims: ["role": .string(user.role)]
        )
    )
}

let policy = AuthPolicy(
    configuration: AuthConfiguration(
        mode: .customOnly,
        validators: [databaseValidator]
    )
)
```

A bearer token is not authentication by itself. It is accepted only when your validator returns `.allow` or when OIDC/JWT validation succeeds.

## Generic Sessions

Generic sessions are application-owned server-side sessions. Configure an `AuthSessionStore`, create a session after login, and send the returned cookie to the browser.

```swift
let sessionStore = InMemoryAuthSessionStore()
let policy = AuthPolicy(
    configuration: AuthConfiguration(
        mode: .customOnly,
        session: AuthSessionConfiguration(
            cookieName: "app-session",
            cookieSecure: true,
            cookieHTTPOnly: true,
            cookieSameSite: .lax,
            cookiePath: "/",
            cookieMaxAge: .days(7),
            store: sessionStore
        )
    )
)

router.post("/login") { context, _ in
    let user = try await users.verifyPassword(context.request)
    let principal = AuthPrincipal(subject: user.id, email: user.email, source: "database")
    let record = try await policy.createSession(for: principal)

    guard let cookie = policy.sessionCookieHeader(for: record) else {
        try await context.respond(status: 500, Data("session unavailable".utf8))
        return
    }

    try await context.respond(
        status: 302,
        headers: [("set-cookie", cookie), ("location", "/")],
        Data()
    )
}
```

`InMemoryAuthSessionStore` is for development, tests, and single-process demos. Production deployments should provide an `AuthSessionStore` backed by durable storage so sessions can be revoked, shared across instances, and survive restarts.

## Cookies

Cookie configuration is typed. Use `Duration` for lifetimes and `AuthCookieSameSite` for `SameSite`.

```swift
let cookie = AuthCookieConfiguration(
    name: "app-session",
    path: "/",
    maxAge: .hours(12),
    secure: true,
    httpOnly: true,
    sameSite: .lax
)
```

Use `.strict` when possible. Use `.none` only when cross-site cookie behavior is required, and keep `secure` enabled.

## HTTP/3 Guard

`HTTP3AuthGuard` protects request handlers and attaches a typed session payload.

```swift
let policy = AuthPolicy(configuration: AuthConfiguration(mode: .oidcOnly, oidc: oidcConfiguration))
let authGuard = HTTP3AuthGuard<QuiverAuthSession>(policy: policy)

await server.onRequestSession(authGuard.resolver)

let protected = authGuard.protect(router.handler, scope: .except(["/health", "/login"]))

await server.onRequest { context in
    try await protected(context)
}
```

Handlers can read the authenticated payload from the request session.

```swift
router.get("/me") { context, _ in
    guard let auth = context.session.get("auth", as: QuiverAuthSession.self) else {
        try await context.respond(status: 500, Data("missing auth session".utf8))
        return
    }

    try await context.respond(status: 200, Data(auth.subject.utf8))
}
```

For WebTransport or other Extended CONNECT routes, use `protectExtendedConnect` and keep `allowedProtocols` narrow.

## OIDC Login

The browser login flow uses OAuth 2.0 Authorization Code with PKCE and OIDC nonce validation.

```swift
let oidcConfiguration = OIDCConfiguration(
    issuer: "https://issuer.example.com",
    audience: "my-client-id",
    jwksURL: "https://issuer.example.com/.well-known/jwks.json",
    login: OIDCLoginConfiguration(
        enabled: true,
        discoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
        clientID: "my-client-id",
        clientSecret: "my-client-secret",
        redirectURI: "https://app.example.com/auth/callback",
        callbackSuccessPath: "/",
        scope: "openid profile email",
        serverSession: OIDCServerSessionConfiguration(
            enabled: true,
            cookieMaxAge: .days(7)
        )
    )
)
```

Important fields:

| Field | Meaning |
| --- | --- |
| `issuer` | Expected `iss` claim. Configure this for real providers. |
| `audience` | Expected `aud` claim, usually the OAuth/OIDC client ID. |
| `hs256SharedSecret` | Shared secret for HS256 validation. Prefer JWKS for external providers. |
| `jwksURL` | Explicit JWKS endpoint for asymmetric JWT verification. |
| `staticJWKs` | In-process JWKs for verification when discovery/network lookup is not desired. |
| `discoveryURL` | OIDC discovery document URL. If omitted, QuiverAuth derives it from `issuer`. |
| `authorizationEndpoint` | Explicit authorization endpoint when discovery is not used. |
| `tokenEndpoint` | Explicit token endpoint when discovery is not used. |
| `redirectURI` | Exact callback URL registered with the provider. |
| `redirectPath` | Local callback path used when `redirectURI` is inferred. |
| `scope` | Requested scopes. Include `openid` for OIDC. |
| `tokenEndpointAuthMethod` | Optional token endpoint auth override: `.clientSecretBasic`, `.clientSecretPost`, or `.none`. |
| `sessionCookieName` | OIDC browser session cookie name. Defaults to `z-token`. |

The server-session path stores the provider token set in memory and sends only an opaque session id to the browser. Authentication uses the ID token. Access tokens are reserved for provider APIs such as UserInfo and are not treated as authentication JWTs.

## Explicit Login, Callback, And Logout Routes

Applications can let `HTTP3AuthGuard.protect` intercept callback requests, or expose explicit routes.

```swift
router.get("/login") { context, _ in
    guard let loginURL = await policy.loginRedirectURL(for: context.request) else {
        try await context.respond(status: 500, Data("OIDC login is not configured".utf8))
        return
    }

    try await context.respond(
        status: 302,
        headers: [
            ("location", loginURL.absoluteString),
            ("cache-control", "no-store"),
        ],
        Data()
    )
}

router.get("/auth/callback") { context, _ in
    guard let response = await policy.oidcCallbackResponse(for: context.request) else {
        try await context.respond(status: 404, Data("not an OIDC callback".utf8))
        return
    }

    try await context.respond(
        status: response.status,
        headers: response.headers,
        response.body
    )
}

router.post("/logout") { context, _ in
    guard let response = await policy.logoutResponse(for: context.request) else {
        try await context.respond(status: 404, Data("logout unavailable".utf8))
        return
    }

    try await context.respond(
        status: response.0,
        headers: response.1,
        response.2
    )
}
```

Do not hardcode provider authorization URLs in HTML. Always generate login URLs server-side so QuiverAuth can create and remember per-login `state`, `nonce`, and PKCE values.

## JWT Validation

OIDC/JWT validation checks:

- compact JWT shape
- signature, unless `allowUnverifiedSignature` is enabled for tests
- `iss`, when configured
- `aud`, when configured
- `exp`
- `nbf`
- non-empty `sub`

Use JWKS or static JWKs for external providers. Use HS256 only for tokens issued and verified inside your own trust boundary.

## Application JWT Issuing

Use `AuthJWTIssuerConfiguration` and `AuthPolicy.issueJWT` for application-owned HS256 tokens.

```swift
let secret = try loadSecretFromEnvironment()
let policy = AuthPolicy(
    configuration: AuthConfiguration(
        mode: .oidcOnly,
        oidc: OIDCConfiguration(
            issuer: "https://app.example.com",
            audience: "quiver-app",
            hs256SharedSecret: secret
        ),
        jwtIssuer: AuthJWTIssuerConfiguration(
            issuer: "https://app.example.com",
            audience: "quiver-app",
            defaultTTL: .minutes(15),
            hs256SharedSecret: secret,
            keyID: "local-hs256"
        )
    )
)

let token = try policy.issueJWT(
    for: AuthPrincipal(subject: user.id, email: user.email, source: "database"),
    additionalClaims: ["role": .string(user.role)]
)
```

Keep HS256 secrets out of source control, logs, and client-visible configuration. Rotate them like any other signing secret.

## Forwarded Identity

Forwarded identity mode is for deployments where a trusted gateway authenticates the request before it reaches Quiver. By default, forwarded identity and cookie-session auth require the Quiver gateway marker. Keep `requireGatewayMarkerForForwardedIdentity` enabled unless the deployment has an equivalent trust boundary.

```swift
let policy = AuthPolicy(
    configuration: AuthConfiguration(
        mode: .forwardOnly,
        requireGatewayMarkerForForwardedIdentity: true
    )
)
```

## Security Checklist

- Configure `issuer` and `audience` for production OIDC/JWT validation.
- Keep `allowUnverifiedSignature` disabled outside tests and local diagnostics.
- Prefer server-side OIDC sessions so browser cookies contain opaque session ids, not provider tokens.
- Treat ID tokens, access tokens, refresh tokens, session ids, and HS256 secrets as credentials.
- Keep cookies `Secure`, `HttpOnly`, and `SameSite=Lax` or stricter.
- Use HTTPS redirect URIs and register exact redirect URIs with the provider.
- Keep token endpoint client secrets out of source control and logs.
- Use durable `AuthSessionStore` implementations for production generic sessions.
- Use short JWT lifetimes and rotate signing secrets.
- Keep protected scopes explicit and small for public routes such as health checks, login, callback, and logout.

## Specs

| Spec | Relevance |
| --- | --- |
| OAuth 2.0 RFC 6749 | Authorization code flow, token endpoint, client authentication. |
| PKCE RFC 7636 | `code_verifier`, `code_challenge`, `S256`. |
| OpenID Connect Core 1.0 | ID tokens, nonce, UserInfo, standard claims. |
| OpenID Connect Discovery 1.0 | `.well-known/openid-configuration`, endpoints, JWKS URI, supported auth methods. |
| JWT RFC 7519 | `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`. |
| JWK RFC 7517 | JSON Web Keys and JWKS documents. |
| JWS RFC 7515 | JWT signature verification. |
