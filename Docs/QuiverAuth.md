# QuiverAuth

`QuiverAuth` adds authentication middleware for HTTP/3 requests and Extended CONNECT/WebTransport handlers. It is intended to let an application built on Quiver protect routes without embedding provider-specific authentication logic in every handler.

The package currently supports:

- forwarded identity from a trusted gateway or reverse proxy
- bearer JWT extraction from request headers
- OIDC-style JWT validation with issuer, audience, expiry, not-before, subject, and signature checks
- browser OIDC authorization-code login with state, nonce, PKCE, callback handling, and a local session cookie
- in-memory server-side OIDC sessions with token refresh and optional UserInfo hydration
- typed auth session payloads in `HTTP3Session`

## Authentication model

`QuiverAuth` is centered around three types:

| Type | Role |
| --- | --- |
| `AuthConfiguration` | Defines auth mode, trusted headers/cookies, and optional OIDC configuration. |
| `AuthPolicy` | Evaluates an HTTP/3 request and returns allow/deny decisions. |
| `HTTP3AuthGuard` | Wraps request handlers, handles OIDC callbacks, redirects browser requests to login, and attaches authenticated session data. |

`AuthPolicy` produces an `AuthPrincipal` when authentication succeeds. `HTTP3AuthGuard` stores that principal in the request `HTTP3Session` under a namespace, `auth` by default.

## Auth modes

| Mode | Behavior |
| --- | --- |
| `.forwardOnly` | Only trusts forwarded identity headers/cookies from the Alt-Svc gateway marker. |
| `.oidcOnly` | Requires OIDC/JWT authentication. Forwarded identity is ignored. |
| `.composite` | Tries OIDC/JWT first, then forwarded identity/cookie auth. |

Use `.oidcOnly` when Quiver itself owns authentication. Use `.forwardOnly` when another gateway already authenticated the request. Use `.composite` only when both patterns are intentionally supported.

## Browser OIDC flow

The browser flow is the standard OAuth 2.0 Authorization Code flow with OIDC and PKCE:

```text
Browser GET /login
  -> QuiverAuth creates state, nonce, PKCE verifier/challenge
  -> server redirects to provider authorization_endpoint

Provider login/consent
  -> provider redirects to /auth/callback?code=...&state=...

QuiverAuth callback handling
  -> validates state
  -> exchanges code at token_endpoint
  -> checks nonce in the ID token when present
  -> stores token set server-side or stores a token cookie
  -> sets the session cookie
  -> redirects to callbackSuccessPath

Browser requests protected routes
  -> cookie is evaluated
  -> ID token is validated
  -> optional UserInfo claims are merged
  -> route handler receives an auth session
```

For a UI, prefer a button or link to your own login endpoint:

```html
<a href="/login">Login</a>
```

Do not hardcode a provider authorization URL in HTML unless the URL was generated server-side. The server must create and remember per-login `state`, `nonce`, and PKCE values.

## Basic route protection

```swift
import HTTP3
import QuiverAuth

let policy = AuthPolicy(configuration: AuthConfiguration(mode: .oidcOnly, oidc: oidcConfiguration))
let authGuard: HTTP3AuthGuard<QuiverAuthSession> = HTTP3AuthGuard(policy: policy)

await server.onRequestSession(authGuard.resolver)

let router = HTTP3Router()

router.get("/health") { context, _ in
    try await context.respond(status: 200, Data("ok".utf8))
}

router.get("/private") { context, _ in
    guard let auth = context.session.get("auth", as: QuiverAuthSession.self) else {
        try await context.respond(status: 500, Data("missing auth session".utf8))
        return
    }

    try await context.respond(status: 200, Data("hello \(auth.subject)".utf8))
}

let protected = authGuard.protect(router.handler, scope: .except(["/health"]))

await server.onRequest { context in
    try await protected(context)
}
```

## Explicit login and callback endpoints

The current guard can redirect protected browser requests automatically, but demos and applications are easier to understand when they expose auth endpoints explicitly.

Recommended endpoint shape:

| Endpoint | Protected | Purpose |
| --- | --- | --- |
| `GET /` | No | Demo page with login/status links. |
| `GET /health` | No | Health check. |
| `GET /login` | No | Creates the provider authorization URL and redirects the browser. |
| `GET /auth/callback` | No | Handles provider callback, exchanges the code, sets the local session cookie. |
| `GET /logout` or `POST /logout` | No | Clears the local session cookie and server session. |
| `GET /me` | Yes | Returns the authenticated user claims. |
| `GET /private` | Yes | Example protected resource. |
| `GET /me-debug` | Yes | Shows raw token claims, UserInfo claims, and merged claims. |

Example `/login` route:

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
```

Callback handling can be automatic: send the callback path through the guarded handler and `HTTP3AuthGuard.protect` will intercept it before route protection runs. The callback path does not need to be listed as public in this mode.

```swift
let protected = authGuard.protect(router.handler, scope: .except([
    "/",
    "/health",
    "/login",
]))
```

For an explicit callback route outside the guarded handler, use the public callback helper:

```swift
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
```

## Generic OIDC configuration

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
        tokenEndpointAuthMethod: nil // auto-detect from discovery when possible
    )
)
```

Important values:

| Value | Meaning |
| --- | --- |
| `issuer` | Expected `iss` claim in ID tokens. |
| `audience` | Expected `aud` claim, usually your OAuth/OIDC client ID. |
| `jwksURL` | Provider JWKS endpoint used for JWT signature verification. |
| `jwksURL` omitted | QuiverAuth uses discovery `jwks_uri` when `issuer` or `discoveryURL` is configured. |
| `discoveryURL` | OIDC discovery document URL. If omitted, it is inferred from `issuer`. |
| `authorizationEndpoint` | Explicit authorization endpoint if discovery is not used. |
| `tokenEndpoint` | Explicit token endpoint if discovery is not used. |
| `redirectURI` | Callback URL registered with the provider. |
| `redirectPath` | Local callback path used when `redirectURI` is inferred. Defaults to `/auth/callback`. |
| `scope` | Space-delimited scopes requested from the provider. Must include `openid` for OIDC. |
| `extraAuthorizationParameters` | Provider-specific authorization parameters such as OIDC `claims`, `prompt`, or custom consent flags. |
| `tokenEndpointAuthMethod` | Optional override for token endpoint authentication: `.clientSecretBasic`, `.clientSecretPost`, or `.none`. If omitted, QuiverAuth uses discovery metadata when available. |
| `sessionCookieName` | Cookie used to link the browser to the QuiverAuth session. Defaults to `z-token`. |

## Twitch example

Twitch publishes OIDC discovery at:

```text
https://id.twitch.tv/oauth2/.well-known/openid-configuration
```

Important Twitch values:

| Field | Value |
| --- | --- |
| issuer | `https://id.twitch.tv/oauth2` |
| authorization endpoint | `https://id.twitch.tv/oauth2/authorize` |
| token endpoint | `https://id.twitch.tv/oauth2/token` |
| JWKS URI | `https://id.twitch.tv/oauth2/keys` |
| UserInfo endpoint | `https://id.twitch.tv/oauth2/userinfo` |
| token endpoint auth method | `client_secret_post` |

Expected configuration shape:

```swift
let twitchOIDC = OIDCConfiguration(
    issuer: "https://id.twitch.tv/oauth2",
    audience: "<twitch-client-id>",
    jwksURL: "https://id.twitch.tv/oauth2/keys",
    login: OIDCLoginConfiguration(
        enabled: true,
        discoveryURL: "https://id.twitch.tv/oauth2/.well-known/openid-configuration",
        authorizationEndpoint: "https://id.twitch.tv/oauth2/authorize",
        tokenEndpoint: "https://id.twitch.tv/oauth2/token",
        clientID: "<twitch-client-id>",
        clientSecret: "<twitch-client-secret>",
        redirectURI: "https://your-app.example.com/auth/callback",
        scope: "openid user:read:email",
        tokenEndpointAuthMethod: .clientSecretPost,
        extraAuthorizationParameters: [
            "claims": #"{"id_token":{"email":null,"email_verified":null,"preferred_username":null},"userinfo":{"picture":null,"updated_at":null}}"#
        ],
        serverSession: OIDCServerSessionConfiguration(
            enabled: true,
            userInfoEndpoint: "https://id.twitch.tv/oauth2/userinfo"
        )
    )
)
```

Register the exact `redirectURI` in the Twitch Developer Console. Twitch requires exact redirect URI matching.

## Current generic OIDC behavior

The implementation is provider-generic and follows OAuth 2.0 Authorization Code, PKCE, OIDC Core, OIDC Discovery, JWT, JWS, and JWK conventions for the parts it supports.

Implemented behavior:

| Area | Behavior |
| --- | --- |
| Token endpoint authentication | Supports `.clientSecretBasic`, `.clientSecretPost`, and `.none`. If unset, QuiverAuth consults discovery `token_endpoint_auth_methods_supported`, then falls back to Basic when a client secret exists. |
| Discovery metadata | Decodes `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `issuer`, `token_endpoint_auth_methods_supported`, and `id_token_signing_alg_values_supported`. |
| JWKS resolution | Uses explicit `jwksURL` first, then discovery `jwks_uri` when available. |
| UserInfo endpoint | Uses explicit `serverSession.userInfoEndpoint`, then discovery `userinfo_endpoint`, then skips UserInfo. |
| Token response scope | Accepts both OAuth string scopes and provider array scopes, normalizing them to a space-delimited string. |
| Route helpers | Exposes `loginRedirectURL(for:)`, `oidcCallbackResponse(for:)`, and `logoutResponse(for:)` for explicit app/demo routes. |

## Remaining limitations

### 1. ID token validation hardening

Current validation checks:

- JWT shape
- signature
- `iss`, when configured
- `aud`, when configured
- `exp`
- `nbf`
- non-empty `sub`

Useful generic additions:

| Validation | Why |
| --- | --- |
| `iat` sanity window | Reject tokens issued too far in the future or too old, when configured. |
| `azp` validation | Required by OIDC Core in some multi-audience cases. |
| algorithm allow-list | Enforce expected signing algorithms from config or discovery. |
| structured nonce validation context | Nonce is checked during callback today; moving it into a reusable validation context would make validation clearer. |

Spec references:

- OpenID Connect Core 1.0, ID Token Validation
- JWT RFC 7519

### 2. Access token and ID token separation

QuiverAuth should treat tokens according to their role:

| Token | Role |
| --- | --- |
| ID token | JWT for authentication; validate signature and claims. |
| Access token | Credential for UserInfo/provider APIs; may be opaque and should not be assumed to be a JWT. |
| Refresh token | Used only with the token endpoint to refresh the token set. |

`OIDCTokenSet.validationToken()` currently prefers `idToken`, then falls back to `accessToken`. That fallback is useful for non-standard providers but is not generally OIDC-correct because many access tokens are opaque. A generic implementation should allow this fallback only by explicit configuration.

### 3. Production session storage

`OIDCServerSessionStore` is currently an in-memory actor. That is acceptable for a demo and single-process development server, but production applications usually need:

- persistence across restarts
- shared state across multiple instances
- session revocation
- expiration cleanup
- encrypted-at-rest token storage

Introduce a protocol-backed store, for example:

```swift
public protocol OIDCSessionStore: Sendable {
    func create(tokenSet: OIDCTokenSet) async throws -> OIDCServerSessionRecord
    func get(sessionID: String) async throws -> OIDCServerSessionRecord?
    func update(sessionID: String, tokenSet: OIDCTokenSet) async throws
    func delete(sessionID: String) async throws
}
```

## Relevant specs

| Spec | Relevance |
| --- | --- |
| OAuth 2.0 RFC 6749 | Authorization code flow, token endpoint, client authentication. |
| PKCE RFC 7636 | `code_verifier`, `code_challenge`, `S256`. |
| OpenID Connect Core 1.0 | ID tokens, nonce, UserInfo, standard claims. |
| OpenID Connect Discovery 1.0 | `.well-known/openid-configuration`, endpoints, JWKS URI, supported auth methods. |
| JWT RFC 7519 | `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`. |
| JWK RFC 7517 | JSON Web Keys and JWKS documents. |
| JWS RFC 7515 | JWT signature verification. |

## Security notes

- Never set `allowUnverifiedSignature` in production.
- Always configure `issuer` and `audience` for real providers.
- Keep client secrets out of source control and logs.
- Use HTTPS redirect URIs in production.
- Register exact redirect URIs with the provider.
- Keep session cookies `Secure`, `HttpOnly`, and `SameSite=Lax` or stricter unless your deployment requires otherwise.
- Treat access and refresh tokens as secrets.
- Use persistent session storage for production multi-instance deployments.
