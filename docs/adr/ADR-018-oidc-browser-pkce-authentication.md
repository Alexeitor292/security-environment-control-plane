# ADR-018 — OIDC Browser Authorization Code + PKCE Login

- **Status:** Accepted — implemented (OIDC-B slice)
- **Date:** 2026-07-13
- **Milestone:** OIDC-B — Browser Authorization Code + PKCE Login
- **Deciders:** Implementation engineering
- **Related:** ADR-017 (backend bearer verification — the trusted boundary this consumes); Charter §13
  (security model); `docs/architecture/secp-001-design.md` §11.

## Context

ADR-017 (OIDC-A) established strict backend bearer-token verification: a presented access token is
cryptographically verified and its exact `sub` is mapped to a pre-provisioned internal user, with
organization/roles/permissions resolved from SECP's database. The browser, however, still used a
placeholder "Continue as dev-admin" screen and never obtained a real token. OIDC-B replaces that
placeholder with a real, provider-neutral **OpenID Connect Authorization Code flow with PKCE (S256)**
through the public browser client, sending the resulting **access token** as
`Authorization: Bearer <token>` to the existing API. The backend remains authoritative for all token
and identity validation; the frontend derives NO authorization from token claims.

## Decision — locked

1. **The browser is a public OIDC client** (`secp-web`).
2. **Authorization Code flow with PKCE S256** is the only browser flow.
3. **Implicit, hybrid, password grant, and client credentials are forbidden** for the browser.
4. **The browser has no client secret.**
5. A **maintained, provider-neutral OIDC client library** owns authorization-response validation,
   `state`, `nonce`, PKCE generation, token exchange, discovery, and logout protocol handling — not a
   hand-rolled implementation.
6. **`oidc-client-ts`** is the library — declared as the caret range `^3.5.0` in `package.json` (per
   the repo-wide caret policy) and **lockfile-resolved to 3.5.0**; this is a caret range, not an exact
   version pin. It is provider-neutral and compatible with the current React 18 / TypeScript 5.6 /
   Vite 8 toolchain. The Keycloak-specific JS adapter was not used.
7. **The access token is the only token sent to the SECP API.**
8. **The ID token is never used as an API bearer credential** and never grants an organization, role,
   or permission. It is used only as the standards-defined end-session hint at logout.
9. **`/api/v1/me` is the authoritative authenticated identity** for the browser.
10. **Token claims are not used for SECP authorization or organization selection.**
11. **Browser storage is session-scoped only:** no localStorage, no IndexedDB token persistence, no
    database persistence, no SECP-created cookies, no service-worker token cache.
12. **`offline_access` is never requested.** Omitting `offline_access` does **not** by itself prevent
    an ordinary refresh token — an authorization-code response MAY still return one — so this is a
    scope hygiene measure, not the refresh-token control.
13. **SECP does not request, retain, persist, expose, or use a browser refresh token.** This is
    enforced in depth: (a) the dev Keycloak `secp-web` client disables refresh-token issuance
    (`use.refresh.tokens = "false"`) so the token endpoint returns none; and (b) regardless of what
    any provider returns, the frontend strips `refresh_token` before persisting the user
    (`SanitizingUserStore`, sessionStorage only) and retains only a refresh-token-free projection of
    the user in controller/context state — so no refresh token reaches application state, React
    context, an app-facing auth method, the SECP API, logs/errors/URLs, or a refresh/renewal grant.
    Any future long-lived-session behavior requires a separate, reviewed design.
14. **Access-token expiration clears the local authenticated state** and requires a fresh interactive
    login (no automatic silent renewal, no refresh-token grant, no silent-renew callbacks).
15. Authorization transaction state, `nonce`, and PKCE verifier use **sessionStorage through the
    reviewed library** because they must survive the redirect round-trip.
16. **An invalid callback, state mismatch, nonce mismatch, token error, or API 401 fails closed** and
    cannot enter the protected application.
17. **The development fallback is available only when the backend reports `mode = dev_fallback`.**
18. **Production uses OIDC mode only** (the backend never reports dev-fallback in production).
19. **Return paths are same-origin relative application paths**, sanitized against open redirects.
20. **Logout clears local browser auth state** before/along with provider logout.
21. This PR adds **no** backend session, BFF, token database, JIT user provisioning, token-derived
    RBAC, or multi-issuer support.
22. **OIDC-C production deployment and operational runbooks remain future work.**

### Public auth-config endpoint

`GET /api/v1/auth/config` is **public** (no auth), secret-free, network-free (no discovery/JWKS
fetch), and side-effect-free (no DB mutation/audit). It returns `{mode, issuer, client_id, audience,
scope, redirect_path, post_logout_redirect_path}`. `mode` is server-derived (`dev_fallback` only when
the safe dev fallback is enabled; otherwise `oidc` — so production can never silently be dev-fallback).
`scope` is the fixed `openid profile email` (excludes `offline_access`); the callback paths are fixed
relative routes. It contains no client secret, token, or credential.

### Frontend architecture

A `AuthController` (framework-agnostic, fully unit-testable in the node test env) owns the auth state
machine with every side effect injected; the React `AuthProvider` is a thin adapter that wires the
real oidc-client-ts `UserManager`, `/api/v1/me`, and the sessionStorage seam. The `UserManager` user
store is a narrow `SanitizingUserStore` that removes `refresh_token` before any user value is written
(and re-sanitizes/clears a stale value on read, failing closed on malformed data); the separate
authorization-transaction state store (`state`/`nonce`/PKCE verifier) is a plain session store that
must survive the redirect. `AuthBoundary` guards
every application route (protected content and domain API calls occur only once authenticated).
`AuthCallback` processes exactly one authorization callback and `replace`-navigates to the sanitized
return path (carried through the OIDC `state`), removing the code/state query parameters. The API
client attaches the bearer through a narrow token seam only for protected requests (never on the
public auth-config, never cross-origin, never in a URL/body/log); a 401 clears the session (no
auto-replay), a 403 preserves it, and a 503 `authentication_unavailable` shows a provider-unavailable
message. Frontend-visible auth errors are bounded categories (`authentication_required`,
`callback_invalid`, `authentication_unavailable`, `session_expired`, `configuration_invalid`) — never
a token, code, state, nonce, verifier, claim, subject, or provider detail.

## Non-goals

Backend session/BFF, refresh-token session, silent renew, multi-issuer, SCIM/federation, JIT
provisioning, token-derived RBAC, email/username identity linking, and OIDC-C production deployment.

## Consequences

- Frontend affordance hiding by permission may improve UX, but the backend remains the authoritative
  authorization boundary; the frontend enforces no security decision.
- Deployments configure the public browser client id (`SECP_OIDC_WEB_CLIENT_ID`, default `secp-web`),
  register the exact redirect URI (`/auth/callback`) and post-logout URI (`/login`), and require PKCE
  S256 on the IdP client. This ADR unseals no provisioning or infrastructure path.
