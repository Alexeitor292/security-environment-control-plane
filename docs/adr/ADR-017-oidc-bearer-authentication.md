# ADR-017 — OIDC Bearer-Token Authentication (backend verification)

- **Status:** Accepted — implemented (OIDC-A slice)
- **Date:** 2026-07-13
- **Milestone:** OIDC-A — Strict Backend Bearer-Token Verification and Internal Identity Binding
- **Deciders:** Implementation engineering
- **Related:** Charter §13 (security model), §7 (identity); ADR-004 (approval gate — authorization is
  separate from authentication); `docs/architecture/secp-001-design.md` §11.

## Context

Until this slice the control-plane API rejected every `Authorization` header and authenticated only
through a clearly-gated **development fallback principal**. Real, production-grade authentication is
the next serious production-readiness blocker. This ADR locks the **backend token-verification
boundary**: a cryptographically verified OIDC access token mapped to a pre-provisioned internal
user. It deliberately does **not** implement the interactive browser login flow (Authorization Code
+ PKCE, redirects/callback, token/session lifecycle, logout, login UX) — that is the future
**OIDC-B** slice, which will consume this trusted backend boundary.

## Decision

A request carrying `Authorization: Bearer <access-token>` is accepted **only** when the header is
syntactically valid; the token uses the allowed asymmetric algorithm; the signature verifies against
the configured issuer's JWKS; `iss` exactly matches configuration; the configured API audience is
present; the token is unexpired; `nbf` (when present) is valid; `iat` is present and valid within a
bounded clock skew; `sub` is present, a bounded non-empty string; the exact `sub` maps to exactly one
pre-provisioned internal user; and that user's roles/permissions are resolved from SECP's database.

The following decisions are **locked**:

1. **One issuer per deployment.** Exactly one configured OIDC issuer is trusted per SECP deployment
   in this slice. (No multi-issuer support — see non-goals.)
2. **Subject is the identity key.** The token's exact `sub` claim maps to `app_user.subject`. The
   lookup is byte-exact: no lowercase, trim, normalize, slugify, or any transformation.
3. **Pre-provisioned users only.** There is **no** just-in-time user creation. A valid token for an
   unprovisioned subject is *unauthenticated*, not a signal to create a user.
4. **`sub` only.** `email`, `preferred_username`, `name`, realm roles, client roles, `groups`, and
   every other claim are **not** used to find users or to grant permissions.
5. **Database-owned authorization.** Organization membership and SECP permissions come exclusively
   from SECP database records (the user's `organization_id` and role assignments).
6. **RS256 only.** The currently accepted signing algorithm is `RS256`, from a fixed code allowlist.
7. **No symmetric / `none` / caller-selected algorithms.** Symmetric algorithms, `alg=none`,
   algorithm-confusion, and any caller-influenced algorithm choice are refused before key selection.
8. **Discovery/JWKS are configured trust infrastructure.** They are derived solely from the
   configured issuer — never caller-provided input, never a database row.
9. **Bearer-first.** A presented `Authorization` header is always evaluated before the development
   fallback; a token is never silently ignored.
10. **No fallback on token failure.** An invalid/unverifiable Bearer token never falls back to the
    dev-admin principal.
11. **Fallback only without a header.** A no-`Authorization` request may use the dev fallback only
    when its existing non-production gate (`SECP_AUTH_DEV_MODE=true` **and** `SECP_APP_ENV != production`)
    permits it.
12. **Production requirements.** Production refuses to boot unless the dev fallback is disabled, the
    issuer is an HTTPS origin+path with no embedded credentials/query/fragment, the audience is
    non-empty, and the bounded verifier settings (timeouts, cache lifetimes, clock skew, maximum
    sizes) are within safe ranges.
13. **Authentication ≠ authorization.** A valid token establishes identity only. The existing
    per-route, per-permission, and organization checks remain authoritative.
14. **Browser login is future work.** Authorization Code + PKCE, redirects/callback, token/session
    lifecycle, logout, and interactive login UX are the OIDC-B slice, not this one.

### Verifier contract (implementation lock)

`secp_api.oidc.OidcVerifier` normalizes the configured issuer by removing a single trailing slash;
fetches `<issuer>/.well-known/openid-configuration`; requires discovery `issuer` to exactly equal the
configured issuer; obtains `jwks_uri` from validated discovery; fetches/parses JWKS; selects the key
by exact `kid`; refreshes JWKS **exactly once** on an unknown `kid`; verifies with PyJWT under the
fixed `["RS256"]` allowlist; and caches discovery + JWKS with bounded, single-entry, monotonic
expirations. It performs **no** network access at import time and **none** on requests that carry no
Bearer token; it never follows redirects, uses bounded connect/read/write/pool timeouts, disables
ambient proxy/env, requires 2xx responses, caps response size before JSON parsing, rejects URL
userinfo, requires HTTPS resource URLs in production, and fails closed on unavailable/malformed trust
metadata. It never caches raw tokens or decoded claims and never persists JWKS to the database.

### Error contract

External authentication failures are **closed and redacted**: HTTP `401 {"error":{"code":
"unauthenticated"}}` with `WWW-Authenticate: Bearer`. A temporary verifier-infrastructure failure
(discovery/JWKS unavailable or malformed) is a distinct HTTP `503 {"error":{"code":
"authentication_unavailable"}}`, also with `WWW-Authenticate: Bearer`. The response never reveals
whether the cause was a bad signature, expiration, issuer, audience, `kid`, missing subject, unknown
internal user, malformed token, provider response, or network failure. Server logs may record ONE
bounded reason category (e.g. `header_invalid`, `token_malformed`, `algorithm_refused`, `key_unknown`,
`signature_invalid`, `claims_invalid`, `subject_unknown`, `provider_unavailable`) and never the
Authorization header, raw token, JWT segments, decoded claims, subject, email, JWK material, or
provider response body.

### Subject uniqueness (schema lock)

`app_user.subject` gains a **partial unique index** (`uq_app_user_subject`, portable across SQLite +
PostgreSQL): every non-null subject is globally unique, while multiple NULL subjects (users not yet
linked to an IdP identity) remain permitted. Email is **not** made globally unique and the existing
`(organization_id, email)` constraint is retained. The upgrade fails closed — without printing any
subject value — if pre-existing duplicate non-null subjects exist. The deterministic dev identity is
a well-formed UUID that equals both the dev fallback subject and the dev Keycloak user's id (so the
same seeded user resolves on both paths); it is never seeded in production.

## Non-goals (explicitly out of scope for this slice)

- **No multi-issuer support.** A future version will require an `(issuer, subject)` identity model to
  trust more than one issuer; this slice trusts exactly one and introduces no external identity table.
- **No SCIM or user federation, and no automatic account provisioning.** Users are provisioned out of
  band; the API only *reads* `app_user.subject`.
- **No interactive login / PKCE / cookies / sessions / refresh tokens / logout** (OIDC-B).
- **No remote token introspection and no opaque tokens.** Verification is local (signature + claims).

## Consequences

- The 136 `Depends(current_principal)` call sites are unchanged: real verification lives inside the
  dependency, preserving every per-route authorization check.
- Deployments must configure the issuer to exactly match the `iss` their IdP mints, provision each
  operator's `app_user.subject` = their IdP `sub`, and keep the IdP's signing keys rotatable (the
  verifier refreshes JWKS on an unknown `kid`).
- This ADR unseals **no** provisioning or infrastructure mutation; it establishes identity only.
