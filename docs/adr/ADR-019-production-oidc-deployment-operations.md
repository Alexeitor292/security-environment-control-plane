# ADR-019 — Production OIDC Deployment Guardrails, Preflight, and Operations

- **Status:** Accepted — implemented (OIDC-C slice)
- **Date:** 2026-07-13
- **Milestone:** OIDC-C — Production OIDC Deployment Guardrails, Preflight, and Operations
- **Deciders:** Implementation engineering
- **Related:** ADR-017 (backend bearer verification — OIDC-A, the trusted boundary consumed here);
  ADR-018 (browser Authorization Code + PKCE — OIDC-B); Charter §13 (security model);
  `docs/architecture/secp-001-design.md` §11; `docs/runbooks/oidc-production.md`.

## Context

OIDC-A (ADR-017) established strict backend bearer verification and OIDC-B (ADR-018) added the public
browser Authorization Code + PKCE login. Both are merged. What was missing was a **safe, well-defined
way to deploy** that authentication architecture to production and to reason about it operationally:
the production origin/edge contract, Host/forwarded-header trust, CORS in a bearer-token world, a
token-free deployment preflight, a placeholder-only reference configuration, and runbooks. OIDC-C
adds those guardrails. It **does not** certify the whole SECP platform as production-ready, unseal any
real provisioning/infrastructure mutation, or begin the first real disposable-lab lifecycle.

## Decision — locked

### Canonical application origin

1. Production has **one canonical public application origin** (example only: `https://secp.example.com`).
2. The production web application and the public SECP API are presented through **that same origin**.
3. Public API paths remain under `/api/`.
4. Browser callback and logout URLs are therefore `https://secp.example.com/auth/callback` and
   `https://secp.example.com/login`.
5. Production **cross-origin** browser/API deployment is out of scope for this slice.
6. Production **CORS is disabled** because the browser and API are same-origin.
7. Development may retain the exact localhost web origin required by the Vite dev server.

### Canonical issuer

8. One canonical **external HTTPS issuer** is configured.
9. The **exact same issuer string** is (a) returned to the browser, (b) expected in the access-token
   `iss`, and (c) used by the API for discovery and JWKS retrieval.
10. No separate browser issuer, internal issuer, backchannel issuer, or token-rewrite mechanism.
11. Split-horizon DNS may resolve the same canonical hostname differently inside the deployment, but
    the **issuer URL string remains identical**.
12. The issuer must be reachable with valid TLS from **both** the user's browser and the API runtime.
13. The production identity provider is **externally operated** and is **not bundled** into SECP
    production deployment assets.

### Public client

14. The browser client remains **public**; 15. **no client secret exists**; 16. Authorization Code +
    **PKCE S256** remains the only browser flow; 17. **exact** callback, logout, and web-origin
    registration is required; 18. **wildcard redirect URIs are forbidden**; 19. refresh-token
    issuance, storage, and use remain **forbidden** (ADR-018).

### Edge and proxy trust

20. TLS terminates at a **reviewed edge/ingress**. 21. The API is **not directly exposed** around
    that edge. 22. Forwarded headers are trusted **only** from explicitly configured internal proxy
    addresses, never from arbitrary clients. 23. Host validation uses an **explicit production
    allowlist** (derived from the canonical public origin, plus an optional documented internal
    health host). 24. Host or forwarded-header misconfiguration **fails closed**.

### Health and dependency behavior

25. API process **liveness must not depend on the IdP** being online. 26. An IdP outage must not
    cause a crash loop. 27. Authentication requests may return the existing closed
    `authentication_unavailable` (503) during an outage. 28. Deployment **preflight** and operator
    diagnostics may actively check discovery/JWKS, but **normal liveness must not**.

### Operational truth

29. OIDC-C provides production authentication **deployment guardrails and runbooks**.
30. OIDC-C **does not** certify the whole platform as production-ready.
31. Real provider mutation and the complete real disposable-lab lifecycle remain **sealed or
    incomplete**.
32. **Approval never becomes execution** because authentication is deployable.

## Implementation

- **`SECP_PUBLIC_ORIGIN`** (config) is the canonical public origin. In production it is validated as
  an exact HTTPS origin — scheme `https`, a host, no userinfo/query/fragment, no path beyond `/`, no
  wildcard, bounded length — and the callback/logout URLs and the Host allowlist derive from it. It
  is **not** returned from any endpoint (the browser already knows its own origin).
- **CORS** reflects the bearer-token architecture: no SECP cookie is used, so CORS never needs
  credentials. Production requires `SECP_CORS_ALLOW_ORIGINS` to be **empty** (same-origin) and the
  CORS middleware is not added. Development enables CORS only for the exact configured origin(s),
  `allow_credentials=False`, with an explicit method allowlist (`GET, POST, OPTIONS`) and header
  allowlist (`Authorization, Content-Type`), a bounded preflight cache, and no exposed headers.
  Unsafe CORS values (wildcard, protocol-relative, HTTP-in-prod, userinfo/path-bearing, localhost in
  production, multiple production origins) are **refused** — never silently rewritten.
- **Host validation** uses Starlette's `TrustedHostMiddleware` in production with the canonical host
  (and optional `SECP_INTERNAL_HEALTH_HOST`); `www_redirect=False` so no redirect is built from the
  Host header; `/health` is subject to the same allowlist (no bypass). Development/test apply no
  allowlist for convenience/determinism. Browser callback URLs derive from `window.location.origin`,
  never from a backend Host header.
- **Preflight** — `python -m secp_api.oidc_preflight` — reuses the OIDC-A hardened HTTP seam
  (`fetch_document_bytes` / `require_safe_url` / `build_client_factory`: bounded timeout/size, no
  redirects, `trust_env=False`) to fetch discovery + JWKS, require the discovery issuer to exactly
  match configuration, validate endpoint URLs are HTTPS with no userinfo, confirm at least one usable
  RSA signing key with a non-empty `kid`, and report whether S256 is advertised. It **never** logs
  in, obtains/validates a user token, requires a password/secret, prints a discovery body/JWK/token,
  touches the database, or writes an audit event. Stable exit codes: `0` ok, `1` local config
  invalid, `2` provider unavailable, `3` provider metadata invalid. Absence of advertised S256 is an
  operator **warning**, not proof — the operator confirms PKCE S256 is enforced on the IdP client.
- **Frontend same-origin** — the API base is `window.location.origin` in a browser build with no
  explicit `VITE_API_BASE_URL`; production never falls back to a localhost API. The bearer is only
  ever attached to that resolved API origin.

## Consequences

- Same-origin production deployment is the **locked** OIDC-C model; a cross-origin browser/API split
  would need a separate reviewed design (CORS + forwarded-header trust re-opened).
- Users must already exist internally; the exact OIDC `sub` binds to one pre-provisioned user
  (ADR-017). Token email/username/roles/groups cannot provision or relink a user. SECP has **no**
  first-class production identity-lifecycle API/UI/CLI in this slice; a direct DBA change is outside
  the SECP application mutation path and is **not** SECP-audited (it creates no `AuditEvent`), so any
  unavoidable emergency change must use the operator's own controlled, externally-audited DB-change
  process. Production rollout must not proceed until the required `sub` bindings are independently
  verified. A transactional, authorization-gated, SECP-audited identity-administration workflow
  remains future work. The operator procedure + verification gate are in
  `docs/runbooks/oidc-production.md`.
- This ADR unseals **no** provisioning/infrastructure path and adds no backend session/BFF, cookie,
  token database, JIT provisioning, or refresh-token flow. Long-lived browser sessions remain future,
  separately-reviewed work.
