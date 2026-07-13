# SECP production OIDC deployment — reference guardrails (ADR-019 / OIDC-C)

These are **reference deployment guardrails, not a turnkey production stack**. They describe the
same-origin production authentication model and the environment guardrails a deployment must satisfy.
Nothing here deploys anything, bundles an identity provider, introduces credentials, or unseals any
infrastructure action. Real provisioning and the complete real disposable-lab lifecycle remain sealed
or incomplete. See [ADR-019](../../docs/adr/ADR-019-production-oidc-deployment-operations.md) and the
operations runbook at [`docs/runbooks/oidc-production.md`](../../docs/runbooks/oidc-production.md).

> **This does not make the whole SECP platform production-ready.** OIDC-C makes the *authentication
> architecture* safely deployable and operationally understandable. Pre-provisioned internal
> identities are still required, the development stack remains unsafe for production, and real
> infrastructure execution remains sealed.

## Files

- [`oidc.env.example`](./oidc.env.example) — placeholder-only environment guardrails. No secrets, no
  client secret, no private key, no token, no real hostname, no admin credentials. `DATABASE_URL` and
  all other credentials come from the deployment's secret manager and are intentionally omitted.

There is intentionally **no production Compose/Kubernetes stack and no production Keycloak container**
here. A governing production deployment contract is out of scope for this slice; do not invent one.

## Same-origin model (summary)

- One canonical public origin (example only: `https://secp.example.com`) serves both the web app and
  the public SECP API (`/api/`). Callback/logout URLs are `…/auth/callback` and `…/login`.
- CORS is **disabled** in production (same-origin); `SECP_CORS_ALLOW_ORIGINS` must be empty.
- Host validation allows only the canonical host (plus an optional documented internal health host).
- The issuer is one canonical external HTTPS string, identical for the browser, the token `iss`, and
  the API's discovery/JWKS. The IdP is externally operated and not bundled.
- The browser client is public (no secret); Authorization Code + PKCE S256 only; no refresh tokens.
- Do not set `VITE_API_BASE_URL` in the production web build (same-origin).

## User identity (required before rollout)

All required internal users and their exact OIDC `sub` bindings must already exist in SECP and be
**independently verified before rollout**. SECP has **no** first-class production identity-lifecycle
API/UI/CLI in this slice; a direct DBA `subject` change is outside the SECP application mutation path
and is **not** SECP-audited (creates no `AuditEvent`) — any unavoidable emergency change must use the
operator's own controlled, externally-audited DB-change process. A transactional, authorization-gated,
SECP-audited identity-administration workflow remains future work. See the runbook §3.

## Pre-deployment validation

Run the token-free preflight against the target configuration before going live (it performs no
login, obtains no token, and touches no database):

```
SECP_APP_ENV=production python -m secp_api.oidc_preflight        # human-readable
SECP_APP_ENV=production python -m secp_api.oidc_preflight --json # categories/booleans only
```

Exit codes: `0` ok · `1` local configuration invalid · `2` provider unavailable · `3` provider
metadata invalid.

## Edge-security checklist (documented, NOT auto-enforced here)

The reviewed TLS edge/ingress in front of SECP is expected to enforce the controls below. **These are
requirements for the edge, not controls implemented by this repository** — do not treat them as active
unless your committed, validated edge/ingress artifact actually enforces them:

- [ ] TLS 1.2+ (or the current organization baseline) terminating at a reviewed edge.
- [ ] HSTS at the external HTTPS edge.
- [ ] `X-Content-Type-Options: nosniff`.
- [ ] A restrictive `Referrer-Policy`.
- [ ] Clickjacking protection via CSP `frame-ancestors` (or an equivalent).
- [ ] A CSP that permits **only** the exact application origin and the exact OIDC origin(s) required
      by *your* deployed provider. Do not commit a CSP naming a fake hard-coded provider domain, and
      do not use `connect-src https:` as a lazy universal allowlist.
- [ ] Callback responses are not cached.
- [ ] Callback query strings are not logged.
- [ ] Request-size limits at the edge.
- [ ] The backend API is not publicly reachable **around** the edge.
- [ ] Forwarded headers (`X-Forwarded-Host` / `X-Forwarded-Proto` / `Forwarded`) are trusted **only**
      from the explicitly configured internal proxy addresses, never from arbitrary clients.
