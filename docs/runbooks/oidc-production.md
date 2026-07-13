# Runbook — Production OIDC operations (ADR-019 / OIDC-C)

Operational procedures for deploying and running SECP's OIDC authentication in production. This
covers the **authentication architecture only**. It does **not** make the whole SECP platform
production-ready: pre-provisioned internal identities are required, real provisioning remains sealed,
and the complete real disposable-lab lifecycle is incomplete.

Related: [ADR-017](../adr/ADR-017-oidc-bearer-authentication.md) (backend bearer verification),
[ADR-018](../adr/ADR-018-oidc-browser-pkce-authentication.md) (browser PKCE login),
[ADR-019](../adr/ADR-019-production-oidc-deployment-operations.md) (this slice),
[`infra/production/`](../../infra/production/README.md) (reference guardrails).

Throughout: never put tokens, authorization codes, `state`, `nonce`, PKCE verifiers, JWK material, or
provider response bodies in tickets, logs, or chat. Safe to record: exact timestamps, deployment
version, issuer **hostname**, and a bounded failure **category**.

## 1. Pre-deployment

- [ ] Decide the **one canonical public origin** (example only: `https://secp.example.com`); the web
      app and the SECP API (`/api/`) are served **same-origin** from it.
- [ ] DNS resolves the canonical hostname to the reviewed edge/ingress (split-horizon DNS may resolve
      it differently inside the deployment, but the issuer **string** stays identical).
- [ ] A trusted TLS certificate is valid for the canonical origin, and the issuer presents valid TLS.
- [ ] Both the **user's browser** and the **API runtime** can reach the exact issuer over HTTPS.
- [ ] The exact issuer string is agreed and identical for: the browser (`/api/v1/auth/config`), the
      access-token `iss`, and the API's discovery/JWKS. No separate browser/internal/backchannel
      issuer, no token rewriting.
- [ ] Same-origin edge routing is configured; `SECP_CORS_ALLOW_ORIGINS` is empty; `SECP_PUBLIC_ORIGIN`
      is the canonical HTTPS origin; `VITE_API_BASE_URL` is **unset** in the production web build.
- [ ] Secrets (`DATABASE_URL`, etc.) are injected from the deployment's secret manager, never
      committed. There is no client secret (public client) and no refresh-token flow.
- [ ] Database migrations run **separately** (`alembic upgrade head`) from the API replicas — the API
      never auto-creates the schema or seeds an admin in production.
- [ ] Required internal users and their exact OIDC `sub` bindings already exist and have been
      **independently verified** (§3) — rollout must not proceed otherwise.
- [ ] Production flags remain sealed: `SECP_AUTH_DEV_MODE=false`, `SECP_WORKFLOW_DISPATCH_MODE=temporal`,
      `SECP_ENABLE_FAKE_PROVISIONING=false`, `SECP_ENABLE_REAL_PROVISIONING=false`,
      `SECP_ENABLE_OPENTOFU_SUBPROCESS=false` (the Settings validator hard-refuses any other value).

## 2. IdP client registration

Register the browser client on the externally-operated IdP (not bundled by SECP):

- [ ] **Public** client (no secret).
- [ ] Authorization Code flow **enabled**.
- [ ] **PKCE S256 required**.
- [ ] Implicit flow **disabled**.
- [ ] Password / direct-access grant **disabled**.
- [ ] Service account / client credentials **disabled**.
- [ ] **Exact** callback URI `https://<canonical>/auth/callback` — no wildcard.
- [ ] **Exact** post-logout URI `https://<canonical>/login` — no wildcard.
- [ ] **Exact** web origin `https://<canonical>` — no wildcard.
- [ ] No `offline_access`.
- [ ] Refresh-token issuance **disabled** where the provider supports it (defense in depth: the
      frontend also strips any refresh token — ADR-018).
- [ ] The access token carries the exact `secp-api` audience.
- [ ] The token issuer exactly matches `SECP_OIDC_ISSUER`.

Then run the token-free preflight (§4) to confirm discovery/JWKS agree before any user logs in.

## 3. User identity (pre-provisioning) and the remaining gap

- **All required users and their exact OIDC `sub` bindings must already exist in SECP BEFORE
  production rollout.** The exact OIDC `sub` binds to exactly one internal user (`app_user.subject`);
  organization/roles/permissions come only from SECP's database. Token `email` / `username` /
  `roles` / `groups` **cannot** provision or relink a user, and there is **no** just-in-time
  creation. Do **not** rely on email-based linking.
- **SECP currently has no first-class production identity-lifecycle API, UI, or operator command**
  for creating internal users or setting/rotating a `subject`. There is no supported in-application
  mutation path for this in OIDC-C.
- **A direct database change is OUTSIDE the supported SECP application mutation path.** It bypasses
  the application services and is **NOT** automatically protected by SECP's application audit service
  (no `AuditEvent` is created). Do **not** treat a direct DB write as satisfying SECP's audit
  invariant, and do not run ad-hoc SQL as a routine provisioning step.
- **If an emergency DBA change is unavoidable**, perform it only through the operator organization's
  own controlled database-change process, with an **external** (out-of-band) audit/change record and
  review — never as, or described as, an SECP-audited application action.
- **Production rollout must not proceed until the required internal users and `subject` bindings have
  been independently verified** — e.g. a read-only confirmation that each intended operator's IdP
  `sub` maps to exactly one intended internal user.
- **A transactional, authorization-gated, SECP-audited identity-administration workflow (API/UI/CLI)
  remains future work.** Do not invent an unsupported production user-management path in the meantime.

## 4. Rollout

1. Validate configuration **offline** (the Settings validator refuses an unsafe production config at
   startup; a misconfig fails fast rather than booting unsafe).
2. Run the **OIDC preflight** against the target config (no login, no token, no DB write):
   `SECP_APP_ENV=production python -m secp_api.oidc_preflight` (add `--json` for CI). Exit `0` = ok,
   `1` = local config invalid, `2` = provider unavailable, `3` = provider metadata invalid.
3. Run database migrations **separately** from the API replicas.
4. Deploy API / worker / web **behind the edge** (the API is not publicly reachable around it).
5. Check **liveness** — `/health` returns `{"status":"ok"}` and does **not** contact the IdP.
6. Check the **public auth config** — `GET /api/v1/auth/config` returns `mode: "oidc"` (production can
   never be `dev_fallback`), the issuer, public client id, audience, fixed scope, and relative paths.
7. Complete **one canary login** through the browser PKCE flow.
8. Verify `GET /api/v1/me` returns the expected pre-provisioned identity.
9. Verify a **permitted** route succeeds.
10. Verify a **controlled 403** (a route the identity lacks permission for) is denied.
11. Verify **logout** clears local state and invokes the provider end-session.
12. Verify an **expired/invalid token** returns a closed **401**.
13. Verify an **IdP outage** surfaces the closed **503** `authentication_unavailable` (not a crash).
14. Verify **no dev fallback** — a request with no `Authorization` header is refused (not dev-admin).

## 5. Key rotation

- Publish **overlapping old + new** signing keys at the IdP (both `kid`s in JWKS).
- Rely on the verifier's **exact-`kid` JWKS refresh** (a bounded, single refresh on an unknown `kid`).
- Validate rotation with the **preflight** (confirms a usable RSA signing key is present).
- Do **not** restart the API solely to accept a new unknown `kid` — the bounded refresh already picks
  it up; restart only when diagnosing a suspected cache problem.
- Remove the **old** key only after the maximum token-lifetime + JWKS-cache **overlap** has elapsed.

## 6. Outage response

- Distinguish **API liveness** (independent of the IdP) from **authentication availability** (needs
  the IdP). An IdP outage yields closed `503 authentication_unavailable`, not a crash loop.
- Do **not** enable the dev fallback.
- Do **not** disable TLS verification.
- Do **not** bypass signature / audience / issuer checks.
- Existing sessions keep working only for the **valid lifetime of their access token** — there is
  **no refresh-token recovery**. When the IdP returns, new logins resume normally.

## 7. Disable / revoke access

- Revoke the provider sessions/tokens where the IdP supports it.
- Disable or unbind the **internal subject** through the documented supported operator process (§3) —
  e.g. clearing/rotating the internal user's `subject` so the IdP `sub` no longer maps to a user.
- Remove internal role assignments where appropriate.
- Confirm `/api/v1/me` and protected routes **fail closed** for that identity.
- Never rely on **browser logout alone** as revocation — it clears local browser state, not server or
  provider trust.

## 8. Rollback

- Roll back the application version **without** enabling dev mode or the dev fallback.
- Preserve the current database migration compatibility rules (do not downgrade the schema under a
  running newer API; follow the project's migration policy).
- Do **not** restore old wildcard redirect/CORS rules.
- Do **not** restore a client secret or a refresh-token flow.
- Run the **preflight** again after rollback to confirm the (possibly older) config still agrees with
  the IdP.

## 9. Incident evidence

- Record only **safe reason categories** (e.g. `provider_unavailable`, `signature_invalid`,
  `authentication_unavailable`) plus exact timestamps, deployment version, and the issuer **hostname**.
- **Never** put tokens, authorization codes, `state`, `nonce`, PKCE verifiers, JWK material, or
  provider response bodies in tickets or logs.
