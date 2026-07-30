---
paths:
  - "apps/api/**"
---

# Control-plane API (`apps/api/secp_api`)

## Canonical systems — extend, never duplicate

| Concern | Canonical | Do not build |
| --- | --- | --- |
| Authentication | `deps.py:resolve_principal` (bearer verified first, never falls back) | a second acceptance path: API key header, machine JWT, service account |
| Authorization authority | `auth.py:Principal` | a third authority type. `ExchangeAuthority = Principal \| VerifiedEnrollmentExchangeActor` already exists — that precedent is not an invitation |
| Org scoping | `Principal.require_org()` (53 uses, 25 modules) | raw `actor.organization_id != loaded.organization_id` comparisons |
| Audit | `audit.py:record()` — the only `AuditEvent(` construction site | a second recorder |
| Production refusal | `config.py:_reject_unsafe_production_config` | a fourth `@model_validator`; extend the existing problems list |
| Dispatch | `dispatch.py` enqueue-only seam | inline execution anywhere but the bootstrapped Simulator |

## Invariants you can break silently

- **Authorization is service-layer, not router-layer.** Routers never call `require()`; services
  call `Principal.require(...)`. A new router that checks permissions itself looks correct and is
  architecturally wrong.
- **A route without `Depends(current_principal)` is silently public.** Nothing enumerates the
  allowed public routes; only `routers/auth_config.py` is deliberately unauthenticated.
- **Immutability is triple-layered.** A new lifecycle table needs *both* an `immutability.py`
  `before_flush` guard (portable/SQLite) *and* a PostgreSQL trigger. Adding only one leaves the
  other write path unguarded, and the tests may still pass.
- `v1alpha2` versions may only be created by the publication service; `catalog.py:create_version`
  refuses them.
- Plans re-verify their one-version binding on every mutation and fail closed with a redacted
  `plan_version_binding_invalid`.

## Contended files — check `docs/program/FILE_OWNERSHIP.md` first

`enums.py` (highest churn in the repo; `Permission` and `AuditAction` are deterministic
tail-anchor conflicts), `models.py` (the tail import/registration block at ~:2005-2061),
`config.py`, `main.py`, `immutability.py`, `errors.py`, `deps.py`, `schemas.py`, `dispatch.py`,
`apps/api/tests/conftest.py`.
