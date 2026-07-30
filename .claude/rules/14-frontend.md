---
paths:
  - "apps/web/**"
---

# Frontend (`apps/web`)

React 18 + TypeScript 5.6 + Vite. 20 routes in one `createBrowserRouter` (`main.tsx:35-77`),
every application route wrapped in one `AuthBoundary`. Nearly all pages are wired to real
backend endpoints — the "simulated" framing comes from what the backend does, not frontend fakes.

The frontend has its **own required CI context**: *"Frontend (types, lint, build, tests,
security)"*. Backend-only validation does not cover it.

## Machine-enforced security posture — do not weaken

`apps/web/src/auth/boundary.test.ts` scans stripped sources and enforces:

- **Session-scoped tokens only.** No `localStorage`, no `IndexedDB`, no cookies, no
  service-worker cache, no DB persistence.
- **`sessionStorage` only through the reviewed seam.**
- **No refresh token, no silent renewal, no `offline_access`.** Access-token expiry clears local
  state and requires a fresh interactive login.
- **Header-only bearer.** The ID token is never an API credential.
- **Production API base is same-origin**, never a localhost fallback.

`/api/v1/me` is the authoritative browser identity. Token claims never determine organization,
role or permission.

Fail-closed behaviour: invalid callback, `state`/`nonce` mismatch, token error or **401** → back
to `/login` with a sanitized same-origin return path; **403** keeps the session; **503** shows a
provider-unavailable message. Error text is bounded categories — never a token, code, state,
nonce, verifier, claim, subject or provider detail.

## Canonical systems

- **One API client:** `src/api/client.ts` (110 methods) with `resolveApiBase` and
  `buildRequestHeaders`. Never call `fetch()` directly for a download, SSE, WebSocket or stream —
  that re-implements the Authorization header and bypasses the same-origin lock.
- **One token seam:** `src/auth/apiAuth.ts`.

## Contended files

`src/api/client.ts`, `src/api/types.ts` (912 lines — `Principal`/`AuthConfig` share it with every
feature DTO), `src/main.tsx` (the single route table), `src/App.tsx` (nav shell). All four are
edited by nearly every UI milestone; check `docs/program/FILE_OWNERSHIP.md` before touching them.
