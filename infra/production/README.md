# SECP production deployment reference guardrails

These are **reference deployment guardrails, not a turnkey production stack**. They describe the
same-origin OIDC model and the narrow PR5F production activation contract for the existing B8
worker-owned read-only discovery path. Nothing in this directory deploys anything, bundles an identity
provider, commits a deployment value/certificate/private key, installs an operator, or enables
OpenTofu/apply/destroy. See
[ADR-019](../../docs/adr/ADR-019-production-oidc-deployment-operations.md), the
[OIDC operations runbook](../../docs/runbooks/oidc-production.md), and the
[PR5F B8 activation runbook](../../docs/runbooks/pr5f-b8-production-activation.md).

> **This does not make the whole SECP platform production-ready.** OIDC-C makes the *authentication
> architecture* safely deployable and operationally understandable. Pre-provisioned internal
> identities are still required, the development stack remains unsafe for production, and real
> infrastructure mutation remains sealed. PR5F makes only the existing read-only discovery path
> deployable through an explicit reviewed host action; its repository implementation has not been
> installed or exercised by this change.

## Files

- [`oidc.env.example`](./oidc.env.example) — placeholder-only environment guardrails. No secrets, no
  client secret, no private key, no token, no real hostname, no admin credentials. `DATABASE_URL` and
  all other credentials come from the deployment's secret manager and are intentionally omitted.
- [`secp_discovery_activation`](../../apps/deployment/secp_discovery_activation/) — the importable
  PR5F package renders/validates a separately reviewable
  ordinary-worker Compose override and a narrowly allowlisted internal admission-listener artifact
  from root-controlled deployment-local inputs. Rendered deployment artifacts, certificates, keys,
  hostnames, IPs, organization ids, and certificate identities are intentionally not committed here.

There is intentionally **no complete production Compose/Kubernetes stack and no production Keycloak
container** here. PR5F's narrow rendered worker/admission overlay is not a full controller deployment
and must not be treated as one. Do not invent unrelated services or broaden its route/mount scope.

## PR5F B8 boundary

- Host state is fixed at `/var/lib/secp/discovery-worker` and bind-mounted read-write only into the
  ordinary worker at `/var/run/secp`.
- The root-controlled activation profile/artifacts live beneath
  `/etc/secp/discovery-activation`; authenticated evidence/journal lives beneath
  `/var/lib/secp/discovery-activation`.
- The narrow controller and worker overrides are composed only with the fixed root-owned base files
  `/etc/secp/controller/docker-compose.yml` and `/etc/secp/worker/docker-compose.yml`. Their
  content/uid/gid/mode bindings are journaled and compare-and-swap checked before every Compose
  mutation and rollback.
- The controller base Compose file interpolates fixed `${SECP_*}` variables, supplied explicitly with
  the single code-owned fixed environment file `/etc/secp/controller/secp.env` via `--env-file` on
  every controller Compose op (activation, retry, compensation, rollback) — never a profile path,
  ambient environment, or working-directory guess. It must be a nonempty single-link root-owned
  (`uid 0`, mode `0600`/`0640`) regular file containing only single-line `NAME=value` assignments
  that resolve to a non-empty literal. Empty, multi-line/quoted-spanning, `export`-prefixed,
  inline-commented, and `$`-bearing values are refused before staging (compose-go expands `$VAR`
  even inside double quotes, and the fixed child environment would resolve it to an empty string) —
  single-quote a literal that must contain `$`/`#`/`"`/spaces. Before any controller mutation the
  package proves it covers every interpolated `${SECP_*}`. Only a private digest/uid/gid/mode binding is journaled
  (never the bytes) and re-proven before each controller Compose mutation and rollback; any drift
  refuses closed. The worker never receives it (it keeps its service-level `env_file`). The contents
  never appear in the journal, status, evidence, exceptions, or argv. **Deployment must atomically
  copy the already-reviewed protected environment file to this canonical path before installation.**
- The worker receives a read-only pinned CA certificate, never the admission server private key.
- The listener exposes only the existing worker-discovery-admission routes. Worker identity is the
  existing Ed25519 signed-nonce proof, **not client-certificate mTLS**.
- The admission endpoint's DNS name is the exact certificate SNI/SAN identity, while the proxy binds
  only the reviewed private listener IP. The worker has exactly one `extra_hosts` DNS-to-listener-IP
  mapping; host probes connect to the IP while validating the DNS identity.
- The ordinary worker retains its exact reviewed base image, health/hardening and sole queue
  `secp-orchestration`, but that image is **not** the whole PR5F runtime. A complete deterministic
  `secp_api` + `secp_worker` ZIP, pinned by digest, is imported at the fixed root-owned path, mounted
  read-only at `/opt/secp/secp-pr5f-runtime-overlay.zip`, and made the exact `PYTHONPATH`. No partial
  overlay or image-only readiness claim is valid.
- Controller preflight binds the exact deployment-reviewed `controller_api_baseline_image_digest`
  at head `c4e2f9a1b7d3`; the controller then uses a separately built, digest-qualified
  `controller_api_image` containing PR5F, whose actual identity and head `d8f1a2b3c4e5` must verify.
  The admission proxy is also
  digest-pinned and its actual hardening, mounts, network ownership, and private listener are checked.
- The `d8f1a2b3c4e5` PostgreSQL migration installs and validates a named `CHECK` fence that rejects new
  `ed25519_signed_nonce` registrations throughout the signed two-host handoff. A runtime rollback
  requires the exact current, complete role-local journal: its preliminary compatibility read must
  pass, then the exact transaction-owned API container or worker overlay engages the durable fence;
  internal compensation rebinds and re-engages it immediately before mutation. The controller
  downgrade independently canonicalizes and retains the same fence for the pre-PR5F interval.
- TLS production input is import-only: controller CA/certificate/key files and the worker's CA-only
  copy use the exact `/etc/secp/discovery-activation/import/` paths and metadata described by the
  runbook. The overlay import is exactly
  `/etc/secp/discovery-activation/import/secp-pr5f-runtime-overlay.zip` (`root:root 0644`).
- No operator service/queue/registration is installed.
- Public runtime evidence contains only a redacted configuration-shape digest. The full Docker
  configuration is bound by a domain-separated HMAC derived from the root-controlled evidence key,
  kept only in the `root:root 0600` live rollback journal, and compared in constant time. Mount
  isolation uses no-follow device/inode/type identities across two samples, so path aliases,
  bind-mount/hardlink/symlink overlap, unresolvable sources, and identity drift refuse closed.
- Controller and worker exchange only detached-signed fixed-path handoffs: controller outbox offer to
  worker inbox, then worker outbox result to controller inbox. The operator transports each
  payload/attestation pair unchanged as `root:root 0640`; only the controller's second explicit
  install can finalize: it commits and independently authenticates aggregate evidence while the
  exact live fence remains engaged, then releases the fence and freshly proves both the released
  state and the complete aggregate chain. A crash after evidence commit resumes from
  `awaiting-finalization`; a crash after release is reverified idempotently. `verify` and `status`
  remain read-only and never engage or release the fence.
- The existing read-only Proxmox strap is not replaced. After fresh persistent worker-key generation,
  its key is rotated/bound solely by the existing idempotent Read-Only Bootstrap wizard script. The
  wizard then requires the composite deployment-binding, verification-anchor, and
  rotation/revocation reviews against the exact node revision and fingerprints before identity link;
  an exact expired/revoked same-node link can be atomically renewed to a monotonic identity version,
  while live-read authorization remains a separate approval/binding gate.
- Worker bundle assembly additionally requires the bound session descriptor's recorded SSH
  public-key fingerprint to equal the fingerprint freshly derived from the current local worker key;
  stale or legacy descriptors are refused before the fixed bundle is touched. Live discovery scopes
  identity uniqueness to Ed25519 signed-nonce registrations, while the composite same-label review
  refuses and preserves any active non-Ed25519 identity rather than revoking it.
- No controlled-live plan composition is installed, no real OpenTofu plan has run, apply/destroy are
  unavailable, and PR6 remains frozen.

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
