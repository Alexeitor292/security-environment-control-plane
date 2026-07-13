# SECP-001 — Control Plane Foundation: Design

**Status:** Accepted for implementation
**Milestone:** SECP-001
**Governing document:** [`docs/PROJECT_CHARTER.md`](../PROJECT_CHARTER.md)
**Related ADRs:** ADR-001 … ADR-005

---

## 1. Purpose and scope

SECP-001 establishes the **control-plane foundation** for the Security Environment
Control Platform. It delivers a runnable monorepo, a local development stack, the
core domain model, the immutable environment-version model, the deployment-plan
approval workflow, an audit trail, a reference **Simulator Plugin**, and a vertical
slice that drives a two-team simulated exercise from definition to destroy — entirely
against simulated records in PostgreSQL.

SECP-001 deliberately does **not** touch real infrastructure. No Proxmox, VMware,
Hyper-V, cloud accounts, OpenTofu/Terraform providers, Ansible inventories, home
networks, external APIs, or real Wazuh/CTFd/Security Onion. The only execution
environment is local Docker Compose plus the Simulator Plugin. See
[`docs/PROJECT_CHARTER.md` §16](../PROJECT_CHARTER.md) for the MVP scope boundary.

This document explains the design. The slice-by-slice build order, acceptance
criteria, and test expectations live in
[`docs/implementation/secp-001-plan.md`](../implementation/secp-001-plan.md).

---

## 2. Control-plane boundaries

The platform is a **control plane**: the authoritative system of record for desired
state, lifecycle, topology intent, plans, approvals, and audit. Underlying
infrastructure is an *execution target* and a *source of observed state*, never the
system of record (Charter §4.1, Invariant 1).

The boundary is enforced by separating responsibilities into four planes:

```
┌──────────────────────────────────────────────────────────────────────┐
│  Experience plane        apps/web        React + TypeScript            │
│    - dashboards, editors, approval screens, topology, audit views      │
└───────────────▲────────────────────────────────────────────────────────┘
                │ HTTP/JSON (versioned REST)
┌───────────────┴────────────────────────────────────────────────────────┐
│  Core control plane      apps/api       FastAPI                         │
│    - authN/authZ, org/team/RBAC, templates, immutable versions          │
│    - plan generation, approval gate, audit, topology projection (read)  │
│    - NEVER executes privileged infrastructure actions                   │
└───────────────▲───────────────────────────────────────▲────────────────┘
                │ WorkflowDispatcher (interface)         │ SQLAlchemy
                │                                          │
┌───────────────┴───────────────────┐      ┌─────────────┴────────────────┐
│  Orchestration plane  apps/worker  │      │  System of record  PostgreSQL │
│    - durable workflows (Temporal)  │      │   control-plane tables +      │
│    - drives plugins via contract   │      │   simulated-resource tables   │
│    - deploy / reset / destroy       │      └───────────────────────────────┘
└───────────────▲────────────────────┘
                │ Plugin API (versioned contract)
┌───────────────┴────────────────────────────────────────────────────────┐
│  Plugins                 plugins/simulator                              │
│    - validate / plan / apply / status / reset / destroy / health        │
│    - Simulator writes ONLY simulated records to PostgreSQL               │
└──────────────────────────────────────────────────────────────────────────┘
```

**Hard boundary rule (Charter Invariants 6, 7):** the API process must not run shell
commands, IaC engines, configuration management, or provider SDKs. It may only:

1. read/write control-plane state in PostgreSQL,
2. generate deterministic deployment plans (pure functions over an environment
   version), and
3. *dispatch* workflow runs through a `WorkflowDispatcher` interface.

All privileged or side-effecting execution happens in the **worker** through
**plugins**. In SECP-001 the only plugin is the Simulator, whose "side effects" are
limited to writing simulated rows — but the seam is built as if the plugin were
Proxmox, so the boundary is real, not cosmetic.

---

## 3. API versus worker responsibilities

| Concern | API (`apps/api`) | Worker (`apps/worker`) |
| --- | --- | --- |
| AuthN / AuthZ | ✅ owns | consumes scoped context |
| Org / User / Role / Team CRUD | ✅ | — |
| Template + immutable version | ✅ create/read | reads version snapshot |
| Plan generation | ✅ pure, deterministic | — |
| Approval gate | ✅ records decision | refuses to apply unapproved plans |
| Workflow dispatch | ✅ *enqueues* runs | ✅ *executes* runs |
| Plugin execution | ❌ never | ✅ only here |
| Observed-state ingestion | reads projection | ✅ writes via plugin status |
| Audit events | ✅ for API mutations | ✅ for workflow transitions |

The API and worker share **models and contracts** (one SQLAlchemy model layer, the
plugin API package, the scenario-schema package) but have **different privileges and
different runtime trust**. The API is internet-adjacent; the worker is isolated and
holds the credentials/capabilities to touch execution targets (none real in SECP-001).

The **dispatch seam** is an interface, `WorkflowDispatcher`, with two
implementations:

- `InlineDispatcher` — runs the orchestration synchronously in-process. Used for
  tests and for a zero-dependency local demo. Because the Simulator only writes
  simulated rows, running it inline is safe; this is explicitly a *development*
  convenience, documented as such.
- `TemporalDispatcher` — enqueues the workflow on Temporal; the separate worker
  process executes it durably. This is the production-shaped path.

The mode is selected by `WORKFLOW_DISPATCH_MODE` (`inline` | `temporal`). See
[ADR-005](../adr/ADR-005-workflow-engine-boundary.md).

---

## 4. Plugin boundary and contract approach

Every external integration is a **plugin** behind a versioned contract (Charter §11,
Invariant 8). The contract lives in [`contracts/plugin-api`](../../contracts/plugin-api)
and is independently versioned (`v1`). It defines a capability surface:

```
validate(spec)            -> ValidationResult
plan(version, instances)  -> PluginPlan          # deterministic, no side effects
apply(plan)               -> ApplyResult          # creates/updates resources
status(instance)          -> ObservedState        # observed state read-back
reset(instance)           -> ResetResult          # restore known-good baseline (idempotent)
destroy(instance)         -> DestroyResult         # idempotent, safe to retry
health()                  -> HealthReport          # liveness + capability + version
```

Design rules:

- The control plane talks to **capabilities, never to a vendor**. There are no
  provider-specific columns or branches in the core (Charter Invariant 9). A plugin
  advertises which capabilities it supports via `health()`.
- Plans are **deterministic** functions of an immutable environment version plus the
  set of target instances. The same version + targets always produce the same plan
  shape. This is what makes "approve exactly what will happen" meaningful.
- `apply`, `reset`, and `destroy` are **idempotent state-machine steps**. They accept
  being called again on an already-converged instance and return success without
  duplicating resources.
- Plugins are configured through **secure references**, not plaintext secrets
  (Charter §11). In SECP-001 the Simulator needs no secrets.

See [ADR-003](../adr/ADR-003-plugin-contract.md).

---

## 5. Desired state vs. observed state

The platform distinguishes the state vocabulary from Charter §14:

- **Desired state** — the immutable `EnvironmentVersion` spec. What the operator
  asked for.
- **Planned state** — the `DeploymentPlan`: a deterministic, reviewable expansion of
  desired state into concrete create/configure/reset/destroy actions for specific
  instances.
- **Observed state** — what a plugin's `status()` reports about the simulated
  resources (nodes up, networks present, lifecycle state). Stored on
  `EnvironmentInstance` and the simulated-resource tables.

Reconciliation in SECP-001 is shallow: `apply` writes simulated resources, `status`
reads them back, and the topology projection (read model) joins desired + observed.
Full drift detection and reconcile loops are an SECP-002+ concern and are recorded as
a placeholder.

The control plane never lets observed state overwrite desired state. Observed state is
attached *alongside* the version, so a reset can always return to the known-good
baseline declared by the version (Charter Invariant 14).

---

## 6. Immutable environment version model

`EnvironmentTemplate` is a mutable, human-facing concept ("Web Breach 101"). An
`EnvironmentVersion` is an **immutable snapshot** of that template's declarative spec
(Charter §7, Invariant 2).

Mechanics:

- A version stores the full normalized spec as JSON plus a **content hash**
  (SHA-256 of canonicalized spec) and a monotonically increasing `version_number`
  per template.
- Once a version row is `created`, the application layer refuses any update to its
  `spec`, `content_hash`, or `version_number`. Enforcement is layered:
  1. **Service layer** — no update path exists; the repository exposes create + read
     only for version spec fields.
  2. **Database guard** — a trigger/`CHECK`-style protection (or an `ON UPDATE`
     rejection in Postgres) prevents spec mutation even on direct SQL. Documented in
     the migration; in tests we assert the service layer rejects it.
- Every `Exercise` references **exactly one** `EnvironmentVersion`
  (Charter Invariant 3). Every `DeploymentPlan` is generated from **exactly one**
  version (Invariant 4). The plan stores the version's `content_hash` so an approver
  can verify the plan matches the version they think they're approving.

See [ADR-002](../adr/ADR-002-scenario-versioning.md).

---

## 7. Deployment-plan approval workflow

Approval is a hard gate (Charter Invariants 4, 5). The lifecycle:

```
draft ─validate→ validated ─plan→ planned ─submit→ awaiting_approval
                                                        │
                                       approve ◄────────┤────► reject → validated
                                                        ▼
                                                    approved ─apply→ deploying → running
```

Rules enforced by the service layer and tested:

- A `DeploymentPlan` is generated only from a `validated` (or later) version-backed
  exercise. Generation moves the exercise to `planned`.
- Submitting moves to `awaiting_approval`. Apply is **refused** unless the plan is
  `approved` by a user holding an approver role. Attempting to apply an unapproved
  plan raises a domain error and writes an audit event recording the refusal.
- Approval records *who*, *when*, and the *version content hash* approved. If the
  underlying version could somehow differ from the approved hash, apply refuses.
- Approval and rejection are themselves audited mutations.

See [ADR-004](../adr/ADR-004-approval-gate.md).

---

## 8. Per-team environment isolation model

An `Exercise` runs one environment version for N teams. **Each team assignment creates
its own `EnvironmentInstance`** (Charter Invariant 5, §8). Instances are isolated by
default (Invariant 11); cross-instance connectivity must be explicitly declared and
approved (Invariant 12) — not in scope for SECP-001, recorded as a placeholder.

Isolation is modeled, in SECP-001, as **data isolation in the projection**:

- Each `EnvironmentInstance` owns its own simulated networks, nodes, and topology
  edges. Simulated networks get per-team CIDRs from a deterministic allocation
  strategy (`per-team`), so team 1 and team 2 never share a subnet.
- The topology projection for a team is filtered to that team's instance id. The API
  authorization layer ensures a participant in team 1 cannot read team 2's instance
  (org + team scoping).
- There are **no shared edges** between two team instances in the simulated topology.
  Shared services (identity, scoring) are modeled as separate nodes that, in a real
  deployment, must not create lateral connectivity (Charter §8); in SECP-001 they are
  represented as out-of-band references, not as topology edges into team networks.

A test asserts that two teams' instances have disjoint network CIDRs, disjoint node
sets, and no cross-instance topology edges.

---

## 9. Reset and destroy state-machine behavior

Reset and destroy are **idempotent state-machine operations** (Charter Invariants 14,
15; assignment Phase 2 rule 8).

**Reset** restores a single instance to the known-good baseline declared by its
environment version:

```
running ─reset→ resetting ─(plugin.reset)→ running
```

- Reset operates per `EnvironmentInstance` (one team can be reset without touching the
  others).
- Idempotency: calling reset on an instance already at baseline is a no-op success.
  The plugin rebuilds simulated nodes/networks deterministically from the version, so
  the resulting topology is identical regardless of how many times reset runs.

**Destroy** tears down all instances of an exercise:

```
running ─destroy→ destroying ─(plugin.destroy per instance)→ destroyed
```

- Destroy is idempotent: destroying an already-`destroyed` exercise/instance returns
  success without error and without creating duplicate audit/teardown work.
- Destroy is safe to retry after a partial failure; each instance's destroy is
  independently idempotent, so a retry completes the remainder.

Both operations are driven through the worker boundary and the plugin contract, and
every transition emits an audit event.

---

## 10. Topology projection model

Topology is a **live operational projection**, not a stored diagram (Charter §8, §14).
The projection is computed (read-side) by joining:

- declared intent (networks/roles from the environment version),
- simulated inventory (`SimulatedNetwork`, `SimulatedNode`),
- topology edges (`SimulatedTopologyEdge`),
- lifecycle/health state on the instance.

The API exposes a per-team topology endpoint returning a normalized graph
(`nodes[]`, `edges[]`, plus node health/role/lifecycle), shaped for direct consumption
by React Flow on the frontend. The administrator global topology (all instances) is a
read placeholder for SECP-001's two-team demo (the demo focuses on per-team views).

The projection is deterministic given instance state, so the frontend can re-render on
poll without surprises.

---

## 11. Security model

### 11.1 Local development (SECP-001)

- **OIDC-compatible IdP** (Keycloak-compatible dev server) provides authentication.
  All default credentials are documented as **UNSAFE FOR PRODUCTION** in
  `.env.example` and the README.
- **The API cryptographically verifies bearer tokens (ADR-017 / OIDC-A).** A
  presented `Authorization: Bearer` token is accepted only when it is RS256-signed
  (a fixed allowlist — no symmetric/`none`/caller-selected algorithms), its signature
  verifies against the configured issuer's JWKS, its `iss` exactly matches
  configuration, the configured API audience is present, it is unexpired with valid
  `nbf`/`iat` within a bounded clock skew, and its exact `sub` maps to exactly one
  **pre-provisioned** internal user (`app_user.subject`). Organization and permissions
  are resolved from the database; the token's roles, groups, email, or organization
  claims grant nothing; there is no just-in-time user creation. Discovery/JWKS are
  deployment-configured trust infrastructure (never caller/DB input), fetched with
  bounded timeouts, no redirects, no ambient proxy, and size caps, and cached with
  bounded monotonic expirations. Failures are closed/redacted (`401 unauthenticated`
  with `WWW-Authenticate: Bearer`; `503 authentication_unavailable` when the IdP is
  unreachable).
- **The browser obtains that access token via Authorization Code + PKCE (ADR-018 /
  OIDC-B).** The public `secp-web` client (no secret) runs the code + PKCE (S256) flow
  through `oidc-client-ts`, reading the public, secret-free `GET /api/v1/auth/config`,
  and sends only the **access token** as `Authorization: Bearer`; the ID token is never
  an API credential. `/api/v1/me` is the authoritative browser identity — token claims
  grant no organization/role/permission. Tokens are session-scoped only (no
  localStorage/DB persistence, no `offline_access`, no silent renewal). SECP does not
  request, retain, or use a browser **refresh token**: the dev Keycloak client disables
  refresh-token issuance (`use.refresh.tokens=false`) and — because omitting
  `offline_access` does not by itself stop an ordinary refresh token — the frontend also
  strips any `refresh_token` before persisting the user and keeps only a refresh-token-free
  projection in memory. An invalid callback, state/nonce mismatch, or API 401 fails closed
  to `/login`; access-token expiry requires a fresh interactive login.
- **Production deployment guardrails, preflight, and runbooks (ADR-019 / OIDC-C).** A
  **same-origin** production model is locked: one canonical HTTPS public origin
  (`SECP_PUBLIC_ORIGIN`, validated as an exact origin) serves both the web app and the
  `/api/` SECP API, and the browser callback/logout URLs derive from it. Production **CORS
  is disabled** (the API uses stateless bearer tokens, never cookies; empty allow-origins),
  while development allows only the exact configured origin without credentials or
  wildcards. A production **Host allowlist** (canonical host + optional internal health
  host, never `*`) fails closed with no `/health` bypass, and callback URLs are never built
  from a backend Host header. A token-free operator **preflight**
  (`python -m secp_api.oidc_preflight`) reuses the OIDC-A hardened HTTP seam to check
  discovery/JWKS, exact issuer agreement, HTTPS endpoints, and a usable RSA signing key —
  without logging in, obtaining a token, or touching the database/audit — and normal
  liveness/startup never contacts the IdP. This makes authentication **deployable**; it does
  **not** make the whole platform production-ready, and real provisioning stays sealed.
- A documented dev-only **fallback principal** keeps the stack runnable without a
  configured realm, honored only on a no-`Authorization`-header request; it is gated
  behind `AUTH_DEV_MODE=true` and refuses to enable when `APP_ENV=production`. A
  presented bearer token is always verified first and never falls back.
- **No production secrets** are present. Secrets are read from environment / `.env`
  (git-ignored). `.env.example` contains only placeholders.
- Authorization is **organization-scoped RBAC**: every resource carries an
  `organization_id`; the authorization layer rejects cross-org access (Charter
  Invariant; assignment Phase 2 rule 7). Roles gate sensitive actions (approve,
  apply, destroy).
- The API never executes privileged actions; the worker is the only component that
  drives plugins (Invariants 6, 7).

### 11.2 Future production (documented direction, not built in SECP-001)

- Per-environment network isolation enforced at the infrastructure layer; environment
  workloads denied default egress to management/home/corporate/public networks
  (Charter Invariant 17, §13).
- Short-lived credentials, encrypted secrets at rest, encrypted transport, signed
  plugin artifacts, dependency + container scanning in CI (Charter §13). CI in
  SECP-001 already includes dependency/security scanning as a starting point.

These are recorded as explicit placeholders; SECP-001 builds the seams (RBAC,
audit, approval gate, plugin contract) that production hardening will extend.

---

## 12. Why the Simulator Plugin is a reference implementation, not a throwaway mock

A mock exists to make a test pass and is discarded. The **Simulator Plugin is a
reference implementation** of the real plugin contract, kept and maintained, because:

1. **Contract conformance.** It implements the *exact same* `PluginProtocol` that the
   Proxmox/OpenTofu/Ansible plugins will implement (Charter §11). It is the executable
   definition of "what a correct plugin does," and a conformance test suite runs
   against it — and will run against every future plugin.
2. **It exercises the real seams.** It runs through the worker, the dispatcher, the
   plan/approve/apply gate, the lifecycle state machine, and the audit trail. Nothing
   about the control plane is faked to accommodate it; only the *execution target* is
   simulated (rows instead of VMs).
3. **Permanent value.** It remains the substrate for CI, demos, local development,
   load/soak testing of the orchestration engine, and regression testing of the
   control plane — none of which should require real Proxmox. It is a first-class,
   supported integration, listed as `simulator` in `requiredPlugins`.
4. **Honesty (Charter §12, decision rules).** It is explicitly labeled simulated
   everywhere. It never pretends to create real infrastructure; it creates rows it
   clearly marks as simulated. This satisfies "do not pretend an integration is real
   when it is simulated."

---

## 13. Component inventory (what SECP-001 builds)

| Area | Path | Notes |
| --- | --- | --- |
| Web app | `apps/web` | React + TS + Vite + React Flow |
| Control-plane API | `apps/api` | FastAPI, SQLAlchemy 2.0, Alembic |
| Worker boundary | `apps/worker` | Temporal worker + shared orchestration |
| Scenario schema | `contracts/scenario-schema` | versioned JSON Schema + Pydantic models |
| Plugin contract | `contracts/plugin-api` | versioned `PluginProtocol` (v1) |
| Simulator plugin | `plugins/simulator` | reference implementation |
| Dev stack | `infra/dev` | Docker Compose: postgres, minio, keycloak, temporal(+ui), api, worker, web |
| Scenarios | `docs/scenarios` | `web-breach-101.yaml` |
| Vulnerability packs | `docs/vulnerability-packs` | `weak-ssh` reference pack metadata |
| Tests | `apps/api/tests`, `tests/` | pytest suites |
| CI | `.github/workflows/ci.yml` | format/lint/typecheck/test/schema/security |

---

## 14. Explicit non-goals and placeholders for SECP-001

Recorded honestly per the assignment's decision rules:

- No real infrastructure, IaC apply, configuration management, or real security tools.
- Temporal path is wired but the default demo/test path is the inline dispatcher;
  durable-execution hardening (signals, heartbeats, retries policy tuning) is
  SECP-002+.
- Drift detection / continuous reconcile loop: placeholder.
- Cross-environment connectivity declaration + approval: placeholder.
- Administrator global topology aggregation, scoring/validation event ingestion,
  AI copilot, reporting: out of scope (later milestones).
- Production security hardening (secret encryption at rest, mTLS, plugin signing):
  documented direction, not built.

Every placeholder above is also referenced where it appears in code or docs.
