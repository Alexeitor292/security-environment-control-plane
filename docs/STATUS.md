# Project Status — Current Capability Ledger

**Status of this document:** point-in-time implementation snapshot (descriptive).
**Governing document:** [`docs/PROJECT_CHARTER.md`](PROJECT_CHARTER.md).
**Design lock:** authoring convergence — publishing an approved topology revision into a canonical immutable EnvironmentVersion — is design-locked (not implemented) by [`ADR-016`](adr/ADR-016-authoring-convergence-environment-version-publication.md).
**Publication contract (PR A):** the `controlplane.security/v1alpha2` publication composition, canonical-topology reconstruction, whole-definition environment hash, and server-derived publication fingerprint are now **contract-complete** as a pure, database-free contract. Publication **persistence, API route, permission, audit, and UI are not implemented**; approval still does not publish; and this contract enables **no** plan generation, EnvironmentVersion creation, or infrastructure execution. `v1alpha1` is unchanged.
**Publication persistence & service (PR B):** the pure PR-A contract is now persisted by a transactional, org-scoped, fail-closed, idempotent control-plane service (`publish_version`) that composes an approved topology revision + its passing validation result into a new immutable `controlplane.security/v1alpha2` `EnvironmentVersion` under a `SELECT FOR UPDATE` template lock, guarded by a distinct `version:publish` permission and the new publication-binding columns/constraints/immutability trigger. This service is **not externally reachable**: there is **no** publication HTTP route, request/response API schema, read model, `version.published` audit action, or UI; approval still publishes nothing on its own; and it creates **no** exercise, deployment plan, or workflow dispatch and contacts **no** infrastructure. Direct `create_version` now persists only `v1alpha1`, so a caller-fabricated `v1alpha2` publication envelope cannot bypass the service. The end-to-end authoring→publication→plan workflow remains **incomplete**. `v1alpha1` is unchanged.

[`docs/PROJECT_CHARTER.md`](PROJECT_CHARTER.md) remains the authoritative product and
architecture charter — the mission, the domain model, the architectural invariants (§6),
and the milestone direction (§17). **STATUS.md** is a point-in-time snapshot of what the
code merged into `main` actually does today, classified against a small closed vocabulary.
Where the charter describes intent and direction, this ledger describes the current
implementation. This document is **descriptive, not an activation authority**: nothing
here enables, unseals, or authorizes any real-infrastructure action, and no statement here
overrides the charter, an ADR, a config gate, or a code seal.

Every claim below is grounded in merged code and its enforcing tests, not in milestone
prose. The overriding truth is simple: **the only complete, real execution path is
simulated.** Every path toward real infrastructure is either built against fakes, sealed
by default, or not yet implemented.

---

## A. Status taxonomy

A capability is labelled with exactly one of the following (a capability may carry a
second qualifier such as `production-blocked` where a production validator or code seal
also applies):

| Label | Meaning |
| --- | --- |
| **implemented-simulated** | Fully implemented and exercised end-to-end, but every effect is a simulated record in the control-plane database via the simulator plugin. No real infrastructure is created. |
| **implemented-fake-only** | Implemented and exercised, but only against in-process fakes / injected test doubles. The real adapter is not the shipped runtime path and no real endpoint is contacted. |
| **controlled-live-read-only** | A real, **read-only** integration wired into the shipped runtime that can contact an explicitly authorized target — but only after a complete, fail-closed gate chain passes. Sealed by default; never mutates. |
| **sealed-by-default** | The real implementation (or its architecture) exists in the tree but ships disabled and fail-closed: the shipped default composition refuses at the first privileged boundary. Reachable, if at all, only through an explicit, reviewed, deployment-local profile with every gate satisfied. |
| **contract-complete** | The durable schema, contracts, and code for a capability exist and are tested, but the capability is not wired into any shipped runtime path — it is dormant. |
| **partially-implemented** | Part of the capability exists; the remainder does not. |
| **not-implemented** | No implementing code exists. The capability appears, if at all, only as names/strings in schemas, seed data, or test fixtures. |
| **production-blocked** | Cannot be activated in production by design: a production-config validator (`Settings`) or a hard code seal refuses it. |

---

## B. Milestone standing

Classified from code + enforcing tests (charter §16–§17 defines the roadmap).

| Milestone | Standing | Basis |
| --- | --- | --- |
| **SECP-001 — Control Plane Foundation** | `implemented-simulated` | The simulator plugin creates only database records; the full lifecycle (immutable version → deterministic plan → explicit approval → simulated execution → per-team topology → reset/destroy → audit) is proven end-to-end. Org-scoped RBAC and immutable audit are real. |
| **SECP-002A — Provider / Discovery Foundation** | `contract-complete` | The original provider/discovery foundation is contract-complete: the read-only Proxmox plugin advertises `validate`/`health`/`discover`/`status` only (`plan`/`apply`/`reset`/`destroy` refuse), and execution targets, immutable inventory snapshots, and network/address reservations are real. Its own discovery still runs only against simulated/mock (fake/injected) transports — no real endpoint. The later worker-owned SSH discovery extension is a **separate** `controlled-live-read-only` path (see SECP-002B-1B and §E), not part of this foundation. |
| **SECP-002B-0 — Provisioning Safety Harness (fake OpenTofu runner)** | `implemented-fake-only` | Immutable, secret-free provisioning manifests bound to an approved plan + pinned target; a blast-radius scope policy; a worker-only runner seam implemented solely by a `FakeOpenTofuRunner` (no subprocess/network/binary). Target-bound deploy is refused by default. |
| **SECP-002B-1A — Sealed OpenTofu Architecture** | `sealed-by-default`, `production-blocked` | The real worker-only OpenTofu execution architecture exists behind a sealed `ProcessExecutor` seam. The real subprocess executor cannot be constructed even when armed (`_B1A_SUBPROCESS_SEALED = True`); the factory always returns the fake executor; the subprocess arm is additionally refused in production. |
| **SECP-002B-1B — First Real Disposable-Lab Lifecycle** | `partially-implemented`, `production-blocked` | The controlled worker-owned SSH live **read-only** discovery path exists and is `controlled-live-read-only` (sealed by default; see §E) — but the **complete real dry-run / apply / verify / destroy disposable-lab lifecycle does not exist yet**. Target onboarding and the declarative staging-lab workflow are `implemented-fake-only`. The full staging-live activation series (worker identity/admission, resolver authorization + resolution lease, live Proxmox provider, apply/verify/rollback/teardown engine, Ed25519 signed-nonce proof-of-possession, worker-mounted discovery) is `contract-complete` but ships **sealed** and `production-blocked`: the composition fails closed at the first privileged boundary and **no real Proxmox host has ever been contacted**. |
| **SECP-002C — Reconciliation / reset / destroy (against real infrastructure)** | `not-implemented` | Reset/destroy exist only for the simulated control plane; "reconcile" exists only as fake/logical simulation. There is no observed-state reconcile loop against real infrastructure. |
| **SECP-003 — Configuration & Content (Ansible, roles, vuln packs)** | `not-implemented` | No Ansible runner, role implementations, or vulnerability-pack framework. `ansible`/`kali` appear only as policy/capability/role strings and scenario content names. |
| **SECP-004 — Detection / Validation / Scoring (Wazuh, CTFd, telemetry)** | `not-implemented` | No telemetry pipeline, score/validation events, or alert overlays. `wazuh`/`ctfd` appear only in scenario-schema fixtures and as simulator capability strings. |
| **SECP-005 — AI Copilot** | `not-implemented` | No AI module, model client, prompt/tool-scoping seam, or authoring-assist endpoint anywhere in the codebase. |
| **SECP-006 — Enterprise Readiness** | `partially-implemented`, `production-blocked` | Foundations exist: organization/tenant scoping, RBAC foundations, immutable audit, and production safety guards (the `Settings` production validator hard-refuses dev auth, inline dispatch, fake provisioning, and the OpenTofu subprocess). Production OIDC bearer verification (still an explicit placeholder, see §D), additional IdPs, advanced RBAC, HA, backup/restore, plugin signing, cloud-provider plugins, and full enterprise operations do **not** exist yet. |

---

## C. Current truthful capability matrix

| Capability | Status | Notes |
| --- | --- | --- |
| Simulator deployment | `implemented-simulated` | Only complete deployment lifecycle; DB-only effects. |
| Immutable environment versions | `implemented-simulated` | Real; immutability enforced (charter Invariant 2). |
| Deterministic deployment plans + approval | `implemented-simulated` | Real plan generation; explicit approval gate (Invariants 4–5). |
| Durable workflow / outbox boundary | `implemented-simulated` | Real inline dispatch (default) + durable Temporal path + transactional outbox publisher. |
| Topology workspace | `implemented-simulated` | React topology workspace (client canvas); server persistence is separate (below). |
| Durable topology revisions | `implemented-simulated` | Saved revisions are immutable (`content_hash`-pinned; ORM + DB triggers). |
| Topology validation / submission / approval | `implemented-simulated` | Separately-permissioned, audited state machine; approval is a decision only (see §D). |
| Target onboarding | `implemented-fake-only` | draft → preflight → review → approval → active; the preflight collector inspects nothing real. |
| Simulated preflight / evidence | `implemented-fake-only` | Redacted immutable evidence from a fake worker collector. |
| Controlled worker-owned live read-only discovery | `controlled-live-read-only` | Sealed by default; reachable only via the reviewed deployment-local profile + full gate chain (see §E, Path A). |
| Dormant HTTP live-evidence collector | `contract-complete`, `sealed-by-default` | Transport + collector + orchestration + authorization contracts exist but are **not activated** (default-disabled, no shipped caller). See §E, Path B. |
| Worker identity / admission | `contract-complete`, `sealed-by-default` | Durable identity registration + Ed25519 signed-nonce admission handshake exist; shipped runtime is deny-by-default (the sole reviewed identity construction is unwired). |
| Resolver authorization + lease foundations | `contract-complete`, `sealed-by-default` | Durable resolver-activation authorization + single-use resolution lease exist and fail closed; the shipped secret resolver stays sealed (`credential_unavailable`). |
| Fake OpenTofu runner | `implemented-fake-only` | Pure-function runner; no subprocess/network/binary; refused in production. |
| Real OpenTofu subprocess | `sealed-by-default`, `production-blocked` | Hard-sealed by code constant; no config flag or grant can arm it in B1-A; refused in production. |
| Real Proxmox mutation | `sealed-by-default`, `production-blocked` | Hardened mutation transport is contract-complete (tests only); the deployment consumer hardcodes a sealed composition. |
| Reconciliation (real infrastructure) | `not-implemented` | — |
| OIDC authentication | `not-implemented`, `production-blocked` | Bearer verification not implemented; only a dev-fallback identity, refused in production (see §D). |
| Ansible / configuration management | `not-implemented` | — |
| Wazuh / telemetry | `not-implemented` | — |
| CTFd / scoring | `not-implemented` | — |
| AI copilot | `not-implemented` | — |
| Artifacts / reporting | `partially-implemented` | Provisioning change-sets and immutable audit records exist; after-action / executive reporting is not implemented. |

---

## D. Critical distinctions

These separations are real and enforced in code; conflating them misstates current truth.

- **Local topology canvas state is not a saved revision.** Client edits are not persisted until a save writes an immutable `TopologyRevision`.
- **A saved revision is not necessarily validated.** A saved revision is `draft`; validation is a separate, permissioned action.
- **Validation is not submission.** Submission is refused unless the revision is validated with a current matching result.
- **Submission is not approval.** Approve/reject is a separate, separately-permissioned, audited decision on a submitted revision.
- **Approval is a decision only.** Approving a topology revision records a decision and sets the approved-revision pointer — **nothing else**.
- **An approved topology revision is not yet a canonical published EnvironmentVersion.** Approving a topology revision does not publish a canonical EnvironmentVersion and does not generate a deployment plan.
- **EnvironmentVersion publication is not plan generation.** The plan generator binds to an `EnvironmentVersion`, not a topology revision.
- **Plan approval is not execution.** Approving a plan does not activate real provisioning (charter Invariant 5).
- **Controlled live read-only discovery is not provisioning, and is not the complete disposable-lab lifecycle.** It is read-only and imports no mutation code; the full real dry-run / apply / verify / destroy lifecycle does not exist yet.
- **Candidate plans produced by discovery are non-executable.** Live apply remains sealed.
- **The complete real dry-run / apply / verify / destroy lifecycle is not yet available.** It is sealed by default.
- **OIDC bearer-token verification is not implemented.** Any presented bearer token is explicitly rejected before any fallback.
- **The development fallback identity is not production authentication.** It is a clearly-gated dev-only principal, hard-refused in production, and must never be described as production auth.

---

## E. Current real-infrastructure boundary

There are two distinct real-infrastructure paths. They have different statuses and must not
be conflated.

### Path A — worker-owned SSH controlled read-only discovery (`controlled-live-read-only`)

This path is wired into the shipped worker discovery consumer, but it is **sealed by
default**. It can perform strictly read-only host contact against an explicitly authorized
Proxmox target **only** when the deployment-local, worker-owned controlled-integration
profile is enabled **and** the complete fail-closed gate chain passes, each gate enforced
before any host contact:

1. deployment-local controlled-integration profile enabled + valid admission material
   (endpoint, worker identity key/anchor, CA bundle);
2. exactly one approved worker identity for the org;
3. enrollment / onboarding drift check;
4. strict, descriptor-pinned mounted-bundle validation;
5. control-plane Ed25519 signed-nonce proof-of-possession admission (one-time);
6. endpoint-binding + live-read authorization re-verification;
7. host-key `known_hosts` pin proven before any SSH invocation;
8. post-probe one-time admission consume + worker-identity re-check.

With the profile disabled (the shipped default) discovery is sealed and contacts nothing.
The path imports no mutation-capable module and produces only a **non-executable** candidate
plan.

### Path B — HTTP target-evidence collector (`contract-complete`, dormant / sealed)

The hardened read-only HTTP transport, the closed read-only request policy, the collector,
the read-only-preflight orchestration, and the resolver-activation authorization contracts
are fully built and tested — but **not activated**. The HTTP target-evidence collector
remains dormant: its runtime gate is default-disabled and it has no shipped caller; the
read-only-preflight consumer ships a denying worker-identity verifier, a sealed activation
gate, and a sealed secret resolver, so it always terminates `credential_unavailable` and
contacts nothing. **The existence of transport and collector contracts must not be described
as activation.**

### Boundary statements (all currently true)

- **Real Proxmox provisioning remains unavailable.**
- **The OpenTofu subprocess remains hard-sealed** and is refused in production.
- Ownership observation and every other mutation gate remain fail-closed.
- **No UI or API approval alone activates infrastructure execution.**

---

## F. Production blockers

Before the platform can be operated against real infrastructure in production, at minimum:

- **Real OIDC bearer-token verification** (replacing the dev-fallback placeholder).
- **Canonical topology → EnvironmentVersion publication convergence** (an approved topology
  revision does not yet become a canonical published version).
- **The first controlled disposable-lab dry-run / apply / verify / destroy** lifecycle.
- **Real observed-state reconciliation and reset/destroy** against real infrastructure.
- **Configuration management** (Ansible runner, roles, vulnerability packs).
- **Detection, telemetry, scoring, and reporting maturity** (Wazuh/CTFd/telemetry/reports).

---

## G. Ordered next steps

The approved sequence (this ledger is step 0; it is descriptive and does not itself
activate anything):

0. Project status normalization *(this document)*
1. Authoring Convergence and Environment Version Publication Contract
2. Production OIDC authentication
3. First controlled disposable-lab lifecycle
4. SECP-002C reconciliation
5. SECP-003 configuration / content
6. SECP-004 detection / validation / scoring
7. SECP-005 AI
8. SECP-006 enterprise readiness

---

*STATUS.md is descriptive, not an activation authority. It records what exists today; it
does not enable, unseal, or authorize any real-infrastructure action. The charter and the
code seals remain authoritative.*
