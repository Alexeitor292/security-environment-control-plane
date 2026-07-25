# ADR-026 — automated management-plane bootstrap, real host adapters, and worker enrollment

- **Status:** Accepted for SECP-PR5G. Closes the real host-adapter gap that [ADR-025](ADR-025-management-plane-bootstrap.md)
  deliberately deferred (PR5E shipped the engine + the closed typed adapter *contract* but SEALED every
  production leaf), and adds the provider-neutral **worker-enrollment state-machine transition
  contract** (pure functions — NOT a durably-persisted workflow) and the **signed controller-offer /
  worker-result handoff protocol contracts** so the primitives exist for a fresh controller and a
  fresh worker to be bootstrapped from a signed release bundle without editing files, calculating
  digests, or hand-copying handoff documents. Deferred to SECP-PR5H (and beyond) are the enrollment
  **network transport** (SEALED behind an explicit adapter), durable enrollment persistence, the
  transactional revision/nonce compare-and-swap, restart recovery, and a supported production CLI
  entrypoint. This ADR does **not** claim automatic cross-host enrollment or a one-command customer
  installation is exercised end to end; root-gated CI proves real adapter *mechanics* + real migration
  *execution*, not a completed customer production rollout.
- **Date:** 2026-07-21
- **Milestone:** SECP-002B-1B — **PR5G** (automated management-plane bootstrap + enrollment), following
  PR5E (bootstrap foundation) and the PR5F/PR5F.1/PR5F.2 production-activation line. **PR6 (first apply)
  remains frozen.** The controlled-live operator remains **disabled and stopped**.
- **Related:** [ADR-025](ADR-025-management-plane-bootstrap.md) (contract + sealed defaults, extended
  here), [ADR-024](ADR-024-operator-deployment-package.md) (pinned read-only host adapters + pinned exec,
  composed), [ADR-023](ADR-023-commissioning-automation-foundation.md) (hardened filesystem + evidence
  idioms, composed), the PR5F handoff/attestation primitives (`secp_discovery_activation.handoff`,
  reused verbatim). Runbooks: `docs/runbooks/pr5e-management-bootstrap.md`,
  `docs/runbooks/pr5c-commissioning-experience.md`, `docs/runbooks/pr5f-b8-production-activation.md`.

## Problem

PR5E's engine performs **no** host effect directly — it drives four injected, closed, typed seams
(`ManagementHostObserver`, `ControllerBootstrapAdapter`, `WorkerBootstrapAdapter`,
`ManagementRollbackAdapter`) plus a `ManagementEvidenceAuthenticator`. The shipped leaves are all
`Sealed*` and fail closed, so on the shipped repository bootstrap/adoption/status/rollback all refuse.
That is safe but not yet a product: a fresh host cannot actually be brought up. PR5G supplies the
**real** leaves by *composition* of already-reviewed primitives (never duplicating security-sensitive
behavior), plus the **pure enrollment/handoff contracts** that a later working product path will use.

**Correction (truth pass).** PR5G supplied real host adapters **and pure enrollment/handoff
contracts**. It did **not** supply durable enrollment persistence, and it did **not** activate a
network transport — so it did **not** remove hand-copying of the controller-offer / worker-result
documents through a working product path. Durable persistence, CAS, the single-use nonce ledger and
restart/expiry recovery arrived in **PR5H-A**
([ADR-027](ADR-027-durable-worker-enrollment-foundation.md)); the transport that actually removes the
manual copy is **PR5H-B**.

## Decision — real adapters by composition (this PR)

New module `secp_management/real_adapters.py` supplies production leaves, wired **out of band** by a
new `secp_management/production.py` resolver (the CLI still cannot select or inject an adapter; the
default `EngineDeps()` remains fully sealed). Each real leaf is a thin, closed orchestration over
reviewed seams:

- **`RealHostObserver`** — `platform()` reports real `docker_present`/`compose_present`/versions via a
  pinned container-runtime/compose probe (never a shell); `observe_worker()`/`observe_controller()`
  derive an **independent, deliberately narrower host-readiness predicate** (present + running +
  healthy + operator present/disabled/stopped + ordinary-queue-contained →
  `"prepared"`/`"sealed_prepared"` LABELS) directly from the one coherent PR5D observation.  This is
  **not** a call into the full `secp_commissioning.status.commissioning_status` /
  `secp_operator_deployment.verify.build_verification` engines — those enforce additional invariants
  (evidence records, tool/contract identity, per-image snapshot digests, path bindings) that the
  management **engine** applies authoritatively during adopt/commit; it never trusts these host-side
  labels alone.  The observer emits the mandatory **ABA generation marker** (`worker_generation_marker`
  / `controller_generation_marker`) over the complete container-id/restart/pid/started/InvocationID tuple,
  so a restart/replace between admission and commit is detected. It exposes **no** start/stop/restart
  verb (read-only, built on `secp_operator_deployment.host_adapters.LocalServiceStateAdapter` /
  `LocalContainerRuntimeAdapter`, and cross-checks an **independent** expected-identities pin — the
  profile is never the sole authority).
- **`RealControllerBootstrapAdapter`** / **`RealWorkerBootstrapAdapter`** — consume only the typed,
  engine-derived inputs (`VerifiedArtifact`, `ReviewedConfig`, `ReviewedUnit`, `ControllerBootstrapPlan`
  / `WorkerBootstrapPlan`). `load_image` reads the digest-checked archive, loads it through the pinned
  container runtime, and proves the **loaded** image digest equals the signed purpose-specific image
  digest (`verify_loaded_image`) — never trusting the archive digest or a floating tag. `install_config`
  / `install_unit` / `install_ordinary_config` / `install_deployment_package` / `install_operator_unit_disabled`
  write **only** the fixed `ManagementLocations` paths through the hardened `RealFilesystem`
  (`atomic_install`, root-owned `0640`, symlink/hardlink/ownership/mode fail-closed). The operator unit
  is rendered by `render_operator_unit_disabled` (no `[Install]`/`WantedBy`) and is installed
  **disabled + stopped** — never enabled or started. `run_migrations` runs the fixed
  `('alembic','upgrade','head')` argv; `start_stack`/`start_ordinary` run the closed compose argv
  pattern. Every host command goes through the single reviewed subprocess seam
  `secp_operator_deployment.host_process.RealCommandRunner` (`shell=False`, `_FIXED_ENV` only — no
  ambient env/PATH/CWD/HOME inference, pinned `/proc/self/fd` exec, DEVNULL stdin, own process group,
  bounded output + timeout, group-kill on timeout, redacted reason codes). Each adapter accumulates a
  `BootstrapReceipt` of exactly the objects it created and exposes `compensate(receipt)` that removes
  **only** those objects, returning `CompensationResult(proven=…)`; any residual forces
  `recovery_required`.
- **`RealRollbackAdapter`** — maps a `path_binding_digest(role, path)` to its **own** fixed layout path
  (identity / release-record / release-sig / evidence / evidence-attestation) and performs a hardened
  removal; it exposes **no** generic delete-any-path verb.
- **`LocalManagementEvidenceAuthenticator`** — mirrors `secp_discovery_activation.evidence_key`: a
  root-owned `0600` Ed25519 key, `key_id()` + `attest(message)` signing **only** the exact
  `evidence_attestation_message` the engine derives (never arbitrary caller bytes). Production commits
  no private key; a reviewed public trust anchor is pinned for verification.

## Decision — enrollment state-machine + handoff protocol CONTRACTS (this PR; NOT durable)

New module `secp_management/enrollment.py` defines the **provider-neutral** enrollment domain:

- **`WorkerEnrollmentInvitation`** — a short-lived, single-use, content-addressed, **non-secret**
  invitation created by the controller (issued to an administrator, displayable/downloadable in the
  browser). It binds an exact controller identity/HTTPS origin, a pinned or enrollment-established trust
  anchor, an expiry, a nonce, and a monotonic sequence — no provider fields, no private key, no host
  path.
- **`EnrollmentState`** transition **contract** — the implemented chain is
  `invited → worker_bound → offer_transported → result_transported → verified → healthy`, plus
  `refused` and `recovery_required`. (**Correction:** an earlier draft of this ADR wrote
  `worker_identity_bound`; the implemented state constant is **`worker_bound`**, and the database
  CHECK constraint enumerates that spelling.) `healthy` is **terminal success**;
  `recovery_required` is the **remediation terminal** and the only absorbing state; `refused` is a
  refusal state that the pure contract still permits to move to `recovery_required`, so it is **not**
  unconditionally terminal.
  Each transition is revision-guarded, sequence/predecessor-chained, transaction-bound, and expiring;
  wrong-controller / wrong-worker / wrong-transaction / wrong-release / expired / conflicting inputs
  refuse closed. At the PR5G head these were **pure functions over immutable value objects** — no
  datastore, no compare-and-swap, no single-use-nonce ledger and no restart recovery.

  **Correction (truth pass).** PR5H-A implemented that persistence layer, and its compare-and-swap is
  over **`revision` + `state_digest`** — those two columns are the UPDATE predicate.
  `predecessor_digest` is the **append-only chain binding** recorded in the revision history, **not**
  a CAS column; describing it as one would misstate the implementation.
- **Handoff transport** — the PR5F canonical, detached-Ed25519 controller-offer / worker-result records
  are reused **verbatim** (`secp_discovery_activation.handoff`: `issue_handoff_attestation`,
  `verify_handoff`, sequence/predecessor/transaction/expiration binding). PR5G reuses their
  **canonical contracts** verbatim and does not alter their bytes or signatures. **Correction:** PR5G
  does **not** transport them automatically — `EnrollmentTransport` remained **sealed**, so no
  management-plane protocol exchange occurs at that head. Automatic transport is PR5H-B.

The actual **network contact** (worker → controller outbound HTTPS) is implemented behind an explicit
`EnrollmentTransport` Protocol whose shipped default is **sealed** (`enrollment_transport_not_activated`).
The state-machine transition contract, invitation/authorization contracts, and replay/expiry/sequence
transition *semantics* are complete and hermetically tested as **pure functions**.  Deferred to **PR5H**
(and beyond) are: the socket-level worker→controller exchange; **durable persistence** of enrollment
state; the **transactional revision/predecessor compare-and-swap** and **single-use-nonce ledger** that
make replay-uniqueness durable across a persisted history; and **restart recovery**.  Enrollment is
therefore a proven *contract* at this head, not yet a product-durable enrollment workflow.

## Provider neutrality (reviewed)

Management-plane identities, release records, installation evidence, enrollment records, and bootstrap
configuration carry **no** Proxmox (or any provider) fields. The controller/worker bootstrap is defined
purely in terms of container images, compose/systemd artifacts, queues, and Ed25519 identities — all
provider-agnostic. A site worker later hosting a Proxmox / Kubernetes / AWS / Azure / GCP / VMware
plugin uses the *same* bootstrap; provider onboarding is a separate later workflow on the infrastructure
plane. A static boundary test proves no provider string appears in the management identity/release/
evidence/enrollment schemas.

## Installer experience (TARGET product experience — not delivered by PR5G or PR5H-A)

**Correction (truth pass).** The commands below are the intended **target** experience. They are
**not** delivered capabilities at the PR5G or PR5H-A head: no supported mutating production
enrollment/bootstrap CLI entrypoint is registered, and the default CLI remains sealed. **PR5H-B** is
expected to deliver commands *equivalent to* the following; the exact syntax is **not** irrevocably
accepted here, because the code does not yet define it:

- `secpctl release verify`
- `secpctl bootstrap controller`
- `secpctl bootstrap worker`
- status / recover / rollback operations

Whatever syntax PR5H-B settles on, these **safety properties are accepted and preserved**: dry-run is
the default (both `--write` and `--confirm` are required to mutate); **no secrets on argv**; **no
caller-selectable adapter**; and no arbitrary host, path, command, compose-project, service-name,
endpoint or executable-selection controls. Secrets enter only through a reviewed local secret source
or the short-lived enrollment exchange, and non-secret configuration has a strict versioned schema.

## Browser surfaces (FUTURE PR5H-B browser/API boundary — not delivered)

**Correction (truth pass).** Neither PR5G nor PR5H-A registers an enrollment API route or any browser
UI; a guard test asserts no enrollment router is registered and that no enrollment router module
exists. The following describes the **intended PR5H-B** boundary.

A management API will be able to create a worker-enrollment invitation, expose a downloadable
**non-secret** enrollment artifact / short code, and report controller/worker installation status,
signed-evidence identities + safe fingerprints, progress + refusal-reason categories, and
`recovery_required` with retry/rollback guidance. The browser **never** receives a private key, executes a host command, accepts a host
path, selects an adapter, bypasses local administrative confirmation, activates the operator, submits an
OpenTofu workflow, or contacts a provider. Root host operations are never executed from a browser
request.

## Evidence + rollback model

Unchanged from PR5E and reused: strict nonsecret `BootstrapEvidence` is written **last**, then its
detached attestation is the true commit point (a sealed authenticator refuses before evidence is
written). Every mutation adapter records an exact receipt; compensation removes only transaction-owned
effects and reports `recovery_required` whenever removal cannot be proven. Rollback removes the fixed
evidence/identity/release documents in reverse and reverifies each is gone; a no-op or partial rollback
refuses rather than reporting a false success.

## Preserved safety invariants

Ordinary queue `secp-orchestration`; operator queue `secp-controlled-live-v1`; the ordinary worker never
polls the operator queue; the controlled-live operator stays disabled and stopped;
`_OPERATOR_ACTIVATION_SEALED = True`; `_PLAN_ONLY_PROCESS_SEALED = False`; both generic
`_B1A_SUBPROCESS_SEALED = True`; no OpenTofu apply/destroy; no real plan-generation submission; no
Proxmox/provider mutation; no provider-specific logic in the management bootstrap; no API-to-host
privileged execution; no arbitrary shell/command endpoint; no weakening of approval/authorization/
evidence/rollback gates. PR6 remains frozen.

## PR5H reconciliation — what shipped and what is next

**PR5H-A — implemented foundation** (see
[ADR-027](ADR-027-durable-worker-enrollment-foundation.md)):

- the enrollment **schema** (four provider-neutral tables) on the new sole head `b6e2f4a9c1d7`;
- a **durable repository** with a single rehydration choke point that fully re-validates every row;
- a transactional **compare-and-swap over `revision` + `state_digest`**, combined with row locking;
- a durable single-use **nonce ledger**, consumed atomically at the first successful worker binding;
- an **append-only revision history** chained by `predecessor_digest`;
- **restart / lost-response recovery** and a bounded, deterministic **expiry sweep**;
- consolidated provider-neutrality, plane-boundary, schema-parity, concurrency, inertness and leakage
  **guards**;
- a dedicated exact-head **PostgreSQL CI no-skip gate**.

**PR5H-B — exact next product slice:**

- the worker-initiated outbound HTTPS **`EnrollmentTransport`**, with exact origin and
  pinned/enrollment-established trust, **no redirects**, **no ambient proxy**, **no silent
  system-trust fallback**, bounded payloads and **no private-key transport**;
- a **supported production CLI**;
- an **authorization-gated, audited enrollment API**;
- a **minimal UI**;
- **full restart recovery across the transport boundary**;
- a **two-host-equivalent automated-enrollment acceptance** test;
- **zero-residual rollback**.

Automatic enrollment becomes complete **only after PR5H-B's end-to-end acceptance passes**. Nothing at
the PR5G or PR5H-A head is a one-command customer installation.
