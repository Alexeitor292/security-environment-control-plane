# ADR-026 — automated management-plane bootstrap, real host adapters, and worker enrollment

- **Status:** Accepted for SECP-PR5G. Closes the real host-adapter gap that [ADR-025](ADR-025-management-plane-bootstrap.md)
  deliberately deferred (PR5E shipped the engine + the closed typed adapter *contract* but SEALED every
  production leaf), and adds the durable **worker-enrollment state machine** and the **signed
  controller-offer / worker-result handoff protocol contracts** so a fresh controller and a fresh
  worker can be bootstrapped from a signed release bundle without editing files, calculating digests,
  or hand-copying handoff documents. The **network transport** for enrollment remains SEALED behind an
  explicit adapter with a precise next-PR boundary (SECP-PR5H); this ADR does **not** claim automatic
  cross-host enrollment is exercised end to end.
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
behavior), plus the durable enrollment/handoff machinery that removes the remaining manual steps
(hand-copying the controller-offer / worker-result documents between hosts).

## Decision — real adapters by composition (this PR)

New module `secp_management/real_adapters.py` supplies production leaves, wired **out of band** by a
new `secp_management/production.py` resolver (the CLI still cannot select or inject an adapter; the
default `EngineDeps()` remains fully sealed). Each real leaf is a thin, closed orchestration over
reviewed seams:

- **`RealHostObserver`** — `platform()` reports real `docker_present`/`compose_present`/versions via a
  pinned container-runtime/compose probe (never a shell); `observe_worker()`/`observe_controller()`
  compose the **PR5C** commissioning status (`secp_commissioning.status.commissioning_status` →
  `"prepared"`) and the **PR5D** deployment verifier (`secp_operator_deployment.verify.build_verification`
  → `"sealed_prepared"`) and emit the mandatory **ABA generation marker** (`worker_generation_marker` /
  `controller_generation_marker`) over the complete container-id/restart/pid/started/InvocationID tuple,
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

## Decision — durable enrollment state machine + handoff protocol contracts (this PR)

New module `secp_management/enrollment.py` defines the **provider-neutral** enrollment domain:

- **`WorkerEnrollmentInvitation`** — a short-lived, single-use, content-addressed, **non-secret**
  invitation created by the controller (issued to an administrator, displayable/downloadable in the
  browser). It binds an exact controller identity/HTTPS origin, a pinned or enrollment-established trust
  anchor, an expiry, a nonce, and a monotonic sequence — no provider fields, no private key, no host
  path.
- **`EnrollmentState`** state machine — `invited → worker_identity_bound → offer_transported →
  result_transported → verified → healthy` with explicit `refused` / `recovery_required` terminals.
  Every transition is revision-guarded, replay-protected (nonce + sequence + predecessor binding),
  transaction-bound, and expiring; wrong-controller / wrong-worker / wrong-transaction / wrong-release /
  expired / replayed inputs refuse closed.
- **Handoff transport** — the PR5F canonical, detached-Ed25519 controller-offer / worker-result records
  are reused **verbatim** (`secp_discovery_activation.handoff`: `issue_handoff_attestation`,
  `verify_handoff`, sequence/predecessor/transaction/expiration binding). PR5G transports them through a
  management-plane protocol instead of hand-copied files, but does not alter their canonical bytes or
  signatures.

The actual **network contact** (worker → controller outbound HTTPS) is implemented behind an explicit
`EnrollmentTransport` Protocol whose shipped default is **sealed** (`enrollment_transport_not_activated`).
The state machine, invitation/authorization contracts, replay/expiry/sequence semantics, and their
tests are complete and hermetic; only the socket-level exchange is deferred.

## Provider neutrality (reviewed)

Management-plane identities, release records, installation evidence, enrollment records, and bootstrap
configuration carry **no** Proxmox (or any provider) fields. The controller/worker bootstrap is defined
purely in terms of container images, compose/systemd artifacts, queues, and Ed25519 identities — all
provider-agnostic. A site worker later hosting a Proxmox / Kubernetes / AWS / Azure / GCP / VMware
plugin uses the *same* bootstrap; provider onboarding is a separate later workflow on the infrastructure
plane. A static boundary test proves no provider string appears in the management identity/release/
evidence/enrollment schemas.

## Installer experience (this PR)

`secpctl release verify --bundle <b>`, `secpctl bootstrap controller --bundle <b> --configuration
<validated-nonsecret-config> --write --confirm`, and `secpctl bootstrap worker --bundle <b> --enrollment
<short-lived-nonsecret-artifact> --write --confirm`. Dry-run remains the default (both `--write` and
`--confirm` are required to mutate). No secrets on argv; no arbitrary path/host-effect knobs; no
caller-selectable adapter; secrets enter only through a reviewed local secret source or the short-lived
enrollment exchange. Non-secret configuration has a strict versioned schema (no arbitrary paths,
commands, compose projects, service names, endpoints, or executable selection).

## Browser surfaces (this PR: backend + minimal status)

A management API can create a worker-enrollment invitation, expose a downloadable **non-secret**
enrollment artifact / short code, and report controller/worker installation status, signed-evidence
identities + safe fingerprints, progress + refusal-reason categories, and `recovery_required` with retry/
rollback guidance. The browser **never** receives a private key, executes a host command, accepts a host
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

## Exact next PR (SECP-PR5H)

Activate the sealed `EnrollmentTransport`: the worker-initiated outbound HTTPS exchange (exact origin,
pinned/enrollment-established trust, single-use short-lived authorization, no redirects, no ambient
proxy, no system-trust fallback unless justified, bounded payloads, no private-key transport, no remote
command execution), driven by the state machine and contracts delivered here, with an end-to-end
two-host enrollment acceptance test. Only after that test passes may automatic enrollment be described
as complete.
