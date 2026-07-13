# ADR-020 — First real disposable-lab lifecycle (architecture lock)

- **Status:** Accepted **only as an architecture lock** for future implementation. This ADR is
  **design-only**. It **activates nothing**, unseals nothing, and authorizes no execution. It is not
  the implementation PR and not the activation PR.
- **Date:** 2026-07-13
- **Milestone:** SECP-002B-1B — First Real Disposable-Lab Lifecycle
- **Related:** Charter §5 (Layers 4/5/7), §6 (Invariants 4–7, 11, 12, 17), §13; ADR-011 (immutable
  provisioning manifests), ADR-012 (worker-only provisioning runner), ADR-013 (sealed OpenTofu
  runtime + isolated-lab activation), ADR-014 (target onboarding + isolation models); architecture
  `docs/architecture/secp-002b-1b-real-lab-lifecycle.md`; plan
  `docs/implementation/secp-002b-1b-plan.md`; checklist
  `docs/proxmox/b1b-lab-prerequisite-checklist.md`; runbook skeleton
  `docs/runbooks/b1b-first-real-lab.md`.

> **This document changes no application code, no Settings, no environment example, no seal, and no
> activation path. Both B1-A hard seals (`_B1A_SUBPROCESS_SEALED = True` in
> `apps/worker/secp_worker/provisioning/process_executor.py` and
> `apps/worker/secp_worker/provisioning/activation.py`) remain exactly `True`. No real OpenTofu
> process, plan, apply, or destroy has ever run; no real Proxmox host has ever been contacted.**

## Context

ADR-013 (B1-A) built the sealed real-OpenTofu seam — immutable `ToolchainProfile` provenance, the
worker-only `OpenTofuRunner` behind a sealed `ProcessExecutor`, provider-neutral `WorkspaceRenderer`,
the canonical redacted change-set approval (`plan_json.canonicalize_plan_json` + `change_set_hash`),
the transient exact-prepared-plan apply/destroy (`PreparedOpenTofuPlan`, `apply_prepared`,
`destroy_prepared`), and the isolated-lab activation gate (`RealLabActivationGrant`,
`build_process_executor`) — **proven end-to-end with fakes** (`FakeProcessExecutor`,
`FakeToolchainVerifier`, `FakeSecretResolver`) and sealed so no real binary, endpoint, provider, or
secret is ever touched. ADR-014 added the approved-and-active `TargetOnboarding` with an immutable,
enforceable declared boundary. Controlled worker-owned SSH **read-only** discovery exists as a
separate `controlled-live-read-only` path (ADR-015/SECP-B-series), sealed by default.

B1-B is chartered to run the **first real, worker-only OpenTofu lifecycle** against **one
intentionally disposable, non-production, isolated Proxmox target**. That is too large and too
dangerous to unseal in one step. This ADR **locks the target architecture, the ordered lifecycle,
the phased unsealing, the threat model, and the acceptance contract** so the future implementation is
a sequence of small, independently reviewed, fail-closed changes — not new architecture invented
under pressure. It deliberately commits **no** real value: no hostname, IP, node/storage/bridge/VLAN
name, CIDR, VM-ID, username, token, fingerprint, `secret_ref`, state-backend name, or binary digest
appears anywhere in source control. Every example in the B1-B documents is **clearly fake,
non-routable, and non-runnable**.

## Decision — locked

### A. Purpose and environment

1. B1-B is the **first controlled real-infrastructure lifecycle**.
2. It is permitted **only** against **one** intentionally disposable, non-production, isolated Proxmox
   target.
3. It is **not** a general production-provisioning release.
4. It is **never** eligible when `SECP_APP_ENV=production` (the existing `Settings` production
   validator already hard-refuses `enable_opentofu_subprocess`, `enable_real_provisioning`, inline
   dispatch, and dev auth in production; B1-B does not weaken that).
5. **Physical isolation is preferred.**
6. **Logical isolation is allowed only** when the declared `TargetOnboarding` boundary is complete,
   enforceable, audited, and **independently verified** (the `no_route_to_protected` preflight check
   must pass for `logical` isolation).
7. **No real target value** — credential, secret reference, network allocation, provider URL,
   certificate fingerprint, backend name, or binary digest — is committed to the repository.
8. Every real value is supplied through a reviewed **deployment-local activation dossier** outside
   source control (Section D).

### B. Lifecycle stages (17, separate and explicit)

Each stage is a distinct, durable, human-or-worker action. **No stage automatically triggers the
next.** **Approval is always a decision, never execution.**

1. immutable `EnvironmentVersion` (ADR-016);
2. approved target-bound `DeploymentPlan`;
3. immutable `ProvisioningManifest` (bound to plan + target config/scope/onboarding/toolchain hashes);
4. **approved and active** `TargetOnboarding` with no boundary drift (ADR-014);
5. **passing real read-only eligibility evidence** (Section E);
6. **verified** `ToolchainProfile` via a real `ToolchainVerifier` (Section F);
7. **verified remote-state readiness** (Section G);
8. **real plan-only** operation (`init`/`plan`/`show -json` only);
9. **canonical redacted change set** (`canonicalize_plan_json` → `change_set_hash`);
10. **explicit human approval of that exact change-set hash** (`ProvisioningChangeSetApproval`,
    `provisioning:approve`);
11. **apply of the exact prepared binary plan** (`apply_prepared`; Section I/J);
12. **post-apply observed-state and isolation verification** (Section K);
13. **separately generated destroy plan**;
14. **separate human approval of the exact destroy change-set hash**;
15. **destroy of the exact prepared destroy plan** (`destroy_prepared`; Section L);
16. **zero-residue verification** (Section L);
17. **immutable closeout record**.

### C. Phased unsealing (operation-specific)

The future implementation proceeds through **independently reviewed phases**. **A configuration flag
alone must never advance between phases.** Each live capability requires a **deliberate
code-and-review change plus the full runtime gate**.

- **Phase 1 — real worker-local toolchain attestation.** Real on-disk filesystem verification only.
  **No endpoint contact. All process execution remains sealed.**
- **Phase 2 — real read-only eligibility + boundary verification.** Real read-only Proxmox
  inspection producing immutable redacted evidence. **No OpenTofu execution. No mutation.**
- **Phase 3 — remote-state + just-in-time secret-resolution readiness.** Validate the remote backend,
  state locking, backup/restore, and worker-only JIT secret injection. **No plan/apply/destroy.**
- **Phase 4 — real OpenTofu `init`/`plan`/`show` only.** **Apply and destroy remain independently
  impossible** (see the mechanism below).
- **Phase 5 — first apply.** Apply may be enabled **only for one exact approved prepared plan**,
  after a successful, reviewed Phase-4 plan.
- **Phase 6 — destroy.** Destroy may be enabled **only through its own exact approved prepared destroy
  plan** — never by reusing an apply approval.
- **Phase 7 — closeout and zero-residue evidence.**

**Mechanism — how plan-only is made technically incapable of apply/destroy (not merely
discouraged).** Capability is gated **per operation** by a **code-level seal constant** (the existing
`_B1A_SUBPROCESS_SEALED` pattern, split into independent per-capability constants such as a plan seal,
an apply seal, and a destroy seal), **plus** an operation-specific runtime enablement, **plus** an
operation-specific human approval, **plus** the full runtime gate. Unsealing plan-only (Phase 4) sets
**only** the plan/`init`/`show` seal to `False`; the **apply and destroy seal constants remain `True`
code constants**, so `SubprocessProcessExecutor` (or the specific `apply_prepared`/`destroy_prepared`
worker code path) **refuses construction/execution unconditionally** for those operations — exactly as
B1-A refuses all subprocess execution today. A plan-only worker build is therefore *technically
unable* to apply or destroy: no configuration flag, environment variable, caller, grant, or approval
can flip a seal constant. Advancing a capability is a reviewed source change to that constant, and
even then the runtime gate (Section J) must fully pass. **This ADR does not implement the mechanism.**

### D. Activation dossier

A **deployment-local, human-reviewed activation dossier** binds the real values needed for one B1-B
run **without entering source control**. It binds:

organization; execution target; onboarding record; exact node allowlist; exact storage allowlist;
exact bridge/VLAN boundary; exact CIDR reservations; exact VM-ID range; resource quotas;
deny-external-connectivity policy; trusted TLS identity; least-privileged credential **reference**
(never a raw credential); OpenTofu executable identity/version/digest; module-bundle identity/hash;
provider lockfile hash; offline-mirror identity; renderer version; remote-state backend reference;
state-locking proof; state backup/restore proof; recovery owner; emergency-stop owner; approval
actors; review timestamp; and dossier revision/hash.

**The dossier carries no raw credential** — only an opaque `secret_ref` resolved worker-side
just-in-time. **Durable-vs-external split (decided):** the SECP database retains only **redacted,
hashed, secret-free** evidence — the dossier **revision/hash**, the bound `ExecutionTarget` /
`TargetOnboarding` / `ProvisioningManifest` / `ToolchainProfile` **ids and content hashes**, the
`effective_boundary_hash`, the `scope_policy` hash, the `secret_ref` **only as an opaque reference**
(never when it reveals backend structure), the approval actor ids, and bounded categories/timestamps.
The **raw dossier**, real values, and credential remain **external operator evidence** held in the
deployment's secret manager and reviewed change record, never in SECP durable rows, HCL, rendered
artifacts, audits, logs, or API responses.

### E. Real eligibility preflight

A **worker-only, read-only** preflight (Phase 2) proves, before any toolchain/plan work: the approved
target identity matches; TLS is verified (`verify_tls=false` is refused); declared nodes exist;
declared storage exists and is **disposable**; the declared bridge/VLAN boundary exists; the VM-ID
range does not collide; CIDRs do not overlap protected ranges; quotas are enforceable; **no route**
exists to home, management, corporate, or public networks; the external-connectivity policy remains
`deny`; the credential capability is **least-privileged and scoped**; the target configuration has
**not drifted**; and the onboarding evidence still matches the current boundary.

Preflight evidence is **immutable, redacted, org-scoped, target-bound, timestamped, hash-bound, and
short-lived / explicitly expiry-bound**, and is **invalidated by any boundary drift**. **No caller
assertion alone is sufficient** — evidence is produced by real worker read-only inspection, never
accepted from the request. This preflight is stricter than, and distinct from, the existing
`controlled-live-read-only` discovery path.

### F. Toolchain integrity

A **real** worker-side `ToolchainVerifier` (`RealToolchainVerifier`, replacing `FakeToolchainVerifier`
only under the reviewed real-lab build) must attest, **before** any `init`/`plan`/`apply`/`destroy`:
the exact executable; the exact version; the binary-integrity digest; the provider lockfile; the
module bundle; the offline provider mirror; the renderer; the CLI configuration; the remote-state
backend class; and the **runtime-download prohibition**. **No network provider download is allowed
during execution.** **No floating version, `latest`, wildcard, or unverified binary is allowed** (the
existing `validate_toolchain_profile` already rejects these at the control-plane; the verifier
re-checks the on-disk reality). **No fake verifier may satisfy a real-lab gate**, and **no fake-runner
fallback may occur** in a real-lab request.

### G. Remote state

Require: **remote state only** (no local backend, no local fallback); encryption at rest; **state
locking**; least-privileged worker access; deployment-local secret injection; **tested backup and
restoration**; exact workspace/state identity binding; state ownership scoped to the one disposable
lab; and **no state contents in logs, audits, or API responses**.

**State-vs-provider disagreement (decided):** if the remote state and the provider's observed state
disagree at any check (preflight, post-apply verification, or destroy), the operation records the
closed outcome **`state_disagreement`** and **fails closed** to **`recovery_required`** — never an
automatic re-apply, re-plan, or destroy. Reconciliation is an operator-visible decision requiring a
fresh preflight and, where destructive, a fresh exact approval.

### H. Secret handling

Locked: **worker-only, just-in-time** resolution; **the API never resolves or receives the
credential**; no raw secret enters DB rows, HCL, rendered durable artifacts, audit events, API
responses, logs, exceptions, or change-set summaries; secrets enter **only** the allowlisted
child-process environment (`build_process_env` with `ALLOWED_ENV_KEYS` + `TF_VAR_`/`TF_LOG` prefixes,
plus `build_lab_secret_env`); child-process output is **bounded and redacted** (`redact_env`,
output-size cap); **no ambient environment inheritance** beyond the explicit allowlist; **no shell
strings**; and **never `shell=True`** (argv arrays only). The final trusted resolver seam
(`WorkerSecretResolver`) ships **sealed** (`SealedSecretResolver` → `credential_unavailable`) until
Phase 3 replaces it under review; the API-side resolver never exists.

### I. Plan review and TOCTOU (consistent with ADR-013)

The real plan flow **preserves ADR-013's exact prepared-plan behavior**:

1. render **once** (`WorkspaceRenderer` → `RenderedWorkspace`, ephemeral 0o700/0o600);
2. **initialize offline** (offline mirror, runtime download disabled);
3. generate **one** binary plan;
4. run `show -json`;
5. **canonicalize and redact** (`canonicalize_plan_json` — keeps only address/mode/type/name/
   provider/actions/replacement + workspace/provenance hashes; drops before/after/sensitive/config/
   state/raw; malformed fails closed);
6. compute the **change-set hash** (`change_set_hash`);
7. persist **only safe review metadata** (redacted canonical change set + hashes on
   `ProvisioningOperation.result`; **never the raw binary plan**);
8. obtain **explicit human approval** of that exact hash (`ProvisioningChangeSetApproval`);
9. re-enter **only** through the exact approved prepared-plan contract.

**Apply executes the exact approved binary plan (`apply_prepared`), never a second render or plan.**
The raw binary plan is **transient**, never persisted as durable application data, and always removed
in a `finally` block.

**Chosen TOCTOU-safe survival model (decided, consistent with ADR-013's amendment):** the transient
`PreparedOpenTofuPlan` **deliberately does not survive worker restart** between approval and apply.
Only the human approval is durable (`ProvisioningChangeSetApproval`, the exact `change_set_hash`). On
the apply attempt the worker **re-prepares a fresh plan** (render → offline init → one plan →
canonicalize → hash) **within a single worker attempt**, requires the freshly-computed canonical
`change_set_hash` to **exactly match** the durable human approval (and re-asserts every binding hash),
and then applies **that same freshly-prepared plan file** via `apply_prepared` with **no second render
or plan**. If the canonical hash differs — because the target, scope, reservations, manifest,
toolchain, or observed provider state drifted since approval — it **fails closed** and requires a
fresh dry run and a fresh approval. This preserves exact-plan integrity **without persisting an unsafe
raw binary plan** and eliminates the time-of-check/time-of-use gap. Destroy uses the same model with
its own separate approval and `destroy_prepared`.

### J. Apply boundary (gate)

Apply requires **all** existing B1-A bindings **plus**: fresh passing eligibility evidence (E);
current activation-dossier hash (D); current toolchain attestation (F); a held remote-state lock (G);
the exact approved change-set hash (I); the exact prepared plan (I); an explicit `RealLabActivationGrant`
(minted only after the full gate, binding `manifest_id`); operation-specific **apply** enablement
**and** its code-level unseal (C); the **Temporal/durable worker path** (`dispatch_mode="temporal"`;
inline refused); a **non-production** environment; **no external connectivity** (policy `deny`); **no
fake runner or executor** (defense-in-depth `b1a_fake_only` rejection removed only for the real build,
replaced by a real-verifier requirement); and **no drift** of target, policy, reservation, manifest,
profile, renderer, bundle, state, or approval. **Apply is not callable directly by the API** — the API
only records intent and approvals; the worker executes (Charter Invariants 6, 7; enforced by
`tests/test_architecture_boundary.py` and `tests/test_provisioning_boundary.py`).

### K. Verification

Post-apply verification **must compare**: the approved change-set resources; the remote state; the
Proxmox **observed inventory**; expected VM/container/network/disk identities; the target boundary;
reservations; resource quotas; network-isolation checks; **no-route checks**; and expected
health/readiness criteria. **A successful OpenTofu exit code alone is not sufficient.**

Closed verification outcomes: **`verified`**, **`verification_failed`**, **`state_disagreement`**,
**`isolation_failed`**, **`recovery_required`**. **No automatic success is recorded before
verification completes**; a run reaches a successful terminal state only on `verified`.

### L. Destroy and zero-residue

Destroy requires: its own **newly generated** change set; its own **redacted canonical hash**; its own
**explicit human approval** (`provisioning:approve`, distinct from the apply approval); the exact
prepared **destroy** plan (`destroy_prepared`); the **full current gate** evaluation (J); a held
remote-state lock; and **no automatic reuse of the apply approval**. Destroy is **idempotent and
retry-safe** (an already-`destroyed` operation returns its durable record with no re-execution).

**Zero-residue verification must prove absence of** — inside the declared boundary — guests;
disks/volumes; network attachments; generated firewall entries; reservations/leases that should be
released; workspace artifacts; transient binary plans; state objects that should be removed; and
provider-created lab resources. **Destroying resources does not automatically prove cleanup**: zero
residue is an independent read-only provider + state re-inspection, recorded as `zero_residue_confirmed`
or `zero_residue_failed`.

### M. Partial failure and recovery

**Fail closed** for: interrupted plan; interrupted apply; partial apply; worker crash; state-lock
loss; provider timeout; verification failure; isolation failure; destroy failure; state/provider
disagreement; credential revocation; and toolchain drift. **No automatic blind re-apply or blind
destroy.** Every non-terminal failure records an **operator-visible durable state** (a bounded closed
category on `ProvisioningOperation`), and any destructive recovery action requires a **fresh exact
approval**. A **manual-cleanup procedure must be documented and available before the first apply**
(runbook + checklist), with a named recovery owner.

### N. Emergency stop

A **deployment-local kill mechanism** can **stop new privileged work** without silently changing
historical records. It **must not**: mutate approvals into success; erase evidence; enable a fake
fallback; bypass state locking; or claim that running provider operations can always be atomically
cancelled. The design distinguishes: **preventing new work** (deterministic — refuse to start new
gated operations); **terminating a local worker process** (best-effort — the child process is killed;
partial provider effects may remain → `recovery_required`); **stopping a Temporal workflow**
(cancels/terminates the durable workflow, not necessarily an in-flight provider call); **provider-side
operations already in progress** (may complete or partially complete regardless — never assumed
atomically cancellable); and **manual containment** (operator boundary action, e.g. network isolation,
as a last resort). The kill switch is an operator control, not an SECP application mutation of state.

### O. Audit and evidence

Safe audit/evidence categories (immutable events): preflight requested/completed/refused; toolchain
attested/refused; real plan generated/refused; change set approved/rejected; apply
requested/started/completed/failed; verification completed/failed; destroy
planned/approved/started/completed/failed; zero-residue confirmed/failed; recovery required; kill
switch activated.

Audit data **may** contain: ids, hashes, bounded categories, counts, timestamps. It **may not**
contain: credentials; secret references when they reveal backend structure; raw OpenTofu output; raw
plan JSON; the binary plan; state contents; provider response bodies; endpoint-auth material; rejected
caller data; or private-key material.

### P. Minimum first-lab scope

The smallest resource shape already representable by the current architecture (scenario/manifest/
adapter/staging contracts) and sufficient to prove a real lifecycle. Prefer: **one** target; **one**
allowed node; **one** dedicated disposable storage target; **one** isolated network boundary; **one**
bounded CIDR; **one** minimal disposable guest (or the smallest existing supported fixture); strict
CPU/RAM/disk limits; and **no external connectivity**. **Do not invent unsupported resource
behavior.** **Implementation prerequisite:** if the current worker renderer/adapter cannot yet emit a
genuinely minimal *real* Proxmox resource (as opposed to the fake fixture `show -json`), that renderer
capability is an explicit **implementation prerequisite for B1B-PR5**, not something to fabricate in a
document.

### Q. Success definition

B1-B is complete **only** when **one human-reviewed run** has durable evidence for: target
qualification; real plan; exact approval; real apply; observed-state verification; isolation
verification; separate destroy plan; separate destroy approval; successful destroy; zero-residue
verification; state closeout; an immutable audit chain; and documented recovery observations. **A
passing unit test or a fake executor does not satisfy B1-B completion.**

## Threat model

For each threat: **Prevention** / **Detection** / **Durable evidence** / **Refusal behavior** /
**Recovery owner** / **Deferred residual risk**.

| Threat | Prevention | Detection | Durable evidence | Refusal | Recovery owner | Deferred residual risk |
| --- | --- | --- | --- | --- | --- | --- |
| Configuration-only unseal | Capability is a **code seal constant**, never a flag (C) | Seal test asserts constants `True` | Seal test result; commit review | Gate returns fail-closed; executor refuses | Reviewer | Reviewer error introducing a bad seal change |
| Direct executor construction | `SubprocessProcessExecutor.__init__` refuses while sealed | Seal test; construction raises | Refusal audit category | `ProcessExecutionError` | Worker owner | Post-unseal build with wrong seal |
| Injected executor | `run_real_provisioning` rejects non-`b1a_fake_only` (real build requires real verifier) | Gate rejection | Refusal event | Fail closed before secret/runner | Worker owner | Malicious worker image (out of scope) |
| Fake-runner fallback | **No fake fallback** in a real-lab request | Gate asserts real verifier/runner | Refusal event | Fail closed | Worker owner | — |
| Plan-only → apply escalation | Separate apply seal constant + apply enablement + apply approval | Missing apply approval/seal | Refusal event; approval rows | Fail closed | Reviewer + approver | Reviewer flips both seals in one PR (review control) |
| Stale approval | Fresh canonical hash must match; boundary/state re-checked | Hash mismatch | Approval + operation hashes | Fail closed → new approval | Approver | — |
| Target drift | Target `config_hash` re-compared at gate | Hash mismatch | Manifest/target hashes | Fail closed | Operator | — |
| Scope-policy drift | `provisioning_scope_policy_hash` re-compared | Hash mismatch | Scope hash | Fail closed | Operator | — |
| Reservation drift | `reservations_hash` re-compared | Hash mismatch | Reservation hash | Fail closed | Operator | — |
| Toolchain drift | Verifier re-attests on-disk vs profile hashes | Attestation failure | Toolchain attestation event | Fail closed | Worker owner | — |
| Provider-mirror substitution | Offline mirror identity attested; no runtime download | Mirror-id mismatch | Attestation event | Fail closed | Worker owner | Compromised mirror content (integrity digest mitigates) |
| Binary replacement | Executable identity + integrity digest attested | Digest mismatch | Attestation event | Fail closed | Worker owner | Digest chosen from compromised source (dossier review) |
| Lockfile substitution | Provider lockfile hash attested | Hash mismatch | Attestation event | Fail closed | Worker owner | — |
| Module-bundle substitution | Module-bundle hash attested | Hash mismatch | Attestation event | Fail closed | Worker owner | — |
| Renderer drift | Renderer version pinned in profile + manifest | Version mismatch | Renderer version | Fail closed | Worker owner | — |
| Remote-state substitution | Exact workspace/state identity binding | Identity mismatch | State-identity hash | Fail closed | Operator | — |
| State-lock loss | Lock required and re-checked; loss → recovery | Lock check | Operation state | `recovery_required` | Operator | Provider lock backend outage |
| Secret leakage | Worker-only JIT; allowlist env; redaction; no durable secret | Redaction tests | Only redacted refs | N/A (never persisted) | Worker owner | Provider echoing secret in output (bounded+redacted) |
| Ambient environment leakage | Env allowlist (`build_process_env`); no inheritance | Env-scan tests | Redacted env record | Drop non-allowlisted | Worker owner | — |
| Shell injection | argv arrays only; never `shell=True` | Boundary tests | — | N/A | Worker owner | — |
| Path traversal | Executable path validated (bare id / approved absolute); ephemeral workspace | Renderer/runner validation | — | Fail closed | Worker owner | — |
| Symlink/workspace attacks | Ephemeral 0o700/0o600 workspace, always cleaned | Materialize self-clean | — | Fail closed | Worker owner | Shared-host symlink race (dedicated disposable host) |
| Raw plan / state persistence | Only redacted canonical set persisted; binary plan transient | Boundary/redaction tests | Redacted change set | N/A | Worker owner | — |
| TOCTOU (plan→apply) | Re-prepare + exact hash match, apply same plan, one attempt (I) | Hash mismatch | Approval + operation hashes | Fail closed | Approver | Provider state change mid-apply (verification catches) |
| Approval replay | Approval unique per `(manifest, kind, hash)`; `mark_consumed` | Consumed check | Approval status | Fail closed | Approver | — |
| Cross-organization binding | `organization_id` equality across target/profile/manifest | Org mismatch | Org ids | Fail closed | Operator | — |
| Partial apply | Fail-closed; verification compares observed vs approved | Verification | Operation + verification state | `recovery_required` | Recovery owner | Provider partial effects (manual cleanup) |
| Repeated terminal operation | Terminal idempotency before privileged setup | Status check | Terminal record | Idempotent no-op | Worker owner | — |
| Interrupted destroy | Destroy idempotent/retry-safe; zero-residue re-verified | Zero-residue check | Destroy + residue state | Re-verify, fail closed | Recovery owner | Provider residue (zero-residue catches) |
| Zero-residue false positive | Independent provider + state re-inspection, not exit code | Residue mismatch | Residue evidence | `zero_residue_failed` | Recovery owner | Provider hiding a resource (boundary-scoped scan) |
| External route exposure | Preflight no-route + deny-external; verification re-checks | Route check | Isolation evidence | `isolation_failed` | Operator | Undetected out-of-band route (physical isolation preferred) |
| Shared-cluster boundary escape | Physical isolation preferred; logical only if enforceable+verified | Preflight boundary | Boundary evidence | Fail closed | Operator | Hypervisor escape (out of scope; dedicated host) |
| Compromised worker | Worker-only trust; seals; least-privileged credential | Out of band | — | N/A | Security owner | Full worker compromise (deferred; image supply chain) |
| API directly executing infra | Architecture tests forbid API runner/executor/subprocess imports | Boundary tests | Test results | N/A | Reviewer | — |
| Live values in source control | Docs use fake non-routable placeholders; test scans examples | Lock test | Test results | N/A | Reviewer | — |
| Docs as an activation guide | Runbook is a non-runnable skeleton; lock test asserts it | Lock test | Test results | N/A | Reviewer | — |
| Architecture/status overclaim | STATUS truth tests; lock test asserts seals/partial status | Truth tests | Test results | N/A | Reviewer | — |

## Consequences

- B1-B becomes a **sequence of small, reviewed, fail-closed changes** against a disposable lab, not a
  large new-architecture step. Each live capability is a deliberate code-and-review unseal plus a full
  runtime gate.
- The architecture lock **activates nothing**. All B1-A seals remain `True`; no real process, plan,
  apply, destroy, or Proxmox contact has occurred; controlled `controlled-live-read-only` discovery
  status is unchanged.
- This ADR intentionally does **not** decide provider-specific resource semantics beyond what the
  current renderer/adapter already represent; a genuinely minimal real resource may be an
  implementation prerequisite (P).

## Non-goals

Production provisioning; multi-target or general fleet provisioning; automatic plan→apply or
apply→destroy; any activation, unseal, or configuration change; any endpoint/binary/secret/local-env
access; committing real values; and implementing the phased mechanism, verifier, preflight, remote
state, or secret resolver in this PR.
