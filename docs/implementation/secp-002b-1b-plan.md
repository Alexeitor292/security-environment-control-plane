# SECP-002B-1B — Implementation plan (PR decomposition)

**Status:** implementation plan for the future B1-B milestone, locked by
[ADR-020](../adr/ADR-020-first-real-disposable-lab-lifecycle.md) and detailed in
[`docs/architecture/secp-002b-1b-real-lab-lifecycle.md`](../architecture/secp-002b-1b-real-lab-lifecycle.md).
This document is **design-only**. It **activates nothing** and unseals nothing. B1B-PR1 (this
architecture lock) is docs/tests only; every later PR is a separate, independently reviewed change.

**Global invariants for every PR below:** the API never runs a process or resolves a secret; no
`shell=True`; no floating/`latest`/wildcard toolchain; no local state; no runtime provider download;
no external connectivity; no automatic plan→apply or apply→destroy; no fake fallback in a real-lab
request; no raw plan/state/secret persisted; no real value committed to source control; both B1-A
subprocess seals stay `True` until the specific PR that unseals a specific capability by a reviewed
code change. **No configuration flag alone advances a capability.**

## Phase / activation map

| PR | Capability unsealed | Live contact | Mutation | Both B1-A seals after |
| --- | --- | --- | --- | --- |
| B1B-PR1 | none (architecture lock) | none | none | `True` / `True` |
| B1B-PR2 | real on-disk toolchain attestation | worker filesystem only | none | `True` / `True` |
| B1B-PR3 | real read-only eligibility preflight | read-only Proxmox | none | `True` / `True` |
| B1B-PR4 | remote-state + JIT secret readiness | state backend + secret manager (read/validate) | none | `True` / `True` |
| B1B-PR5A | **real plan activation prerequisites (no process)** | none | none | `True` / `True` (**plan-only seal also `True`**) |
| B1B-PR5B | real `init`/`plan`/`show` (plan-only) | Proxmox read + plan | none (plan only) | plan-only unsealed; **generic subprocess + apply/destroy seals stay `True`** |
| B1B-PR6 | first apply + verification | Proxmox apply + read | one disposable lab | apply unsealed; **destroy seal stays `True`** |
| B1B-PR7 | destroy + zero-residue | Proxmox destroy + read | destroy of that lab | destroy unsealed |
| B1B-PR8 | closeout | none | none | reviewed defaults |

**Realized status (current truth).** PR1–PR5A are implemented; **PR5B is now activated**: the
dedicated plan-only code seal is `_PLAN_ONLY_PROCESS_SEALED = False` and the reviewed executor
identity was advanced `v1 → v2`. Consistent with the "Both B1-A seals after" column, **both B1-A
subprocess seals remain `True`** and apply/destroy remain impossible; only `init` / non-destroy
`plan` / `show` are executable. Flipping the seal did not arm production — the shipped
`PlanExecutionComposition` is still disabled, so ordinary `run_plan_generation` refuses at the
composition gate before any I/O. **No real Proxmox host/provider/state backend/secret manager has
been contacted, no real plan exists, and no deployment-local composition is committed.** PR6 has not
begun and does not begin until the first reviewed exact-hash real plan and PR5B merge.

---

## B1B-PR1 — Architecture lock (this PR)

- **Allowed code surfaces:** `docs/adr/`, `docs/architecture/`, `docs/implementation/`,
  `docs/runbooks/` (non-runnable skeleton only), `docs/proxmox/b1b-lab-prerequisite-checklist.md`,
  `docs/STATUS.md`, and cross-cutting architecture/status truth tests under `tests/`.
- **Forbidden code surfaces:** all `apps/api`, `apps/worker`, frontend, models, migrations, Settings,
  environment examples, Docker Compose, Kubernetes, CI workflows, shard config, timing weights,
  OpenTofu modules, provider lockfiles, process executors, activation factories, secret resolvers,
  transports, provider clients. **Neither B1-A seal may change.**
- **Activation before → after:** sealed → sealed (unchanged).
- **Live-contact level:** none. **Mutation level:** none.
- **Required tests:** `tests/test_b1b_architecture_lock.py` (design-only assertions + both seals
  `True`); existing `tests/test_architecture_boundary.py`, `tests/test_provisioning_boundary.py`,
  `apps/api/tests/test_no_real_process.py`, `apps/api/tests/test_lab_activation_gate.py`, and the
  STATUS truth tests must stay green **unchanged**.
- **Human-review gate:** architecture + threat-model review; confirm no live value committed.
- **Rollback:** revert the docs/tests commit (no runtime impact).
- **Evidence required:** approved ADR-020; approved architecture + plan; enforcing test green.
- **Completion:** merged docs/tests; seals still `True`; STATUS still `partially-implemented`,
  `production-blocked`.

## B1B-PR2 — Real toolchain attestation

**Status: implemented by this slice** (worker-local, filesystem-only `RealToolchainVerifier` +
`ToolchainFilesystemLayout`; expanded facet set; comprehensive tests over inert fixtures). No
execution capability was unsealed; both B1-A subprocess seals remain `True`; the verifier is not
wired into the runner/`run_real_provisioning` default (still fake). B1B-PR3 remains next.

- **Allowed:** the worker `ToolchainVerifier` real implementation (`RealToolchainVerifier`) —
  **filesystem verification only** of the on-disk executable/version/binary-digest/module-bundle/
  lockfile/offline-mirror/renderer/CLI-config/remote-state-backend-class/no-runtime-download.
- **Forbidden:** any endpoint contact; any OpenTofu execution; any subprocess execution; any secret
  resolution; API changes beyond recording an attestation evidence category. **Both subprocess seals
  stay `True`.**
- **Activation before → after:** sealed → attestation-only (no execution capability).
- **Live-contact:** worker local filesystem only. **Mutation:** none.
- **Required tests:** real-verifier unit tests over fixture toolchains (attest + refuse on any facet
  mismatch); a test that attestation performs no subprocess/network; seals still `True`.
- **Human-review gate:** verifier review; confirm no execution path added.
- **Rollback:** revert; verifier falls back to inert/refusing.
- **Evidence:** attestation pass/refuse events (redacted).
- **Completion:** real attestation works on-disk; no execution unsealed.

## B1B-PR3 — Real eligibility preflight

**Status: implemented by this slice** (sealed by default). A worker-owned `run_real_eligibility_preflight`
seam reuses the **existing** dormant read-only Proxmox transport (Path B, `run_live_readonly_collection`)
and the **existing** immutable `TargetPreflight`/`TargetEvidenceRecord` tables (no parallel evidence
table) to produce redacted, org/target/onboarding/authorization/worker-identity/policy-bound, hash-bound,
expiry-bound `live_verified` eligibility evidence via a versioned, deterministic, provider-neutral
eligibility policy. **Transport choice (documented truthfully):** the authoritative transport is the
HTTP read-only Proxmox collector (Path B), because it is the only shipped transport whose normalized
observations feed the mandated `compare_boundary_to_evidence` pipeline and the network/CIDR/isolation
dimensions the SSH discovery path (Path A, `target_discovery`) structurally cannot observe; the two paths
are independent (neither delegates to the other) and are never both activated. **Durable execution is
part of PR3 (not deferred to PR4):** the API is enqueue-only (durable `WorkflowRun` + outbox; inline
execution refused with no fallback); a worker-only `EligibilityPreflightWorkflow`/activity loads the
authoritative records and runs the seam; live-evidence persistence is worker-only (the API cannot import
it) and takes a typed evaluator result (the source/level label alone can never create live evidence). The
seam is **durably wired but default-disabled**: the shipped `build_eligibility_composition` is fully sealed
(no transport/resolver/collector; the seal is an out-of-band reviewed composition, never an env flag), so
the durable path runs to completion but refuses at the seal before any contact. The actual production
collector, through the reviewed GET allowlist, yields `unverifiable`/`ineligible` — **never `eligible`**
(isolation/VM-ID/quota/disposability are not inferred; reaching `eligible` is a documented deployment
prerequisite), proven by an integration test over the exact real chain. No OpenTofu runs, nothing is
mutated, both B1-A subprocess seals remain `True`, and no real Proxmox host has been contacted. B1B-PR4
(remote-state + JIT secret readiness) remains next.

- **Allowed:** a worker-only, **read-only** Proxmox eligibility/boundary preflight producing
  immutable, redacted, org-scoped, target-bound, timestamped, hash-bound, expiry-bound evidence
  (target identity, TLS verified, nodes/storage/bridge/VLAN exist, VM-ID no collision, CIDR no
  overlap, quotas enforceable, **no-route**, deny-external, least-privileged credential, no target
  drift, onboarding still matches).
- **Forbidden:** any OpenTofu execution; any mutation; API-side secret resolution or process
  execution; accepting caller-asserted eligibility. **Both subprocess seals stay `True`.**
- **Activation before → after:** attestation-only → attestation + read-only eligibility.
- **Live-contact:** **read-only** Proxmox. **Mutation:** none.
- **Required tests:** preflight over injected read-only transport fixtures (pass + each refusal);
  evidence immutability/redaction/expiry/drift-invalidation; no mutation import; seals still `True`.
- **Human-review gate:** read-only transport + evidence review.
- **Rollback:** revert; preflight seam returns to unavailable.
- **Evidence:** preflight requested/completed/refused (redacted).
- **Completion:** real read-only eligibility evidence; still no OpenTofu, no mutation.

## B1B-PR4 — Remote-state and secret-resolution readiness

**Status: implemented by this slice** (sealed by default; locked by
[ADR-021](../adr/ADR-021-remote-state-and-jit-secret-readiness.md)). Two SEPARATE durable,
worker-owned readiness operations now exist — `remote_state_readiness` and `plan_secret_readiness` —
each with the full chain: API request → transactionally durable `WorkflowRun` + outbox → Temporal
workflow → worker activity → fresh-session authoritative record loading → complete gate → readiness
adapter → typed evaluation → immutable evidence → **STOP**. Neither operation invokes the other;
passing eligibility requests neither; completing both creates **no plan**.

**Remote-state readiness** validates backend CONTROL METADATA through a provider-neutral, explicitly
injected `RemoteStateReadinessAdapter` whose contract **has no state-body surface at all** (an
adapter exposing `read_state`/`upload_state`/`force_unlock`/… is refused before invocation). Ten
mandatory facets — backend class (remote only), transport security, server-derived namespace
identity, encryption-at-rest proof, locking proof, backup proof, restore proof, least-privileged
access, empty-or-expected namespace, no local fallback — must ALL pass explicitly; any unprovable
fact fails closed to `unverifiable`. **PR4 performs no backup and no restore against real state**: it
VALIDATES external proofs, never invents them.

**Plan-secret readiness** proves two things without revealing a target credential: the worker can
AUTHENTICATE to the secret backend (the reviewed `ResolverSelfTest`), and opaque `SecretMaterial`
projects into ONLY the allowlisted child-process environment (exercised with an **inert sentinel**;
no process runs; `os.environ` is neither read nor mutated — `plan_env` does not import `os` at all).
**`WorkerSecretResolver.resolve()` is never called; the actual target provisioning credential is NOT
resolved as project evidence.** It requires its own dedicated, time-bounded, revocable
`PlanSecretReadinessAuthorization` (a `readiness:approve` permission, a complete human-review evidence
set) plus a single-use CAS `PlanSecretResolutionLease` (fixed `N=3` budget; `begin_attempt` is the
last thing before the secret boundary).

**Purpose is plan-only.** `PlanSecretPurpose` has exactly ONE member (`plan_read`) — apply and destroy
purposes are **unrepresentable**, not merely rejected. The API is **enqueue-only** (the inline
dispatcher refuses with no fallback) and the shipped composition is fully **sealed** (no adapter, no
self-test), so the durable path runs to completion yet refuses at the seal before any state backend or
secret manager is contacted. No OpenTofu ran, nothing was mutated, both B1-A subprocess seals remain
`True`, and **no real state backend, secret manager, or Proxmox host has been contacted**. B1B-PR5A
(real plan activation prerequisites — no process) remains next; B1B-PR5B (real `init`/`plan`/`show`)
follows it.

- **Allowed:** remote-state backend validation (remote only, encryption at rest, state locking,
  least-privileged access, tested backup/restore, exact workspace/state identity binding); worker-only
  JIT secret injection readiness (`WorkerSecretResolver` real path replacing `SealedSecretResolver`,
  allowlisted child env via `build_process_env`/`build_lab_secret_env`, redaction).
- **Forbidden:** any plan/apply/destroy; local state or local fallback; API-side secret resolution;
  state contents in logs/audits/responses. **Both subprocess seals stay `True`.**
- **Activation before → after:** read-only eligibility → + state/secret readiness (still no execution).
- **Live-contact:** state backend + secret manager (validate/self-test readiness) — **supported by the
  code, NOT exercised as project evidence** (the shipped composition is sealed). **Mutation:** none.
- **Required tests:** backend validation refuses local/unlocked/unencrypted; backup/restore proof;
  JIT resolution injects only allowlisted redacted env; no secret persisted; seals still `True`.
- **Human-review gate:** state + secret-handling review.
- **Rollback:** revert; resolver returns to sealed `credential_unavailable`.
- **Evidence:** state readiness + resolution readiness (redacted).
- **Completion:** state + secret readiness **contracts** proven over fixtures; still no plan/apply/
  destroy. **A passing fixture is not operator deployment readiness** — the prerequisite-checklist
  boxes for remote state and least-privileged credentials remain unchecked.

### Implementation prerequisites for B1B-PR5 surfaced by PR4 — current truth (updated by PR5A)

PR4's readiness contracts left a defined set of prerequisites before any real plan may run. Their
status **as of the PR5A boundary** is:

1. **Operation-specific credential separation was not real at PR4.** `ExecutionTarget` had ONE
   generic `secret_ref`, so PR4 bound a plan-read PURPOSE CLASS + a reviewed reference SCHEME and made
   **no least-privilege claim about the credential itself**. **PR5A closes this**: two distinct
   credential purposes now exist — `provider_plan_read` and `state_backend_plan` — each with its own
   dedicated opaque reference and its own versioned credential binding; the generic `secret_ref`
   remains only for simulated/dev compatibility and **cannot satisfy a real-plan gate**. Apply and
   destroy credential purposes remain **absent / unrepresentable**. No least-privilege claim is made
   from the purpose label alone — actual scope is backed by reviewed activation-dossier evidence.
2. **No third independent credential-reference source existed** for provisioning at PR4 (the manifest
   is secret-free by design). **PR5A closes this**: the opaque credential-binding id + version are now
   bound in **three** independent authoritative places — the current target credential configuration,
   the immutable `ProvisioningManifest`, and the approved activation dossier — for **both** purposes,
   and the worker requires exact agreement (target == manifest == dossier). The actual reference is
   still loaded only in worker memory after the identity comparison.
3. **PR2's toolchain attestation is now durable (corrected).** The PR4 security amendment made the
   worker-produced `ToolchainAttestationRecord` a durable, immutable evidence row (a matching profile
   hash is a *declaration*, not evidence); both readiness operations already require the exact current
   attestation record id + evidence hash. There is **no** remaining in-memory-only attestation gap.
4. **The activation dossier now fails closed (corrected), and a real reviewed dossier is added by
   PR5A.** The placeholder sentinel is refused everywhere (binding, readiness, capability, combined
   status, audit). PR5A adds the **durable, explicit, human-reviewed activation-dossier lifecycle**
   (draft → evidence → approved → revoked/expired/superseded) that persists only safe bindings and
   proof metadata; **the detailed dossier remains deployment-local and outside source control**, and a
   real reviewed dossier record is still required before any live plan.
5. **Path B still cannot reach `eligible` through the reviewed GET allowlist alone.** PR5A closes this
   **honestly** with a deterministic combined evaluation that distinguishes observed live evidence
   from independently-approved deployment-control (dossier) evidence and from unsupported/unverifiable
   claims — it does **not** widen the GET allowlist to force eligibility, add a third collector, or
   promote simulated/test-only evidence. Reaching `eligible` against a real target still requires an
   operator deployment.

## B1B-PR5A — Real plan activation prerequisites (no process)

- **Allowed:** close every remaining PR5 prerequisite **without executing any process**: the durable
  reviewed activation-dossier lifecycle; operation-specific credential separation
  (`provider_plan_read` + `state_backend_plan`); three-way target/manifest/dossier credential binding;
  honest eligibility closure (deployment-control evidence + combined evaluator); a dedicated
  `RealPlanGenerationAuthorization` (`plan_generation` purpose only); a pure `PlanGenerationReadiness`
  helper; the **sealed** plan-only process seam design; the two-`SecretMaterial` projection contract;
  and the durable enqueue-only `real_plan_generation` workflow skeleton that STOPS at the plan-only
  seal.
- **Forbidden:** executing OpenTofu / any subprocess; constructing `SubprocessProcessExecutor` or an
  unsealed plan executor; contacting Proxmox / a state backend / a secret manager; loading a provider;
  rendering a real workspace for execution; resolving a real credential; creating a binary plan;
  mutating infrastructure; unsealing anything; beginning PR5B. **Both B1-A subprocess seals — and the
  new plan-only process seal — stay `True`.**
- **Activation before → after:** readiness → **prerequisites closed, still sealed** (no capability
  unsealed).
- **Live-contact:** **none.** **Mutation:** **none.**
- **Required tests:** dossier placeholder/incomplete/wrong-binding/expired/tampered refusals and "no
  live values"; credential purpose distinctness + three-way agreement + rotation invalidation + raw
  UPDATE + replica-mode; eligibility combined-evaluation honesty; plan-generation authorization
  lifecycle + dedicated permission; plan readiness requires every binding; the sealed plan-only
  executor cannot be constructed or called and `plan -destroy`/apply/arbitrary flags are refused by
  its grammar; the workflow is enqueue-only, inline-refused, ids-only, and STOPS at the seal; PostgreSQL
  enforcement; both B1-A seals `True`.
- **Human-review gate:** prerequisite-closure + threat-model review; confirm nothing is unsealed.
- **Rollback:** revert the PR5A commit (no runtime capability change).
- **Evidence:** dossier lifecycle events; plan-generation authorization events; `plan_generation`
  requested/started/**refused** (never `completed` — no plan executes).
- **Completion:** every PR5 prerequisite closed and the complete ordering proven up to (but not past)
  the plan-only seal; **no process, no plan, no mutation**; both B1-A seals + the plan-only seal `True`.

## B1B-PR5B — Live plan-only execution

- **Allowed:** unseal **only** real `init`/`plan`/`show -json` for **one** disposable target (a
  reviewed change to the **plan-only** seal constant only — the generic `SubprocessProcessExecutor`
  seal and the apply/destroy seals stay `True`), through the operation-restricted plan-only process
  capability, producing the canonical redacted change set + `change_set_hash`; human review +
  exact-hash approval flow end-to-end against the real target.
- **Forbidden:** apply and destroy (their seal constants **stay `True`** — technically incapable);
  the generic subprocess executor (its seal **stays `True`**); automatic plan→apply; fake fallback;
  runtime provider download; external connectivity; raw plan/state persistence.
- **Activation before → after:** prerequisites-closed → plan-only (generic subprocess + apply/destroy
  still sealed).
- **Live-contact:** Proxmox read + real plan. **Mutation:** **none** (plan only).
- **Required tests:** real plan generates a redacted canonical change set; apply/destroy + the generic
  subprocess executor still refuse (their seals `True`); TOCTOU re-prepare/hash-match logic; no raw
  plan/state persisted; exact-hash approval required.
- **Human-review gate:** first real plan review; confirm apply/destroy remain impossible.
- **Rollback:** re-seal the plan-only constant; revert.
- **Evidence:** real plan generated/refused; change set approved/rejected (redacted).
- **Completion:** one reviewed real plan + exact approval; **no apply**.

> **Implementation progress (build-out state — superseded by the "Realized status" note above, which
> records the final activation: the plan-only seal is now `_PLAN_ONLY_PROCESS_SEALED = False`, the
> executor identity is `v2`, both B1-A seals stay `True`, and the shipped composition stays disabled
> so production still refuses).** The COMPLETE plan-only execution path was implemented and proven
> end-to-end against a tiny **inert local fixture**. **Mechanism:** the separate controlled-live
> `bpg/proxmox` renderer + render-safety scanner (one LXC container; the fake adapter can never reach
> it), capability-bound argv derivation, the hardened `PlanOnlyProcessExecutor.run` (reachable while
> sealed only via an explicit token-gated **test-only** path no shipped module references), the safe
> ephemeral workspace, the create-only `PlanChangePolicyEvaluator`, and `PlanOnlyOpenTofuRunner`
> (no apply/destroy method). **Durable orchestration (now wired):** the immutable append-only
> `RealPlanGenerationResult` + the CAS `PlanGenerationExecutionLease` (single active lease per
> operation fingerprint, fixed shared budget never reset on recovery, `begin_attempt` before any
> secret contact, `recovery_required` terminal) + the extended attempt lifecycle, on a new migration
> at the single Alembic head (`c4e2f9a1b7d3`, `ENABLE ALWAYS` triggers, partial-unique CAS index,
> closed-status CHECKs, truthful downgrade) with ORM immutability guards; a ~50-binding
> non-serializable `PlanOnlyCapability` bound to the exact reviewed process/renderer implementation
> digests; a worker-only, fully-sealed-by-default `PlanExecutionComposition` (no env flag/URL/target
> row/PATH/binary/boolean can activate it; classification bound to the actual executor factory);
> FRESH execution-time re-attestation via the real `RealToolchainVerifier` (POSIX for controlled-live;
> paths from the verified layout, never PATH); a SEPARATE two-credential JIT resolver seam (never the
> generic `secret_ref` fallback); typed HTTPS-only runtime inputs + the exact explicit child
> environment; the upgraded `run_plan_generation` ordering (production refuses at the sealed
> composition gate before any filesystem/secret/render/executor/process); and the exactly-once durable
> result wired to a PENDING, human-only, exact-hash `ProvisioningChangeSetApproval` for a PROSPECTIVE
> apply — never auto-approved, and approving it enqueues no PR6, calls no apply/destroy, and issues no
> apply capability. A 24-vector adversarial review found **0 confirmed breaks**. **No real Proxmox
> host has been contacted; no provider plugin has been downloaded or run; no real OpenTofu process has
> run against any endpoint; no plan against real infrastructure exists.** The "real target" execution
> named above is a later, human-supervised operator validation — it has NOT occurred. The POSIX
> inert-subprocess tests are designed for GitHub CI and have not yet produced authoritative CI
> evidence (nothing is pushed). The seal flip is the deliberate, reviewed LAST step (ADR-022 §9),
> performed only once operator validation is authorized, and is out of scope for the current change.

## B1B-PR6 — First apply and verification

- **Allowed:** unseal **only** apply for **one exact approved prepared plan** (a reviewed change to
  the **apply** seal constant); apply via `apply_prepared` under the full gate (ADR-020 §J); post-apply
  observed-state + isolation verification (§K).
- **Forbidden:** destroy (its seal **stays `True`**); automatic apply→destroy; apply of any plan other
  than the exact approved prepared plan; recording success before verification completes; API-direct
  apply.
- **Activation before → after:** plan-only → apply-enabled for the one approved plan (destroy sealed).
- **Live-contact:** Proxmox apply + read. **Mutation:** **one disposable lab**.
- **Required tests:** apply requires the exact prepared plan + fresh hash match + full gate; drift
  refuses; verification produces `verified`/`verification_failed`/`state_disagreement`/
  `isolation_failed`/`recovery_required`; exit-code-alone is insufficient; destroy still refuses.
- **Human-review gate:** first real apply review + go/no-go; recovery owner on standby.
- **Rollback:** re-seal apply; manual cleanup procedure (must exist before this PR).
- **Evidence:** apply requested/started/completed/failed; verification completed/failed (redacted).
- **Completion:** one verified real apply; **no automatic destroy**.

## B1B-PR7 — Destroy and zero-residue

- **Allowed:** unseal **only** destroy through its **own** newly generated destroy change set, its own
  redacted canonical hash, and its own **separate** human approval (a reviewed change to the
  **destroy** seal constant); destroy via `destroy_prepared` under the full gate; zero-residue proof
  (§L); state closeout.
- **Forbidden:** reusing the apply approval for destroy; assuming destroy proves cleanup; leaving
  state/workspace/transient-plan residue.
- **Activation before → after:** apply-enabled → destroy-enabled (its own approval).
- **Live-contact:** Proxmox destroy + read. **Mutation:** destroy of that lab.
- **Required tests:** destroy requires its own approval + gate; idempotent/retry-safe; zero-residue is
  an independent provider+state re-scan producing `zero_residue_confirmed`/`zero_residue_failed`.
- **Human-review gate:** first real destroy review; zero-residue sign-off.
- **Rollback:** re-seal destroy; manual containment + cleanup.
- **Evidence:** destroy planned/approved/started/completed/failed; zero-residue confirmed/failed.
- **Completion:** one successful destroy + confirmed zero residue + state closeout.

## B1B-PR8 — Closeout

- **Allowed:** evidence review; STATUS correction to reflect one completed reviewed run; lessons
  learned; a **review** of seals/defaults (not an automatic expansion).
- **Forbidden:** automatic expansion to other targets; leaving any capability unsealed by default;
  overclaiming production readiness.
- **Activation before → after:** run-complete → reviewed defaults (capabilities **re-sealed by
  default**; each future run re-unseals under review).
- **Live-contact:** none. **Mutation:** none.
- **Required tests:** STATUS truth tests updated to the real, evidenced state; seals reflect the
  reviewed default.
- **Human-review gate:** closeout review.
- **Rollback:** n/a (documentation).
- **Evidence:** the full immutable audit chain from one run; documented recovery observations.
- **Completion:** B1-B success definition (ADR-020 §Q) met by evidence from **one** real run — not a
  test or fake.
