# ADR-022 — Plan-only activation and the process boundary

- **Status:** **Accepted** for the **B1B-PR5A** architecture **and** the later **B1B-PR5B** execution
  slice. PR5A is implemented by the same slice that adds this ADR; it **executes no process and
  unseals nothing**. PR5B is a separate, independently reviewed change that unseals **only** the
  operation-restricted plan-only process capability by a reviewed code change to a **new** seal
  constant.
- **Date:** 2026-07-14
- **Milestone:** SECP-002B-1B — First Real Disposable-Lab Lifecycle, **PR5** (ADR-020 §C Phase 4),
  split into **PR5A** (prerequisite closure, no process) and **PR5B** (plan-only execution).
- **Related:** ADR-011/012 (immutable manifests, worker-only runner), **ADR-013** (sealed OpenTofu
  runtime + isolated-lab activation — the `_B1A_SUBPROCESS_SEALED` mechanism, `PreparedOpenTofuPlan`,
  `ProvisioningChangeSetApproval`, `canonicalize_plan_json`/`change_set_hash`), ADR-014 (onboarding),
  ADR-015 (live read-only collector), **ADR-020** (B1-B architecture lock — §C phased unsealing, §D
  dossier, §I plan review + TOCTOU), **ADR-021** (remote-state + JIT secret readiness — the readiness
  contracts, the opaque `CredentialBinding`, the activation-dossier placeholder, the controlled-live
  adapter capability). Architecture `docs/architecture/secp-002b-1b-real-lab-lifecycle.md`; plan
  `docs/implementation/secp-002b-1b-plan.md`.

> **No OpenTofu process has run. No plan has been generated. No `SubprocessProcessExecutor` has been
> constructed. No new plan-only process executor has been constructed. No provider has loaded. No real
> state backend, secret manager, or Proxmox host has been contacted. No real credential has been
> resolved. No binary plan or raw `show -json` exists. Both B1-A hard seals
> (`_B1A_SUBPROCESS_SEALED = True` in `apps/worker/secp_worker/provisioning/process_executor.py` and
> `apps/worker/secp_worker/provisioning/activation.py`), and the new plan-only process seal, remain
> exactly `True`.**

## Context

ADR-020 §C locks B1-B as operation-specific phased unsealing: each capability (plan, apply, destroy)
has its **own** code seal constant, its **own** runtime enablement, and its **own** human approval,
so a plan-only build is *technically unable* to apply or destroy. ADR-013 built the sealed generic
`SubprocessProcessExecutor` (`_B1A_SUBPROCESS_SEALED = True`) that runs the real OpenTofu argv, plus
the exact-prepared-plan / redacted-change-set / exact-hash-approval discipline. ADR-021 (PR4) added
the last readiness contract and, in its security amendment, the durable toolchain attestation, the
opaque `CredentialBinding`, the controlled-live adapter capability, and the fail-closed
activation-dossier placeholder — while leaving five explicit prerequisites before a real plan.

Phase 4 ("real `init`/`plan`/`show` only") is the first phase that would run a real OpenTofu process.
That is too large to unseal in one step, so it is split:

- **PR5A** closes every remaining prerequisite and proves the complete ordering **up to, but not
  past, the plan-only process seal** — executing nothing.
- **PR5B** unseals **only** the operation-restricted plan-only process capability.

This ADR locks that boundary so PR5B is a small reviewed unseal, not new architecture invented under
pressure.

## Decision — locked

### 1. PR5A executes no process; PR5B executes only plan-read subcommands

- **PR5A executes no process of any kind.** It constructs no executor, resolves no credential, renders
  no execution workspace, creates no binary plan, and contacts nothing. It ends **before** any
  subprocess construction.
- **PR5B may execute only three OpenTofu subcommands:** `init` (offline), a **non-destroy** `plan`,
  and `show -json` against that exact transient plan file. **Apply, destroy, and `plan -destroy` are
  not merely refused at runtime — they are outside the plan-only capability's grammar entirely** (§4).

### 2. The generic subprocess executor stays sealed; plan-only gets a NEW seal

- The existing generic `SubprocessProcessExecutor` remains sealed in **both** PR5A and PR5B
  (`_B1A_SUBPROCESS_SEALED = True`). Plan-only execution does **not** unseal it and does **not** route
  through it.
- Plan-only execution uses a **separate, narrow `PlanOnlyProcessExecutor`** with its **own** code seal
  constant (`_PLAN_ONLY_PROCESS_SEALED`). In **PR5A that constant is `True`** — the plan-only executor
  cannot be constructed or invoked, exactly as B1-A refuses all subprocess execution today. PR5B is a
  reviewed change that sets **only** the plan-only constant to `False`; the generic subprocess seal
  and the apply/destroy seals stay `True` code constants.
- **Apply and destroy can never share the plan capability.** The plan-only executor's grammar admits
  no apply/destroy tokens (§4); apply/destroy remain the province of the still-sealed generic executor
  (`apply_prepared`/`destroy_prepared`), which is a distinct, separately-reviewed future unseal.
  Apply and destroy therefore remain **technically impossible** for a plan-only build.

### 3. No configuration flag alone creates a capability; the full gate is mandatory

A plan-only capability requires **all** of: the plan-only seal unsealed (a reviewed code change — never
a flag); a **real, reviewed, deployment-local activation dossier** (the placeholder is refused
everywhere); **current eligible live evidence**; **operation-specific plan and state credentials**
(`provider_plan_read` + `state_backend_plan`, each an opaque versioned binding); **exact agreement of
the opaque credential bindings across target, manifest, dossier, and worker**; a current durable
toolchain attestation; current remote-state and both secret readiness records; an approved
`RealPlanGenerationAuthorization` bound to the exact plan-only capability contract version; a current
worker identity; and a non-production environment on the durable Temporal worker path. **No
environment variable, backend kind, URL, installed SDK, `PATH` entry, database row, caller flag, or
dossier label alone creates a capability.**

### 4. The plan-only capability and its command grammar (locked for PR5B)

The plan-only capability is **worker-only, non-serializable, operation-specific, dossier-bound,
authorization-bound, manifest-bound, worker-bound, and expiring**. It is issued only after the full
gate, behind a module-private token; it cannot be serialized, pickled, placed in a Temporal argument,
persisted, or constructed by API code; and a **fake or injected generic executor cannot satisfy it**
(a reviewed implementation digest is pinned, exactly as ADR-021's adapter capability).

Its command grammar admits **only**:

- an **exact pinned executable** (the attested toolchain binary; bare safe identifier or approved
  absolute worker path — never a caller path);
- `-chdir=<approved ephemeral workspace>` (worker-owned, ephemeral 0o700/0o600, always cleaned);
- `init` with exact **offline** flags (offline mirror, no runtime download, read-only lockfile);
- `plan` with `-input=false`, `-no-color`, `-lock=true`, an exact transient `-out`, and **no
  `-destroy`**;
- `show -json` against **that exact transient plan file**.

It **rejects every other command or token**, including: `apply`; `destroy`; `plan -destroy`; `import`;
`refresh`; `state`; `output`; `workspace`; `providers` mirror/lock mutations; `console`;
`force-unlock`; `taint`/`untaint`; arbitrary subcommands; arbitrary plan paths; arbitrary cwd; shell
strings; response files; environment interpolation; and any additional flag not explicitly reviewed
here. Rejection is fail-closed and precedes any process construction.

### 5. The API is enqueue-only; the Temporal worker owns execution

The API may create durable `WorkflowRun` + `WorkflowDispatchOutbox` records (identifiers only — no
secret, no credential, no target config) and expose bounded read models. It **never** constructs an
executor, resolves a credential, renders a workspace, or runs a process. The inline dispatcher
**refuses with no fallback**. Execution belongs **only** to a registered Temporal worker workflow +
activity that opens a fresh session, re-derives the complete authoritative binding, evaluates
combined plan-readiness, and — in PR5A — **refuses at the plan-only seal and STOPS**.

### 6. Raw binary plans and raw `show -json` are never durable

Consistent with ADR-013/ADR-020 §I: the transient binary plan and the raw `show -json` are
**worker-local and never persisted** as durable application data. Only the **redacted canonical change
set + `change_set_hash`** and safe review metadata are durable. In PR5A **nothing of this exists yet**
(no plan runs); the discipline is locked here for PR5B.

### 7. A generated plan does not authorize apply; approval is separate and exact-hash-bound

A generated plan is **review evidence, not authorization to apply**. Apply (a future phase) requires a
**separate** explicit human approval of the **exact** `change_set_hash` (`ProvisioningChangeSetApproval`,
`provisioning:approve`) — never inferred from the plan-generation authorization, the dossier, or the
readiness records. The `RealPlanGenerationAuthorization` added in PR5A authorizes **only**
`plan_generation`; it does not authorize apply, destroy, provider mutation, state mutation, credential
rotation, or dossier approval.

### 8. A restart discards the transient plan; apply must regenerate and exactly match approval

Consistent with ADR-020 §I's TOCTOU-safe model: the transient `PlanOnlyPreparedPlan` **deliberately
does not survive a worker restart**. Only the human approval is durable. A future apply attempt
**re-prepares a fresh plan within one worker attempt**, requires the freshly-computed canonical
`change_set_hash` to **exactly match** the durable approval (and re-asserts every binding hash), and
applies **that same freshly-prepared plan** — never a persisted binary plan and never a second render
or plan. PR5A persists no plan and therefore relies on nothing across restart.

### 9. PR5A ends before subprocess construction

The PR5A durable path runs the complete ordering — authoritative load → combined plan-readiness →
plan-only seal — and **refuses at the seal before any process executor is constructed**. A bounded,
secret-free `plan_generation_refused` audit is recorded. **No `completed` outcome exists in PR5A
because no plan executes.**

## What PR5A adds (all secret-free, all sealed)

1. A durable, explicit, human-reviewed **activation-dossier lifecycle** (draft → evidence recorded →
   approved → revoked/expired/superseded). Approval requires a **dedicated** permission and creates,
   enqueues, executes, resolves, and contacts **nothing**. Only safe bindings and proof metadata are
   persisted; the detailed dossier stays deployment-local and outside source control. The placeholder
   sentinel is refused everywhere.
2. **Operation-specific credential separation**: `provider_plan_read` and `state_backend_plan`, each
   an opaque versioned binding sourced from its own dedicated reference; the generic `secret_ref`
   remains dev/simulated-only and cannot satisfy a real-plan gate. Apply/destroy purposes are absent.
3. **Three-way credential binding**: the opaque binding id + version agree across the current target
   configuration, the immutable manifest, and the approved dossier — for both purposes. Any rotation
   after manifest generation or dossier approval invalidates the dossier, readiness, plan-generation
   authorization, and combined plan-readiness, while historical records stay immutable.
4. **Honest eligibility closure**: a deterministic combined evaluation distinguishing observed live
   evidence, independently-approved deployment-control (dossier) evidence, and unsupported/unverifiable
   claims — without widening the GET allowlist, adding a collector, or promoting simulated evidence.
5. A dedicated **`RealPlanGenerationAuthorization`** (`plan_generation` only) and a pure
   **combined plan-readiness** helper.
6. A **sealed** `PlanOnlyProcessExecutor` design + the two-`SecretMaterial` (provider + state) JIT
   projection contract (no process runs in PR5A).
7. The durable, enqueue-only **`real_plan_generation`** workflow skeleton that STOPS at the seal.

## Security amendment (hardened before push)

Four boundaries were tightened before this PR is pushed; none weakens a seal:

1. **The generic `secret_ref` fallback can never satisfy a real-plan gate.** A `CredentialBindingSource`
   (`dedicated_operation` vs `legacy_generic`) is part of a binding's immutable identity (ORM + PG,
   `ENABLE ALWAYS`). Every real-plan gate (dossier create/approve, combined readiness, plan-generation
   authorization, the future PR5B resolution) resolves credentials ONLY through
   `require_real_plan_credential_reference` / `real_plan_credential_bindings`, which require two
   DEDICATED, DISTINCT, independently-bound references. A legacy `secret_ref` change can no longer
   rotate or refresh a dedicated (real-plan) binding.
2. **An observed-live failure always dominates approved deployment-control evidence.** A closed,
   versioned per-dimension source policy declares which dimensions are observed-live-required vs
   supplementable; a dossier can never relabel an observed dimension as control-plane; and the
   per-dimension source + result are folded into the canonical evidence hash.
3. **The dossier binds ONE exact live preflight.** It pins the preflight id + evidence hash and folds
   the full provenance (source/level/outcome/policy+contract+allowlist versions/authorization/worker/
   config/onboarding/timestamps) into the dossier hash. It refuses a preflight containing a live
   failure, and a new/changed preflight invalidates the dossier at approval and in combined readiness
   — without mutating any historical record.
4. **`revocation_reason_code` is a closed code, set only on revocation and never again** (ORM + PG,
   `ENABLE ALWAYS`).

## Threat model (PR5A / plan-only boundary)

| Threat | Prevention | Detection | Refusal | Residual risk |
| --- | --- | --- | --- | --- |
| Config-only unseal of plan-only | Plan-only capability is a **code seal constant**, never a flag | Seal test asserts constant `True` | Executor construction refused | Reviewer flips the constant in error (review control) |
| Plan-only → apply/destroy escalation | Grammar admits no apply/destroy tokens; apply/destroy stay separate sealed constants | Grammar test | Fail closed before any process | Reviewer flips multiple seals in one PR (review control) |
| Generic executor substitution | Generic `SubprocessProcessExecutor` stays sealed; a fake/injected generic executor cannot satisfy the plan-only capability (pinned digest) | Seal + capability tests | Fail closed | Compromised worker image (out of scope) |
| `plan -destroy` / argv injection | Fixed argv builders; explicit no-`-destroy`; identifier allowlist; never a shell string | Grammar + identifier tests | Fail closed | — |
| Arbitrary cwd / plan path | `-chdir` and `-out`/`show` bound to the worker-owned ephemeral workspace + exact transient plan file | Grammar test | Fail closed | — |
| Dossier placeholder / forgery / cross-org reuse | Placeholder refused everywhere; dossier binds org/target/manifest/plan + evidence fingerprint; approval is a dedicated permission | Binding compare | Fail closed | Reviewer approving a bad dossier (review control) |
| Generic-credential fallback / purpose confusion | Real-plan gate requires the dedicated `provider_plan_read` + `state_backend_plan` bindings; the generic `secret_ref` cannot satisfy it; apply/destroy purposes unrepresentable | Purpose + binding compare | Fail closed | — |
| Post-approval credential rotation | Rotation bumps the binding version; three-way agreement then fails; dossier/readiness/authorization invalidated | Version compare | Fail closed | — |
| Raw SQL credential swap / replica-mode bypass | ORM `before_flush` + PostgreSQL ENABLE ALWAYS triggers rotate on any `UPDATE` of either reference | Rotation trigger | Auto-rotate | — |
| Caller-forced eligibility | Combined evaluation requires an allowed source per mandatory dimension; a caller boolean or dossier label alone is insufficient | Combined evaluator test | Fail closed | — |
| Plan-generation authorization treated as apply approval | The authorization authorizes only `plan_generation`; apply requires a separate exact-hash approval | Type + purpose | Fail closed | — |
| Secret / workflow-argument leakage | Enqueue-only; ids-only Temporal args; no secret persisted/logged/audited; no credential resolved in PR5A | Leak scan | N/A | — |
| Automatic readiness→plan or approval→plan | Every transition is a separate explicit request; nothing auto-dispatches | Ordering tests | N/A | — |
| Status overclaim | STATUS truth tests; this ADR's "no process/no plan" statement | Truth tests | N/A | Reviewer error |

## Consequences

- Phase 4 becomes two small reviewed slices. PR5A closes every prerequisite with **zero** new
  execution capability; both B1-A seals and the new plan-only seal remain `True`.
- PR5B becomes a single reviewed unseal of one narrow, operation-restricted plan-only capability, with
  the generic subprocess executor and the apply/destroy capabilities still technically impossible.
- Operator work is unchanged and still required: a real reviewed activation dossier, operation-scoped
  credentials, and a real eligible target are deployment-local operator responsibilities that code
  cannot fabricate.

## Non-goals

Any process execution, plan, apply, or destroy in PR5A; unsealing the generic subprocess executor in
PR5A **or** PR5B; apply/destroy capability; automatic plan→apply; committing any real endpoint,
credential, secret reference, state key, or deployment value; and beginning PR5B.
