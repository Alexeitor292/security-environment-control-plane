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

> **(PR5A state.) No OpenTofu process has run. No plan has been generated. No
> `SubprocessProcessExecutor` has been constructed. No new plan-only process executor has been
> constructed. No provider has loaded. No real state backend, secret manager, or Proxmox host has
> been contacted. No real credential has been resolved. No binary plan or raw `show -json` exists.
> Both B1-A hard seals (`_B1A_SUBPROCESS_SEALED = True` in
> `apps/worker/secp_worker/provisioning/process_executor.py` and
> `apps/worker/secp_worker/provisioning/activation.py`), and the new plan-only process seal, remain
> exactly `True`.**

> **PR5B mechanism addendum (mechanism build-out — superseded by the seal-flip addendum below).**
> The plan-only execution **mechanism** is now
> implemented and exercised — but **only against a tiny inert local fixture**, and **only** through an
> explicit, token-gated **test-only** construction path that no shipped module references (an
> architecture scanner enforces this). Under that test-only path the plan-only executor's `run`
> launches the inert fixture (`shell=False`, absolute pinned executable, exact explicit child env,
> `stdin=DEVNULL`, process-group timeout, output cap) and the runner drives `init`/`plan`/`show`,
> producing a redacted canonical change set + `change_set_hash` that is then discarded. **The shipped
> production issuer stays sealed: `_PLAN_ONLY_PROCESS_SEALED` remains exactly `True`, and both B1-A
> seals remain exactly `True`.** No real provider plugin has been downloaded or loaded; no real state
> backend, secret manager, deployment credential, or Proxmox host has been contacted; no real
> OpenTofu process has run against any endpoint; no plan against real infrastructure exists. The
> durable result/lease (+ migration `c4e2f9a1b7d3`), the ~50-binding capability hardening, the FRESH
> execution-time re-attestation, the SEPARATE two-credential JIT resolution, the exactly-once durable
> result + PENDING human-only exact-hash approval, and the upgraded workflow ordering are now **all
> implemented and tested** (a 24-vector adversarial review found 0 confirmed breaks), but the seal
> flip (§9) — the deliberate, reviewed LAST step, gated on authorized operator validation — was
> **not** performed at the time of that addendum, and both the shipped `PlanExecutionComposition` and
> the shipped controlled-live executor factory remain sealed.

> **PR5B seal-flip activation addendum (current truth).** The dedicated plan-only code seal is now
> `_PLAN_ONLY_PROCESS_SEALED = False` (a reviewed one-constant change in
> `apps/worker/secp_worker/plan_gen/process_boundary.py`), and the reviewed executor implementation
> identity was advanced `secp-002b-1b-pr5b/plan-only-executor/v1 → v2` (so any capability, activation,
> or composition bound to the old sealed `v1` digest is refused). The `PlanOnlyProcessExecutor` can
> now be constructed on the production path — but **exclusively** through `issue_plan_only_executor`,
> with an exact `PlanOnlyExecutionContext` carrying a controlled-live `PlanOnlyCapability` that the
> executor independently re-verifies; a direct/token-less construction is still refused. **Both B1-A
> hard seals remain exactly `True`, the command grammar admits only `init` / non-destroy `plan` /
> `show`, and apply/destroy remain technically impossible.** Unsealing the CODE did **not** arm
> production: the shipped `build_plan_execution_composition()` stays disabled and empty, so ordinary
> production `run_plan_generation` still refuses at the composition gate — before any filesystem
> access, fresh attestation, workspace creation, rendering, resolver/secret contact, executor
> construction, or subprocess — creating no lease, attempt, durable result, or pending approval.
> **No real Proxmox host, provider plugin, state backend, secret manager, or deployment credential
> has been contacted; no real plan against real infrastructure exists; no live deployment-local
> composition is committed to the repository.** The first supervised operator plan (one reviewed,
> disposable lab) is **still pending** — the next action after CI is deployment-local operator
> preparation of a separately reviewed composition + the supervised exact-hash plan; **PR6 (first
> apply) does not begin** until that first exact-hash real plan has been reviewed and PR5B is merged.

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

**Authoritative destination binding (PR5B correction).** The provider endpoint and the HTTP
state-backend addresses/control endpoints were independently-supplied deployment-local values, so
readiness could validate backend A while OpenTofu planned against backend B, and the provider
endpoint could differ from the approved Proxmox target. BEFORE any lease, secret resolution,
workspace, or process (`plan_gen/destination_binding.py`, invoked at the top of the activated path):
the provider endpoint is derived from the approved `ExecutionTarget.config["base_url"]`
(`plugin_name == "proxmox"`, config re-hashed) and required to **canonically equal** (HTTPS,
lowercase host, 443-normalized, no userinfo/query/fragment, exact path — no DNS) the composition
endpoint; and the OpenTofu `TF_HTTP_ADDRESS`/`LOCK`/`UNLOCK` are derived from the immutable
`ToolchainProfile.state_backend.reference` (its hash re-verified) and required to equal the
composition state inputs. The remote-state readiness transport's `control_origin` is likewise bound
to that same reference before any contact, and its control paths are refused if any collides with the
deployment state object (a mis-set capabilities/metadata path can never read state; the readiness
lock is a dedicated readiness-only namespace); the transport obeys an EXACT method-to-endpoint policy
(HEAD→metadata, GET→capabilities, LOCK/UNLOCK→readiness-lock — no generic method/URL). The durable
anchor tying readiness evidence to the plan binding is the high-entropy `toolchain_profile_hash` +
server-derived `state_namespace_identity`; raw endpoints stay memory-only and redacted (never in
audit/logs/errors/durable state/Temporal/provenance). Any mismatch refuses with a bounded reason
before external contact.

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

### 10. Concrete resolver/adapter implementations live in-repo but ship SEALED

The reviewed, in-repository CONCRETE implementations of the two external-contact seams are committed
so they can be reviewed, but are **inert until a reviewed composition explicitly injects them** —
exactly like the read-only-preflight `OpenBaoWorkerSecretResolver`:

- **`OpenBaoPlanSecretResolver`** (`plan_gen/openbao_plan_resolver.py`) implements
  `WorkerPlanSecretResolver`. With **no injected client** (the default) it enforces the FULL
  plan-execution contract — capability type, the candidate request AND the capability's own contract
  verified per-fact against the authoritative expectation, then the `openbao`/`vault` scheme boundary
  — and only THEN fails closed. It resolves the **authoritative** reference (from the expectation,
  never the candidate) via an injected `ConcreteOpenBaoPlanSecretClient` over a **sealed-by-default**
  transport, wrapping the result in short-lived `SecretMaterial`. It logs / returns / persists no
  secret or reference.
- **`HttpRemoteStateReadinessAdapter`** (`readiness/http_state_adapter.py`) implements
  `RemoteStateReadinessAdapter`. Its ONLY public surface is `{contract_version, evaluate}`, so
  `assert_no_state_body_surface` accepts it; it has **no state-body method**. The actual backend
  contact is an injected `RemoteStateControlProbe` (`ConcreteHttpStateControlProbe` over a
  **sealed-by-default** `ApprovedStateBackendControlTransport`). The concrete probe performs bounded
  control-metadata validation only, decides namespace occupancy from **metadata/version identity**
  (never a state body), and runs an ephemeral lock probe that holds exactly ONE readiness lock and
  **always releases it in a `finally`**. The adapter ALWAYS takes the backend kind, the immutable
  toolchain-profile hash, and the namespace identity from the **authoritative binding** (never from
  the probe) and **never self-attests** an occupied-namespace marker; the pure evaluation then fails
  closed on any unprovable facet.

Neither concrete implementation contacts a backend at construction or in tests, and **no endpoint,
token, credential, bucket/object name, or state key is present anywhere in the repository**.

**The concrete production HTTPS transports are in-repo and hardened.** The "sealed-by-default"
transport is only the *shipped composition default*; the repository also contains the ACTUAL concrete
transports a reviewed deployment injects (they live at the worker top level because `plan_gen` /
`readiness` are boundary-forbidden from importing `httpx`):

- **`OpenBaoHttpTransport`** (`openbao_plan_http_transport.py`) performs the single OpenBao KV-v2
  `GET /v1/<mount>/data/<path>` read; and
- **`HttpStateControlTransport`** (`state_control_http_transport.py`) performs the bounded
  control-metadata requests (HEAD occupancy, GET capabilities, LOCK/UNLOCK on a DEDICATED readiness
  namespace) — it exposes **no state-body method and no generic request method**, so a state payload
  cannot be requested through it.

Both enforce (via `hardened_http.py`): HTTPS-only exact origin (no userinfo/query/fragment/non-root
path, validated at construction); TLS verified against an EXPLICIT CA `ssl.SSLContext` (never system
trust, never disabled); `trust_env=False`; `follow_redirects=False`; bounded connect/read/write/pool
timeouts, streamed response-size cap, and bounded JSON depth/container/string counts; a strict method
+ exact-path allowlist (no arbitrary URL/path joining); authentication ONLY from a typed,
**non-serializable** `WorkerAuthMaterialProvider` (no environment-token fallback); no retry of a
secret read; and closed reason codes with **no** origin/token/reference/CA-path/response-body/raw-error
leak in any repr/log/audit/error/Temporal/durable-state. Construction contacts nothing.

**The controlled-live composition is bound to the EXACT concrete chain — not merely the Protocol.**
Each concrete class carries a reviewed `IMPLEMENTATION_ID`; verification (`assert_concrete_openbao_
plan_resolver` in the plan composition; `assert_concrete_state_adapter` via the controlled-live
readiness provider) walks resolver→client→transport / adapter→probe→transport and refuses unless each
object's **un-forgeable `module.qualname` identity** AND declared registration match the pinned
reviewed values, AND the whole chain is production-bound. This refuses a duck-typed resolver, a foreign
subclass, a forged registration/digest, a correct-Protocol-wrong-implementation object, a
provider/state purpose swap, a sealed transport, and a test/fake transport in a controlled-live
composition. A `test_only` composition is intentionally exempt (it can never produce controlled-live
evidence). The external bootstrap supplies deployment VALUES (origin, CA path, auth-material provider,
endpoint paths) — never a transport class or an arbitrary request callable.

### 11. The reviewed operator bootstrap is deployment-local and outside this repo

The shipped worker registers only the always-sealed module-level activities. A **separately reviewed,
root-controlled operator entrypoint maintained OUTSIDE this repository** builds its activity set via
`secp_worker.operator_bootstrap.build_operator_activity_set(...)` from fully-constructed, typed,
controlled-live compositions (into which it injects the §10 concrete implementations). The factory
is the safe in-repo seam: it accepts only typed dependencies, refuses a missing / shipped-sealed /
test-only / wrong-classification composition, performs no I/O, and holds **no** deployment value.
Merely importing or calling it activates nothing — a live plan still requires an explicit
controlled-live object graph AND every authoritative database gate passing at request time.

To make the registration ATOMIC, `build_operator_worker_registration(...)` returns ONE immutable
`OperatorWorkerRegistration(task_queue, workflows, activities, activity_names)` — the distinct
operator queue (`resolve_operator_task_queue`, fails closed unless distinct from the shipped queue),
EXACTLY the five controlled-live workflow classes, and their five corresponding bound activity
callables (stable, unique names; no deploy/reset/destroy/discovery). The external entrypoint registers
this single object rather than assembling queue / workflows / activities independently and risking a
mismatch; the fields are immutable tuples.

### 12. Deterministic operator task-queue routing

The shipped sealed worker and a controlled-live operator worker would, on the SAME task queue,
register the SAME activity names — so Temporal would route a real-plan task **non-deterministically**
to either (sometimes the sealed worker, which refuses). To remove that ambiguity the shipped worker
polls only `settings.temporal_task_queue`, and an operator deployment sets a **distinct**
`settings.temporal_operator_task_queue` (refused by a Settings validator if blank-shaped, wildcard,
or equal to the shipped queue). The pure `secp_api.workflow_routing.resolve_task_queue` pins each
outbox row's queue by workflow kind at enqueue time: the five controlled-live operator-owned kinds
(`real_plan_generation` + the four readiness/eligibility prerequisites) route to the operator queue
**when one is configured**, and everything else — plus ALL kinds when no operator worker is deployed
— stays on the shipped queue (unchanged sealed-refusal behaviour; never a silent hang on an unpolled
queue). Configuring a queue **activates nothing**; it only decides which reviewed worker may pick up
work that still passes every gate.

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
| Config-only unseal of plan-only | Plan-only capability is a **code seal constant**, never a flag | Seal test asserts the exact constant value (now `False`); the shipped composition is disabled | Direct/token-less construction refused; shipped path refuses at the composition gate | Reviewer flips the constant in error (review control) |
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
| Non-deterministic routing (sealed vs operator worker share a queue) | Shipped worker polls only the shipped queue; a DISTINCT operator queue is required + validated (blank/wildcard/equal refused); each outbox row's queue is pinned by kind at enqueue | Routing + config tests | Fail closed (misrouted controlled-live work hits the sealed worker → refuses) | Operator deploys its worker on the shipped queue (deployment control) |
| Concrete adapter/resolver auto-activation or state-body smuggling | Both concrete implementations ship SEALED (no injected client/probe → fail closed); the state adapter exposes only `{contract_version, evaluate}` and reads no state body; identity comes from the authoritative binding; the lock probe releases in a `finally` | No-state-body-surface + sealed-default + ready-only-when-genuine tests | Fail closed | Reviewer injects a real client/probe out of band (review + operator control) |
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
