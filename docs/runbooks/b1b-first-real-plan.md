# Runbook — SECP-002B-1B PR5B: first real plan-only execution

This runbook distinguishes what is **implemented and tested in software** from what is a **later,
human-supervised operator validation** against a real disposable Proxmox target. It is deliberately
explicit that **no real target has been planned** during development.

## Current state (software)

- **PR5A — prerequisite closure — MERGED.** Durable activation-dossier lifecycle, operation-specific
  credential separation, combined plan-generation readiness, and the enqueue-only workflow that
  **STOPS at the sealed plan-only boundary**. No process runs.
- **PR5B — plan-only execution — IMPLEMENTED (complete durable path); plan-only seal now `False`.**
  The
  controlled-live `bpg/proxmox` renderer + render-safety scanner (one LXC container), capability-bound
  argv derivation, the hardened `PlanOnlyProcessExecutor.run`, the safe ephemeral workspace, the
  create-only `PlanChangePolicyEvaluator`, and `PlanOnlyOpenTofuRunner.generate_plan` are proven
  **end-to-end against a tiny inert local fixture** through an explicit, token-gated **test-only**
  construction path. The durable orchestration is now wired: the immutable `RealPlanGenerationResult`
  + the CAS `PlanGenerationExecutionLease` (+ migration `c4e2f9a1b7d3`); a ~50-binding
  non-serializable `PlanOnlyCapability` bound to the exact reviewed implementation digests; the
  fully-sealed-by-default `PlanExecutionComposition`; FRESH execution-time re-attestation; a SEPARATE
  two-credential JIT resolver seam; typed HTTPS-only runtime inputs + the exact explicit child
  environment; the upgraded `run_plan_generation` ordering (production refuses at the disabled
  composition gate); and the exactly-once durable result + PENDING human-only exact-hash approval
  (never auto-approved). The final reviewed activation flipped the dedicated plan-only code seal to
  `_PLAN_ONLY_PROCESS_SEALED = False` and advanced the executor identity `v1 → v2`; **both B1-A
  subprocess seals remain exactly `True`**, apply/destroy stay impossible, and — because the shipped
  composition is still disabled — production `run_plan_generation` still refuses before any I/O,
  creating no lease/attempt/result/approval.
- **Pre-contact activation blockers — CLOSED (reviewed, still sealed).** Deterministic operator
  task-queue routing (ADR-022 §12): a distinct `SECP_TEMPORAL_OPERATOR_TASK_QUEUE` (validated) to
  which the control plane routes the five controlled-live kinds only when configured, so the operator
  worker — never the shipped sealed worker — receives real-plan/readiness work. And reviewed
  in-repository CONCRETE `OpenBaoPlanSecretResolver` + `HttpRemoteStateReadinessAdapter`
  implementations (ADR-022 §10), both **sealed by default** (no injected client/probe → fail closed),
  with no committed endpoint/credential/state key and no backend contact in tests.
- **Not performed (gated on authorized operator validation):** a separately reviewed, activated
  deployment-local `PlanExecutionComposition` (into which the §10 concrete implementations are
  injected); the first supervised operator plan against a real disposable target; and PR6 (first
  apply). No such composition is committed to the repository.

## The inert local fixture (what the tests exercise)

The plan-only execution tests run a tiny purpose-built local executable that: opens no network,
mutates nothing outside the ephemeral workspace, emits bounded fixture `show -json`, lives under an
explicit temporary trusted root, and **is never accepted as controlled-live provider evidence**
(`example.test/fake/labproxmox` is refused by the render scanner; the controlled-live provider source
is `bpg/proxmox`). A passing fixture test proves the **mechanism** only — never that a real target was
planned.

## The seal flip (PERFORMED in this reviewed change)

Per ADR-022 §9, flipping `_PLAN_ONLY_PROCESS_SEALED` to `False` is the deliberate, reviewed **LAST**
code step, performed only after the whole PR5B path (durable result/lease, capability hardening,
re-attestation, JIT secrets, approval, workflow) was implemented, hardened, and green in
authoritative CI. It is a code-and-review change to a single constant, never a config flag, env var,
or injected executor, and it advances the reviewed executor identity `v1 → v2` so a capability,
activation, or composition bound to the old sealed `v1` digest can never activate the executor.
Flipping the CODE does not arm production: the shipped `PlanExecutionComposition` is still disabled,
so `run_plan_generation` still refuses at the composition gate before any I/O.

## Deployment-local prerequisites still required before the first supervised real plan

The seal is flipped, but a first real plan CANNOT occur until an operator, out of band, supplies a
**separately reviewed, activated** deployment-local `PlanExecutionComposition` (an enabled gate; the
explicit `ToolchainFilesystemLayout` + POSIX trusted workspace root; the exact provider version pin;
the controlled-live renderer/process registrations bound to their exact reviewed digests; the
provider + state runtime-input sources; the SEPARATE provider/state resolver activations; process
limits; the deployment activation-dossier hash; the worker identity; and the `controlled_live`
classification bound to the sealed production issuer) — plus a real attested on-disk OpenTofu
toolchain, a reviewed disposable Proxmox target, and JIT provider/state credentials in a real secret
manager. None of that is committed here.

## The governed worker path — shipped-sealed vs. operator bootstrap

The first supervised plan runs through the SAME durable path as production — API enqueue-only →
outbox → Temporal workflow → worker activity → fresh session → authoritative orchestration — never a
manual direct `run_plan_generation(..., composition=...)` call. The composition reaches the durable
activity through an explicit, constructor-injected provider seam:

- **The shipped `secp-worker` entrypoint** (`secp_worker.main`) registers the module-level activities
  from `secp_worker.temporal_app`, each constructed with its **SEALED** composition provider
  (`SealedPlanExecutionCompositionProvider` / `SealedReadinessCompositionProvider` /
  `SealedEligibilityCompositionProvider`). Ordinary startup therefore refuses at the composition gate
  before any filesystem/toolchain read, rendering, workspace, resolver contact, secret contact,
  executor construction, subprocess, lease, running attempt, durable result, or pending approval. No
  environment variable, settings value, database row, or Temporal argument can change this — the
  provider is injected, not looked up; there is no module-global mutable composition and no
  monkeypatch/service-locator seam. The plan-only code seal is `False` and both B1-A seals stay
  `True`, so apply/destroy remain impossible regardless.
- **The repository exposes the safe seam only:** the class-based Temporal activities
  (`RealPlanGenerationActivity(composition_provider)`, etc.), the provider contracts
  (`PlanExecutionCompositionProvider` / `ReadinessCompositionProvider` /
  `EligibilityCompositionProvider`, classified `sealed_default` / `controlled_live` / `test_only`),
  and the operator factory `secp_worker.operator_bootstrap.build_operator_activity_set(...)`. The
  factory accepts ONLY fully-constructed, typed, controlled-live compositions (never a raw dict),
  fails closed on a missing / shipped-sealed / `test_only` / wrong-classification composition, and
  performs no network/filesystem/database/secret contact — mirroring the
  `staging_live/composition.py` explicit-injection precedent. The registered activity NAMES are
  stable, so the workflow dispatches by name regardless of which provider a worker injected.
- **The deployment-local operator worker entrypoint is maintained OUTSIDE this repository** — a
  root-controlled file that constructs the controlled-live compositions (with real endpoints,
  backend addresses, secret references, VM-IDs, node/storage/bridge names, filesystem paths, and
  OpenBao paths) and calls `build_operator_activity_set(...)`, then starts a Temporal worker
  registering `activity_set.registerable_activities()` under the same stable names **on the DISTINCT
  operator task queue** returned by `secp_worker.operator_bootstrap.operator_task_queue(settings)`
  (i.e. `SECP_TEMPORAL_OPERATOR_TASK_QUEUE`, validated distinct from the shipped queue). Because the
  control plane routes the five controlled-live kinds to that queue only when it is configured
  (ADR-022 §12), the operator worker deterministically receives the real-plan-generation workflow and
  its readiness prerequisites, and the shipped sealed worker never picks them up. **No such
  entrypoint and none of those values are committed here.** If that operator uses a fixed
  root-owned descriptor to carry nonsecret parameters, the descriptor path must be fixed by the
  bootstrap code, every path component lstat-checked, symlinks refused, the file bounded with
  restrictive ownership/permissions, and its schema/version/digest validated; it may carry no
  credential or secret reference; and merely placing it can never bypass implementation activation
  or the authoritative database gates.
- **Readiness prerequisites** (controlled-live eligibility, toolchain attestation, remote-state,
  plan-secret) use the SAME bootstrap-injection pattern: each Temporal activity obtains its
  composition from its own injected provider and retains its SEPARATE authority (the readiness
  composition carries independent per-operation seams/activations). No readiness operation triggers
  plan generation, and each remains independently request-driven. The operator bootstrap can thus
  generate fresh, controlled-live, authoritative prerequisite evidence through the governed worker
  paths before the plan.

**Exact stop point:** with the shipped worker, the durable plan/readiness path STOPS at the
composition gate (refused, nothing persisted). The first live plan occurs only when the reviewed
operator worker — with its controlled-live compositions and real prerequisites — runs it. **That has
still not occurred: no real Proxmox/OpenBao/state-backend contact, no real plan, no operator
entrypoint or deployment value is committed.**

## Concrete resolver/adapter implementations (in-repo, reviewed, SEALED by default)

The two external-contact seams now have reviewed CONCRETE implementations in the repository so a
reviewer can read exactly what a controlled-live deployment would inject — but both ship inert
(ADR-022 §10), exactly like the read-only-preflight `OpenBaoWorkerSecretResolver`:

- **`OpenBaoPlanSecretResolver`** (`plan_gen/openbao_plan_resolver.py`) — the plan-execution
  `WorkerPlanSecretResolver`. With no injected client (the default) it enforces the full
  plan-execution contract (capability + request + capability-contract verified per-fact against the
  authoritative expectation, then the `openbao`/`vault` scheme boundary) and THEN fails closed. It
  resolves the **authoritative** reference via an injected `ConcreteOpenBaoPlanSecretClient` over a
  sealed-by-default transport, returning short-lived `SecretMaterial`. No secret, reference, endpoint,
  or token is logged, returned, persisted, or committed.
- **`HttpRemoteStateReadinessAdapter`** (`readiness/http_state_adapter.py`) — the
  `RemoteStateReadinessAdapter`. Its ONLY public surface is `{contract_version, evaluate}` (no
  state-body method), the actual contact is an injected `RemoteStateControlProbe`
  (`ConcreteHttpStateControlProbe` over a sealed-by-default `ApprovedStateBackendControlTransport`),
  and it performs bounded control-metadata validation only. Namespace occupancy is decided from
  metadata/version identity (never a state body); the ephemeral lock probe holds one readiness lock
  and always releases it in a `finally`; identity comes from the authoritative binding; and it never
  self-attests an occupied-namespace marker. With no injected probe it refuses.

The ACTUAL concrete production HTTPS transports are also in the repository (at the worker top level,
since `plan_gen`/`readiness` may not import `httpx`): **`OpenBaoHttpTransport`**
(`openbao_plan_http_transport.py`, the KV-v2 `GET`) and **`HttpStateControlTransport`**
(`state_control_http_transport.py`, HEAD/GET/LOCK/UNLOCK control metadata with **no state-body /
generic-request method**). Both enforce, via `hardened_http.py`: HTTPS-only exact origin; TLS verified
against an EXPLICIT CA `SSLContext`; `trust_env=False`; `follow_redirects=False`; bounded
timeouts/response-size/JSON; a strict method+path allowlist; a typed **non-serializable**
`WorkerAuthMaterialProvider` (no env-token fallback); and closed reason codes with no
origin/token/body/error leakage. Construction contacts nothing.

The controlled-live composition binds the EXACT concrete chain by un-forgeable `module.qualname`
identity + reviewed `IMPLEMENTATION_ID` (see `assert_concrete_openbao_plan_resolver` /
`assert_concrete_state_adapter`): a duck-typed / foreign / sealed / test / wrong-purpose substitute —
or a real class over a sealed/fake transport — is refused. A reviewed deployment-local
`PlanExecutionComposition` / `ReadinessComposition` injects these concrete classes with deployment
VALUES (origin, CA path, auth-material provider, endpoint paths) — **never a transport class or an
arbitrary request callable**; **nothing in this repository injects a real transport, and no
backend/endpoint/credential is present.** Their tests inject only fakes / an `httpx.MockTransport` and
contact no network.

## Operator live-plan validation (later, human-supervised — HAS NOT OCCURRED)

With the seal flipped and a reviewed composition supplied, a human operator — against ONE reviewed,
disposable LXC target on an existing approved node/storage/isolated-bridge with a reserved VM-ID and
exact quotas — drives a single real `init`/`plan`/`show`, reviews the redacted canonical change set,
and records the exact-hash human approval. **This is a supervised operator step; it is not part of
development and had not happened as of this change.** No apply and no destroy occur in PR5B; PR6 (the
first apply) does not begin until that first exact-hash real plan has been reviewed and PR5B merged.
