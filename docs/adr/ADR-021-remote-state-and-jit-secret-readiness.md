# ADR-021 — Remote-state and worker-only JIT secret readiness (B1B-PR4)

- **Status:** **Accepted** for the B1B-PR4 readiness architecture **and its implementation** (this
  ADR is implemented by the same slice). It **unseals no execution capability**: the shipped
  composition is sealed, and both B1-A subprocess seals remain `True`.
- **Date:** 2026-07-13
- **Milestone:** SECP-002B-1B — First Real Disposable-Lab Lifecycle, **PR4** (ADR-020 §C Phase 3).
- **Related:** ADR-007 (secret references + worker-only resolution), ADR-011/012/013 (manifests,
  worker-only runner, sealed OpenTofu + lab activation), ADR-014 (target onboarding), ADR-015
  (live read-only collector), **ADR-020** (B1-B architecture lock — §C Phase 3, §D dossier, §G remote
  state, §H secret handling, §O audit); architecture
  `docs/architecture/secp-002b-1b-real-lab-lifecycle.md`; plan
  `docs/implementation/secp-002b-1b-plan.md`; checklist
  `docs/proxmox/b1b-lab-prerequisite-checklist.md`; runbook
  `docs/runbooks/b1b-first-real-lab.md`.

> **No OpenTofu process has run. No state backend has been contacted as project evidence. No secret
> manager has been contacted as project evidence. No provisioning credential has been resolved as
> project evidence. No Proxmox mutation has occurred. No OpenTofu state payload exists. No provider
> plugin has loaded. No activation grant exists. Both B1-A hard seals
> (`_B1A_SUBPROCESS_SEALED = True` in `apps/worker/secp_worker/provisioning/process_executor.py` and
> `apps/worker/secp_worker/provisioning/activation.py`) remain exactly `True`.**

## Context

ADR-020 locks B1-B as a sequence of small, independently reviewed, fail-closed slices. PR2 added
real worker-local **filesystem** toolchain attestation (no execution, not wired into the runner).
PR3 added a durable, default-disabled, worker-owned **read-only eligibility preflight** producing
immutable, expiry-bound, hash-bound `live_verified` evidence.

ADR-020 §C Phase 3 is *"remote-state + just-in-time secret-resolution readiness: validate the remote
backend, state locking, backup/restore, and worker-only JIT secret injection. **No plan/apply/
destroy.**"* That is the last readiness contract before PR5 may run a real plan. It is dangerous for
two reasons that have nothing to do with OpenTofu: it is the first time SECP would touch a **remote
state backend**, and the first time the worker would touch a **secret manager** on the provisioning
path. Both must be provable **without** reading a state payload and **without** resolving a target
provisioning credential.

## Decision — locked

### 1. Readiness is not execution

- **Remote-state readiness is not state execution.** It validates backend CONTROL METADATA. It never
  creates, reads, writes, uploads, downloads, copies, restores, migrates, deletes, or exposes an
  OpenTofu state payload.
- **Secret readiness is not infrastructure execution.** It proves the worker can *authenticate* to
  the secret backend and that opaque material *projects* into exactly the allowlisted child-process
  environment. It runs no process.
- **Readiness approval is a decision only.** Creating an authorization does not run readiness.
  Approving an authorization does not run readiness.
- **Readiness STOPS.** A `ready` outcome authorizes nothing, unseals nothing, and dispatches nothing.

### 2. The two readiness operations are SEPARATE explicit operator actions

`remote_state_readiness` and `plan_secret_readiness` are two distinct durable operations. Neither
invokes the other. Passing eligibility requests neither. Completing both creates no plan. Every
transition is a separate, explicit, permission-gated human action.

### 3. The API is enqueue-only

The API may create durable `WorkflowRun` + `WorkflowDispatchOutbox` records and expose bounded,
redacted read models. It may **not**: contact a state backend; contact a secret manager; construct a
resolver or a state adapter; inspect a target connection value; construct a process environment;
receive secret material; resolve a secret; or call worker readiness orchestration. The inline
dispatcher **refuses with no fallback** (`InlineExecutionForbidden`); when Temporal is unavailable
the request simply does not execute.

### 4. Worker-only durable execution

Each readiness action executes **only** through a registered Temporal worker workflow + activity
(`RemoteStateReadinessWorkflow` / `PlanSecretReadinessWorkflow`, registered **only** in
`apps/worker/secp_worker/main.py`). The worker opens a **fresh session** and loads **all**
authoritative records itself. Inline execution and any in-process fallback are refused.

### 5. Default-disabled composition

The shipped `build_readiness_composition()` is fully **sealed**: the gate is disabled and no state
adapter, resolver self-test, or resolver contract is injected. The durable path therefore runs end to
end and **refuses at the seal before any state backend or secret manager is contacted**. **No
environment variable, backend kind, URL string, installed SDK, `PATH` entry, database row, or API
request can activate it.** Only a separately reviewed deployment-local composition may inject the
adapters **and** the authorization material.

### 6. Reuse without semantic overloading

Reused as-is: worker identity/admission; the CAS + revision lifecycle patterns; `SecretMaterial`;
the `ResolverSelfTest` / `SealedResolverSelfTest` seam; the `ResolutionLeaseStatus` /
`ResolutionLeaseReason` vocabulary and the B2-3 lease CAS/retry semantics; the Temporal + outbox
dispatch pattern; the immutable-evidence and bounded-audit conventions; the `secret_refs` scheme
grammar.

**Deliberately NOT reused** (doing so would make the schema's own foreign keys FALSE):

- `ResolverActivationAuthorization` — its `preflight_id` is a NOT-NULL FK to
  `readonly_staging_preflight`, its `live_read_authorization_id` is a NOT-NULL FK to
  `live_read_authorization`, its purpose is server-forced to `readonly_staging_preflight`, its single
  active-operation slot is keyed on `preflight_id`, and its evidence kinds (e.g.
  `transport_get_only_canonical`) are definitionally false for a **mutating** provisioning
  credential. A provisioning-secret operation has no such rows. A new
  `PlanSecretReadinessAuthorization` is therefore required to keep the meaning true.
- `ResolutionLease` — its `live_read_authorization_id` is a NOT-NULL FK to
  `live_read_authorization` and is part of its uniqueness key. A new
  `PlanSecretResolutionLease` mirrors the identical CAS/retry contract on a truthful key.
- `TargetEvidenceRecord` — its semantics are bound to live read-only TARGET evidence. Remote-state
  readiness gets its own `RemoteStateReadinessRecord`.

### 7. PR4 establishes PLAN-readiness only

- The only representable secret purpose is **`plan_read`** — a READ-ONLY provider credential class
  for a future `init`/`plan`/`show`.
- **Apply and destroy purposes are not merely rejected — they are unrepresentable**: they are absent
  from the `PlanSecretPurpose` enum, so pydantic refuses such a request body before any service code
  runs, and `assert_plan_only_purpose` refuses them again at the service, at approval, and in the
  worker. There is **no generic "all operations" credential readiness**.
- No apply/destroy authorization may be approved and no apply/destroy secret lease may be acquired.
  Future apply/destroy readiness belongs to their own separately reviewed phases (ADR-020 §C).

### 8. The state-body claim — stated precisely (narrowed in the security amendment)

Here is **exactly** what is true, and exactly what is not.

**What SECP enforces (proven by tests):**

- The `RemoteStateReadinessAdapter` **protocol exposes no state-body method.** It declares exactly
  two members — `contract_version` and `evaluate` — and there is no interface member through which a
  state payload could be requested, returned, or persisted.
- **Readiness code never requests a state body.** No call site in the readiness package asks for
  state content, and the typed `RemoteStateAdapterReport` has no field that could carry one.
- **Known state-body method surfaces are refused before invocation.** `assert_no_state_body_surface`
  is an *allowlist* over the class MRO `__dict__`s and the instance `__dict__` raw values: it detects
  a descriptor **without invoking it** (so a `@property def get_state` that would download state is
  never executed) and refuses any public invocable member outside `{contract_version, evaluate}` —
  including a state reader under an unknown name such as `fetch_tfstate`.
- The reviewed controlled-live adapter must additionally be **independently activation-bound** (§16)
  and **code-reviewed** as deployment-local material.

**What SECP does NOT and CANNOT claim:**

- **An arbitrary injected Python implementation's internals cannot be proven safe by reflection
  alone.** Reflection observes the *surface*, not the *behaviour*: an adapter whose `evaluate` body
  opens a socket and downloads the state file exposes no forbidden member and would pass every
  structural check. **Nothing here claims that reflection proves an adapter's internal implementation
  performs no state access.** The interface guarantee is a guarantee about the *contract*, not about
  arbitrary code someone injects behind it.
- Therefore the real control on adapter behaviour is **human code review of the deployment-local
  adapter plus its activation dossier** — not reflection.
- **A compromised worker remains residual risk.** A worker that runs attacker-controlled code can do
  anything the worker's credentials permit, including reading state directly, entirely outside the
  adapter seam. PR4 does not, and cannot, defend against that from inside the same process.

The no-state-body interface tests are **not weakened** by this narrowing: the protocol surface, the
report shape, and the refusal trap all remain enforced.

### 9. Mandatory remote-state facets (all required for `ready`)

`backend_class`, `transport_security`, `namespace_identity`, `encryption_at_rest`, `locking`,
`backup_proof`, `restore_proof`, `least_privileged_access`, `empty_or_expected_namespace`,
`no_local_fallback`.

There is no partial credit: `ready` requires every mandatory facet to pass **explicitly**; an
explicit violation is `not_ready`; **any fact that cannot be PROVEN fails closed to `unverifiable`**
— never a fabricated pass. Closed outcomes: `ready` / `not_ready` / `unverifiable` / `expired` /
`drifted` / `refused`.

Locked sub-decisions:

- **State namespace identity is server-derived**, deterministic, opaque, and collision-resistant:
  `sha256(prefix | organization | target | onboarding | manifest | manifest_content_hash | plan)`.
  It is never caller-selected, never derived from a mutable display name, and never reusable across
  organizations (the organization id is inside the digest).
- **Encryption at rest requires an explicit backend-derived proof.** It is never inferred from
  "HTTPS" and never inferred from the backend type. An absent proof is `unverifiable`.
- **Locking requires an explicit capability proof AND proven contention detection.** A documentation
  flag, a successful metadata read, or a backend type is never sufficient. `force_unlock_available`
  and `caller_supplied_owner` are refusal conditions.
- **An ephemeral lock probe is backend CONTROL METADATA, not an infrastructure mutation.** An adapter
  may perform one only in a **dedicated readiness namespace**, and it must be idempotent, bounded,
  released in a `finally`, cancellation-safe, target/namespace-bound, and incapable of force-unlocking
  another owner. A probe that was not released fails closed (a leaked readiness lock is a durable side
  effect). **When lock capability cannot be proven without touching a real state payload, the result
  is `unverifiable`.**
- **Backup and restore proofs are VALIDATED, never invented.** **PR4 performs no backup and no
  restore against real state.** A proof carries only an immutable proof id, an issuer, a
  performed-at time, its backend/namespace binding, and an expiry — never backup content, restore
  content, a path, or an object name. A restore proof must evidence a **successful TESTED restore**;
  a mere restore capability is not proof. A stale or future-dated proof is refused.
- **Least privilege requires exact allowed-action evidence.** A successful metadata read alone is
  never proof. `delete`, `force_unlock`, `admin`, `list_all`, and wildcard grants are excessive for a
  plan-only operation. Unavailable scope evidence is `unverifiable`.
- **The first lab may not adopt existing unrelated state.** Occupancy is decided from
  metadata/version identity **only** — the body is never read. An undeterminable occupancy is
  `unverifiable`.

### 10. Mandatory plan-secret facets (both required for `ready`)

- **`backend_authentication_readiness`** — the worker can AUTHENTICATE to the configured secret
  backend through the reviewed `ResolverSelfTest`. It returns **no target provisioning secret**,
  surfaces **no secret reference**, and **no backend response body is persisted**. A self-test that
  returns anything other than a bounded, opaque token is treated as leaking backend details and is
  **refused** rather than persisted.
- **`jit_injection_contract`** — supplying opaque `SecretMaterial` to the plan environment builder
  produces **only** the exact allowlisted variables (`TF_VAR_pm_api_token`), inherits no ambient
  environment, mutates no `os.environ`, creates no shell string, writes no HCL or durable artefact,
  and **runs no process**. It is exercised with an **INERT, worker-generated sentinel** — never a
  target credential, never from the backend, never persisted.

Closed outcomes: `ready` / `not_ready` / `unavailable` / `expired` / `drifted` / `refused`.

**`WorkerSecretResolver.resolve()` is NEVER called by the readiness path. The actual target
provisioning credential is not resolved as project evidence.**

### 11. Exact deployment bindings and expiry are mandatory

One strict, immutable `ReadinessBinding` is DERIVED from authoritative records — never accepted from
a caller, a request body, a Temporal argument, or an adapter. It binds: organization; environment
version id + content hash; deployment plan id + content hash; provisioning manifest id + content
hash; execution target id + config hash; onboarding id + boundary hash; effective-boundary hash; the
exact current eligibility preflight id + evidence hash + policy version + expiry; toolchain profile
id + hash + the real toolchain-attestation policy version; the remote-state backend BINDING HASH and
the server-derived NAMESPACE IDENTITY; the activation-dossier hash; the worker identity registration
id + version; the readiness operation kind; the readiness policy version; the adapter/resolver
contract version; and (for plan-secret) the authorization id + version + expiry and the prior
state-readiness record id + evidence hash.

**The binding REFUSES whenever the current PR3 eligibility result is not `live_verified` + `eligible`
+ current + unexpired + undrifted + hash-valid.** There is **no production shortcut that upgrades
`unverifiable` into `eligible`.** (The Path B collector, through the currently reviewed GET
allowlist, still cannot produce `eligible` — that remains a documented deployment prerequisite. The
readiness test fixtures reach `eligible` only through the narrow existing PR3 test-fixture path with
an explicitly-injected activation composition.)

### 12. Readiness evidence is immutable and drift-invalidated

Historical records are **append-only**: a prior successful readiness record is **never** mutated into
failure and **never** erased (an ORM guard plus a PostgreSQL trigger refuse every UPDATE and DELETE).
Validity is **DERIVED** on every read. A change to **any** bound fact yields a different operation
fingerprint, hence a **new** immutable record. An expired record is reported as `expired` — never
replayed as fresh readiness.

### 13. Nothing sensitive is ever persisted, logged, audited, returned, or hashed

**Never persisted / logged / audited / returned / serialized / hashed:** a state body, state JSON,
state metadata containing resource identities, an object key, a backend URL, a bucket / container
name, an account id, an access key, a lock payload, a provider body, a secret, **a secret reference**,
**a hash of a secret reference**, a backend locator, an endpoint, a namespace name, a token, a backend
response body, an environment variable value, or exception detail.

**Safe evidence may contain only:** a bounded backend CLASS, an OPAQUE backend binding hash, an
OPAQUE namespace hash, bounded facet names + statuses, bounded reason codes, opaque external proof
ids, the resolver / self-test / env / policy / adapter versions, safe hashes, timestamps, an expiry,
and an evidence hash. Every durable reason code is a member of the closed `ReadinessReason` catalog;
a free-form or oversized adapter reason code is dropped, never persisted verbatim.

### 14. Zeroization is NOT claimed

Python `str` is immutable and interned; a secret's bytes **cannot be reliably scrubbed from memory**.
This design therefore makes **no cryptographic zeroization claim**. It minimizes **lifetime** and
**references** instead: the revealed value exists only inside the returned mapping, every reference is
dropped immediately, and no copy is ever taken by logging, `repr`, serialization, hashing, or
persistence.

### 15. No fake adapter may satisfy a controlled-live readiness gate

A `ready` outcome produced with an injected fake adapter, a fake self-test, or fixture records is a
**unit-test result**, not deployment evidence. **Passing fixture tests do not prove that the
operator's real backend or secret manager is ready.**

### 16. The DURABLE toolchain attestation (a profile hash is not evidence)

A matching `ToolchainProfile` id/hash and a verifier-policy version are **not an attestation**. The
profile is a **declaration**; evidence is a durable `ToolchainAttestationRecord` produced by the
worker actually running B1B-PR2's reviewed `RealToolchainVerifier` against an **explicit,
deployment-local, immutable `ToolchainFilesystemLayout`**.

- The attestation path is **worker-owned and readiness-only**. It executes **no binary**, runs **no
  subprocess**, opens **no socket**, loads **no provider**, renders **no workspace**, constructs **no
  `OpenTofuRunner` / process executor / activation grant**, and performs **no import-time I/O**.
- Nothing is inferred from `PATH`, the cwd, `HOME`, or any environment variable: the complete layout
  is supplied explicitly by the reviewed composition.
- **`RealToolchainVerifier` remains unwired into execution.** `OpenTofuRunner` and
  `run_real_provisioning` still default to `FakeToolchainVerifier`; this readiness-only seam is the
  sole construction site outside tests, and it runs no OpenTofu.
- The **shipped composition carries no layout**, so no shipped runtime path can attest anything: the
  seam refuses at the seal before touching the disk. Tests use inert temporary toolchain fixtures.
- The record stores **only**: organization; worker identity id + version; toolchain profile id +
  hash; the verifier policy version; the verified **facet names**; bounded reason codes; the
  collection time; an expiry; an evidence hash; and the operation fingerprint. It stores **no path,
  no filename, no executable content, no provider content, no CLI content, and no raw
  expected/observed digest**.
- **Both readiness operations require the exact current attestation record id + evidence hash.**
  Combined readiness refuses when there is no attestation, when it failed, when it expired, when the
  profile id/hash changed, when the verifier policy changed, when the worker identity changed, or
  when the evidence hash does not recompute.

### 17. The OPAQUE credential binding (closing the `secret_ref` substitution gap)

`ExecutionTarget.secret_ref` is a mutable, opaque pointer, and PR4 may not persist a
secret-reference hash (§13) — so a plan-secret authorization could once be approved against reference
*A* and silently serve reference *B*, with **no stored value changing**.

The fix names the credential *selection* without describing it: a `CredentialBinding` — a bare
**opaque UUID + a monotonic version** (plus organization, target, purpose class, lifecycle status and
timestamps). There is deliberately **no column** that could hold a secret, a secret reference, a hash
of a reference, a locator, a backend path, or a credential value. **The actual reference stays
worker-only and is compared in memory only.**

- The current `secret_ref` selection maps to exactly **one** active binding id + version.
- **Changing `secret_ref` rotates the binding — unavoidably.** It is enforced twice: an ORM
  `before_flush` hook (the portable SQLite + PostgreSQL layer) and a PostgreSQL trigger on
  `execution_target` that **auto-rotates** even for a raw/Core `UPDATE` that bypasses the ORM
  entirely. The supported service path (`credential_binding:manage`) announces itself with a
  transaction-scoped flag so the rotation happens exactly once. **Credential replacement can never be
  invisible.**
- The authorization binds the binding id + version; the **operation fingerprint** folds them in; the
  lease binds them through the fingerprint; the plan-secret readiness record binds them; and the
  current-validity helper compares them against the current binding. A rotation therefore invalidates
  every prior authorization and readiness record **without modifying any historical evidence**.

**Still true and still disclosed:** PR4 does *not* implement true plan/apply/destroy credential
separation. The binding proves the *selection did not change*; it does not prove the credential is
least-privileged. That remains a B1B-PR5 prerequisite.

### 18. The CONTROLLED-LIVE adapter provenance capability

**A self-declared `contract_version` is not provenance.** Any object can claim any string, so the
adapter's own word can never be the basis for contacting a real backend or a real secret manager.

A worker-only, **non-serializable** `ReadinessAdapterCapability` is therefore required before either
seam runs. It binds: the adapter registration id; the adapter kind; the **reviewed implementation
identity/digest**; the adapter contract version; the operation kind; the activation dossier hash; the
authorization id/version/expiry; the organization; the target, onboarding, manifest and plan; the
worker identity id + version; and the capability expiry.

- **Construction is sealed behind a module-private token** and happens only after authoritative
  activation verification. An adapter-reported version alone cannot create one.
- A **fake adapter cannot obtain a production capability** — even one that claims the exact expected
  contract version and returns fully-passing evidence: the reviewed activation pins a *different*
  implementation digest, so it is refused before any contact. (There is a regression test for exactly
  this.)
- The state adapter's `evaluate` requires the **state** capability; the resolver self-test requires
  the **plan-secret** capability; the recorder refuses to persist evidence without proof a capability
  was verified.
- The capability **cannot be serialized, pickled, placed in a Temporal argument, persisted, or
  constructed by API code** — the architecture boundary forbids the API from importing the factory at
  all.
- The **default shipped composition has no capability**, so both seams refuse **before contact**.
- Tests may use an **explicitly named** test-only capability factory. Evidence produced under it is
  permanently marked `test_only` and **can never make combined readiness current**: controlled-live
  evidence rejects it.

### 19. The activation-dossier placeholder FAILS CLOSED

There is exactly one explicit placeholder sentinel (`READINESS_ACTIVATION_DOSSIER_PLACEHOLDER`). It
is a refusal, never a default-allow:

- the authoritative production binding refuses it;
- remote-state readiness cannot return `ready` with it;
- plan-secret readiness cannot return `ready` with it;
- `ProvisioningReadinessStatus` can never be current/ready with it;
- an adapter capability cannot be produced with it;
- the audit never represents it as approved deployment evidence.

Tests use a clearly test-only dossier fixture. **A real, reviewed, deployment-local activation
dossier remains required before any live readiness run** — it is not shipped, not generated, and not
inferable.

## Live-deployment readiness: SUPPORTED, NOT EXERCISED

**Explicitly stated, as required:** live deployment-local readiness is **merely supported by the
code**. It has **not** been exercised as project evidence.

- No real remote-state backend has been contacted. No real secret manager has been contacted.
- No real backup or restore has been performed. No external proof has been issued or validated
  against a real backend.
- No real target provisioning credential has been resolved.
- The shipped composition is sealed and injects no adapter and no resolver self-test.
- Every test uses fixture ORM records, injected fakes, and an inert sentinel.

**No claim of real external readiness is made.** Real readiness requires a separate, reviewed,
deployment-local activation performed by an operator — which has not been performed.

## Threat model (B1B-PR4)

| Threat | Prevention | Detection | Durable evidence | Refusal | Residual risk |
| --- | --- | --- | --- | --- | --- |
| Caller-selected backend | The backend is derived from the pinned `ToolchainProfile`; the adapter is INJECTED, never discovered from env/kind/PATH/SDK/URL/caller | Adapter binding-hash compare | Opaque backend binding hash | `state_backend_reference_drift` | A reviewer injecting a wrong adapter |
| Backend-reference substitution | Report `backend_binding_hash` must equal the binding's | Hash mismatch | Binding hash | `state_backend_reference_drift` | — |
| State-namespace collision / cross-org reuse | Server-derived digest includes the organization + target + onboarding + manifest + plan | Namespace compare | Opaque namespace hash | `state_namespace_mismatch` | — |
| Local-state fallback | `kind` refused at the control plane, at the worker verifier, at the gate, AND at the readiness facet; `local_fallback_available` is a refusal | Facet | `backend_class` = `local` | `state_backend_local` / `state_local_fallback_available` | — |
| State-body access / state-content leakage | The adapter contract HAS no state-body method; an adapter exposing one is refused before invocation | Surface scan | Refusal reason | `state_body_access_attempted` | A compromised adapter reading state internally (out of scope: it is deployment-local reviewed code) |
| TLS disablement / redirect / proxy inheritance | Explicit `tls_mode`, `certificate_validation_enabled`, `trusted_identity_policy`, `redirect_observed`, `proxy_inheritance_enabled`, `destination_stable` | Facet | Reason codes | `state_tls_disabled` / `state_redirect_observed` / `state_trust_env_enabled` | — |
| Forged encryption / lock proof | Proofs must be bound to the exact backend binding hash AND namespace hash, be fresh, and carry safe metadata | Binding + freshness compare | Opaque proof id | `*_proof_unbound` / `*_proof_stale` | An issuer that lies (operator review of the issuer) |
| Stale backup / restore proof | Bounded max-age + the proof's own expiry; future-dated proofs refused; restore requires `restore_tested` | Freshness compare | Opaque proof id | `state_backup_proof_stale` / `state_restore_proof_stale` | — |
| Force-unlock / lock theft / probe race | `force_unlock_available` and `caller_supplied_owner` are refusals; the probe must be released in a `finally` | Facet | Reason codes | `state_lock_force_unlock_available` / `state_lock_probe_not_released` | Backend-side lock outage |
| Adapter substitution | Pinned `adapter_contract_version`; a mismatch refuses BEFORE invocation | Version compare | Adapter version | `adapter_contract_mismatch` | — |
| Caller-supplied secret reference | The reference is re-derived from the AUTHORITATIVE target row reached only through the manifest's pinned config hash | Config-hash compare | (none — the reference is never stored) | `target_config_drift` | — |
| Secret-reference logging / hashing | The reference never leaves `_authoritative_reference_scheme`; only its bounded SCHEME is persisted. A reference HASH column does not exist | Column scan | — | N/A | — |
| Authorization confusion with live-read | A DEDICATED `PlanSecretReadinessAuthorization` table + a DEDICATED `readiness:approve` permission; the live-read authorization has different FKs and a different purpose | Type + FK | Authorization row | `secret_authorization_binding_invalid` | — |
| Apply/destroy purpose confusion | `PlanSecretPurpose` has ONE member; pydantic, the service, approval, and the worker each refuse anything else | Enum + 4 assertions | `secret_purpose` | `secret_authorization_purpose_invalid` | Adding an enum member is a reviewed code change |
| Authorization replay / expiry omission | Single-use CAS lease; mandatory `authorization_expiry`; revocation takes effect immediately | Lease status | Lease row | `replay_refused` / `secret_authorization_expired` | — |
| Worker-identity substitution | Exactly one approved, unexpired registration; its id AND version must equal the authorization's | Identity compare | Worker identity id/version | `worker_identity_untrusted` | — |
| Lease-key omission / duplicate budget / retry reset | The key is `(authorization_id, authorization_version, operation_fingerprint)` — and the fingerprint folds in EVERY other fact. Worker identity is deliberately NOT in the key | Unique constraint | Lease row | `lease_held` / `retry_bound_exceeded` | — |
| Backend contact before `begin_attempt` | `begin_attempt` is the LAST statement before the self-test; an ordering test asserts `attempt_count == 1` inside the self-test | Ordering test | Lease attempt count | `lease_refused` | — |
| Fake resolver satisfying a controlled-live gate | The shipped default is sealed; a `ready` from a fake is documented as a unit result, never deployment evidence | Composition test | — | `sealed` / `resolver_sealed` | Reviewer overclaim (this ADR + STATUS forbid it) |
| Self-test leaking backend details | The reason code must match a bounded opaque token; anything else is REFUSED, not persisted | Token shape | `resolver_self_test_leaked_details` | fail closed | — |
| Secret in Temporal args / DB / audit / log / exception | Workflow args carry ids only; a sentinel-leak test scans every readiness/audit/workflow row; adapter and self-test exceptions are never surfaced | Leak scan | — | N/A | — |
| Ambient env inheritance / `os.environ` mutation / shell injection / key collision | `plan_env` does not import `os` at all; an AST test asserts it; duplicate/case-colliding/unknown keys, NUL/newline, and oversized values are refused; no shell string is built | AST + unit tests | — | `jit_env_contract_violation` | — |
| Python zeroization overclaim | The limitation is documented in code and here; no zeroization is claimed | Review | — | N/A | **Accepted, disclosed** |
| Readiness triggering a plan | No readiness module imports a dispatcher, a runner, an executor, a renderer, or an activation grant (AST tests) | Boundary tests | — | N/A | — |
| B1-A seal weakening | Both seals asserted `True` (runtime + exactly-one-assignment source scan) | Seal tests | — | N/A | — |
| Status overclaim | STATUS truth tests + this ADR's "supported, not exercised" statement | Truth tests | — | N/A | Reviewer error |

## Adversarial-review findings — confirmed and fixed in this slice

A separate adversarial review (five independent attack lenses, each finding double-verified by two
refutation agents) found the following **real** defects in the first implementation. All are fixed,
each with a regression test in `apps/api/tests/test_readiness_threat_regressions.py`.

| # | Confirmed defect | Fix |
| --- | --- | --- |
| 1 | The adapter's **raw `backend_class`** was persisted, audited, and returned verbatim — an adapter could put a backend URL in a `String(20)` evidence column and the API response. | Normalized at the emission point onto the closed `{remote, local, unknown}` vocabulary. The facet decision still compares the RAW value, so `" Remote "` still fails. |
| 2 | `assert_no_state_body_surface` was a **denylist evaluated with `getattr`** — so an adapter defining `@property def get_state` that downloads the state body would have had that body **downloaded by the guard itself**, and a state reader under any other name (`fetch_tfstate`) passed. | Replaced with an **allowlist over the class MRO `__dict__`s + instance `__dict__` raw values**. It detects a descriptor **without invoking it**, and refuses any public *invocable* member outside `{contract_version, evaluate}`. |
| 3 | The proof-id shape (`[A-Za-z0-9._-]{1,120}`) is exactly the alphabet of a **DNS hostname / S3 bucket / state-file name**, so a backend locator could be persisted verbatim as a proof id, issuer, or self-test proof — and `re.match(r"^…$")` additionally admitted a **trailing newline**. | *First fix (superseded):* persist only an opaque `sha256:` digest of the label. **The security amendment went further:** an unsalted digest of an *enumerable* locator is itself an offline **confirmation oracle**, so the digest was removed too. External proof ids (`encryption`/`lock`/`backup`/`restore`/self-test) are now **UUID columns** — a UUID cannot *be* a locator, and its digest confirms nothing. A label-shaped proof id is refused outright (`state_proof_id_not_opaque`), and nothing derived from it is persisted. Every validator uses `fullmatch`. |
| 4 | `empty_or_expected_namespace` was **self-attested**: any syntactically valid adapter-chosen marker turned an OCCUPIED namespace into a pass. | The marker is now **server-derived** (`state_namespace_marker(namespace_identity)`) and must match exactly. |
| 5 | The terminal-replay short-circuit fired on **NON-ready** records, so one transient backend blip permanently poisoned the operation and the bounded **N=3 retry budget was unreachable**. | Only a **`ready`** record short-circuits. Non-ready attempts append as immutable attempt history; the idempotency index is now **PARTIAL on `outcome = 'ready'`**, so exact-once still holds for success. |
| 6 | A readiness record could **expire while its binding was still valid**, and the exact-once constraint would then block a fresh `ready` row forever. | Both readiness TTLs are **pinned to the eligibility TTL**. Readiness is collected *after* eligibility, so an expired readiness record always implies an already-refused binding. |
| 7 | The self-test's **failure `reason_code` was passed as its success `proof_id`** — recording the opposite of what happened, and making `ready` unreachable for a conformant self-test with an empty reason code. | A dedicated `PlanSecretSelfTestResult` adds an **explicit, opaque `proof_id`**. A success with no proof label fails closed to `unverifiable` rather than fabricating a pass. |
| 8 | The **lock proof was not bound to the backend** (unlike the encryption/backup/restore proofs). | `LockCapabilityProof` now carries `backend_binding_hash`, checked exactly like the others. |
| 9 | The approved **evidence fingerprint was never RECOMPUTED** by any consumer (the reviewed sibling contract does). | The worker recomputes it from the current evidence rows and compares, before any secret-backend contact. |
| 10 | `PLAN_SECRET_ENV_CONTRACT_VERSION` escaped **every currency check** — a bumped JIT env contract left stale readiness reported `ready`. | Added to the combined current-readiness check. |
| 11 | The read model's `current` flag ignored **binding drift** (it checked only the record). | `current` is now derived from the freshly loaded authoritative binding + fingerprint agreement. |
| 12 | The 422 validation body **echoed a rejected `purpose: "apply"`** on the one readiness route that accepts a body. | The manifest-nested create route is registered in the redacted-validation route list. |

## Accepted, disclosed residual risks

These were found by the adversarial review, confirmed, and **deliberately not "fixed"** because the
honest fix is out of scope or forbidden. They are disclosed rather than hidden.

> **Two risks previously accepted here were removed outright by the security amendment** and are
> kept below only as a record of what changed:
>
> - the **backend-reference confirmation oracle** (an unsalted digest of an enumerable locator) — the
>   `state_backend_binding_hash` column is **gone**, and no persisted, audited, or returned value is a
>   direct digest of a backend reference, backend URL, bucket/container/object key, secret reference,
>   or credential locator. The backend is anchored instead by the immutable `ToolchainProfile`
>   content hash, an opaque adapter-registration UUID, and a server-derived namespace hash computed
>   over non-sensitive UUIDs. External proof ids are **UUID columns** — a UUID cannot *be* a locator,
>   and its digest confirms nothing. (§5 of the amendment.)
> - the **invisible post-approval `secret_ref` swap** — closed by the opaque `CredentialBinding`
>   (§17), without storing the reference or any hash of it.

1. **Adapter behaviour is guaranteed by human review, not by reflection.** The protocol exposes no
   state-body method and the structural trap refuses known state-body surfaces before invocation —
   but an arbitrary injected Python implementation's *internals* cannot be proven safe by reflection
   alone (§8). The reviewed, activation-bound, code-reviewed deployment-local adapter is the control.

2. **A compromised worker remains residual risk.** A worker running attacker-controlled code can
   reach the state backend or the secret manager directly, entirely outside the adapter seam. No
   in-process control can prevent that.

3. **PR4 does not implement plan/apply/destroy credential separation.** The opaque credential binding
   proves the *selection* did not change; it makes **no least-privilege claim** about the credential
   itself. Binding a dossier-supplied, separately-scoped plan-read credential remains a B1B-PR5
   prerequisite.

4. **The plan-secret resolver contract version is declared on the injected composition, not attested
   by the self-test object.** The composition *is* the reviewed deployment-local injection point, so
   the value there is a reviewed value — and the self-test now additionally requires a reviewed
   activation + capability (§18), so a self-declared version is no longer sufficient anywhere.

## Consequences

- SECP gains the **last readiness contract** before a real plan — with **zero** new execution
  capability. Both B1-A seals remain `True`.
- Two new durable operations, one new authorization + evidence pair, one new lease, and two new
  immutable evidence tables exist. They are **secret-free and backend-locator-free by construction**.
- **Operator work is unchanged and still required.** The prerequisite checklist boxes for remote
  state (§6) and least-privileged credentials (§4) remain **unchecked**: code that can validate a
  proof is not a proof.

## Known implementation prerequisites for B1B-PR5 (stated, not fabricated)

1. **Operation-specific credential separation is NOT yet real.** `ExecutionTarget` has exactly ONE
   generic `secret_ref`. PR4 therefore binds a **plan-read purpose class** and a reviewed reference
   **scheme** — it does **not** prove the underlying credential is actually least-privileged or
   distinct from a future apply/destroy credential. Separate, operation-scoped provisioning
   credentials (and a separate STATE-BACKEND credential, which PR4 does not resolve at all — the
   deployment-local adapter authenticates itself) are an **explicit implementation prerequisite for
   PR5**. **No least-privilege claim is made about the credential itself.**
2. **There is no third independent credential-reference source.** `ProvisioningManifest` is
   secret-free by design, so — unlike the read-only preflight path, which has a separate
   `LiveReadCollectionBinding.credential_ref` — a genuine three-way reference comparison does not
   exist for provisioning. PR4 enforces the strongest binding that is actually TRUE: the reference is
   re-derived from the `ExecutionTarget` reached ONLY through the manifest's pinned
   `target_config_hash`, and its SCHEME must equal the human-reviewed scheme on the authorization. A
   real third source (e.g. a dossier-bound credential reference) is a PR5 prerequisite.
3. **B1B-PR2's toolchain attestation evidence is in-memory only and is NOT persisted.** PR4
   therefore binds the toolchain **profile identity + the attestation policy version**, not a durable
   on-disk attestation record. A durable deployment-local attestation record is a PR5 prerequisite.
4. **The activation dossier is still a placeholder literal** (`no-activation-dossier/b1b-pr4`),
   consistent with PR3. Modelling a real dossier hash is a future reviewed change that will (correctly)
   invalidate every prior readiness fingerprint.
5. **Path B still cannot produce `eligible` through the reviewed GET allowlist.** Reaching `eligible`
   against a real target remains a documented deployment prerequisite (ADR-015 / B1B-PR3).

## Non-goals

Any plan, apply, or destroy; any OpenTofu or Terraform subcommand; any subprocess; any workspace
render; any state-payload access of any kind; any real backup or restore; resolving the target
provisioning credential; an API-side resolver; apply/destroy secret purposes; a fake adapter
satisfying a controlled-live gate; committing any real endpoint, backend name, credential, secret
reference, state key, TLS fingerprint, bucket name, path, token, key, or deployment value; and
starting B1B-PR5.
