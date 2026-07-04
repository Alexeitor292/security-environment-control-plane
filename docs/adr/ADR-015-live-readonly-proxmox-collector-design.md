# ADR-015 — Live read-only Proxmox collector: threat model and activation design

- **Status:** Accepted (design/threat-model only — no implementation, no live access)
- **Date:** 2026-07-02
- **Milestone:** SECP-002B-1B-2 (Live Read-Only Proxmox Collector Threat Model and Activation)
- **Related:** Charter §5 (Layers 4/5/7), §6 (Invariants 6, 7, 11, 12), §13; ADR-006, ADR-007,
  ADR-008, ADR-013, ADR-014;
  [design package](../architecture/secp-002b-1b-2-live-readonly-proxmox-collector.md),
  [activation checklist](../proxmox/live-readonly-collector-activation-checklist.md)

## Context

SECP-002B-1B-1 delivered immutable, **simulated-only** target evidence, worker-owned simulated
collection, provider-neutral boundary↔evidence comparison, a full-record evidence hash, a
`target_preflight → target_evidence_record` binding, audit records, and approval gates. Live
provider evidence and the `provider_worker` collector remain **sealed**.

Before writing any real provider connector we must lock the threat model, the read-only
contract, the non-mutation enforcement, the credential/target-binding, the execution model, and
the human activation requirements. This ADR records those decisions. It changes **no runtime
behaviour**: no client/SDK/HTTP/socket/subprocess is added, no real target is contacted, no
credential/endpoint is created, and the live-evidence seal is not lifted.

## Decision

1. **The first live collector is read-only and worker-owned.** It observes an approved
   disposable/staging Proxmox target and produces the *existing* provider-neutral evidence
   payload; it reuses the B1-B-1 validate → compare → hash → persist → audit → bind pipeline
   unchanged. The only new boundary that ever touches a real target is the worker↔Proxmox
   read path.

2. **In-scope evidence is minimal:** nodes, storage, network segments, VM-ID
   availability/ranges, capacity/quotas, and read-only isolation-posture signals. Guest
   config/agent/console, tasks, backups, firewall contents, and ACL/user enumeration are out
   of scope. Provisioning/mutation is a later, separate milestone.

3. **Non-mutation by construction.** The future transport enforces, before send, a **GET-only
   method allowlist** and a **closed endpoint allowlist**; it denies unknown endpoints, does
   not follow redirects, and refuses cross-target destinations. No task/action/config/console/
   agent/backup/upload/write endpoint is ever reachable. This is proven with a fake transport
   **before** any live-capable code.

4. **Credentials stay opaque and worker-only; jobs are fully bound.** Control-plane records
   hold only an opaque `secret_ref`; the worker resolves it just-in-time into a transient
   credential and never logs/persists/hashes/returns/audits the secret. Every collection job —
   and its idempotency key — binds, at minimum, **all** of: `execution_target_id`, the target
   `config_hash`, `onboarding_id`, the onboarding `boundary_hash`, `authorization_id` **and**
   authorization expiry/version, `evidence_source` / `verification_level`, and the
   collector-contract / endpoint-allowlist version. The idempotency key is an **immutable
   binding fingerprint** over all of these values — including a canonical authorization
   **expiry** (not only its version) — so any mismatch, expiry change, target/config/boundary
   drift, or contract-version mismatch **fails closed** and yields **no reusable passing
   result**.

5. **Durable, default-disabled execution.** Live collection runs on the durable worker path
   only (inline refused), behind a **default-disabled** feature gate, with deterministic
   idempotency, bounded timeout, capped idempotent-GET retries, cancellation, immutable
   evidence retention, and fail-closed (`unverifiable`) failure semantics.

6. **Fail closed, never infer — but note integrity ≠ truthfulness.** Missing/malformed/
   ambiguous observations are `unverifiable`; a dimension passes only on an explicit matching
   observation. The immutable full-record hash detects **post-collection alteration and binding
   drift** — it does **not** prove the response was truthful and cannot detect evidence that was
   **false at collection time**. There is **no remote attestation**: a compromised target or
   worker can return plausible false data that passes comparison; a hostile target does **not**
   necessarily fail closed. TLS identity, target/config/boundary binding, worker hardening,
   minimal collection, audit, and human review reduce — but do not remove — this residual.

7. **`fully_segregated` isolation requires specific verification.** Generic inventory, bridge/
   VNet presence, and segment names are **insufficient**. A collector may return `passed` for
   `fully_segregated` only when every required isolation assertion — dedicated lab segment
   identity, no protected-network uplink/routing, no default route / external connectivity where
   policy is `deny`, and required host-side isolation controls — is verified via approved,
   allowlisted, read-only observations and deterministic rules. Any unavailable, ambiguous,
   unsafely-observable, or out-of-scope fact is `unverifiable` and blocks approval; it is never
   inferred from incomplete inventory.

8. **Human activation gate.** A real collector may be enabled only after the
   [activation checklist](../proxmox/live-readonly-collector-activation-checklist.md) is
   completed and an explicit human authorization is recorded — in a **future** PR.

### Non-weakening

This ADR does not weaken the live-evidence seal, worker-only execution, secret references +
JIT worker resolution, immutable evidence/audit, onboarding approval gates, or the
architecture boundary that forbids `apps/api` from importing any provider/collector code.

## Consequences

**Positive**
- A reviewed, conservative, test-first path to real read-only evidence with an explicit,
  default-deny activation gate and a documented threat model.
- The existing evidence pipeline is reused, minimizing new attack surface.

**Negative / risks**
- Residual risks (over-scoped credential, read-side disclosure, TLS trust, semi-trusted
  target) remain and are accepted only behind the checklist + recorded authorization.

**Placeholder (future PRs)**
- Fake transport + allowlist tests → adapter behind a disabled gate → staging validation →
  independent security review → separate authorization to enable → (later) provisioning.

No real infrastructure, endpoint, credential, provider, SDK, HTTP client, or secret is
introduced by this ADR.

## Amendment — dormant, default-disabled implementation (SECP-002B-1B-4, 2026-07-02)

The dormant live read-only collection path now exists in code, but every real execution path
remains **disabled by default** and unreachable from the API, UI, dispatcher, or normal
onboarding-preflight lifecycle. It is testable exclusively via injected fakes.

- **Default-disabled gate.** A worker-owned `LiveReadCollectionGate` defaults to `enabled=False`
  and is **not** wired to environment variables, Compose, API settings, UI, or any mutable
  runtime endpoint. A disabled gate fails **before** secret resolution, transport construction,
  endpoint validation, provider request creation, or evidence generation/persistence. Tests may
  enable it only through direct dependency injection.
- **Immutable binding.** A frozen `LiveReadCollectionBinding` carries `execution_target_id`,
  `target_config_hash`, `onboarding_id`, `boundary_hash`, `authorization_id`,
  `authorization_version`, canonical `authorization_expiry`, `evidence_source`,
  `verification_level`, `collector_contract_version`, and `endpoint_allowlist_version`. A
  missing, expired, malformed, or internally-inconsistent binding is refused **before** any
  secret resolution or transport construction.
- **Secret boundary.** The worker's existing `SecretResolver` Protocol (opaque `secret_ref` →
  transient `ProviderCredential`) is reused; **no real secret backend** is implemented; secrets
  are never stored/logged/hashed/serialized/audited/returned. Disabled or invalid cases never
  call the resolver.
- **Collector.** A plugin-owned `LiveReadOnlyProxmoxCollector` uses the PR-#10 closed canonical
  path policy, issues only allowlisted GETs through an **injected** transport, uses the existing
  pure normalizer, **never infers isolation**, and returns only an in-memory provider-neutral
  observed dict. It creates no evidence record. `fully_segregated` cannot pass; incomplete or
  generic inventory stays `unverifiable`.
- **Transport hardening.** `HttpxReadOnlyTransport` now applies `assert_request_allowed` before
  client construction, forces `verify_tls=True`, sets `trust_env=False`, disables and explicitly
  refuses redirects, and validates the base URL (HTTPS, no userinfo/query/fragment/escape). It
  remains dormant — no real endpoint is contacted anywhere.
- **No activation wiring.** The normal preflight dispatcher is unchanged; no live evidence source
  is added to any persistence flow; `SealedProviderTargetEvidenceCollector` stays sealed; the
  simulated collector is unchanged. **A later, separately-authorized activation PR — gated on
  the human activation checklist and an independent security review — is required before this
  dormant collector can be reached outside unit tests.** No real Proxmox target was contacted,
  and no secret backend, API trigger, database persistence path, or live activation exists.

Two follow-up hardening fixes close remaining contract gaps (still dormant/fake-only):

- **Strict no-query-parameters contract.** This milestone allowlists **no** query parameters, so
  both transports (`Fake` and `Httpx`) accept **only** `None` or an empty `dict` and refuse
  everything else (`[]`, `()`, `""`, `0`, `False`, any non-empty mapping) with
  `QueryParametersRefused` **before** client construction or canned-response lookup. The base URL
  must normalize exactly to the Proxmox API root `/api2/json` (with or without a trailing slash);
  an empty or arbitrary path is refused.
- **Real (recomputed) binding bound to a validated config.** A plugin-owned, immutable
  `ValidatedProxmoxTargetConfig` (`parse_proxmox_target_config`) accepts **exactly** `base_url`,
  `verify_tls`, `credential_ref` and rejects unknown/secret-like/nested/mistyped fields (rejected
  raw values are never logged/hashed/returned). `run_live_readonly_collection` receives
  authoritative `ExecutionTarget` + `TargetOnboarding` records, derives parser input and boundary
  only from those records, canonical-hashes **only** the validated model's secret-free binding
  representation (deterministic JSON: sorted keys, compact separators, UTF-8, NaN/inf and
  unsupported types rejected) and compares it to `binding.target_config_hash`, recomputes +
  compares the boundary hash, binds the target's opaque `secret_ref` to the validated
  `credential_ref` by exact in-memory equality (never logged/hashed), and requires a worker-only
  `LiveReadAuthorizationVerifier` (fake-only) to approve. The transport factory receives the
  **validated config** (never a raw dict) + the transient token, so the validated, authorized
  configuration — not a separate factory choice — controls the future transport destination.
  Parse failure, hash mismatch, malformed digest, canonicalization failure, secret-ref mismatch,
  a disabled gate, or an invalid binding all fail closed **without** calling the verifier,
  resolver, transport factory, collector, or any persistence code.

## Amendment — trusted target/onboarding identity binding (SECP-002B-1B-5, 2026-07-02)

`run_live_readonly_collection` no longer accepts an independently-supplied `target_config`,
`declared_boundary`, or `secret_ref`. It now receives only the authoritative `ExecutionTarget`
and `TargetOnboarding` records and derives, in worker memory, the config from
`ExecutionTarget.config`, the boundary from `TargetOnboarding.declared_boundary`, and the opaque
credential reference from `ExecutionTarget.secret_ref` — a caller cannot supply those three values
independently. The runner does **not** query the database; a future, separately-authorized
activation workflow (not built here) loads the trusted ORM records before calling it.

After the disabled gate and structural binding validation, and **before** config parsing,
connection/boundary hashing, authorization, secret resolution, transport construction, collection,
or any persistence, the runner fails closed unless the binding names the exact records and the two
records agree on one identity+relationship: `binding.execution_target_id`/`onboarding_id` match
the record ids, `onboarding.execution_target_id`/`organization_id` match the target,
`plugin_name == "proxmox"`, and a non-empty `secret_ref` is present. `ExecutionTarget.config`
remains secret-free (connection identity only and must not itself carry a credential reference);
the connection hash still covers only `base_url` + `verify_tls`;
`LiveReadCollectionBinding.target_config_hash` denotes that canonical validated-connection hash,
**not** the persisted `ExecutionTarget.config_hash` format; and the credential reference stays
bound by exact three-way in-memory equality (`binding.credential_ref ==
validated_config.credential_ref == ExecutionTarget.secret_ref`), never hashed/logged/echoed.

This amendment adds **no** staging activation, secret backend, API route, UI action, environment
switch, database migration, or real Proxmox access; the simulated collector is unchanged, the
sealed provider collector stays sealed, `fully_segregated` still cannot pass, and legacy provider
discovery (`ProviderInventorySnapshot`) remains separate from target evidence collection.

## Amendment - staging activation authorization contract (SECP-002B-1B-6, 2026-07-02)

B1-B6 creates only the durable authorization and worker-owned loader/verifier contracts required
for a later, separately reviewed single-target staging activation PR. It does **not** authorize,
enable, configure, or connect to any staging target. No real endpoint, target configuration,
secret backend, environment switch, dispatcher wiring, API route, UI action, worker workflow,
transport construction, collector invocation, or live evidence persistence exists after this PR.

- **Durable authorization row.** `LiveReadAuthorization` is provider-neutral and stores only safe
  binding facts: organization id, execution-target id, onboarding id, connection hash, boundary
  hash, authorization version/expiry, collector-contract version, endpoint-allowlist version,
  evidence source, verification level, and state (`draft`, `approved`, `revoked`, `expired`).
  It never stores endpoint URLs or hosts, raw target config, declared-boundary contents,
  credential/secret references, tokens, a hash of a credential reference, observations, or
  evidence payloads. Binding facts are immutable; approval metadata is set once; revocation
  preserves approval history and records explicit revocation metadata plus audit.
- **Worker-owned authoritative loader/verifier contract.** A future activation job must call the
  worker-owned verifier with only pinned ids/version and an injected authoritative repository. The
  verifier loads `ExecutionTarget`, `TargetOnboarding`, and `LiveReadAuthorization`; enforces
  organization consistency, target/onboarding relationship, active target, active onboarding,
  approved and unexpired authorization, non-revocation, current connection hash, boundary hash,
  evidence source, verification level, collector-contract version, endpoint-allowlist version, and
  authorization version; and constructs `LiveReadCollectionBinding` only after every check passes.
  It cannot accept caller-built ORM records as the trust anchor.
- **Direct-instantiation guard.** The dormant runner now uses an injected collector seam. Non-test
  live-read modules do not directly instantiate `LiveReadOnlyProxmoxCollector`, construct
  `HttpxReadOnlyTransport`, or call `run_live_readonly_collection`. The existing legacy inventory
  discovery path remains separate from target evidence collection and cannot satisfy this
  authorization contract.
- **Redaction.** `LiveReadCollectionBinding`, `ValidatedProxmoxTargetConfig`, authorization
  request/result/refusal objects, and authorization audit payloads do not print or serialize
  opaque credential or secret references. Credential references remain bound only by exact
  in-memory equality and are never hashed.

A future PR must explicitly wire exactly one approved target through this authoritative
loader/verifier, preserve these direct-instantiation and redaction guards, and receive separate
human authorization before any live read-only collector can be enabled.

## Amendment - disposable staging target operating design (SECP-002B-1B-7, 2026-07-03)

B1-B7 is documentation-only. It defines the out-of-band operating design and readiness contract
for the first disposable Proxmox staging target
(`docs/proxmox/disposable-staging-target-operating-design.md`): staging target eligibility,
a placeholder-only reference topology (default-deny worker egress, single explicit allow rule,
no DNS-based widening, no proxy inheritance, mandatory TLS verification, redirects disabled,
management-plane segmentation, break-glass rule removal), least-privilege read-only Proxmox
identity design, out-of-band certificate trust and target identity verification, a readiness
evidence checklist completed outside Git, a rollback and kill-switch plan, separation of
responsibilities across control plane / worker / network operator / target administrator /
human approver, and explicit entry criteria a future activation PR must meet before it may be
proposed.

B1-B7 adds **no** target registration, real endpoint or host, credential or secret reference,
certificate data, API/UI/dispatcher/workflow wiring, environment variable or Compose change,
Proxmox access, live evidence persistence, or collector/transport/resolver/authorization
execution. Static documentation guardrail tests
(`apps/api/tests/test_staging_target_operating_design.py`) enforce that the live-read documents
stay free of real infrastructure values and that no staging activation switch exists in code or
infrastructure. All prior dormancy, authorization, redaction, and sealed-evidence guarantees are
unchanged.

## Amendment - isolated staging control-plane topology correction (SECP-002B-1B-8, 2026-07-03)

B1-B8 is a documentation-only correction of the B1-B7 disposable staging design
(`docs/proxmox/isolated-staging-control-plane-design.md`). The B1-B7 reference topology showed a
lone "SECP worker" reaching the target across a single isolated segment; read literally as a
worker with only a target-facing interface, that would strand the worker from the authoritative
API and database the SECP-002B-1B-6 loader/verifier requires. B1-B8 replaces that concept with a
self-contained **isolated SECP staging control-plane VM** that contains a staging-only API,
database, and worker, with API/database/worker communication kept local to the VM over loopback
or an internal container network, and exactly one target-facing path from the staging worker to
one disposable nested Proxmox target API. The staging control plane must never use the production
SECP database or production control-plane services; the future staging authorization is
authoritative only for the isolated staging environment; and no caller-supplied records may
substitute for the staging database. B1-B8 also adds an offline bootstrap requirement, corrects
the nested-on-shared-hypervisor scope language (not equivalent to dedicated-hardware or
hypervisor-level isolation; no untrusted workloads), and withdraws the earlier claim that
destruction is without consequence in favour of bounded, reversible staging resources against
verified production headroom.

B1-B8 adds **no** target registration, real endpoint or host, credential or secret reference,
certificate data, API/UI/dispatcher/workflow/Compose/runtime wiring, environment variable,
Proxmox access, live evidence persistence, or collector/transport/resolver/authorization
execution. Static documentation guardrail tests
(`apps/api/tests/test_isolated_staging_control_plane_design.py`) enforce the correction and the
continued absence of real infrastructure values and activation switches. All prior dormancy,
authorization, redaction, and sealed-evidence guarantees are unchanged.

## Amendment - application-owned declarative staging-lab workflow (SECP-002B-1B-9, 2026-07-03)

B1-B9 makes SECP — not a shell runbook — the owner of the disposable staging lab's desired state
and future provisioning workflow. It adds an application-owned, fake-only capability: a durable
provider-neutral `StagingLab` desired-state record, a deterministic immutable topology compiler,
an explicit approval boundary, a worker-owned fake execution seam, and a controlled teardown,
surfaced through a web UI workflow (create -> plan -> approve -> simulate -> observe -> teardown).

The compiler emits logical resources only: one isolated host-only network with no uplink, no
gateway, and no DNS; a self-contained staging control plane (staging API + database + worker with
no production dependency); one disposable nested Proxmox target; exactly one target-facing
read-only connection policy (staging worker to the nested target API); a known-clean checkpoint +
rollback intent; and a teardown intent — every resource carrying the lab's immutable ownership
label. The compiler and the worker seam fail closed on production control-plane reuse, a
shared/production network, more than one target-facing network or nested target, a missing
self-contained control plane, a standing/auto-renewing authorization, missing ownership labeling,
or an unapproved substrate.

B1-B9 is fake-only. It creates no bridge, VM, VNet, target, token, secret, or connection;
contacts no Proxmox and opens no socket/subprocess; performs no secret resolution and persists no
live evidence; and adds no runtime switch that can activate provisioning. Approving a staging-lab
plan authorizes fake simulation only — it is NOT a SECP-002B-1B-6 `LiveReadAuthorization`, which
remains separately required for any future real read-only collection.
The SECP-002B-1B-8 self-contained staging control-plane constraint remains mandatory. A later,
separately reviewed adapter PR is required before any real provisioning can occur.

### Remediation (durable work items, strict validation, concurrency, eligibility)

The initial B1-B9 draft executed simulation inline in the API process and trusted UI-only
validation. It was reworked so that:

- **The API only enqueues durable, committed work.** `queue_simulation` / `queue_teardown` create
  a `StagingLabWorkItem` (safe logical values only) and move the lab into an explicit
  `simulation_queued` / `teardown_queued` state, then return. A separate **worker consumer**
  (`secp_worker.staging_lab.consumer`) claims exactly one committed queued item with a database
  compare-and-swap, **reloads the authoritative lab/approval/plan-hash/version/organization/
  ownership and lifecycle state**, refuses stale/mismatched/cross-org/drifted/unowned work, and
  only then runs the fake executor and writes observations + completion. The API imports no
  staging-lab worker/executor code and is **not** routed through the inline dispatcher; only the
  worker may enter `simulating` / `tearing_down` or complete work. This consumer runs **fake-only**
  inside the worker process (a bounded poll loop in `secp_worker.staging_lab.runtime`, started by
  the worker entrypoint); the API never runs it. A later, separately reviewed real-adapter PR is
  required before any provider action.
- **Strict backend allowlist validation.** All persisted labels are server-generated from the
  immutable lab id (ownership label, display name); resource class, bootstrap-artifact profile,
  profile, network intent, rollback policy, purpose, lifecycle, and work operation are closed
  backend enums; the substrate is referenced only by UUID (the UI receives a server alias, never
  raw target text); and the single optional caller string is validated against a strict
  kebab-case slug allowlist that structurally excludes URLs, hosts, IPs, paths, ports, and
  secret/credential/token references.
- **Concurrency-safe lifecycle.** A `revision` column plus transactional compare-and-swap updates
  make approval, queueing, worker claim, completion, and teardown fail closed under races (the
  worker claim uses `FOR UPDATE SKIP LOCKED` on PostgreSQL with a portable CAS fallback). Work
  identity is a **server-generated operation fingerprint** over
  `(lab_id, operation, plan_hash, plan_version)` — never a caller-supplied idempotency key; a
  unique fingerprint plus a unique `(lab, operation, plan_hash, plan_version)` scope and a
  partial-unique active index enforce at most one active work item per lab+operation, make a
  retry of the identical operation+plan resolve to the original item, and refuse
  cross-organization association.
- **No caller free text.** Approval/rejection outcomes and work failures use closed decision/
  failure-code enums (never free-text reasons), and staging-lab validation errors return only a
  safe generic code (`invalid_staging_lab_input`) — the rejected input is never echoed in the API
  response, audit trail, or logs.
- **Explicit substrate eligibility.** A target is a staging substrate only when a target admin
  (permission `staging_substrate:manage`, with no lab-creator endpoint) issues a durable
  `StagingSubstrateEligibility` record binding organization, target, Proxmox plugin type, and the
  `nested_proxmox` profile. The service and the compiler independently require eligibility; UI
  filtering alone is insufficient.

## Amendment - app-owned read-only staging preflight (SECP-B2-0, 2026-07-04)

B2-0 adds a real, app-owned, worker-executed **read-only staging preflight** for an already
eligible nested-Proxmox substrate. It verifies only safe readiness facts required before future
app-owned provisioning and mutates nothing (no create/alter/delete/start/stop/clone/snapshot/
upload/download/config).

- **Explicit, short-lived authorization.** An authorized admin creates and approves a short-lived
  `LiveReadAuthorization` for the substrate (`onboarding:approve`); connection and boundary hashes
  are derived server-side (the admin supplies no hashes/endpoints/secrets). This is separate from
  staging-lab approval and is never created automatically from a staging-lab plan or approval.
- **Durable, queue-only API.** A new `ReadonlyStagingPreflight` record binds one immutable
  (organization, target, onboarding, authorization + version) tuple with a server-generated
  operation fingerprint, DB scope-uniqueness, a partial-unique active index, and CAS lifecycle
  transitions. The API only commits `queued` intent; it imports no plugin/worker/transport/
  collector/HTTP code and executes no collection.
- **Worker-only execution, fail-closed.** A worker consumer claims one queued intent
  (`FOR UPDATE SKIP LOCKED` on PostgreSQL; CAS fallback on SQLite), re-verifies the authoritative
  binding via the SECP-002B-1B-6 verifier, and only then would resolve the opaque credential and
  run the sealed GET-only collection path. Only the worker writes outcomes (closed codes:
  `ready`, `not_ready`, `authorization_expired`, `authorization_revoked`, `authorization_invalid`,
  `credential_unavailable`, `tls_or_policy_refused`, `worker_internal_failure`) and only safe
  readiness facts (booleans/counts) — never endpoints/config/observations.
- **Remaining activation dependencies.** No production secret-manager resolver exists, so a
  **sealed** injected worker resolver makes every preflight fail closed as
  `credential_unavailable`: no transport is constructed and nothing real is contacted. A later,
  separately reviewed activation PR must (1) inject a production-safe worker-only secret resolver
  and (2) wire the injected collection runner (reconciling the connection-identity hash with the
  plugin's validated connection representation) before a deliberate live preflight can return
  `ready`. A ready result proves only the collected readiness facts — never host isolation or
  production safety. All prior dormant live-read, trusted-binding, redaction, and sealed-evidence
  guarantees are unchanged.

### Review hardening (SECP-B2-0)

- **Validation redaction.** Request-validation failures on `/api/v1/readonly-preflight` and its
  child routes (a segment-aware match, not a broad prefix) return exactly
  `{"error": {"code": "invalid_readonly_preflight_input"}}` — never the rejected input, request
  body, or Pydantic `input`/`ctx`/`url`/`detail`. Unrelated routes keep FastAPI's default shape.
- **Closed error codes.** Every read-only-preflight service refusal maps to a closed
  `ReadonlyPreflightErrorCode` (`not_found`, `forbidden`, `substrate_ineligible`,
  `authorization_invalid`, `lifecycle_conflict`, `queue_conflict`, `internal_failure`) serialized
  as `{"error": {"code": ...}}` with **no** free-form backend message. The UI maps each closed
  code to fixed local text (unknown → a fixed generic message) and never renders a backend
  message; it also re-applies the readiness-fact allowlist before rendering.
- **Monotonic authorization version.** The authorization version is server-derived and
  monotonic per (target, onboarding) — never caller-supplied and never hardcoded — so renewal
  after a prior authorization expires/revokes proceeds; the unique
  (target, onboarding, version) constraint prevents duplicates under concurrency (a losing insert
  retries with a recomputed version).
- **Terminal CAS/audit consistency.** The worker writes the outcome + safe facts atomically with
  the terminal compare-and-swap; the terminal audit is emitted only if that CAS wins. A stale
  worker whose revision drifted writes no facts, emits no terminal audit, and never overwrites a
  newer lifecycle state.

### Sealed worker-only secret-resolution contract (SECP-B2-1)

The final sealed secret-resolution interface lives entirely in the worker
(`secp_worker.preflight.secret_resolution`). It is the seam a future activation PR binds a real
secret backend to; nothing in it resolves a secret, reads an environment variable, opens a
socket/subprocess, imports a provider or secret-manager SDK, or contacts any backend. The API cannot
import it (architecture boundary test), and the UI has no credential-entry field or
secret-resolution route.

- **Closed resolution-purpose catalog.** `ResolutionPurpose` has exactly one permitted value in
  this phase, `readonly_staging_preflight`; `SUPPORTED_PURPOSES` gates it. Any other purpose is
  refused.
- **Trusted request built only post-verification.** A `TrustedResolutionRequest` can be built
  **only** by `build_trusted_resolution_request(...)`, which requires a
  `VerifiedLiveReadAuthorization` produced by the authoritative binding verifier; its constructor
  is sealed behind a module-private token, so a caller cannot hand-craft one as a trust anchor.
  The request carries a redacted `ResolutionContract`: purpose, organization, execution target,
  onboarding, authorization id + version, authorization expiry, operation fingerprint, expected
  contract version, expected endpoint-policy version, and an opaque `TrustedCredentialReference`.
- **Per-field contract gate.** `assert_resolution_authorized(candidate, authoritative)` refuses
  (with a generic reason code, never a value) on wrong organization / target / onboarding, wrong
  authorization identity or version, wrong operation fingerprint, wrong contract/endpoint-policy
  labels (including a pinned check against the app-side constants), blank or mismatched opaque
  reference, unsupported/mismatched purpose, or an expired authorization.
- **Opaque secret material.** `SecretMaterial` and `TrustedCredentialReference` are slotted,
  `__dict__`-free wrappers with redacted `repr`/`str`/`format` and blocked pickling — impossible
  to persist through ORM/API/audit paths. Production code in this PR never constructs
  `SecretMaterial`; the sealed default never returns one.
- **Sealed default, ordering preserved.** `SealedUnavailableResolver` (shipped as
  `SealedSecretResolver`) runs the contract gate then **always** fails closed
  (`SecretResolutionUnavailable`). The B2-0 ordering is intact:
  authorization/binding verification → pinned policy check → secret-resolution boundary → (future)
  transport factory → (future) collector. Every preflight still ends `credential_unavailable`;
  no transport is constructed and no collector runs.

**Prerequisites a later activation PR must satisfy before wiring a real `WorkerSecretResolver`:**

1. **Independently authenticated worker identity** — the worker authenticates to the secret
   backend as itself; the API and UI have no path to the backend or to secret material.
2. **Approved external secret backend** — a reviewed, production-grade external secret manager,
   never an environment variable, plaintext DB column, Docker secret file, or local-file
   fallback.
3. **Strict reference grammar and access policy** — the opaque `credential_reference` grammar is
   validated and the backend policy scopes each reference to exactly one target.
4. **Short-lived, single-purpose resolution** — resolution yields a short-TTL credential bound to
   the `readonly_staging_preflight` purpose and the exact operation fingerprint; no caching.
5. **Worker-only network path** — only the worker network namespace may reach the backend.
6. **Audit-safe metadata only** — audits record identity/version/outcome codes; never a
   reference value, secret, endpoint, or provider response.
7. **Revocation and rotation** — a revoked/rotated reference resolves closed; expiry is enforced
   by the contract gate; rotation does not resurrect an expired authorization.
8. **Test plan proving no API/UI secret access** — static boundary tests continue to prove the
   API cannot import the resolver and the UI has no credential-entry field or secret-resolution
   route, plus redaction/serialization tests for any real material handoff.

All prior dormant live-read, trusted-binding, redaction, closed-error, monotonic-versioning, and
sealed-evidence guarantees are unchanged.

### Live secret-resolver activation obligations (SECP-B2-2)

SECP-B2-2 is a design/static-contract milestone (no code, no backend, no switch). It records the
non-negotiable obligations a future resolver-implementation PR must satisfy, resolving the two
SECP-B2-1 adversarial-review findings. The full contract is
`docs/architecture/secp-b2-2-live-secret-resolver-activation.md`; the closed evidence gate is
`docs/proxmox/live-secret-resolver-activation-checklist.md`. The resolver-activation checklist and
the collector-activation checklist are **cumulative**: both must be satisfied in full and neither
ever substitutes for the other.

- **A trusted request is not a capability.** Possession of a `TrustedResolutionRequest` or a
  `ResolutionContract` — including one carrying the construction token or forged via
  `__new__`/`dataclasses.replace` — is never proof of authorization. The future resolver treats
  every request as untrusted input and independently re-verifies authorization at resolution time.
  The object seal is best-effort; static AST guardrails plus worker-only execution are the defense.
- **No self-referential trust anchor.** The B2-1 orchestration derives the request and the
  "expected contract" from the same `VerifiedLiveReadAuthorization`, so their comparison is
  self-referential and only re-checks pinned labels/expiry. The future resolver must derive its
  authoritative expectation from an **independent source of truth** — re-loaded authoritative
  records re-verified through the SECP-002B-1B-6 verifier, the app-side pinned constants, and the
  external backend's own policy — never from a caller-built expected contract.
- **Credential-reference three-way binding.** Exact, constant-time equality is required between the
  authoritative `ExecutionTarget.secret_ref`, the re-verified live-read binding reference, and the
  resolver request reference. Any mismatch or blank reference fails closed before backend access;
  the reference is never hashed, logged, audited, serialized, or exposed via `repr`.
- **Replay and single-use resolution lease.** A durable, single-use lease is acquired before
  backend access via a transactional **compare-and-swap**. Single-use, replay refusal
  (`replay_refused`), and the retry budget are **global** per the uniqueness key
  `(authorization_id, authorization_version, operation_fingerprint)` — it does not include
  worker identity, so two workers can never each hold a valid pre-success lease for the same
  operation. Worker identity is required for authenticated issuance, backend authorization, and
  secret-free audit evidence, but is not part of the uniqueness boundary. The bounded retry limit is
  **fixed at N = 3**, counted durably per that uniqueness key across every lease and every worker
  identity; a fresh lease **must not reset or expand** it; a retry is allowed only before
  authorization expiry and while budget remains; once exhausted, resolution is refused
  (`retry_bound_exceeded`) until a new `authorization_version` exists. A lease never outlives the
  authorization. Lease and refusal evidence is durable and **secret-free** (records no reference and
  no material) with closed reason codes.
- **Worker identity and backend policy.** The worker authenticates to the backend as an
  independently issued, out-of-band-rotated identity with no API/UI credential or network path; the
  backend policy authorizes only the exact (worker identity, reference, target, purpose) tuple;
  resolution is short-lived with no caching or reusable credentials; rotation/revocation and a
  fail-closed response mapping are enforced.
- **Formal activation gates (all required, none alone sufficient).** Code review; a separate durable
  approval record; activation configuration outside Git; staging-only target eligibility; time-bound
  versioned authorization; a resolver health/self-test that reveals no secret; and a tested
  revocation/rollback/kill-switch path. Removing or failing any one gate fails closed.

No live resolver, secret backend, secret-manager client, activation switch, or runtime/environment
flag is introduced by SECP-B2-2; the shipped default remains the sealed
`SealedUnavailableResolver` and every preflight still ends `credential_unavailable`.

### Durable lease + sealed activation foundation — implementation status (SECP-B2-3)

SECP-B2-3 implements the **local, fully-sealed** durable-lease and activation-gate foundation from
the B2-2 contract. It adds no secret backend and no live resolver; every preflight still ends
`credential_unavailable`, no transport is constructed, no collector executes, and nothing real is
contacted. This PR does **not** satisfy any B2-2 out-of-band activation evidence — a future
implementation PR must still satisfy every gate in
`docs/proxmox/live-secret-resolver-activation-checklist.md`, and that checklist remains
**cumulative** with the collector-activation checklist.

- **Durable lease schema.** A new `resolution_lease` table (migration `c4e9a1f7d2b3`) persists one
  row per **global operation uniqueness key** `(live_read_authorization_id, authorization_version,
  operation_fingerprint)` — worker identity is **not** in that key. It stores the durable
  `attempt_count` (cap N=3), the current lease instance (`lease_id`, `lease_expires_at`), a
  compare-and-swap `revision`, a closed `status` (`active`/`consumed`/`exhausted`), a secret-free
  `worker_identity_id`, and a closed `reason_code`. It stores **no** credential, credential/secret
  reference, endpoint, target configuration, certificate, backend response, or hash of any of those.
- **Worker-only lease service (portable CAS).** `acquire_lease` / `begin_attempt` / `mark_consumed`
  implement single-use, replay refusal (`replay_refused`), the durable N=3 budget
  (`retry_bound_exceeded`), lease-expiry re-acquisition that preserves the budget, and a
  transactional compare-and-swap (unique-constraint insert + `IntegrityError` fail-closed, plus a
  `(id, revision)` conditional update) that works identically on SQLite and PostgreSQL. A losing
  transition changes no state and emits no audit. `begin_attempt` is the only transition that
  consumes the budget; lease issuance alone never does.
- **Sealed worker identity + activation gate.** `DenyingWorkerIdentityVerifier` (the shipped
  identity default) reads no environment, host file, container metadata, network endpoint, or
  certificate and always denies (`worker_identity_untrusted`); `SealedActivationGate` (the shipped
  gate) is always disabled (`resolution_activation_disabled`) and cannot be enabled via API, UI,
  settings, environment, Compose, a database route, feature flags, or Git-tracked config. Test-only
  approved implementations may be injected to exercise lease transitions but are never selectable by
  production runtime; even then the flow ends at the sealed resolver.
- **Preserved ordering.** The worker enforces: authoritative re-load/re-verification (SECP-002B-1B-6
  verifier) → pinned collector-contract + endpoint-policy check → credential-reference three-way
  binding (authoritative `ExecutionTarget.secret_ref` == verified binding reference == request
  reference, constant-time, never logged/persisted/hashed/audited/rendered) → worker-identity
  verification → sealed activation gate → durable lease acquisition → durable begin-attempt →
  (sealed) secret-resolution boundary → future transport → future collector. In **shipped runtime**
  the deny-by-default identity fails closed **before** lease acquisition and begin-attempt, so no
  lease row is created and no attempt is begun.
- **Secret-free audit.** Durable lease transitions are audited with safe IDs, state names, revision,
  operation fingerprint, worker identity id, and closed reason codes only — never a secret,
  reference, endpoint, target config, backend response, raw exception text, or request body. The
  B2-0 API/UI closed-error behavior is unchanged.
