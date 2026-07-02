# Proxmox Safety Model (SECP-002A)

This document defines the safety controls that make a future Proxmox integration
trustworthy. In SECP-002A only **read-only discovery** exists, and it is never run
against a real endpoint during development, tests, CI, or runtime verification.

## Threat model (what we are protecting against)

1. **Accidental mutation** of real infrastructure (create/modify/delete VMs,
   networks, storage, firewall, etc.).
2. **Secret leakage** (tokens, passwords, keys, certs) into the database, audit
   log, errors, logs, UI, or source control.
3. **Boundary erosion** — the API process gaining the ability to perform privileged
   provider actions.
4. **Cross-organization access** to targets, inventory, or reservations.
5. **Address-space collisions** between concurrent environments.

## Layered controls

### L1 — No real access in this milestone
No real Proxmox endpoint is contacted anywhere. All tests use fakes or an in-process
mock HTTP transport. CI requires no external network and no real Proxmox server.

### L2 — Read-only by construction
The Proxmox plugin advertises only `validate`, `health`, `discover`, `status`. The
HTTP transport allows **GET only**; POST/PUT/PATCH/DELETE/any other method is
rejected **before** a request is sent (`MutatingRequestRefused`). No guest-agent,
console, start/stop, task, or config-mutation calls exist.

### L3 — Capability gating
`apply`, `reset`, `destroy` are not advertised. If structurally present for Protocol
conformance, they raise `UnsupportedCapabilityError` before any provider request.
The control plane checks advertised capabilities before dispatch.

### L4 — Worker-only execution and secret resolution
Provider plugins run **only** in the worker, never in `apps/api` (Charter
Invariants 6, 7). Secret references are resolved **only** in the worker,
**immediately before** a provider operation, via a `SecretResolver`. The API may
validate `secret_ref` syntax but never resolves it. Architecture tests prove the API
imports no provider SDK / HTTP client / Proxmox code / IaC / subprocess.

### L5 — Secret-free persistence
`ExecutionTarget.config` is non-secret JSON; `secret_ref` is an opaque pointer (e.g.
`env:NAME` in dev), never a secret. Secrets never enter snapshots, resources, audit
events, error messages, logs, API responses, or frontend state. Resolution errors
are redacted.

### L6 — Immutability and audit
Target configuration is immutable (new config ⇒ new target). Inventory snapshots are
immutable after completion. Every registration, discovery request/start/complete/
failure, refusal, and reservation lifecycle event is audited. Existing
`environment_version` / `audit_event` DB-level immutability triggers remain.

### L7 — Address-space reservations
CIDRs are reserved transactionally per execution target with overlap prevention, so
concurrent environments cannot collide before any real network exists.

### L8 — Durable, gated execution
Real-provider work uses the Temporal durable path. `InlineDispatcher` refuses any
non-Simulator plugin (identity-based allowlist). The API queues work; the worker
performs it.

## Correction pass controls

- Resolved credentials are opaque transient `ProviderCredential` objects. They are
  not Pydantic models, cannot be converted to dict/JSON, refuse pickling, and
  expose material only through the explicit worker/plugin `reveal_secret()`
  accessor.
- Temporal submission uses a transactional outbox. The API commits queued
  `WorkflowRun` plus outbox intent first; the worker-side publisher submits only
  committed rows. Failures remain durable and retryable.
- Discovery workflow linkage is canonical from `WorkflowRun.snapshot_id` to
  `ProviderInventorySnapshot.id` via a real foreign key.
- CIDR allocation serializes per target by locking the target's address-space
  policy rows inside the database transaction. Address-space policies are strictly
  parsed, overlapping policies on the same target are rejected, and reservation
  prefixes must match the approved policy prefix.
- For the actual `proxmox` plugin and target registration path, `base_url` must be
  `https://`, `verify_tls=false` is rejected, unsupported config keys are rejected,
  and scope policy keys/values are validated. Mock/fake transports used in tests do
  not weaken the validation required for a real target. A future real deployment
  must use a trusted CA or a separately designed certificate-pinning approach.

## Secret reference syntax (dev)

A `secret_ref` is an opaque string of the form `<scheme>:<locator>`. SECP-002A ships
one dev scheme:

- `env:NAME` — the worker's `EnvSecretResolver` reads the secret from environment
  variable `NAME` at execution time. `NAME` must be namespaced (e.g.
  `SECP_PROVIDER_SECRET__<target-id>`). The value is never stored or logged.

A real production secret manager (e.g. Vault, cloud KMS) is a future integration;
the `SecretResolver` interface is shaped to accept additional schemes without
changing callers.

## SECP-002B-1A controls (sealed OpenTofu runner + lab activation)

SECP-002B-1A builds the *real* worker-only OpenTofu architecture but still contacts **no**
live infrastructure and invokes **no** real binary/provider/endpoint anywhere (source,
tests, CI, Docker). The following controls extend the model (ADR-013):

### L9 — Immutable, secret-free toolchain provenance
An `ExecutionTarget` is bound to a worker runtime by an immutable, org-scoped
`ToolchainProfile` (pinned OpenTofu version + binary integrity + adapter/module-bundle
hash + provider lockfile hash + renderer version + **remote** state-backend reference +
offline provider-mirror identity + `isolated_lab` activation class). Profiles reject
floating/`latest`/wildcard/empty/unpinned versions, missing hashes, **local-only state**,
**direct-internet provider downloads**, unknown adapters, and permissive/unconfigured
production-style profiles. The exact profile id + hash are pinned to the plan, manifest,
change-set approval, and apply/destroy; any drift fails closed.

### L10 — Sealed process executor (no real process in B1-A)
The `OpenTofuRunner` runs OpenTofu only through a worker-only `ProcessExecutor`.
`FakeProcessExecutor` is used everywhere in B1-A and runs nothing. A
`SubprocessProcessExecutor` exists but is **inert unless an explicit isolated-lab runtime
gate is armed**, uses **argv arrays only** (never a shell), a fixed restrictive-permission
working directory, an explicit timeout, an output-size cap, an environment allowlist, and
mandatory output redaction. It is **not constructed or invoked anywhere in B1-A**.

### L11 — Deterministic, secret-free workspace rendering
A worker-only adapter/renderer converts an immutable manifest + toolchain profile into a
deterministic, secret-free rendered workspace with a content hash. Provider endpoint and
token are referenced only as input variables injected just-in-time in the worker at real
apply (B1-B), never written into the durable, hashed artifact. Local state is refused;
providers/modules are expected from an offline, pinned, verified mirror.

### L12 — Explicit dry-run change-set approval
Apply requires a human-approved, canonical, redacted **dry-run change-set hash** that still
matches a freshly regenerated dry run. Destroy requires its own separately approved destroy
change set. No automatic apply, no AI approval, no environment-variable bypass. Raw
OpenTofu binary plans are never persisted.

### L13 — Isolated-lab activation gate (default-deny)
Real provisioning is disabled by default. The gate requires: isolated-lab application
mode; Temporal-only (inline refused); an active target whose pinned toolchain profile is
`isolated_lab`; approved plan + immutable manifest; full target/config/policy/reservation/
toolchain hash agreement; an explicit approved dry-run change set; an explicit
real-provisioning setting; worker-only JIT secret resolution; `deny` external connectivity;
a validated remote state backend; and **no fallback** to the fake runner.

## SECP-002B-1B-0 controls (target onboarding)

Target onboarding formalizes *how a target becomes eligible* for real provisioning
(ADR-014). B1-B-0 is design/model/API/fake-only: **no real target is contacted, inspected,
configured, authenticated to, or mutated.**

### L14 — Two isolation models, explicit + declared
Physical isolation (dedicated hardware) is a recommended secure preset, **not** a
requirement. A shared existing environment is allowed **only** with a `logical` isolation
model behind an explicitly declared, enforceable, auditable, independently verifiable
boundary (node/storage/network allowlists, CIDR ranges, VM-ID range, quotas,
deny-by-default external connectivity, opaque least-privilege credential scope). The
declared boundary is immutable (`boundary_hash`).

### L15 — Redacted, immutable preflight evidence (fake-only in B1-B-0)
A worker-only `PreflightCollector` seam produces redacted, structured evidence
(`evidence_hash`, immutable). In B1-B-0 only a `FakePreflightCollector` exists — it inspects
nothing real. Logical isolation additionally requires a passing `no_route_to_protected`
check. `apps/api` never imports the collector.

### L16 — Approval-gated, drift-invalidated activation
A target is cleared for real provisioning only when its onboarding reaches `active`
(create → preflight → review → **human approval** → activate). Approval pins the target
config + scope-policy hashes; any drift invalidates the approval at activation and at the
real-provisioning gate, which now additionally requires an active, non-drifted onboarding.

### L17 — Automated, declarative deployment
Standard provider-backed deployment is automated: SECP allocates IDs/addresses and creates
scenario resources inside the declared boundary. Plans/manifests state
`manual_pre_creation_required=false` and adopt no pre-existing user assets in standard mode;
import/adoption is a future explicit opt-in workflow. Onboarding and scenario deployment are
separate lifecycle stages.

## SECP-002B-1B-2 controls (live read-only collector — design only)

SECP-002B-1B-2 is **design/threat-model/checklist documentation only**: no provider client/
SDK/HTTP/socket/subprocess is added, no real target is contacted, no credential/endpoint is
created, and the B1-B-1 live-evidence seal is **not** lifted (see ADR-015 and the
[design package](../architecture/secp-002b-1b-2-live-readonly-proxmox-collector.md)).

### L18 — Read-only, worker-owned, default-deny live collection (designed, not enabled)
The first real Proxmox collector is designed to be **read-only by construction**: a GET-only
method allowlist plus a closed endpoint allowlist enforced before send, no redirects, no
cross-target destinations, and no task/action/config/console/agent/backup/upload/write endpoint
ever reachable. It runs on the **durable worker only** (inline refused) behind a
**default-disabled** feature gate, binds each job to an approved `(execution_target_id,
config_hash, authorization_id)`, resolves an opaque `secret_ref` just-in-time in the worker
(never logged/persisted/hashed/returned/audited), reuses the immutable full-record evidence hash
and fail-closed (`unverifiable`) comparison, and may be enabled only after the
[activation checklist](live-readonly-collector-activation-checklist.md) is completed and an
explicit human authorization is recorded — all in a **future** PR.

## What a reviewer should verify

- No file contains a real hostname, IP, cluster/node/pool/storage name, VLAN, or
  credential (`test_no_real_endpoints.py`).
- `apps/api` imports nothing that could touch a provider, runner, process executor,
  adapter, workspace rendering, OpenTofu, or `subprocess`
  (`test_architecture_boundary.py`, `test_provisioning_boundary.py`).
- Discovery issues only GET requests (`test_proxmox_plugin.py`).
- Inline execution refuses the Proxmox plugin (`test_inline_refuses_real_provider.py`).
- Toolchain profiles reject floating versions, missing hashes, local state, direct
  downloads, and unconfigured activation (`test_toolchain_profile.py`).
- No test, CI path, Docker verification, or runner invokes a real binary, network,
  provider, or endpoint (`test_opentofu_runner.py`, `test_no_real_process.py`).
- Apply/destroy are refused without — or on drift from — an approved dry-run change set
  (`test_lab_activation_gate.py`).
- The B1-B-2 design PR adds no provider SDK/HTTP client and does not lift the live-evidence
  seal; the design/threat-model/checklist docs exist and are secret-free
  (`test_live_collector_design.py`).
