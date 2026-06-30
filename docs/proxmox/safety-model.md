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

## What a reviewer should verify

- No file contains a real hostname, IP, cluster/node/pool/storage name, VLAN, or
  credential (`test_no_real_endpoints.py`).
- `apps/api` imports nothing that could touch a provider (`test_architecture_boundary.py`).
- Discovery issues only GET requests (`test_proxmox_plugin.py`).
- Inline execution refuses the Proxmox plugin (`test_inline_refuses_real_provider.py`).
