# ADR-012 — Worker-only provisioning runner abstraction and future OpenTofu integration

- **Status:** Accepted (amended SECP-002B-0 correction pass)
- **Date:** 2026-06-30 (amended 2026-06-30)
- **Milestone:** SECP-002B-0
- **Related:** Charter §5 (Layers 4/5), Invariants 6, 7; ADR-003, ADR-005, ADR-007, ADR-010, ADR-011

## Context

Future SECP-002B-1 provisioning will run OpenTofu against a disposable Proxmox lab.
The charter forbids the API from executing privileged infrastructure actions
(Invariants 6, 7); such work must occur only in the worker through a versioned,
replaceable seam. We must define that seam **now**, and prove it end-to-end with a
**fake** runner, without installing or invoking OpenTofu/Terraform and without any
subprocess, network, or provider client.

## Decision

Define a **worker-only** `ProvisioningRunner` protocol with operations:

| Operation | Purpose | Side effects |
| --- | --- | --- |
| `validate(manifest)` | check a manifest is runnable | none |
| `dry_run(manifest, operation_id)` | deterministic change set (plan) | none |
| `apply(manifest, operation_id)` | realise resources | yes, idempotent |
| `destroy(manifest, operation_id)` | tear down | yes, idempotent |
| `status(operation_id)` | read operation status | none |

Only a **`FakeOpenTofuRunner`** is implemented in SECP-002B-0. It:

- runs **no** subprocess, **no** network call, and imports **no** provider client or
  IaC tool;
- produces **deterministic** operation IDs and resource IDs (hashes of the manifest
  content hash + operation kind / resource ref);
- produces **deterministic** dry-run change sets;
- is **idempotent** for apply and destroy (repeated calls converge; the same
  operation id yields the same result);
- returns **redacted** errors and keeps **durable fake operation state**.

### Durable runner state mechanism

`FakeOpenTofuRunner` maintains a process-local `_state` dict (a write-through cache
for within-instance reuse) **and** accepts an optional `state_store: RunnerStateStore`
at construction time.  The `RunnerStateStore` protocol has a single method:
`get(operation_id: str) -> dict | None`.

`DbRunnerStateStore` (in `secp_worker.provisioning.state_store`) implements this
protocol by querying `ProvisioningOperation` rows keyed on `idempotency_key`
(= `sha256(manifest_content_hash + ":" + kind.value)`), returning the terminal
runner state inferred from `op.status` and the resources stored in `op.result`.

On every `apply()`, `destroy()`, and `status()` call the runner first consults its
local `_state` cache; if the operation is absent it falls through to the
`state_store`.  This means a freshly constructed runner instance given a
`DbRunnerStateStore` will answer `status()` correctly after a worker restart
— the `ProvisioningOperation` row written by the prior `run_provisioning` call is
the authoritative state.

`DbRunnerStateStore` is **read-only from the runner's perspective**.  All writes to
`ProvisioningOperation` are performed exclusively by the worker execution layer
(`execution.py` via `secp_api.services.provisioning`) — there is exactly one writer.

Boundary rules:

- The runner lives in `secp_worker` (worker-only). **`apps/api` never imports the
  runner, OpenTofu code, or a provider client, and never resolves secrets.** An
  architecture test enforces this.
- `DbRunnerStateStore` also lives in `secp_worker`; it reads `secp_api.models` and
  `secp_api.enums`, which is an existing and permitted dependency direction.
- The control plane (API) only *generates* manifests (ADR-011) and *records*
  provisioning operations; the **worker** executes the runner.
- The interface is shaped so a future `OpenTofuRunner` can use a **pinned binary and
  pinned provider versions**, resolve secrets **only in the worker** just-in-time
  (ADR-007), and run through the durable Temporal path (ADR-010) — without changing
  callers.

### Safe integration gate

For a target-bound plan the SECP-002A refusal (`assert_deployment_eligible`) remains
the default. The fake runner is reachable **only** when ALL of the following hold:

1. approved plan; 2. pinned target id + config hash; 3. an immutable, validated
manifest; 4. valid, finalized CIDR reservations; 5. a strict provisioning scope
policy; and 6. an explicit `enable_fake_provisioning` setting (dev/test only, refused
in production). Any missing precondition refuses the operation, audited.

## Consequences

**Positive**
- The privileged-execution seam exists and is proven with a fake, keeping the API
  free of runner/provider/IaC code (Invariants 6, 7).
- A fresh runner instance is fully functional after a worker restart: `status()`,
  `apply()` (idempotent noop), and `destroy()` (idempotent noop) all read from the
  durable `ProvisioningOperation` record via `DbRunnerStateStore`.
- No new DB model or migration is required; durable state is derived from the
  already-audited `ProvisioningOperation.result` and `status` columns.
- A future real OpenTofu runner is a drop-in behind the same protocol + gate.

**Negative / risks**
- Two potential runner implementations could drift. Mitigated: the fake implements
  the exact protocol a real runner will, and a conformance-style test suite runs
  against it.

**Placeholder**
- No real OpenTofu/Terraform is installed or invoked. Pinned-binary/provider version
  management, real state storage, and drift handling are SECP-002B-1 / SECP-002C.
