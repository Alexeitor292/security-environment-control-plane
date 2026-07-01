# ADR-012 — Worker-only provisioning runner abstraction and future OpenTofu integration

- **Status:** Accepted
- **Date:** 2026-06-30
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

Boundary rules:

- The runner lives in `secp_worker` (worker-only). **`apps/api` never imports the
  runner, OpenTofu code, or a provider client, and never resolves secrets.** An
  architecture test enforces this.
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
- A future real OpenTofu runner is a drop-in behind the same protocol + gate.

**Negative / risks**
- Two potential runner implementations could drift. Mitigated: the fake implements
  the exact protocol a real runner will, and a conformance-style test suite runs
  against it.

**Placeholder**
- No real OpenTofu/Terraform is installed or invoked. Pinned-binary/provider version
  management, real state storage, and drift handling are SECP-002B-1 / SECP-002C.
