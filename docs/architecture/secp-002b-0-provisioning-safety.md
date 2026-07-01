# SECP-002B-0 — Controlled Provisioning Safety Harness: Design

**Status:** Accepted for implementation
**Milestone:** SECP-002B-0 (first sub-phase of SECP-002B: Controlled Provisioning)
**Governing document:** [`docs/PROJECT_CHARTER.md`](../PROJECT_CHARTER.md)
**Builds on:** SECP-002A (`docs/architecture/secp-002a-proxmox-discovery.md`)
**Related ADRs:** ADR-011 (manifests), ADR-012 (worker-only runner); ADR-006/007/009/010

---

## 1. Purpose and hard boundary

SECP-002B-0 builds the **safety harness** that must exist before any future
worker-only OpenTofu provisioning against a disposable Proxmox lab (SECP-002B-1). It
introduces immutable provisioning manifests, a strict blast-radius scope policy, a
worker-only runner seam with a **fake** OpenTofu runner, and a durable provisioning
operation lifecycle.

It performs **no real provisioning** and contacts **no real infrastructure**. No
OpenTofu/Terraform binary is installed or invoked; no subprocess, shell, SSH, or
provider client runs; no real VMs/containers/networks/storage/firewall are touched.
Every test uses in-process fakes and mock state. **No SECP-002A safeguard is
weakened.**

## 2. Components

```
apps/api/secp_api/
  provisioning_scope.py          strict scope-policy model + validation (control plane)
  services/manifests.py          generate/validate/read immutable manifests (control plane)
  services/provisioning.py       provisioning-operation records + lifecycle (control plane)
  models.py                      ProvisioningManifest, ProvisioningOperation (+ enums)
apps/worker/secp_worker/provisioning/
  runner.py                      ProvisioningRunner protocol + result types + errors (WORKER ONLY)
  fake_opentofu.py               FakeOpenTofuRunner (deterministic, idempotent, durable via store)
  state_store.py                 RunnerStateStore protocol + DbRunnerStateStore (WORKER ONLY)
  execution.py                   run_provisioning worker orchestration + fake gate
```

The **API generates manifests and records operations**; the **worker executes the
runner**. `apps/api` never imports the runner, OpenTofu code, or a provider client,
and never resolves secrets — enforced by an architecture-boundary test.

## 3. Provisioning manifests (ADR-011)

`ProvisioningManifest` is immutable, secret-free, content-hashed, and bound to an
approved plan + target. Generation refuses unless every precondition holds (plan
approved, target hash not drifted, target active, reservations valid+finalized+in
policy+same org, scope policy valid). The manifest content captures: target id +
config hash, validated scope policy snapshot, per-team desired topology (roles,
networks) from the immutable version, the finalized reservation CIDRs, and the
explicit resource limits. Creation and validation are audited.

## 4. Strict provisioning scope policy (§2)

A provisioning-specific policy lives at `ExecutionTarget.scope_policy["provisioning"]`
(the SECP-002A discovery scope keys remain compatible and untouched). Strict
validation — applied only at **manifest generation** and future provisioning paths —
requires explicit allowlists/bounds and **rejects** empty lists, wildcards
(`*`, `any`, `0.0.0.0/0`), unrestricted ranges, or missing limits:

- `allowed_nodes`, `allowed_storage`, `allowed_bridges`, `allowed_templates`
  (non-empty, no wildcards);
- `vmid_range` (`{start, end}`, positive, `start < end`, bounded width);
- `max_teams`, `max_vms`, `max_containers`, `max_total_vcpu`, `max_total_memory_mb`,
  `max_total_disk_gb` (all present, positive where required);
- `allowed_cidr_reservations` (non-empty CIDRs; no `0.0.0.0/0`);
- `external_connectivity` (**default deny**; anything permissive is rejected).

## 5. Worker-only runner + fake (ADR-012)

`ProvisioningRunner` protocol: `validate`, `dry_run`, `apply`, `destroy`, `status`.
`FakeOpenTofuRunner` is the only implementation: deterministic operation/resource IDs
(hashes), deterministic dry-run change sets, idempotent apply/destroy, redacted
errors, durable fake state. No subprocess/network/provider imports.

### Durable runner state

`FakeOpenTofuRunner` accepts an optional `state_store: RunnerStateStore` at
construction.  When provided it is a `DbRunnerStateStore`, which queries
`ProvisioningOperation.idempotency_key` and returns the persisted terminal state
(`applied` or `destroyed`) from the operation's `status` and `result` columns.

On `apply()`, `destroy()`, and `status()` the runner checks its process-local
`_state` cache first; on a miss it falls through to the store.  A fresh runner
instance constructed with `DbRunnerStateStore(session)` therefore answers
`status(operation_ref)` correctly after a simulated worker restart — the
`ProvisioningOperation` row is the authoritative state, no new model is needed.

`DbRunnerStateStore` is read-only from the runner's perspective.  All writes to
`ProvisioningOperation` are performed by the worker execution layer only.

## 6. Durable provisioning operation lifecycle (§4)

`ProvisioningOperation` tracks a manifest's provisioning through a state machine:

```
manifest_generated → pending_approval → queued → dry_run_completed → applying → applied
                                                          │                        │
                                                          └────────► failed ◄──────┘
applied → destroy_queued → destroyed
```

Each operation has a **deterministic idempotency key** = `sha256(manifest_hash +
operation_kind)`, so retries are safe and a duplicate request maps to the same
operation. Every transition is audited. The fake runner's results (change set, apply
summary, destroy summary — all redacted, secret-free) are stored on the operation.

## 7. Safe integration path (§5)

- **Simulator deployment is unchanged.** No simulator code path is touched.
- **Target-bound plans remain refused by default** (`assert_deployment_eligible`).
- The fake runner is reachable **only** through an explicit provisioning-operation
  flow that requires: approved plan + pinned target id/hash + immutable validated
  manifest + valid finalized reservations + strict scope policy + the explicit
  `enable_fake_provisioning` setting (dev/test only; refused in production). Any
  missing precondition refuses (audited).
- The API cannot import runner/OpenTofu/provider code and cannot resolve secrets.

## 8. Explicit non-goals / placeholders

No real OpenTofu implementation, no OpenTofu/Terraform binary, no real Proxmox,
no real VM/container/network/storage/firewall, no secret resolution in this flow's
API path. SECP-002B-1 adds the first disposable isolated Proxmox lab through a
worker-only real OpenTofu runner behind this same seam and gate.
