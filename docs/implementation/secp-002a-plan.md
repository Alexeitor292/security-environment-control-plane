# SECP-002A — Implementation Plan

**Governing document:** [`docs/PROJECT_CHARTER.md`](../PROJECT_CHARTER.md)
**Design:** [`docs/architecture/secp-002a-proxmox-discovery.md`](../architecture/secp-002a-proxmox-discovery.md)

Small vertical slices, each independently testable. Legend: ✅ done · 🟡 partial ·
⬜ not started. Status reflects the intended end state for this milestone.

---

## Slice 0 — Documentation and ADRs ✅
Architecture, this plan, `docs/proxmox/safety-model.md`,
`docs/proxmox/read-only-discovery.md`, ADR-006…010, and a charter SECP-002
sub-phase clarification. Committed separately before code.

## Slice 1 — Generic observed inventory & topology ⬜
Rename `simulated_*` → `environment_network` / `environment_node` /
`environment_topology_edge` with generic provider-neutral columns. Update models,
`ResourcePort`, Simulator plugin, topology service, API responses, topology UI,
Alembic migration (data-preserving), and tests.

**AC:** existing simulator lifecycle + topology behavior unchanged; no
Proxmox-specific columns; migration applies on SQLite and PostgreSQL.
**Tests:** `test_generic_topology_migration.py`, updated isolation/reset/destroy
tests still green.

## Slice 2 — ExecutionTarget ⬜
`ExecutionTarget` model + `secret_ref` syntax validation + immutable config/hash +
service (register/list/get/disable) + plan pinning fields + permissions
(`target:manage`) + audit. Exercise gets optional `execution_target_id`.

**AC:** no plaintext secret can be persisted; immutable config; org-scoped;
DeploymentPlan pins target + config hash when present; simulator exercises work
with no target.
**Tests:** `test_execution_targets.py` (secret rejection, immutability, org scope,
plan pinning).

## Slice 3 — Provider inventory snapshots ⬜
`ProviderInventorySnapshot` + `ProviderInventoryResource` + service. Immutable
after completion; org-scoped; audit on lifecycle.
**Tests:** snapshot immutability, org-scope denial, no-secret-in-snapshot.

## Slice 4 — Network reservations & address-space policy ⬜
`AddressSpacePolicy` + `NetworkReservation` + reservation service (transactional,
overlap-free, release lifecycle).
**AC:** deterministic allocation; collision prevention on same target; concurrent
handling; release; cross-org denial; simulator unchanged.
**Tests:** `test_network_reservations.py`.

## Slice 5 — Plugin contract discovery extension ⬜
`DiscoveryRequest`, `DiscoveryResult`, `DiscoveredResource`,
`TargetValidationResult`, optional `DiscoveryProtocol`,
`UnsupportedCapabilityError`. No `apiVersion` bump.
**Tests:** `test_discovery_contract.py` (optional protocol, unsupported error).

## Slice 6 — Read-only Proxmox plugin ⬜
`plugins/proxmox/`: GET-only transport abstraction, scope filtering, normalization,
validate/health/discover/status only; apply/reset/destroy hard-fail with
`UnsupportedCapabilityError`. Worker/plugin only.
**Tests:** `test_proxmox_plugin.py` (GET-only, non-GET refused, normalization,
scope filter, unsupported capabilities), conformance via mock transport.

## Slice 7 — Worker-only secret resolution ⬜
`SecretResolver` abstraction + `EnvSecretResolver` (dev) + `FakeResolver` (tests).
Redacted errors, never persisted/logged.
**Tests:** `test_secret_resolution.py` (worker-only, redaction, fake resolver).

## Slice 8 — Temporal activation ⬜
`WorkflowStatus.queued`, durable workflow ids; `TemporalDispatcher` enqueues
deploy/reset/destroy/discover; discovery workflow; API queues, worker executes;
inline refuses real providers; simulator inline unchanged.
**Tests:** `test_temporal_dispatch.py`, `test_discovery_workflow.py`,
`test_inline_refuses_real_provider.py`.

## Slice 9 — API & UI Provider Targets ⬜
Routers for targets (list/register/get/disable), discovery request, snapshot view;
React Provider Targets pages with a read-only banner and "provisioning deferred"
notice. No secret-entry form.
**Tests:** API e2e for register + queued discovery (mock); frontend typecheck/build.

## Slice 10 — Boundary & proof tests + validation ⬜
Extend architecture-boundary test (api must not import provider client / HTTP libs
for providers / proxmox / OpenTofu / Terraform / Ansible / subprocess). Add the ten
required proof tests. Run the full validation battery.

## Runtime verification ⬜
Docker Compose up; verify simulator lifecycle unchanged; verify provider-target +
fake discovery via Temporal worker (mock provider, fake resolver); document in
`docs/verification/secp-002a-runtime-verification.md`. No real Proxmox.

## Correction pass

Merge-blocking review fixes applied after the initial slice:

- `ProviderCredential` is an opaque transient value object with explicit
  `reveal_secret()`, redacted string forms, no public secret field, and regression
  tests for JSON/Pydantic/FastAPI/logging/pickle/dict safety.
- Temporal dispatch uses a transactional outbox. API transactions create queued
  `WorkflowRun` plus durable outbox rows; a worker-side publisher submits only
  committed rows, records success/failure, and retries failed rows idempotently.
- CIDR reservations validate strict policy CIDRs/prefixes, reject overlapping
  policies, lock address-space rows per target during allocation, and retry
  uniqueness races without leaking raw `IntegrityError`.
- Discovery workflow linkage is a real foreign key from `WorkflowRun.snapshot_id`
  to `ProviderInventorySnapshot.id`; snapshot workflow ids are derived, not
  persisted twice.
- Proxmox real-target validation requires `https://`, rejects `verify_tls=false`,
  rejects unsupported config keys, and validates scope-policy shape.

---

## Required proof tests (assignment §Validation)

| # | Proof | Test |
| --- | --- | --- |
| 1 | No plaintext secret persisted via target APIs | `test_execution_targets.py` |
| 2 | API cannot import/invoke the Proxmox client | `test_architecture_boundary.py` |
| 3 | Discovery never performs a non-GET HTTP request | `test_proxmox_plugin.py` |
| 4 | Inline execution refuses the Proxmox plugin | `test_inline_refuses_real_provider.py` |
| 5 | Worker discovery records immutable snapshots + audit | `test_discovery_workflow.py` |
| 6 | Simulator lifecycle still passes unchanged | existing suites green |
| 7 | Generic topology migration preserves behavior | `test_generic_topology_migration.py` |
| 8 | CIDR reservations prevent collision per target | `test_network_reservations.py` |
| 9 | Cross-org access to targets/inventory/reservations denied | per-slice tests |
| 10 | No real endpoint/credential in any file | `test_no_real_endpoints.py` |

Additional correction-pass proofs: no Temporal submission before commit; rollback
creates no external work; publish failure remains retryable; outbox retry uses the
same workflow id; discovery outbox is invisible before snapshot/workflow commit;
dangling discovery workflow snapshot references are rejected by ORM and migration
tests; Proxmox real-target validation rejects unsafe TLS/config/scope.

## Build order
0 → 1 → 5 → 7 → 6 (contract+resolver before plugin) → 2 → 3 → 4 → 8 → 9 → 10 →
runtime verification.
