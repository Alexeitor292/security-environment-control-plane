# ADR-010 — Temporal dispatch activation

- **Status:** Accepted
- **Date:** 2026-06-30
- **Milestone:** SECP-002A
- **Supersedes (in part):** ADR-005 placeholder ("Temporal wired but not operational")
- **Related:** Charter §5 (Layer 4), Invariants 6, 7; ADR-005, ADR-006, ADR-007

## Context

ADR-005 introduced a `WorkflowDispatcher` seam with an `InlineDispatcher` (dev/test
default, Simulator only) and a `TemporalDispatcher` *scaffold that raised
"unavailable."* SECP-002A needs the durable path to actually work before any real
provider action is permitted: the API must queue work and the worker must perform
state-changing plugin actions durably.

## Decision

Activate the Temporal path while preserving the inline Simulator-only dev mode:

- Add `WorkflowStatus.queued` and durable workflow identifiers on `WorkflowRun`.
- `TemporalDispatcher` **enqueues** supported workflows (deploy, reset, destroy, and
  the new **discover**) on Temporal instead of raising. It constructs a typed
  workflow request (workflow id, args) — testable without a live server.
- **API queues, worker executes.** For the Temporal path the API creates a
  `WorkflowRun(status=queued)` and enqueues; the worker performs the plugin actions.
  The inline path (Simulator only) still runs orchestration in-process.
- `InlineDispatcher` **refuses any non-Simulator plugin** (identity-based allowlist
  from the SECP-001 hardening). Real providers therefore require Temporal.
- A new **provider discovery workflow** runs discovery in the worker; the API never
  calls the Proxmox plugin and never resolves its secret reference.
- Secret resolution happens in the worker, just-in-time (ADR-007).

### Correction pass: transactional outbox

Independent review identified a race in the original wording: submitting to
Temporal inside the API transaction could let a fast worker read uncommitted state,
or let Temporal accept work that later rolled back. The final SECP-002A design is
therefore:

- The API transaction atomically creates the queued `WorkflowRun`, any required
  snapshot/lifecycle state, and a durable `workflow_dispatch_outbox` row.
- The API never calls Temporal or provider plugins from that transaction.
- A worker-side outbox publisher reads only committed `pending`/`failed` outbox
  rows and submits them to Temporal.
- Successful publish marks the outbox row `submitted`, records `submitted_at`, and
  keeps the durable workflow id on `WorkflowRun`.
- Publish failure marks the row `failed`, increments `attempts`, records a
  redacted `last_error`, and remains retryable.
- Workflow ids are deterministic per workflow run (`<kind>-<workflow_run_id>`).
  Retrying a publisher pass submits the same logical Temporal workflow; an
  already-started workflow id is treated as idempotent success.
- Discovery linkage is canonical from `WorkflowRun.snapshot_id` to
  `ProviderInventorySnapshot.id` via a real foreign key. Snapshots do not persist a
  duplicate mutable workflow id; API responses derive it from the relationship.

Selection stays via `SECP_WORKFLOW_DISPATCH_MODE` (`inline` | `temporal`). Discovery
of a real provider requires `temporal` mode in normal operation.

## Consequences

**Positive:** the durable path is real and demonstrable on the local Temporal
service (with Simulator + mock provider); the API never performs privileged work;
the inline dev experience is unchanged.

The correction pass also guarantees that uncommitted API state cannot be observed
by a Temporal worker and that rollback creates no external Temporal work.

**Negative / risks:** two execution paths risk divergence. Mitigated by both paths
sharing the same orchestration/worker logic; Temporal is a durability wrapper, not a
reimplementation. End-to-end Temporal with a *real* provider is **not** run in
SECP-002A — only Simulator and a fake/mock provider.

**Placeholder:** retry/heartbeat/cancellation tuning and workflow versioning remain
minimal; hardened in later sub-phases.

Outbox retry is durable in SECP-002A; backoff policy, cancellation semantics, and
workflow versioning remain later hardening work.
