# ADR-005 — Workflow engine boundary

- **Status:** Accepted
- **Date:** 2026-06-29
- **Milestone:** SECP-001
- **Deciders:** Implementation engineering
- **Related:** Charter §5 (Layer 4), §15, Invariants 6, 7, 14, 15; ADR-003, ADR-004

## Context

Charter Invariants 6 and 7 require that the API never execute privileged infrastructure
actions and that such actions occur **only** through isolated workflow workers and
plugins. Layer 4 (orchestration) must support long-running operations and resume safely
after worker failure (Charter §5). The charter names **Temporal or equivalent** as the
durable workflow engine (§15).

Tension: SECP-001 must be runnable and fully testable without standing up Temporal, and
the only "execution" is the Simulator writing rows. We need the production-shaped
boundary *and* a hermetic, dependency-free test/demo path.

## Decision

Introduce a `WorkflowDispatcher` interface between the API and execution. The API only
ever *dispatches*; it never executes plugin operations.

```
API ──dispatch(workflow, input)──► WorkflowDispatcher
                                      ├─ InlineDispatcher   (dev/test default)
                                      └─ TemporalDispatcher (production-shaped)
```

- **Orchestration logic** (deploy / reset / destroy) lives in a single module shared by
  both dispatchers, so the *same* code runs whether inline or on Temporal. It calls the
  plugin contract (ADR-003) and writes `WorkflowRun` records and audit events.
- **`InlineDispatcher`** runs the orchestration synchronously in-process. It is the
  default for tests and the local demo. This is safe **only** because the Simulator's
  side effects are limited to simulated rows; it is explicitly a development
  convenience and is documented as such. It still goes through the approval gate
  (ADR-004) and the full lifecycle state machine.
- **`TemporalDispatcher`** enqueues the workflow on Temporal; the separate `apps/worker`
  process hosts the workflows/activities and executes durably with retries and
  recovery. This is the path that real (privileged) plugins will use.
- Selection is via `WORKFLOW_DISPATCH_MODE` (`inline` | `temporal`). The dev compose
  stack runs Temporal + UI + worker so the production-shaped path is demonstrable; the
  default app mode is `inline` so the stack and tests work with zero Temporal coupling.
- The **approval gate and lifecycle checks live in the service layer that both
  dispatchers invoke**, so neither path can bypass safety controls.

## Consequences

**Positive**

- The API stays free of privileged execution (Invariants 6, 7) regardless of mode.
- Tests and the demo run with no external workflow engine; the durable path is wired
  and demonstrable in compose.
- Reset/destroy idempotency (Invariants 14, 15) is implemented once in shared
  orchestration and holds for both dispatchers.

**Negative / risks**

- Two execution paths risk divergence. Mitigation: both call the *same* orchestration
  module; the Temporal layer is a thin durability wrapper, not a reimplementation.
- Inline execution is synchronous and not durable. Accepted for SECP-001 (simulated,
  short operations); production uses Temporal.

**Placeholder**

- Durable-execution hardening (signals for cancel, heartbeats, retry/backoff policy,
  workflow versioning) is wired structurally but tuned in SECP-002+. The Temporal
  worker is included and runnable; end-to-end Temporal execution is not exercised in
  CI.
