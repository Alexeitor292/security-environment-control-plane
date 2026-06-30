# SECP-001 — Implementation Plan

**Governing document:** [`docs/PROJECT_CHARTER.md`](../PROJECT_CHARTER.md)
**Design:** [`docs/architecture/secp-001-design.md`](../architecture/secp-001-design.md)

This plan decomposes SECP-001 into small **vertical slices**. Each slice lists its
goal, the work, acceptance criteria, and the tests that prove it. Slices are ordered
so that each one is independently demonstrable and builds on the previous.

Legend for status: ✅ done · 🟡 partial / placeholder · ⬜ not started.

---

## Slice 0 — Documentation and decisions ✅

**Goal:** Lock architecture decisions before code.

- Design doc, this plan, ADR-001…005.

**Acceptance criteria**

- AC0.1 Design doc covers every topic the assignment requires.
- AC0.2 Five ADRs exist and are internally consistent with the design.

**Tests:** documentation review (no automated test). Committed separately.

---

## Slice 1 — Monorepo + dev stack 🟡

**Goal:** A clean, runnable foundation.

- Monorepo layout (`apps/`, `contracts/`, `plugins/`, `infra/`, `docs/`, `tests/`).
- Docker Compose dev stack: postgres, minio, keycloak (OIDC dev), temporal + UI,
  api, worker, web.
- `.env.example`, README with local-dev instructions, health checks, dev-only
  credentials clearly labeled unsafe.

**Acceptance criteria**

- AC1.1 `docker compose config` validates.
- AC1.2 `.env.example` exists; no real secrets committed anywhere.
- AC1.3 API and worker images build from a shared Python project; web from Node.
- AC1.4 Health endpoints exist for api (`/health`) and worker.

**Tests:** `tests/test_compose_config.py` (compose file parses, only dev-safe
services, no committed secrets). API `test_health.py`.

> 🟡 Note: full `docker compose up` requires pulling images; not exercised in CI by
> default. Compose file is validated structurally.

---

## Slice 2 — Domain model + migrations + audit ✅

**Goal:** Persist the core domain with correct invariants.

- SQLAlchemy models + Alembic migration for: Organization, User, Role, Team,
  EnvironmentTemplate, EnvironmentVersion, Exercise, EnvironmentInstance,
  DeploymentPlan, WorkflowRun, Plugin, Artifact, AuditEvent, and the simulated-
  resource tables (SimulatedNetwork, SimulatedNode, SimulatedTopologyEdge).
- Organization scoping on all tenant resources.
- Audit-event service: every mutation writes an immutable AuditEvent.

**Acceptance criteria**

- AC2.1 EnvironmentVersion is immutable after creation (spec/hash/number).
- AC2.2 Every mutation creates an AuditEvent.
- AC2.3 Cross-organization access is rejected.
- AC2.4 Migration applies cleanly to an empty database.

**Tests:**
`test_environment_version_immutable.py`,
`test_audit_event_created.py`,
`test_org_scoping.py`,
migration smoke test (`test_migrations.py`).

---

## Slice 3 — Lifecycle state machine ✅

**Goal:** A single, authoritative lifecycle with rejected invalid transitions.

- States: draft, validated, planned, awaiting_approval, approved, deploying, running,
  resetting, destroying, destroyed, failed.
- Central transition table; `transition()` rejects illegal moves and audits valid ones.

**Acceptance criteria**

- AC3.1 Permitted transitions succeed and are audited.
- AC3.2 Illegal transitions raise `InvalidTransitionError` and change nothing.

**Tests:** `test_lifecycle_transitions.py` (parametrized over legal + illegal moves).

---

## Slice 4 — Scenario schema + web-breach-101 ✅

**Goal:** Versioned declarative environment schema, validated by tests.

- `contracts/scenario-schema/v1alpha1`: JSON Schema + Pydantic models.
- `docs/scenarios/web-breach-101.yaml`: 2 teams, strict isolation, Kali attacker,
  Ubuntu web server, one isolated team network, Wazuh telemetry, CTFd validation,
  objectives, one vulnerability-pack reference, required plugins.
- `docs/vulnerability-packs/weak-ssh.yaml`: reference pack metadata.

**Acceptance criteria**

- AC4.1 `web-breach-101.yaml` validates against the schema.
- AC4.2 Malformed definitions are rejected with clear errors.
- AC4.3 Breaking schema changes require a new version (documented in ADR-002).

**Tests:** `test_scenario_schema.py` (valid sample passes; mutated samples fail;
required fields enforced).

---

## Slice 5 — Plugin contract + Simulator plugin ✅

**Goal:** A versioned plugin contract and a reference implementation.

- `contracts/plugin-api/v1`: `PluginProtocol` with validate/plan/apply/status/
  reset/destroy/health + typed result models.
- `plugins/simulator`: implements the protocol; writes only simulated rows.
- Conformance test suite that any plugin must pass, run against the simulator.

**Acceptance criteria**

- AC5.1 Simulator passes the contract conformance suite.
- AC5.2 `plan` is deterministic for a given version + targets.
- AC5.3 `apply` creates simulated networks/nodes/edges per instance.
- AC5.4 `reset` is idempotent (baseline identical after repeated reset).
- AC5.5 `destroy` is idempotent (no error on already-destroyed).
- AC5.6 Simulator creates **no** real infrastructure (only `simulated_*` rows).

**Tests:**
`test_plugin_conformance.py`,
`test_simulator_plan_apply.py`,
`test_reset_idempotent.py`,
`test_destroy_idempotent.py`.

---

## Slice 6 — Approval gate + workflow boundary ✅

**Goal:** Plans are approved before apply; execution runs through the worker seam.

- Plan generation from an immutable version (deterministic, stores version hash).
- Approval records who/when/hash; apply refused unless approved.
- `WorkflowDispatcher` interface; `InlineDispatcher` (default) + `TemporalDispatcher`
  scaffold. WorkflowRun records persisted for deploy/reset/destroy.

**Acceptance criteria**

- AC6.1 Apply on an unapproved plan is refused and audited.
- AC6.2 Apply on an approved plan proceeds and creates instances/resources.
- AC6.3 Each team assignment yields its own EnvironmentInstance.
- AC6.4 WorkflowRun records exist for each executed workflow.

**Tests:** `test_approval_gating.py`, `test_per_team_isolation.py`,
`test_workflow_runs.py`.

---

## Slice 7 — Vertical-slice API endpoints ✅

**Goal:** Drive the full controlled flow over HTTP.

Flow: create template → create immutable version → validate → generate plan →
approve plan → start simulated exercise → per-team topologies → reset one team →
destroy exercise → audit log.

**Acceptance criteria**

- AC7.1 Each step has an endpoint; the happy path runs end to end in a test.
- AC7.2 Topology endpoint returns React-Flow-shaped per-team graphs.
- AC7.3 Audit log endpoint returns the chain of mutations for the exercise.

**Tests:** `test_vertical_slice_e2e.py` (drives the whole flow through the FastAPI
TestClient).

---

## Slice 8 — Frontend 🟡

**Goal:** Professional, minimal UI for the flow.

- Login placeholder, dashboard, template/version list, definition editor (structured +
  raw YAML preview), plan approval screen, exercise detail, per-team topology (React
  Flow), audit log.

**Acceptance criteria**

- AC8.1 App builds and type-checks.
- AC8.2 Screens render the lifecycle status clearly and call the API client.
- AC8.3 Topology view uses React Flow with per-team separation.

**Tests:** type-check + build in CI; a smoke component test for the API client.
> 🟡 Styling intentionally minimal; information architecture prioritized.

---

## Slice 9 — CI ✅

**Goal:** Automated quality gates.

- Format (ruff format / prettier), lint (ruff / eslint), type-check (mypy / tsc),
  backend tests (pytest), frontend build, schema validation, dependency/security
  scan (pip-audit / npm audit).

**Acceptance criteria**

- AC9.1 CI workflow runs all gates on push/PR.
- AC9.2 Backend test job is hermetic (SQLite, no external services).

**Tests:** the workflow itself; jobs are the tests.

---

## Test matrix (assignment-required coverage)

| Required coverage | Test |
| --- | --- |
| Immutable environment versions | `test_environment_version_immutable.py` |
| Invalid lifecycle transitions | `test_lifecycle_transitions.py` |
| Approval gating | `test_approval_gating.py` |
| Per-team isolation | `test_per_team_isolation.py` |
| Simulator plan/apply behavior | `test_simulator_plan_apply.py` |
| Reset idempotency | `test_reset_idempotent.py` |
| Destroy idempotency | `test_destroy_idempotent.py` |
| Audit-event creation | `test_audit_event_created.py` |
| Schema validation for web-breach-101 | `test_scenario_schema.py` |
| Full controlled flow | `test_vertical_slice_e2e.py` |

---

## Sequencing summary

Slices 0→2→3 establish state and invariants. 4 and 5 are parallelizable content +
contract work. 6 wires the gate and the worker seam. 7 exposes it over HTTP. 8 puts a
face on it. 9 guards it all. The build order in this run follows: 0, 1, 2, 3, 4, 5, 6,
7, 9 (CI), 8 (frontend), then a full local check pass.
