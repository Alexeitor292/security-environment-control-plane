# ADR-001 — Monorepo for the control plane

- **Status:** Accepted
- **Date:** 2026-06-29
- **Milestone:** SECP-001
- **Deciders:** Implementation engineering
- **Related:** Charter §15, §18; ADR-003 (plugin contract), ADR-005 (workflow boundary)

## Context

SECP-001 spans a React frontend, a FastAPI API, a Python worker, shared contracts
(scenario schema, plugin API), and a reference plugin. These components share types
and contracts and must evolve together (e.g., a scenario-schema bump must update the
API validator, the worker, and the UI in one reviewable change). The charter mandates
"keep every integration replaceable" and "versioned contracts," which only works if
the contract and its consumers move atomically during early development.

Options considered:

1. **Polyrepo** — one repository per component, contracts published as packages.
2. **Monorepo** — all components in one repository with internal packages.

## Decision

Use a **single monorepo** with the layout in the charter/assignment:
`apps/{web,api,worker}`, `contracts/{scenario-schema,plugin-api}`, `plugins/simulator`,
`infra/dev`, `docs/`, `tests/`.

- Python components (`apps/api`, `apps/worker`, `contracts/*` Python packages,
  `plugins/simulator`) form a single Python project managed with **uv** and a shared
  `pyproject.toml`, installed as editable local packages. This lets the API, worker,
  and plugin import the same `secp_*` packages without publishing.
- The web app is an isolated Node/Vite project under `apps/web`.
- CI builds and tests all components from the root.

## Consequences

**Positive**

- Atomic cross-cutting changes (contract + all consumers in one PR).
- One dependency lockfile per ecosystem; consistent tooling (ruff, mypy, pytest).
- Simple local developer experience; one clone, one `docker compose up`.

**Negative / risks**

- A monorepo can grow coupling. Mitigation: contracts live in dedicated packages with
  explicit versioned APIs (ADR-003), and the core never imports provider-specific
  plugin code — it depends only on the contract package.
- CI runs grow over time. Mitigation: path-aware jobs can be added later; not needed
  at SECP-001 scale.

**Replaceability**

A plugin or app can later be extracted to its own repo by publishing the contract
package it depends on; nothing in the design assumes co-location beyond build
convenience.
