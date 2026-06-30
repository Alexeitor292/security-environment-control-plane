# Security Environment Control Platform

An enterprise-grade, AI-native control plane for creating, operating, observing,
validating, resetting, and reporting on controlled security environments.

> **Status:** SECP-001 — Control Plane Foundation. This milestone runs entirely
> against a **local Docker Compose** dev stack and a **simulated** infrastructure
> plugin. It does **not** touch real infrastructure (no Proxmox/VMware/cloud/
> OpenTofu/Ansible/Wazuh/CTFd). See [`docs/PROJECT_CHARTER.md`](docs/PROJECT_CHARTER.md).

## What this is

The control plane is the source of truth for organizations, teams, environment
templates, **immutable environment versions**, deployment plans, approvals,
workflow runs, topology, and an immutable audit trail. Underlying infrastructure
is an execution target reached only through **versioned plugins**, never directly
from the API.

Read these before changing anything:

- [`docs/PROJECT_CHARTER.md`](docs/PROJECT_CHARTER.md) — governing product/architecture charter
- [`docs/architecture/secp-001-design.md`](docs/architecture/secp-001-design.md) — SECP-001 design
- [`docs/implementation/secp-001-plan.md`](docs/implementation/secp-001-plan.md) — vertical slices & acceptance criteria
- [`docs/adr/`](docs/adr/) — architecture decision records

## Repository layout

```
apps/
  web/        React + TypeScript application (Vite, React Flow)
  api/        FastAPI control-plane API (secp_api)
  worker/     Workflow worker boundary (secp_worker)
contracts/
  scenario-schema/  Versioned declarative environment schema (secp_scenario_schema)
  plugin-api/       Versioned plugin contracts (secp_plugin_api)
plugins/
  simulator/  Simulated infrastructure plugin (secp_plugin_simulator)
infra/
  dev/        Docker Compose and local configuration
docs/         Charter, ADRs, architecture, scenarios, vulnerability packs
tests/        Cross-cutting tests
```

The Python components form a single project (see [ADR-001](docs/adr/ADR-001-monorepo.md))
managed with [uv](https://docs.astral.sh/uv/).

## Local development — backend & tests (no Docker required)

The backend and full test suite run with **zero external services** (SQLite +
inline workflow dispatch).

```bash
# 1. Create the environment and install the project (editable) with dev tools.
uv venv --python 3.11
uv pip install -e ".[dev]"

# 2. Run the test suite.
uv run pytest

# 3. Lint / format / type-check.
uv run ruff check .
uv run ruff format --check .
uv run mypy apps contracts plugins
```

Run the API directly (uses SQLite, seeds a dev org/admin and the Web Breach 101 sample):

```bash
uv run uvicorn secp_api.main:app --reload --port 8080
# OpenAPI docs: http://localhost:8080/docs
```

## Local development — full stack (Docker Compose)

The dev stack contains **only development-safe services**. All default
credentials are **DEVELOPMENT ONLY and UNSAFE FOR PRODUCTION** — see
[`infra/dev/README.md`](infra/dev/README.md).

```bash
cp .env.example .env          # development-only placeholders; never commit .env
cd infra/dev
docker compose up --build
```

| Service | URL | Notes |
| --- | --- | --- |
| Web app | http://localhost:5173 | React UI |
| Control-plane API | http://localhost:8080/docs | FastAPI |
| Keycloak (OIDC dev) | http://localhost:8081 | dev realm, dev credentials |
| Temporal UI | http://localhost:8088 | durable workflow UI |
| MinIO console | http://localhost:9001 | object storage |
| PostgreSQL | localhost:5432 | system of record |

See [`infra/dev/README.md`](infra/dev/README.md) for credentials, health checks,
and the workflow dispatch mode (`inline` default vs. `temporal`).

## The controlled flow (SECP-001 vertical slice)

```
Create Template → Create Immutable Version → Validate → Generate Plan →
Approve Plan → Start Simulated Exercise → Per-Team Topologies →
Reset One Team → Destroy Exercise → View Audit Log
```

Every step is approval-gated where required, every mutation is audited, and all
execution is simulated. See the design doc for the boundaries that make this safe.

## Safety

This repository follows strict scope limits for SECP-001: no real infrastructure,
no production secrets, no privileged execution from the API. Secrets are never
committed; `.env` is git-ignored and only `.env.example` (placeholders) is tracked.
