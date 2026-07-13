# Security Environment Control Platform

An enterprise-grade, AI-native control plane for creating, operating, observing,
validating, resetting, and reporting on controlled security environments.

> **Status:** The **simulator remains the only complete deployment lifecycle** — its
> effects are database records, not real infrastructure. Beyond it, the platform now
> includes provider foundations, **controlled worker-owned read-only Proxmox discovery**,
> target onboarding, governance surfaces, and durable topology authoring. **Real Proxmox
> provisioning and real OpenTofu execution remain sealed.** **OIDC authentication is
> implemented** — backend bearer verification (OIDC-A / ADR-017), browser Authorization
> Code + PKCE login (OIDC-B / ADR-018), and production deployment guardrails, a token-free
> preflight, and operations runbooks (OIDC-C / ADR-019). **This does not make the whole
> platform production-ready:** pre-provisioned internal identities are still required,
> same-origin production deployment is the locked model, the development stack remains
> unsafe for production, real provisioning remains sealed, and the complete real
> disposable-lab lifecycle is incomplete. See
> [`docs/PROJECT_CHARTER.md`](docs/PROJECT_CHARTER.md) (governing charter),
> [`docs/STATUS.md`](docs/STATUS.md) (detailed current-capability ledger), and
> [`docs/runbooks/oidc-production.md`](docs/runbooks/oidc-production.md).

## What this is

The control plane is the source of truth for organizations, teams, environment
templates, **immutable environment versions**, deployment plans, approvals,
workflow runs, topology, and an immutable audit trail. Underlying infrastructure
is an execution target reached only through **versioned plugins**, never directly
from the API.

Read these before changing anything:

- [`docs/PROJECT_CHARTER.md`](docs/PROJECT_CHARTER.md) — governing product/architecture charter
- [`docs/STATUS.md`](docs/STATUS.md) — current-capability ledger (what is implemented, simulated, sealed, or not yet built)
- [`docs/adr/`](docs/adr/) — architecture decision records
- [`docs/architecture/secp-001-design.md`](docs/architecture/secp-001-design.md) — SECP-001 foundational design (historical)
- [`docs/implementation/secp-001-plan.md`](docs/implementation/secp-001-plan.md) — SECP-001 vertical slices & acceptance criteria (historical)

## Repository layout

```
apps/
  web/        React + TypeScript application (Vite, React topology workspace)
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

## Current flows

The platform has several **separate** lifecycle stages. An earlier stage passing never
implies a later one, and only the simulator flow runs a complete deployment. See
[`docs/STATUS.md`](docs/STATUS.md) for the exact status of each.

### A. Complete simulator flow (the only complete deployment lifecycle)

```
Create Immutable EnvironmentVersion → Generate Deterministic Plan → Explicit Approval →
Simulator Execution → Per-Team Topology → Reset / Destroy → Audit
```

Every step is approval-gated where required and every mutation is audited. All effects are
simulated database records — no real infrastructure.

### B. Topology-authoring flow

```
Local draft → Saved immutable revision → Validation → Submission → Approval decision → STOP
```

Each transition is separately permissioned and audited. **Approval is a decision only.**
Publication to a canonical `EnvironmentVersion` and plan generation are **future, separate
transitions** — an approved topology revision is not yet a published version and does not
generate a deployment plan.

### C. Controlled live read-only discovery flow

```
Target onboarding / eligibility → Bootstrap & worker-bundle readiness →
Separate live-read authorization → Worker admission & exact endpoint binding →
Fixed read-only probes → Immutable evidence / candidate plan →
Optional exact-plan approval → STOP
```

This path is **sealed by default** and reachable only through the reviewed, deployment-local,
worker-owned profile once every gate passes (see [`docs/STATUS.md`](docs/STATUS.md) §E). It is
**read-only**: it never implies deployment or mutation, and its candidate plans are
non-executable.

## Safety

The control plane performs no privileged infrastructure actions; execution is dispatched to
the isolated worker boundary, and plugins are reached only through versioned contracts.
**Real Proxmox provisioning and real OpenTofu execution remain sealed**, controlled live
read-only discovery is fail-closed and off by default, and **no UI or API approval alone
activates infrastructure execution**. Secrets are never committed; `.env` is git-ignored and
only `.env.example` (placeholders) is tracked. See [`docs/STATUS.md`](docs/STATUS.md) for the
exact boundary between what is simulated, sealed, and not yet implemented.
