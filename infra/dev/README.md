# Local development stack (SECP-001)

This Docker Compose stack runs the full platform locally with **development-safe
services only**. It does **not** touch any real infrastructure. Execution is
simulated by the Simulator Plugin.

> ⚠️ **All credentials in `.env.example` are development-only placeholders and are
> UNSAFE FOR PRODUCTION.** Never put real secrets in `.env`. `.env` is git-ignored.

## Prerequisites

- Docker Engine + Docker Compose v2
- Ports free: 5432, 5173, 7233, 8080, 8081, 8088, 9000, 9001

## Start

```bash
cp ../../.env.example ../../.env     # review the dev-only values first
docker compose up --build
```

## Services

| Service | URL / port | Purpose | Health |
| --- | --- | --- | --- |
| `postgres` | localhost:5432 | system of record | `pg_isready` |
| `minio` | http://localhost:9001 (console), :9000 (S3) | artifact object storage | `mc ready` |
| `keycloak` | http://localhost:8081 | OIDC dev identity provider | `/health/ready` |
| `temporal` | localhost:7233 | durable workflow engine | `tctl cluster health` |
| `temporal-ui` | http://localhost:8088 | workflow UI | — |
| `api` | http://localhost:8080/docs | control-plane API | `GET /health` |
| `worker` | — | workflow worker boundary | process |
| `web` | http://localhost:5173 | React UI | — |

The `api` service runs `alembic upgrade head` before starting, so the schema is
migrated on boot.

## Default development credentials (UNSAFE FOR PRODUCTION)

These come from `.env` (placeholders in `.env.example`):

- **PostgreSQL**: `secp` / `dev-only-postgres-password-change-me`
- **MinIO**: `secp-dev` / `dev-only-minio-password-change-me`
- **Keycloak admin**: `admin` / `dev-only-keycloak-password-change-me`
- **Keycloak dev user**: `dev-admin` / `dev-only-admin-password-change-me`
  (realm `secp`, role `platform-admin`)

## Workflow dispatch mode

`SECP_WORKFLOW_DISPATCH_MODE` selects how deploy/reset/destroy execute (ADR-005):

- `inline` (default): the API runs orchestration in-process. Zero Temporal
  coupling; the easiest way to demo the controlled flow. The `worker` service
  idles (it stays up for a stable Compose target).
- `temporal`: the API enqueues durable workflows; the `worker` process executes
  them via Temporal. This is the production-shaped path.

Both paths run the **same** orchestration code and pass through the approval gate.

## Authentication in dev

The API accepts the Keycloak dev realm. For convenience it also supports a
**dev fallback principal** (`SECP_AUTH_DEV_MODE=true`) so the stack is usable
before wiring a full OIDC login. The fallback is automatically refused when
`SECP_APP_ENV=production`. Full OIDC token verification is a documented SECP-001
placeholder (see the design doc §11).

## Safety notes

- No real Proxmox/VMware/Hyper-V/cloud/OpenTofu/Ansible/Wazuh/CTFd is contacted.
- The API never executes privileged infrastructure actions (Charter Invariants
  6, 7). Plugins run only in the worker boundary.
- Tear down with `docker compose down -v` (the `-v` also removes the dev volumes).
