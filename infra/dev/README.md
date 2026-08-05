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

## Range-capable worker (opt-in)

The default `worker` service **cannot execute a range**. It connects to Temporal, accepts a range
operation, and then refuses at the seal, because the base service passes no `SECP_RANGE_LOCAL_DOCKER`
and mounts no Docker socket. That is correct behaviour and it is also unusable out of the box, so
acceptance runs used to start a worker by hand on the host instead. `docker-compose.range.yml`
replaces that workaround.

> ⚠️ **Docker socket access is root-equivalent on the host.** The overlay bind-mounts
> `/var/run/docker.sock` into the worker. Anything that can talk to that socket can start a
> container that mounts the host filesystem and read, modify or delete any file on the host as root
> — regardless of the worker running as the unprivileged uid 10001. Use it on a development machine
> you are willing to hand root to, and nowhere else. It is refused in production regardless
> (`range_local_docker_enabled` is false when `SECP_APP_ENV=production`), and no production
> composition references it.

**One command**, run from `infra/dev`:

```bash
docker compose -f docker-compose.yml -f docker-compose.range.yml \
  --env-file ../../.env up -d --build
```

`--env-file ../../.env` is **required**. `docker compose` resolves a relative `.env` against its own
project directory (`infra/dev`), never the repo root — omit the flag and every variable resolves
blank, after which Temporal tries to reach PostgreSQL as user `temporal` and the stack fails in a way
that does not name the cause.

What the overlay changes:

| | |
| --- | --- |
| `worker` | builds `Dockerfile.range-worker` (the worker image **plus the `docker` CLI**), sets `SECP_RANGE_LOCAL_DOCKER=true`, mounts the Docker socket, waits for Temporal to be healthy |
| `api` | switches to `temporal` dispatch **only**. It gets **no socket** — the API dispatches range work, it never constructs or runs a provider (Charter Invariants 6/7, ADR-005) |
| `postgres` | republished on host **15432** (see below) |

Both services move to `SECP_WORKFLOW_DISPATCH_MODE=temporal` because `InlineDispatcher` refuses range
operations outright — there is no inline-safe range provider — so on the repo default (`inline`) a
range deploy fails at dispatch before the worker is ever consulted.

The overlay **overrides** `worker` rather than adding a second, profile-gated service: two workers on
the `secp-orchestration` task queue would have Temporal hand roughly half of all range operations to
the socketless one, which reads as an intermittent range bug rather than a configuration error.

### Things that cost an hour if you do not know them

- **A native host PostgreSQL service may own port 5432.** Docker reports the compose postgres as
  published there, the native service is what actually answers, and host-side connections fail
  `password authentication failed` with correct credentials while the *same* credentials work inside
  the container. The overlay therefore republishes on `15432` by default (`!override`, because
  Compose merges `ports` by concatenation and would otherwise keep the conflicting binding). Nothing
  in the stack depends on the host-side port — every service reaches the database at `postgres:5432`
  over the compose network. Set `SECP_DEV_POSTGRES_HOST_PORT=5432` to restore the base mapping.
- **On a native Linux Engine the socket is usually owned by a `docker` group**, not root. Set
  `SECP_RANGE_DOCKER_GID` to the output of `stat -c %g /var/run/docker.sock`; the default `0` matches
  Docker Desktop, where the socket is `root:root` mode `0660`.
- **In Git Bash on Windows, `docker run -v /var/run/docker.sock:...` fails** with
  `mkdir C:\Program Files\Git\var: Access is denied` — MSYS rewrites the path. Prefix the command
  with `MSYS_NO_PATHCONV=1`. Compose files are unaffected.

### Verifying the worker is really range-capable

```bash
docker exec secp-dev-worker-1 python -c "
from secp_api.config import get_settings
from secp_worker.range import get_provider
print('seal open:', get_settings().range_local_docker_enabled)
print('daemon   :', get_provider('local_docker').health())
"
```

Ranges are published on the **host's** loopback (`127.0.0.1:<ephemeral>`), never `0.0.0.0` —
intentionally vulnerable software is never offered to the LAN. Browse a deployed component at the
`host_port` reported by `GET /api/v1/ranges/{id}/resources`.

## Authentication in dev

The API performs **strict OIDC bearer-token verification** (ADR-017). A request with
`Authorization: Bearer <access-token>` is accepted only when the token is RS256-signed, its signature
verifies against the configured issuer's JWKS, its `iss` exactly matches `SECP_OIDC_ISSUER`, the
`SECP_OIDC_AUDIENCE` audience is present, it is unexpired, and its exact `sub` maps to a
**pre-provisioned** `app_user.subject`. Organization and permissions come from the database; token
roles/groups/email grant nothing; there is no just-in-time user creation. An invalid token is a
closed `401 {"error":{"code":"unauthenticated"}}` (a `503 authentication_unavailable` when the IdP's
discovery/JWKS is unreachable) — never a fallback.

For convenience the stack also supports a **dev fallback principal** (`SECP_AUTH_DEV_MODE=true`),
honored **only** on a request that carries **no** `Authorization` header and **only** in
non-production (automatically refused when `SECP_APP_ENV=production`). The dev Keycloak realm ships an
`secp-api` audience mapper and a deterministic dev-admin subject so a real dev token maps to the same
seeded user as the fallback.

**Interactive browser login (Authorization Code + PKCE) is implemented** (ADR-018 / OIDC-B). The web
app reads the public, secret-free `GET /api/v1/auth/config`, runs the code + PKCE (S256) flow through
the public `secp-web` client (no secret) via `oidc-client-ts`, and sends the resulting **access
token** as `Authorization: Bearer` to the API. `/api/v1/me` is the authoritative browser identity;
tokens are session-scoped only (no localStorage/DB persistence, no `offline_access`). The dev Keycloak
issuer differs by host (`keycloak:8080` in-container vs `localhost:8081` in the browser); configure
`SECP_OIDC_ISSUER` to exactly match the `iss` of the tokens you verify. OIDC-C production
deployment/runbook work remains.

### Local login / logout

Open the web app and choose **Sign in with SSO** (OIDC mode) — you are redirected to Keycloak, sign in
with the dev account, and are returned to the app; or **Continue as dev-admin** (dev-fallback mode).
Sign out from the sidebar **Sign out** control, which clears the local session and (when the provider
supplies an end-session endpoint) redirects through Keycloak logout. Tokens are never displayed.

### Provisioning a user's subject

Create the `app_user` row out of band (no JIT provisioning) and set `app_user.subject` to the IdP's
exact `sub` for that user; assign roles via `user_role_assignment`. Rotating the IdP's signing keys
needs no SECP change — the verifier refreshes JWKS once when it sees an unknown `kid`.

### Dev Keycloak smoke test (Docker)

The `secp-web` browser client requires PKCE S256 and disables the direct-access (password) grant, so a
smoke test runs the Authorization Code + PKCE flow (browser, or a scripted code exchange with a PKCE
S256 `code_challenge` and the exact `/auth/callback` redirect — no `client_secret`). Confirm the
authorization request uses `response_type=code` + `code_challenge_method=S256`, complete login with the
dev account (never printing tokens/codes/state/verifier), confirm `/api/v1/me` succeeds with the
resulting access token and renders the DB-backed principal, confirm a forged/expired token is refused
by the backend verifier, and confirm logout clears the local session. Remove the containers afterward.

## Safety notes

- No real Proxmox/VMware/Hyper-V/cloud/OpenTofu/Ansible/Wazuh/CTFd is contacted.
- The API never executes privileged infrastructure actions (Charter Invariants
  6, 7). Plugins run only in the worker boundary.
- Tear down with `docker compose down -v` (the `-v` also removes the dev volumes).
