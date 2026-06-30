# SECP-001 — Runtime Verification

**Last updated:** 2026-06-30 (hardening patch: closed-world allowlist + OIDC placeholder fix)
**Performed on:** Windows 11, Docker Engine 29.4.0, Docker Compose v5.1.2
**Branch:** `feature/secp-001-control-plane-foundation`
**Dispatch mode:** `inline` (default; simulated execution only)

This document records an **actual** run of the local Docker Compose stack — not a
config-only check. Every result below was produced by the commands shown.

> Scope reminder: simulated execution only. No real infrastructure, no real
> security tools. Execution boundary enforced by `secp_api.safety` and the worker.

---

## 1. Commands used

```bash
# from repo root
cp .env.example .env                      # development-only placeholders (git-ignored)

cd infra/dev
docker compose --env-file ../../.env up -d --build

# health
docker compose --env-file ../../.env ps

# vertical slice driven over HTTP against the running API (see §4)
# PostgreSQL inspection via: docker exec secp-dev-postgres-1 psql -U secp -d secp ...
```

PostgreSQL-level immutability tests were also run against a throwaway PG container:

```bash
docker run -d --name secp-pg-test -e POSTGRES_PASSWORD=test -e POSTGRES_USER=test \
  -e POSTGRES_DB=secptest -p 55432:5432 postgres:16-alpine
SECP_TEST_POSTGRES_URL="postgresql+psycopg://test:test@localhost:55432/secptest" \
  uv run pytest apps/api/tests/test_postgres_immutability.py -v
```

---

## 2. Service health (actual)

`docker compose ps` after startup settled:

| Service | Status | Verified |
| --- | --- | --- |
| postgres | Up (healthy) | `pg_isready`; row counts queried |
| minio | Up (healthy) | `GET :9000/minio/health/live` → 200 |
| keycloak | Up (healthy) | `GET :8081/realms/secp/.well-known/openid-configuration` → 200 |
| temporal | Up (healthy) | `tctl cluster health` |
| temporal-ui | Up | `GET :8088/` → 200 |
| api | Up (healthy) | `GET :8080/health` → 200 |
| worker | Up (healthy) | container liveness check (imports worker + resolves settings) |
| web | Up | `GET :5173/` → 200 |

All eight services reached a healthy/reachable state.

> `temporal-ui` and `web` are dev servers without a Compose `healthcheck`; both were
> verified reachable (HTTP 200). `worker` is not an HTTP service (inline mode); its
> health is a container liveness check.

## 3. Endpoint reachability (actual)

```
API /health            200
API /api/v1/me         200
API /api/v1/plugins    200
Keycloak OIDC cfg      200
MinIO health           200
Temporal UI            200
Web app                200
```

The API ran `alembic upgrade head` on boot:
`INFO [alembic.runtime.migration] Running upgrade -> 09a75fd21cf8, initial control-plane schema`.

---

## 4. Simulated vertical slice (actual, against the running stack)

Driven over HTTP against `http://localhost:8080`:

```
1. template=web-breach-101 version=v1 hash=sha256:bd8d77e726a6b
2. exercise=9562a5a2 created+validated
3. plan generated; pre-approval deploy -> HTTP 409 (approval_required)
4. plan approved status=approved approved_hash=sha256:bd8d77e72
5. deploy -> HTTP 200 workflow=completed exercise_state=running
6. team=team1 nodes=4 edges=5 cidrs=['10.20.0.0/24']
6. team=team2 nodes=4 edges=5 cidrs=['10.20.1.0/24']
   isolation: team CIDRs disjoint = True
7. reset team1 -> HTTP 200 workflow_kind=reset noop=True
8. destroy -> HTTP 200; retry -> HTTP 200 noop=True; final=destroyed
9. audit events=15; required present = True
   actions: apply.refused, deploy.completed, deploy.started, destroy.completed,
            destroy.started, exercise.created, exercise.validated, instance.created,
            plan.approved, plan.generated, plan.submitted, reset.completed, reset.started
RUNTIME VERTICAL SLICE OK
```

Demonstrated end-to-end on the live stack: load `web-breach-101` → generate plan →
**approval gate refuses deploy (409)** → approve → deploy two isolated team
environments (disjoint `/24` CIDRs) → reset one team → destroy (idempotent retry)
→ audit log contains every required action.

## 5. PostgreSQL state and DB-level immutability (actual)

Control-plane data persisted to the Compose PostgreSQL:

```
environment_version=1
audit_event=20
exercise=1
simulated_node=0   # correct: nodes cleared by destroy
```

Triggers registered on the running database:

```
secp_audit_event_immutable
secp_environment_version_immutable
```

Real mutations refused at the DATABASE level (raw SQL, bypassing the application):

```
update environment_version set content_hash = 'tampered';
  ERROR:  environment_version is immutable after creation

delete from audit_event;
  ERROR:  audit_event records are immutable and append-only
```

PostgreSQL immutability pytest suite (against a real PG container): **7 passed**,
including a precision test proving non-protected columns *can* still be updated.

---

## 6. Issues found and fixed during runtime verification

Running the stack (not just `docker compose config`) surfaced four real defects:

1. **API could not start** — `alembic ... upgrade head` was run from `/app`, where
   `script_location = migrations` resolved to a non-existent path. Fixed the
   Compose command to run Alembic from `apps/api`.
2. **Keycloak failed to start** — the realm import JSON contained a non-standard
   `_comment` field; Keycloak's strict parser rejected it
   (`UnrecognizedPropertyException`). Removed the field.
3. **Keycloak healthcheck never passed** — it used `CMD-SHELL` (`/bin/sh`, which
   lacks `/dev/tcp`) against port 8080, but Keycloak 25 serves health on the
   management port 9000. Fixed to run under `bash` against `:9000`.
4. **Worker reported unhealthy** — it inherited the shared image's API healthcheck
   (curl `:8080`), which the worker does not serve. Added a worker-specific
   liveness check (import worker + resolve settings).

A fifth defect was found by the PostgreSQL immutability tests and fixed before this
run: the version-immutability trigger compared the `json` `spec` column with
`IS DISTINCT FROM`, which PostgreSQL rejects (`json` has no equality operator).
Fixed by comparing `spec::text`.\r
\r
### Hardening patch 1 (2026-06-30)

Issues 6-8 documented above (closed-world allowlist, OIDC placeholder, MinIO pin).

### Hardening patch 2 (2026-06-30)

9. **Inline-execution allowlist made truly closed-world** � replaced the inline_safe=True keyword argument on egister() with an identity-based model: egister() has no inline_safe parameter; _register_builtin_simulator() (called only by bootstrap) stores the exact SimulatorPlugin instance; is_inline_safe(plugin) is a Python is identity check. A fake plugin named 'simulator', a fresh SimulatorPlugin(), or any plugin claiming simulated=True are all refused. Plugin names are immutable after registration, preventing replacement of the built-in Simulator. 8 new registry/guard tests added.

10. **Bearer token rejected before dev fallback** � current_principal() now checks the Authorization header FIRST. Any bearer token is refused with the SECP-001 placeholder error even when AUTH_DEV_MODE=true, preventing silent token discard. Verified live: GET /api/v1/me with Authorization: Bearer fake.jwt.token -> HTTP 401 with 'SECP-001'/'not implemented' message even with dev auth active.

## 7. Teardown

```bash
docker compose --env-file ../../.env down -v   # also removes dev volumes
docker rm -f secp-pg-test
```

## 8. Honesty notes / limits

- Verified with `SECP_WORKFLOW_DISPATCH_MODE=inline`. The Temporal **service** and
  UI are healthy/reachable, but end-to-end durable execution through Temporal was
  not exercised (ADR-005 placeholder); orchestration ran in-process via the inline
  dispatcher (Simulator only).
- OIDC login flow was not driven end-to-end; the dev fallback principal was used by
  the API (a documented SECP-001 placeholder). Keycloak readiness and the realm’s
  OIDC discovery endpoint were verified reachable.
- This run is reproducible from the commands above on a machine with Docker.
