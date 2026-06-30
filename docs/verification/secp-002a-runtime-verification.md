# SECP-002A — Runtime Verification

**Date:** 2026-06-30
**Performed on:** Windows 11, Docker Engine 29.4.0, Docker Compose v5.1.2
**Branch:** `feature/secp-002a-proxmox-discovery`
**Modes exercised:** `inline` (Simulator dev path) and `temporal` (durable path)

This records an **actual** run of the local Docker Compose stack proving (a) the
existing Simulator lifecycle still works and (b) the **Temporal** path works using
**only the Simulator and a fake/mock provider**. **No real Proxmox endpoint, secret,
or infrastructure was accessed.**

> Safety: discovery used the **mock** Proxmox transport (`SECP_PROVIDER_MOCK=1`),
> which returns canned placeholder inventory and contacts no network. The secret was
> a placeholder (`mock-token-not-a-real-secret`) resolved by the worker only.

---

## 1. Commands

```bash
cp .env.example .env            # dev-only placeholders; git-ignored

cd infra/dev
# Temporal mode + mock provider override (verification only):
docker compose -f docker-compose.yml -f docker-compose.verify.yml \
  --env-file ../../.env up -d --build

# (worker races Temporal's first-boot; restart it once Temporal is SERVING)
docker compose -f docker-compose.yml -f docker-compose.verify.yml \
  --env-file ../../.env restart worker
```

The verification flow was driven over HTTP against `http://localhost:8080`.

## 2. Service health (actual)

```
SERVICE       STATUS
api           Up (healthy)
keycloak      Up (healthy)
minio         Up (healthy)
postgres      Up (healthy)
temporal      Up (healthy)
temporal-ui   Up
web           Up
worker        Up (healthy)
```

The API applied all four migrations on boot
(`09a75fd21cf8 → b2f1a9c7d3e4 → c1f0865cf71b → 29900a63b28f`). The worker logged
`Temporal worker started on task queue secp-orchestration` after Temporal became
`SERVING`.

## 3. Simulator lifecycle via the Temporal path (actual)

```
A. Simulator lifecycle VIA TEMPORAL
  deploy -> HTTP 200, status=queued, dispatch_mode=temporal
  exercise=running instances=[('team1','running'), ('team2','running')]
```

The API **queued** the deploy (status `queued`, `dispatch_mode=temporal`) and the
**worker** executed it durably via Temporal; the exercise reached `running` with two
isolated team instances — proving the Simulator lifecycle works unchanged through the
durable path.

## 4. Provider target + mock discovery via the Temporal path (actual)

```
B. Provider target + MOCK discovery VIA TEMPORAL
  target -> HTTP 201, config_hash=sha256:cfae6cb9c0b, secret_ref=env:SECP_PROVIDER_SECRET__LAB
  discovery -> HTTP 202, status=queued
  snapshot=completed summary={'total': 6, 'by_type': {'node': 2, 'vm': 2, 'container': 1, 'storage': 1}}
  resources=6 types=['container','node','storage','vm']
```

The API **queued** discovery (HTTP 202) without calling the plugin or resolving the
secret; the **worker** resolved the secret reference just-in-time, ran the read-only
(mock) discovery, normalized the inventory, and persisted an **immutable** snapshot.

## 5. Secret never leaks (actual)

```
C. secret never leaks
  'mock-token' anywhere in audit/snapshot/resources: False
  discovery audit actions present: ['discovery.completed','discovery.requested','discovery.started']
```

## 6. Persisted state in PostgreSQL (actual)

```
-- workflow_run (kind | status | dispatch_mode)
discover | completed | temporal
deploy   | completed | temporal
deploy   | completed | inline        # earlier inline runs (Simulator dev path)
reset    | completed | inline
destroy  | completed | inline

-- provider_inventory_snapshot (status | finalized | #resources)
completed | t | 6
```

Both dispatch modes are recorded correctly. The discovery snapshot is `finalized`
(immutable) with 6 normalized resources.

## 7. Inline-mode safety (actual)

In the default inline dev mode, requesting discovery is refused:
`POST /api/v1/targets/{id}/discover → HTTP 403 (inline_execution_forbidden)`, and a
`provider.operation_refused` audit event is written (covered by
`test_provider_targets_api.py` and `test_temporal_dispatch.py`).

## 8. Issues found and fixed during verification

1. **Worker raced Temporal first-boot** — the worker connects once at startup; on a
   cold stack Temporal is not yet `SERVING`, so the worker fell back to idle.
   Mitigation: restart the worker after Temporal is healthy (documented above). A
   connection-retry loop is a noted follow-up.
2. **Stale dev-admin permissions on a persisted volume** — the dev seed created the
   `platform-admin` role only when absent and never refreshed it, so a database
   volume from an earlier milestone lacked the new `target:manage` /
   `inventory:*` permissions. Fixed: `bootstrap_dev` now refreshes the role's
   permission set to the current full set on every startup (dev-only).

## 9. Teardown

```bash
docker compose -f docker-compose.yml -f docker-compose.verify.yml \
  --env-file ../../.env down -v
rm -f ../../.env
```

## 10. Honesty notes / limits

- Discovery was run against the **mock** transport only (`SECP_PROVIDER_MOCK=1`); **no
  real Proxmox endpoint was contacted** anywhere, ever.
- The worker connects to Temporal once at startup (no retry yet); a restart was used
  on the cold stack. The durable execution itself worked (deploy + discover completed
  with `dispatch_mode=temporal`).
- OIDC login was not driven end-to-end; the dev fallback principal was used (a
  documented SECP-001 placeholder). Keycloak readiness was verified.
- The earlier `inline` workflow rows are leftover from the Simulator dev path on the
  same persisted volume; they demonstrate inline behaviour remains intact.

---

## 11. Correction-pass runtime re-run

The correction pass was re-run with explicit throwaway environment variables
rather than reading a `.env` file. The Compose override still used
`SECP_PROVIDER_MOCK=1` and the placeholder
`SECP_PROVIDER_SECRET__LAB=mock-token-not-a-real-secret`.

Additional verified behavior:

```
health -> HTTP 200 {'status': 'ok'}
deploy -> HTTP 200, status=queued, dispatch_mode=temporal
exercise=running instances=[('team1', 'running'), ('team2', 'running')]

target -> HTTP 201, verify_tls=true, secret_ref=env:SECP_PROVIDER_SECRET__LAB
discovery -> HTTP 202, status=queued, workflow_run_id=<derived from WorkflowRun>
snapshot=completed summary={'total': 6, 'by_type': {'node': 2, 'vm': 2, 'container': 1, 'storage': 1}}
resources=6 types=['container', 'node', 'storage', 'vm']
'mock-token' anywhere in audit/snapshot/resources: False

workflow_dispatch_outbox:
submitted | 2

workflow_run:
deploy   | completed | temporal
discover | completed | temporal

provider_inventory_snapshot:
completed | finalized=true | 1
```

The API applied the correction-pass migration `d4c2e7f9a8b1`, which adds the
transactional workflow outbox and the `WorkflowRun.snapshot_id` foreign key. The
runtime run confirmed that both deploy and discover are submitted only through the
outbox publisher and complete through the Temporal worker.
