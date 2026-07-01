# SECP-002B-0 — Runtime Verification

**Date:** 2026-07-01
**Performed on:** Windows 11, Docker Engine 29.4.0, Docker Compose v5.1.2
**Branch:** `feature/secp-002b-provisioning-safety`

This records an **actual** run of the local Docker Compose stack proving the
provisioning **safety harness** works end-to-end using **only the Simulator and the
FakeOpenTofuRunner**. **No real infrastructure, endpoint, secret, credential,
OpenTofu binary, Terraform binary, subprocess, or provisioning tool was accessed.**

> The fake runner runs in the worker behind an explicit gate
> (`SECP_ENABLE_FAKE_PROVISIONING=true`, worker only). It performs no I/O.

## 1. Commands

```bash
cp .env.example .env          # dev-only placeholders; git-ignored

cd infra/dev
docker compose -f docker-compose.yml -f docker-compose.provisioning-verify.yml \
  --env-file ../../.env up -d --build
```

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

The API applied all migrations through `7f15807ffed4 (provisioning manifests and
operations)` on boot.

## 3. Simulator lifecycle unchanged (actual, over HTTP)

```
health: {'status': 'ok'}
SIMULATOR: deploy HTTP 200 dispatch=inline -> exercise=running
```

The Simulator path is unchanged: an exercise deploys inline to `running`.

## 4. Manifest generation — API container / control plane (actual)

Registered a target with a strict provisioning scope policy, built an approved
target-bound plan with two finalized reservations, and generated a manifest:

```
MANIFEST_ID=d3d4ebfd-...
OPERATION_ID=36e81ca4-...
CONTENT_HASH=sha256:861cba2a0e04bd1f...
TOTALS={"teams": 2, "vms": 4, "containers": 0}
HAS_SECRET=False
```

## 5. FakeOpenTofuRunner lifecycle — worker container (actual)

Executed the durable lifecycle through the worker-only runner (gate enabled):

```
gate enable_fake_provisioning: True
after dry_run:      dry_run_completed | creates: 6
after apply:        applied           | applied: 6
after apply retry:  applied           | idempotent_noop: True
after destroy:      destroyed         | destroyed: 6
```

`creates: 6` = 2 team networks + 4 VMs. The apply retry is an idempotent no-op.

## 6. Persisted state + audit chain (actual, PostgreSQL)

```
manifests=1
operations=1
op_status=destroyed

-- provisioning audit chain
manifest.generated
manifest.validated
provisioning.operation_created
provisioning.dry_run_completed
provisioning.apply_started
provisioning.applied
provisioning.destroy_queued
provisioning.destroyed

manifests with secret-like content: 0
```

## 7. Gate-off refusal (actual, worker container)

With the gate disabled, the fake runner is refused and the operation is failed:

```
GATE-OFF REFUSED as expected: fake provisioning runner is disabled; set SECP_ENABLE_FAKE_P...
operation status after refusal: failed
```

## 8. Teardown

```bash
docker compose -f docker-compose.yml -f docker-compose.provisioning-verify.yml \
  --env-file ../../.env down -v
rm -f ../../.env
```

## 9. Honesty notes / limits

- The runner is the **FakeOpenTofuRunner** only; **no OpenTofu/Terraform binary,
  subprocess, network, or provider client was used** — enforced by
  architecture-boundary tests and proven by the boundary of the worker package.
- Manifest generation ran in the **API container** (control plane, no runner); the
  runner ran only in the **worker container** behind the explicit gate — matching
  the API/worker boundary (the API never imports the runner or resolves secrets).
- No real Proxmox endpoint or secret was contacted; the target used placeholder
  configuration (`proxmox.example.test`) and an opaque secret reference that was
  never resolved.
- **Durable runner state mechanism:** `FakeOpenTofuRunner` accepts an optional
  `state_store: RunnerStateStore` (injected as `DbRunnerStateStore(session)` in
  tests and future worker wiring).  On `status()`, `apply()`, and `destroy()` the
  runner checks its process-local `_state` cache and falls through to the store on a
  miss.  `DbRunnerStateStore` queries `ProvisioningOperation.idempotency_key` and
  returns the terminal state inferred from `op.status` + `op.result["resources"]`.
  A fresh runner instance constructed with a `DbRunnerStateStore` therefore answers
  `status()` correctly after a worker restart — the `ProvisioningOperation` row is
  the authoritative state.  No new model or migration is required.
- **Scope-policy hash binding:** `generate_plan()` hashes `scope_policy["provisioning"]`
  and stores `target_scope_policy_hash` on `DeploymentPlan`.  `generate_manifest()`
  verifies the current hash matches the plan's pinned hash (refuses on mismatch or
  NULL); the hash is also stored on `ProvisioningManifest` and in the manifest
  content.  `run_provisioning()` (check 6) requires all three to agree — current
  target, plan, and manifest.  A target manager broadening the policy after approval
  is detected before any manifest or operation is created.  Migration
  `a3b1c0d9e8f7` adds the nullable `target_scope_policy_hash` column to both
  `deployment_plan` and `provisioning_manifest`.
- Executing a fake provisioning operation through a durable Temporal workflow is
  wired conceptually like discovery but is a SECP-002B-1 concern; B-0 executes the
  fake runner directly in the worker for verification.
