---
paths:
  - "apps/worker/**"
---

# Worker plane (`apps/worker/secp_worker`)

## The seal list is NOT the infrastructure-contact surface

Verified: the legacy SECP-002A `discover_activity` is registered on the **shipped** ordinary
Temporal queue (`temporal_app.py:111-140`) and reaches a real `ProxmoxPlugin` over a real httpx
transport, ungated at every hop:
`routers/providers.py:154-160` → `services/inventory.py:51,100` → `discovery.py:32-39`
(`return ProxmoxPlugin()`; the mock transport applies only under a test env var).

Do not reason "not named as sealed, therefore does not exist". Trace the call chain.

## Named seals — never change a value

| Seal | Location | Value |
| --- | --- | --- |
| `_B1A_SUBPROCESS_SEALED` | `provisioning/process_executor.py:123` | `True` |
| `_B1A_SUBPROCESS_SEALED` | `provisioning/activation.py:31` | `True` |
| `_PLAN_ONLY_PROCESS_SEALED` | `plan_gen/process_boundary.py:69` | `False` — deliberately |
| `PlanExecutionGate.enabled` | `plan_gen/composition.py:80` | `False` |

The shipped plan-execution composition being disabled **is** guarded
(`apps/api/tests/test_plan_execution_components.py:78-86`).

## Canonical systems — extend, never duplicate

- **Queue binding:** `main.py:201-206` is the only queue binding. Ordinary queue
  `secp-orchestration`; operator queue `secp-controlled-live-v1`. The ordinary worker never polls
  the operator queue. Never construct a second `Worker(...)` or an `operator_main.py`.
- **Worker identity:** four models already coexist (Ed25519 signed-nonce admission is the wired,
  live-capable one). Do not add a fifth.
- **Secret resolution:** three resolver families already exist (`secrets.py:EnvSecretResolver`
  live; OpenBao and preflight variants sealed). Worker-only — the API can never import them.
- **Outbound HTTPS:** at least five httpx seams already exist. Reuse one.
- **Process execution:** two `ProcessExecutor` families exist (`plan_gen/process_boundary.py` and
  `provisioning/process_executor.py`). Adding "apply support" to either is a hard-deny.
- **Subprocess for host contact:** only `ssh_channel.py` may spawn one.

## Registration hotspot

`main.py` `SHIPPED_WORKFLOWS`/`SHIPPED_ACTIVITIES` and `temporal_app.py`'s shipped sealed
instances are edited by nearly every worker milestone. Treat both as exclusive.
