# SECP-002B-1A — Runtime Verification

**Date:** 2026-06-30
**Branch:** `feature/secp-002b1-opentofu-lab-contract`

This records an **actual** end-to-end run of the sealed OpenTofu contract using **only the
FakeProcessExecutor, fake fixture toolchain profile, and a FakeSecretResolver**. **No live
Proxmox environment was contacted, and no real OpenTofu/Terraform binary, provider,
subprocess, network, or endpoint was invoked.**

## Why this is in-process, not Docker

The SECP-002B-1A safety boundaries forbid touching the Docker socket and downloading
container images, and the real OpenTofu path requires a durable Temporal workflow + armed
subprocess executor that are deliberately **not** wired in B1-A (that is B1-B). So the
authoritative B1-A runtime verification exercises the *real code path* —
`run_real_provisioning`, the `OpenTofuRunner`, the `WorkspaceRenderer`, the change-set
approval model, and the full activation gate — in-process with the fake process executor.
The `infra/dev/docker-compose.lab-contract-verify.yml` override is provided for B1-B and is
configured to stay on the fake executor (the subprocess executor is left disarmed).

The full backend suite (including PostgreSQL immutability + migration) additionally runs in
CI on the authoritative Ubuntu / Python 3.11 / uv environment with a Postgres service.

## Verified run (actual output)

```
== toolchain profile ==
  profile_hash        : sha256:f664d873878d7f63781 ...
  plan==manifest hash : True
  activation_class    : isolated_lab

== subprocess executor is disarmed by default ==
  refused: SubprocessProcessExecutor is disarmed; real OpenTofu executi ...

== dry run (apply preview) ==
  op status           : awaiting_change_set_approval
  change_set_hash      : sha256:4fce2718fd72c3581ce ...
  workspace_hash       : sha256:c0867e1679cd203b557 ...
  approval status      : pending
  summary              : {'create': 8, 'by_type': {'network': 2, 'vm': 4, 'container': 2}}

== apply WITHOUT approval is refused ==
  refused: apply requires an explicit human-approved dry-run change set; none is

== human approves the exact change set, then apply ==
  op status           : applied
  applied resources    : {'create': 8, 'by_type': {'network': 2, 'vm': 4, 'container': 2}}
  approval consumed    : consumed

== inline execution is refused (Temporal required) ==
  refused: real provisioning requires the durable Temporal path; inline execution

== destroy needs its own approved destroy change set ==
  destroy dry status   : awaiting_change_set_approval
  destroy op status    : destroyed

== audit chain ==
   toolchain.profile_created
   provisioning.operation_created
   provisioning.workspace_rendered
   provisioning.change_set_recorded
   provisioning.dry_run_completed
   provisioning.change_set_approved
   provisioning.operation_created
   provisioning.apply_started
   provisioning.applied
   provisioning.operation_created
   provisioning.workspace_rendered
   provisioning.change_set_recorded
   provisioning.dry_run_completed
   provisioning.change_set_approved
   provisioning.operation_created
   provisioning.destroy_queued
   provisioning.destroyed

== secret / endpoint / workspace leakage scan ==
  leaks found         : NONE
```

## What this demonstrates

- **Toolchain hash binding:** the profile hash agrees across profile → plan → manifest, and
  `activation_class=isolated_lab`.
- **Sealed executor:** `SubprocessProcessExecutor` is disarmed by default; every operation
  uses the `FakeProcessExecutor` (no real process).
- **Explicit approval:** a dry run records a *pending* change set; apply is **refused**
  until a human approves that exact hash, then succeeds and the approval is **consumed**.
- **Temporal-only:** inline execution of the real path is refused.
- **Separate destroy approval:** destroy runs only after its own approved destroy change
  set.
- **No leakage:** no secret, endpoint, or workspace filesystem path appears in operation
  records or audit data.

## Automated proof coverage

The 15 required proofs run in the test suite (all green locally):

| # | Proof | Test |
| - | ----- | ---- |
| 1 | API cannot import runner/adapter/executor/OpenTofu/provider/subprocess/secret-resolver | `tests/test_architecture_boundary.py`, `tests/test_provisioning_boundary.py` |
| 2 | `SubprocessProcessExecutor` only in the worker | `tests/test_provisioning_boundary.py` |
| 3 | No real binary/network/provider/endpoint invoked | `apps/api/tests/test_no_real_process.py` |
| 4 | Profiles reject floating versions / missing hashes / local state / direct download / unconfigured | `apps/api/tests/test_toolchain_profile.py` |
| 5 | Toolchain hash binds to plan/manifest (and approvals/apply/destroy) | `test_toolchain_profile.py`, `test_lab_activation_gate.py` |
| 6 | Profile/renderer/bundle/policy/reservation/manifest drift invalidates execution | `test_lab_activation_gate.py`, `test_opentofu_runner.py` |
| 7 | Rendered workspaces are deterministic and secret-free | `apps/api/tests/test_opentofu_runner.py` |
| 8 | Fake executor receives safe argv / restricted cwd / offline flags / redacted env / bounded timeout | `test_opentofu_runner.py` |
| 9 | Apply refused without an approved exact dry-run hash | `test_lab_activation_gate.py` |
| 10 | Apply refused when a regenerated dry run differs | `test_lab_activation_gate.py` |
| 11 | Destroy refused without its own approved destroy change set | `test_lab_activation_gate.py` |
| 12 | Temporal required for real-lab; inline refused | `test_lab_activation_gate.py` |
| 13 | Simulator behavior unchanged | `test_lab_activation_gate.py`, `test_provisioning_integration.py` |
| 14 | Existing B0 fake-runner tests remain valid | `test_fake_opentofu_runner.py`, `test_provisioning_integration.py` |
| 15 | No subprocess output / credentials / secret refs / endpoints / workspace paths leak | `test_lab_activation_gate.py`, `test_opentofu_runner.py` |

## Honesty notes / limits

- The executor is the **FakeProcessExecutor** only; no OpenTofu/Terraform binary,
  subprocess, network, or provider client is used — enforced by architecture-boundary
  tests and the worker package boundary.
- The target used placeholder configuration (`proxmox.example.test`) and an opaque secret
  reference resolved only by a **fake** in-memory resolver; no real secret was read.
- The toolchain profile used clearly-fake, non-routable placeholders (version `9.9.9`,
  repeated-byte `sha256:` digests, a fake offline mirror, and a fake remote state
  reference).
- Arming the real subprocess executor, real remote state, real provider mirror
  verification, and the first real dry-run/apply/destroy against a disposable lab are
  **SECP-002B-1B**, gated by the
  [B1-B lab prerequisite checklist](../proxmox/b1b-lab-prerequisite-checklist.md).
