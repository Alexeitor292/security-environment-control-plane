# SECP-002B-1A — Sealed OpenTofu Runner and Disposable-Lab Activation Contract

**Status:** Implemented (first slice of SECP-002B-1)
**Related:** ADR-013 (design lock), ADR-011/012 (harness), ADR-006/007/010, Charter §5/§6/§13

This document describes the concrete architecture delivered in SECP-002B-1A: the real,
worker-only OpenTofu execution seam, immutable toolchain provenance, provider-neutral
workspace rendering, the explicit dry-run change-set approval model, and the isolated-lab
activation gate — all proven end-to-end with a **fake process executor and fake fixture
profiles**. **No live Proxmox environment is contacted, and no real OpenTofu/Terraform
binary, provider, or endpoint is invoked anywhere** (source, tests, CI, or verification).

## Component map

```
apps/api/secp_api/                      (control plane — never executes the runner)
  toolchain_profile.py                  ToolchainProfileSpec + validate + hash (provider-neutral)
  models.py                             ToolchainProfile, ProvisioningChangeSetApproval,
                                        plan/manifest toolchain bindings
  services/toolchain.py                 register/get/list/disable toolchain profiles
  services/approvals.py                 record / approve / reject / consume change sets
  services/planning.py                  pins the active toolchain profile onto the plan
  services/manifests.py                 copies the toolchain binding into the manifest
  routers/provisioning.py               toolchain + change-set approval endpoints
  config.py                             application-mode / real-provisioning / subprocess-arm gates

apps/worker/secp_worker/provisioning/   (worker only — the ONLY place the runner runs)
  process_executor.py                   ProcessExecutor seam: FakeProcessExecutor +
                                        sealed SubprocessProcessExecutor (inert in B1-A)
  adapters/base.py, adapters/proxmox.py provider-neutral adapter contract + Proxmox rendering
  rendering.py                          WorkspaceRenderer → deterministic secret-free workspace
  change_set.py                         canonical, redacted change-set + hashing
  opentofu.py                           OpenTofuRunner (ProvisioningRunner protocol)
  activation.py                         process-executor factory + JIT secret env
  execution.py                          run_real_provisioning + full activation gate
```

**Boundary:** `apps/api` never imports the runner, process executor, adapter, workspace
rendering, OpenTofu, a provider client, `subprocess`, or the secret-resolution
implementation. Enforced by `tests/test_architecture_boundary.py` and
`tests/test_provisioning_boundary.py`.

## Toolchain profile and hash binding

A `ToolchainProfile` is an immutable, org-scoped, **secret-free**, provider-neutral record
that binds an `ExecutionTarget` to a worker runtime. Its `content` (validated by
`ToolchainProfileSpec`) pins: `runner_kind`, `executable`, exact `opentofu_version`,
`binary_integrity` digest, `adapter_kind`, `module_bundle_id` + `module_bundle_hash`,
`provider_lockfile_hash`, `renderer_version`, a **remote** `state_backend`, an **offline**
`provider_mirror`, and `activation_class` (`isolated_lab` only in B1). Validation rejects
floating/`latest`/wildcard/empty/unpinned versions, missing/malformed hashes, local state,
online mirrors / runtime download, unknown adapters, and permissive activation.

The exact **profile id + content hash** flow through the chain and must agree at every
step; any drift fails closed and requires a new plan + fresh approval + new manifest:

```
ToolchainProfile.content_hash
  → DeploymentPlan.toolchain_profile_hash          (pinned at plan generation)
  → ProvisioningManifest.toolchain_profile_hash    (copied at manifest generation)
  → ProvisioningChangeSetApproval.toolchain_profile_hash  (captured at dry-run)
  → apply / destroy gate: current == plan == manifest == approval
```

The Simulator and B0 fake-runner paths use **no** toolchain profile (the binding is
`NULL`), so they are unaffected; the real-lab gate fails closed when the binding is absent.

## Deterministic, secret-free workspace rendering

`WorkspaceRenderer.render(manifest, profile)` produces a `RenderedWorkspace`: a
`{path: content}` dict with a deterministic `content_hash`, plus recorded manifest / scope /
toolchain / renderer / bundle hashes. The Proxmox adapter emits **fake fixture** HCL
(`labfake_*` resource types, a `example.test/fake/labproxmox` provider) with the provider
**endpoint and token referenced only as input variables** (`var.pm_endpoint`,
`var.pm_api_token`). A remote `backend` block is rendered generically; **local state is
refused**. The renderer refuses renderer-version drift and asserts secret-freeness. Files
are materialized only into an ephemeral 0700 directory with 0600 files.

## Sealed process executor

`OpenTofuRunner` runs OpenTofu only through a `ProcessExecutor` using **argv arrays**
(never a shell), a fixed restrictive-permission `cwd`, an explicit timeout, an output cap,
an **environment allowlist** (`TF_IN_AUTOMATION`, `TF_VAR_*`, …), and mandatory value
**redaction**. `init` carries offline flags (`-get=false`, `-plugin-dir=…`,
`-lockfile=readonly`, `-upgrade=false`). In B1-A the executor is always
`FakeProcessExecutor` (runs nothing, records calls). `SubprocessProcessExecutor` exists but
is **disarmed by default**, refused in production, and **never constructed or invoked** in
B1-A.

## Explicit dry-run change-set approval

```
approved plan → immutable manifest → pinned toolchain profile → rendered workspace
  → OpenTofu dry-run → canonical redacted change-set hash
  → explicit human approval of that exact hash
  → apply ONLY when a freshly regenerated dry-run hash == approved hash
```

`ProvisioningChangeSetApproval` stores the change-set hash, rendered-workspace hash, and
binding hashes (manifest, toolchain, scope policy, reservations) plus a redacted summary —
never a raw binary plan. `apply` regenerates the dry run and requires an APPROVED approval
whose hash matches and whose bindings still hold. `destroy` requires its **own** approved
destroy change set (produced by a `destroy_dry_run`). No automatic apply, no AI approval,
no environment-variable bypass.

## Isolated-lab activation gate

`run_real_provisioning` is refused unless **all** hold (each refusal audited):

1. `SECP_PROVISIONING_APPLICATION_MODE=isolated_lab`;
2. `SECP_ENABLE_REAL_PROVISIONING=true` and not production;
3. Temporal dispatch only — inline is refused;
4. manifest integrity; approved, target-bound plan; active target + config-hash agreement;
5. valid scope policy + hash agreement (target = plan = manifest) + `deny` external
   connectivity;
6. finalized reservation binding (team/CIDR/org/exercise);
7. pinned toolchain profile that is active, `activation_class=isolated_lab`, with full
   profile/plan/manifest hash agreement and a validated **remote** state backend;
8. worker-only, just-in-time secret resolution for mutating operations;
9. an explicit human-approved dry-run change set matching a freshly regenerated dry run;
10. **no fallback** to `FakeOpenTofuRunner`.

## Durable state

The API only requests/records operations and approvals; the worker executes. Durable
`ProvisioningOperation` and `ProvisioningChangeSetApproval` rows carry rendered-workspace
provenance, change-set metadata, approvals, apply/destroy idempotency keys, runner status,
and redacted failures — so a worker restart is safe. No raw OpenTofu binary plan is
persisted.

## What B1-A intentionally does NOT do

No real OpenTofu/Terraform/provider/endpoint is installed, downloaded, or invoked. Arming
`SubprocessProcessExecutor`, wiring real remote state, verifying a real offline mirror, and
the first real dry-run/apply/destroy against a disposable lab are **SECP-002B-1B** — see
the [B1-B lab prerequisite checklist](../proxmox/b1b-lab-prerequisite-checklist.md) and
[why B1-A cannot touch real infrastructure](../development/secp-002b-1a-why-no-real-infra.md).
