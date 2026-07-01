# ADR-013 — Sealed OpenTofu runtime, immutable toolchain provenance, and isolated-lab activation

- **Status:** Accepted
- **Date:** 2026-06-30
- **Milestone:** SECP-002B-1A (first slice of chartered SECP-002B-1)
- **Related:** Charter §5 (Layers 4/5/7), §6 (Invariants 4–7, 11, 12, 17), §13; ADR-003,
  ADR-004, ADR-005, ADR-006, ADR-007, ADR-010, ADR-011, ADR-012

## Context

SECP-002B-0 (ADR-011/012) built the provisioning **safety harness**: immutable,
secret-free `ProvisioningManifest`s, a strict blast-radius scope policy, a worker-only
`ProvisioningRunner` seam implemented **only** by a `FakeOpenTofuRunner`, and a durable
operation lifecycle behind an explicit dev/test gate. No real infrastructure, endpoint,
secret, OpenTofu/Terraform binary, subprocess, or provider client was ever touched.

SECP-002B-1 is chartered to run **real, worker-only OpenTofu** against a **disposable,
isolated Proxmox lab**. That is too large and too dangerous for one step, so it is split:

- **B1-A (this ADR):** build the *sealed runner architecture, immutable toolchain
  provenance, provider-neutral workspace rendering, explicit dry-run change-set approval,
  and the isolated-lab activation contract* — proven end-to-end with a **fake process
  executor and fake fixture profiles**. It must **not** contact, inspect, configure,
  mutate, or validate any live Proxmox environment, and it must **not** invoke a real
  OpenTofu/Terraform binary, provider, or endpoint anywhere (source, tests, CI, Docker).
- **B1-B (future):** register one intentionally disposable, isolated lab target; conduct
  a **human-reviewed real dry run**; obtain explicit approval; perform a narrowly scoped
  **first real apply**; verify; and **destroy**.

This ADR locks the B1-A design. It does **not** weaken the B1 commitment to real
worker-only OpenTofu and isolated Proxmox lifecycle support — it builds the safe seam it
will run behind.

## Decision

### 1. Immutable, provider-neutral toolchain profile

Introduce a versioned, immutable, organization-scoped **`ToolchainProfile`** that binds an
`ExecutionTarget` to a worker-side IaC runtime. It is **secret-free** and
**provider-neutral at the core model level** (Charter Invariant 9): the core stores a
generic `content` JSON plus a `content_hash`; provider/adapter specifics live only in the
worker adapter. A profile records immutable provenance for:

- `runner_kind` (e.g. `opentofu`);
- OpenTofu **executable identity** and **exact expected version** (fully pinned);
- OpenTofu **binary integrity** identifier / digest;
- **adapter** identifier and immutable **module-bundle hash**;
- **provider lockfile hash**;
- **renderer version**;
- **state-backend profile reference** (must be a *remote* backend);
- **activation class** — only `isolated_lab` is eligible in B1;
- required **offline provider-mirror** identity.

Validation (`secp_api.toolchain_profile`, control-plane, provider-neutral) **rejects**:
floating / `latest` / wildcard / empty / unpinned versions; missing integrity or hash
values; **local-only OpenTofu state**; **direct-internet provider download**
configuration; unknown adapter types; and unconfigured / permissive production-style
profiles. Fixtures use clearly fake, non-routable placeholder values only.

The exact profile **id + content hash** are pinned onto the target-bound
`DeploymentPlan`, copied to the `ProvisioningManifest`, and carried into every dry-run
change-set approval and every apply/destroy operation. **Any toolchain-profile drift
fails closed** and requires a new plan, fresh approval, and a new manifest.

### 2. Worker-only OpenTofu runtime behind a sealed process executor

Add an `OpenTofuRunner` implementing the existing `ProvisioningRunner` protocol
(ADR-012). It is **worker-only**. `apps/api` never imports the runner, process-execution
code, workspace rendering, adapter code, provider client code, or `subprocess`
(architecture tests enforce this).

Process execution goes through a worker-only **`ProcessExecutor`** abstraction:

- **`FakeProcessExecutor`** — used by *every* test and the in-process verification. It
  runs nothing; it records the exact `argv`, `cwd`, `timeout`, and (redacted) `env` it was
  handed and returns scripted, secret-free output.
- **`SubprocessProcessExecutor`** — the *only* code that would ever run a real process. It
  uses **argv arrays only** (never a shell string, never `shell=True`), a fixed
  worker-owned working directory with restrictive permissions, an explicit **timeout**,
  an **output-size cap**, an **environment allowlist**, and mandatory **output
  redaction**. It **exists** in the worker package but is **inert unless the explicit
  isolated-lab runtime gate is armed**, and it is **not constructed or invoked anywhere in
  B1-A** (a test proves no real binary/network/provider/endpoint is used).

No credential, secret reference, token, password, endpoint-auth value, or backend
credential may appear in logs, errors, operation records, audit events, API responses, or
workspace artifacts.

### 3. Provider-neutral, deterministic workspace rendering

A worker-only rendering seam converts an **immutable `ProvisioningManifest` + immutable
`ToolchainProfile`** into a deterministic, **secret-free** rendered workspace artifact:

- the rendered workspace has a deterministic **content hash**;
- it records the manifest hash, scope-policy hash, toolchain-profile hash, renderer
  version, and module-bundle hash;
- rendered content contains **no secrets, secret refs, endpoint-auth, or resolved
  credentials** — provider endpoint and token are referenced only as *input variables*
  injected just-in-time in the worker at real-apply time (B1-B), never written into the
  durable, hashed artifact;
- generated files are materialized only in an **ephemeral, restrictive-permission**
  workspace directory;
- **no local state backend** is allowed; provider plugins/modules are expected through an
  **offline, pinned, verified** worker-side mirror;
- the `OpenTofuRunner` **refuses** any unpinned, downloaded-at-runtime, or local-state
  configuration.

Proxmox-specific rendering and resource semantics live entirely in the worker adapter
(`secp_worker.provisioning.adapters`), never in `apps/api` or the core domain models.

### 4. Explicit real change-set approval

A normal approved `DeploymentPlan` and immutable manifest are **necessary but not
sufficient** for a real apply. The durable, auditable approval workflow is:

1. approved `DeploymentPlan`;
2. immutable `ProvisioningManifest`;
3. immutable, pinned `ToolchainProfile`;
4. worker-only **rendered workspace**;
5. OpenTofu **dry-run change set**;
6. **canonical, redacted change-set hash**;
7. **explicit human approval** of *that exact* dry-run result;
8. apply only when the **current regenerated dry-run hash exactly matches** the approved
   hash.

Apply is refused when **any** of these drift: deployment plan, target config, scope
policy, reservations, manifest, toolchain profile, renderer version, adapter/module
bundle, dry-run change set, or approval state. **Destroy follows the same pattern**: a
**separately generated, reviewed, approved destroy change set** is required before any
destruction. There is **no automatic apply after dry run, no AI approval, and no
environment-variable bypass**. Durable approvals store a canonical, redacted, hashed JSON
change-set representation — **never a raw OpenTofu binary plan** (which is not proven
secret-free).

### 5. Isolated-lab activation gate

Real provisioning remains **disabled by default**. A dedicated gate
(`secp_worker.provisioning.activation`) permits a real operation **only** when **all** of:

- explicit **isolated-lab application mode** (`SECP_PROVISIONING_APPLICATION_MODE=isolated_lab`);
- the **Temporal/durable worker path** only — **inline execution is refused**;
- an **active** target whose **pinned toolchain profile** has `activation_class=isolated_lab`;
- an **approved plan** and **immutable manifest**;
- **complete hash agreement** across target config, scope policy, reservations, manifest,
  and toolchain profile;
- an **explicit human-approved dry-run change set** whose hash still matches a freshly
  regenerated dry run;
- an explicit **real-provisioning setting** (`SECP_ENABLE_REAL_PROVISIONING=true`);
- **worker-only, just-in-time** secret resolution (ADR-007);
- external connectivity policy remains **deny**;
- a **remote state backend** profile is present and validated;
- **no fallback** to `FakeOpenTofuRunner` in a real-lab request.

The normal **Simulator path is unchanged**, and the SECP-002A target-bound **inline
deployment refusal** remains in place. The FakeOpenTofuRunner path (ADR-012) also remains
valid behind its own dev/test gate for harness verification.

### 6. Durable workflow and state

The API may **request and record** a provisioning operation and a change-set approval but
**never executes the runner** (Charter Invariants 6, 7). Worker-restart safety covers
rendered-workspace provenance, dry-run change-set metadata, approvals, apply/destroy
idempotency, runner status, and redacted failure records — all derived from durable
`ProvisioningOperation` and `ProvisioningChangeSetApproval` rows (no raw binary plan is
persisted).

## Consequences

**Positive**
- The full real-OpenTofu seam — toolchain provenance, sealed executor, provider-neutral
  rendering, dry-run approval, and the isolated-lab gate — exists and is proven with fakes,
  keeping `apps/api` free of runner / executor / adapter / IaC / subprocess code.
- "Approve exactly this change set" becomes verifiable and tamper-evident: apply is bound
  to an exact, human-approved, redacted dry-run hash and fails closed on any drift.
- B1-B becomes a **configuration + human-review** exercise against a disposable lab, not
  new architecture.

**Negative / risks**
- More immutable entities and hashes. Mitigated by reusing the established content-hash +
  ORM-immutability + gated-worker patterns (ADR-002/006/011/012).
- Two runner and two executor implementations could drift. Mitigated: both runners satisfy
  one protocol with a shared conformance suite; the fake executor mirrors the exact
  `argv`/`cwd`/`timeout`/`env` contract the real one consumes.

**Placeholder (deferred to B1-B)**
- No real OpenTofu/Terraform/provider/endpoint is installed, downloaded, or invoked in
  B1-A. Arming `SubprocessProcessExecutor`, real remote-state wiring, real provider mirror
  verification, drift/reconcile handling, and the first real dry-run/apply/destroy against
  a disposable lab are **B1-B** and later work.
