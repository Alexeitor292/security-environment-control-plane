# ADR-014 — Target onboarding modes, isolation models, and automated declarative deployment

- **Status:** Accepted (amended — enforceable-binding correction pass)
- **Date:** 2026-07-01 (amended 2026-07-01)
- **Milestone:** SECP-002B-1B-0 (Target Onboarding and Automated Deployment Contract)
- **Related:** Charter §5 (Layers 4/5/7), §6 (Invariants 1–7, 11, 12, 17), §13; ADR-006,
  ADR-007, ADR-009, ADR-011, ADR-012, ADR-013

## Context

SECP-002A/B established secret-free execution targets, immutable manifests, worker-only
provisioning, the sealed OpenTofu runner, and the isolated-lab activation gate. Two product
questions remained about *how a target becomes eligible* for real provisioning:

1. Users may **bring a clean server** (new/empty) or **select an existing Proxmox
   node/cluster**. Both must be supportable.
2. A physically dedicated host is preferred but must not be *mandatory*: a shared existing
   environment is acceptable **only** when it has an explicitly declared, enforceable,
   auditable, and independently verifiable **logical isolation boundary**.

Standard provider-backed deployment must be **declarative and automated**: users must not
hand-create scenario VMs, containers, networks, addresses, or storage before returning to
SECP.

## Decision

### 1. Two onboarding modes, two isolation models

Introduce a **provider-neutral** target onboarding model:

- `onboarding_mode` ∈ {`clean_server`, `existing_environment`}.
- `isolation_model` ∈ {`physical`, `logical`}. **Physical isolation (dedicated hardware) is
  a recommended secure preset, not a product requirement.** Logical isolation is valid only
  behind a declared, enforceable, auditable, verifiable boundary.
- `onboarding_status` ∈ {`draft`, `preflight_pending`, `ready_for_review`, `approved`,
  `active`, `rejected`, `retired`}.

The core `TargetOnboarding` model stays provider-neutral; Proxmox-specific validation lives
in the worker adapter/plugin layer, never in `apps/api`.

### 2. Declared boundary + preflight evidence

A `TargetOnboarding` carries an **immutable declared boundary** (provider-neutral: node /
storage / network-segment allowlists, CIDR ranges, VM-ID range, resource quotas, and
deny-by-default external connectivity, plus an opaque least-privilege credential-scope
label) with a `boundary_hash`. A `TargetPreflight` holds **immutable, redacted, structured
evidence** (`evidence_hash`) for checks such as: allowlist membership, non-overlapping
CIDR/VM-ID, capacity within quota, deny external connectivity, **no route to protected
network classes** (required for logical isolation), TLS posture, least-privilege
credentials, and remote-state / pinned-toolchain prerequisites.

**In SECP-002B-1B-0 preflight is fake-only.** A worker-only `PreflightCollector` seam
(`FakePreflightCollector`) derives redacted evidence from the declared boundary and inspects
**no real target**. B1-B fills the seam with a real collector.

### 3. Activation is approval-gated and drift-bound

A target may become **cleared for real provisioning** only when its onboarding is `active`,
which requires: an approved onboarding record; a complete declared boundary; an explicitly
declared isolation model; required preflight evidence present and passing (including
no-route for logical isolation); an opaque, worker-only credential reference; and pinned
`approved_target_config_hash` + `approved_scope_policy_hash`. Any config/scope **drift**
after approval invalidates the approval at activation and at the real-provisioning gate.
The real-provisioning gate (ADR-013) now additionally requires an active, non-drifted
onboarding for the target.

### 4. Automated, declarative deployment

Standard provider-backed deployment is **automated**: SECP allocates VM-IDs and addresses
and creates the required VMs, containers, networks, disks, and attachments **inside the
declared boundary**. Plans and manifests explicitly state this (`deployment_contract` /
`deployment`): scenario resources are created by SECP, `manual_pre_creation_required` is
false, and no pre-existing user assets are adopted in standard mode. **Import/adoption of
pre-existing assets is a future explicit opt-in workflow, never the default path.** Target
onboarding and scenario deployment are **separate lifecycle stages**.

### Non-weakening

This ADR does **not** weaken explicit plan approval, immutable manifests, worker-only
execution, secret references + JIT worker resolution, deny-by-default external connectivity,
scope-policy / resource-cap enforcement, or real apply/destroy approval. It adds an earlier
onboarding gate on top of them.

## Consequences

**Positive**
- Both "clean server" and "existing environment" onboarding are first-class and safe.
- Dedicated hardware is encouraged but not required; shared environments are allowed only
  behind a verified logical boundary.
- Deployment is automated and declarative; users never hand-build scenario infrastructure.
- Onboarding is auditable, immutable where it matters, and drift-invalidated.

**Negative / risks**
- More lifecycle surface. Mitigated by reusing the established validated-spec + content-hash
  + immutability + approval-gate patterns.

**Placeholder (B1-B and later)**
- Real preflight evidence collection, real provider-specific boundary verification, and the
  explicit pre-existing-asset import/adoption workflow are future work. SECP-002B-1B-0 is a
  design/model/API/fake-only contract PR: **no real target is inspected, configured, or
  mutated.**

## Amendment — enforceable-binding correction pass (2026-07-01)

Review found the onboarding boundary + preflight evidence were recorded but not
cryptographically bound into deployment, and that an API caller could submit arbitrary
"passing" checks. The following are now part of the decision:

1. **Onboarding is an enforceable deployment binding.** `DeploymentPlan` and
   `ProvisioningManifest` carry immutable `target_onboarding_id`, `onboarding_boundary_hash`,
   `approved_preflight_id`, `approved_preflight_evidence_hash`, and
   `onboarding_verification_level`; the manifest echoes them into its immutable `content`
   (and `content_hash`). A **target-bound plan may be generated only when exactly one active
   onboarding exists** for the target and binds it. **Manifest generation and the real
   worker gate require exact agreement** across onboarding record → plan → manifest →
   recomputed approved-preflight evidence, and **fail closed** on boundary drift, evidence-
   hash change, verification-level/collector change, stale/altered evidence, target-config
   drift, scope-policy drift, or ambiguous active onboarding.

2. **Simulated vs live-verified evidence.** Preflight evidence carries a
   `verification_level` (`simulated` | `live_verified`) and a `collector_kind`
   (`fake_declared_boundary` | `provider_worker`). The API preflight route is a **request**
   that produces only `simulated` / `fake_declared_boundary` evidence — it takes **no**
   caller-supplied checks or collector labels, so **no API path can forge live eligibility**.
   A fake collector may only produce `simulated` evidence; only the trusted worker
   `provider_worker` collector may produce `live_verified`. **Live real provisioning
   structurally requires `live_verified` evidence** — simulated evidence supports onboarding
   UX/review but never unlocks live provisioning. B1-B-0 records simulated evidence only.

3. **Complete, hash-bound evidence package.** The evidence hash covers the schema version,
   onboarding id, boundary hash, target config hash, scope-policy hash, toolchain profile
   id/hash, verification level, collector kind + identity, a monotonic evidence version, and
   every redacted check (status + detail) — and **no** secrets/endpoints/credentials/raw
   inventories. Approval pins the exact `approved_preflight_id` + evidence hash + boundary
   hash + verification level and verifies completeness, integrity, and match to the current
   target; later preflights cannot silently replace approved evidence. Activation and the
   worker gate recompute and require the exact approved package.

4. **At most one active onboarding per target.** Enforced by a portable partial unique index
   (`WHERE status='active'`) **and** service-level checks; `active_onboarding_for_target`
   **fails closed** on zero or multiple actives — it never silently picks the newest.
   Activating a second onboarding is refused until the first is retired.

5. **Boundary ⊆ target scope.** A declared boundary must be equal to or strictly narrower
   than the target provisioning scope (nodes, storage, network segments, CIDRs, VM-ID range,
   quotas, external connectivity) — a broader boundary is refused at creation. The worker
   must execute only within the `boundary ∩ scope` intersection (designed + tested with
   fakes; a provider adapter seam handles future provider-specific naming). No real Proxmox
   inspection is implemented.

No real infrastructure, endpoint, credential, or provider is accessed by any of these
corrections.
