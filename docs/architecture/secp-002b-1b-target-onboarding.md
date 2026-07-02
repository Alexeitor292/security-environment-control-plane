# SECP-002B-1B-0 — Target Onboarding and Automated Deployment Contract

**Status:** Implemented (design/model/API/fake-only slice of SECP-002B-1B)
**Related:** ADR-014 (design lock), ADR-006/007/009/011/012/013, Charter §5/§6/§13

This document describes the provider-neutral target onboarding contract, the redacted
preflight evidence model, the automated declarative deployment semantics, and the two
supported user journeys. **No real target is contacted, inspected, configured, mutated, or
validated in this slice** — preflight is fake-only.

## Two isolation models, two onboarding modes

- **Isolation model** — `physical` (dedicated host/cluster, the recommended secure preset,
  **not** a requirement) or `logical` (a shared existing environment behind an explicitly
  declared, enforceable, auditable, independently verifiable boundary).
- **Onboarding mode** — `clean_server` (bring a new/empty eligible server) or
  `existing_environment` (select an existing node/cluster and declare a constrained
  boundary). SECP deploys **only** inside the declared boundary.

## Component map

```
apps/api/secp_api/                       (control plane — never inspects a real target)
  onboarding.py                          OnboardingBoundarySpec + preflight model + lifecycle
                                         (provider-neutral validation, redaction, hashing)
  models.py                              TargetOnboarding, TargetPreflight (immutable-bound)
  services/onboarding.py                 lifecycle: create → preflight → submit → approve →
                                         activate/retire; active_onboarding_for_target + drift
  routers/onboarding.py                  control-plane REST for the whole lifecycle
  services/planning.py                   plan summary states the automated deployment contract
  services/manifests.py                  manifest content states automated deployment

apps/worker/secp_worker/onboarding/      (worker only)
  preflight.py                           PreflightCollector protocol + FakePreflightCollector
```

**Boundary:** `apps/api` never imports the worker preflight collector (or any worker /
provider / runner / subprocess / secret-resolver code) — enforced by the architecture and
provisioning boundary tests.

## Onboarding lifecycle

```
draft ── record preflight ──▶ preflight_pending ── submit ──▶ ready_for_review
      ── human approve ──▶ approved ── activate (drift-checked) ──▶ active
(rejected / retired are reachable; retired is terminal)
```

- **Declared boundary** (`OnboardingBoundarySpec`, provider-neutral) — node / storage /
  network-segment allowlists (no wildcards), CIDR ranges, VM-ID range (bounded), resource
  quotas, **deny-by-default** external connectivity, and an opaque least-privilege
  `credential_scope` label. Immutable after creation (`boundary_hash`).
- **Preflight evidence** (`TargetPreflight`) — immutable, redacted, structured checks with an
  `evidence_hash`. Required checks must all pass to submit; **logical** isolation additionally
  requires `no_route_to_protected`. A fake collector derives evidence from the declared
  boundary and inspects nothing real.
- **Approval** pins `approved_target_config_hash` + `approved_scope_policy_hash`; **activation**
  refuses if either has drifted since approval. The real-provisioning gate (ADR-013)
  additionally requires an active, non-drifted onboarding for the target.

## Automated, declarative deployment

Target-bound plans carry a `deployment_contract` and manifests carry a `deployment` block
stating: `mode=automated`, `provisioning_model=declarative`,
`scenario_resources_created_by_secp=true`, `manual_pre_creation_required=false`,
`user_provided_preexisting_assets=[]` (excluded from standard mode), and `subject_to_approval`
/ `subject_to_scope_policy`. SECP allocates VM-IDs and addresses and creates the required
VMs, containers, networks, disks, and attachments — **users do not manually pre-create
scenario infrastructure.** Import/adoption of pre-existing assets is a future explicit opt-in
workflow, never the default. Onboarding and scenario deployment are **separate stages**.

## User journeys

### A. Clean Server

1. The user chooses a clean/eligible host and registers an execution target (secret-free,
   opaque credential reference).
2. The user creates an onboarding (`clean_server`, usually `physical` isolation) and completes
   the **guided boundary setup** (nodes/storage/network/CIDR/VM-ID/quotas/deny-external).
3. A preflight is recorded (fake in B1-B-0) and reviewed; the user **submits** for review.
4. A human **approves** the onboarding; the user **activates** it.
5. The user requests a scenario; SECP generates an approved plan and immutable manifest whose
   deployment contract states SECP will **create the scenario resources automatically**, then
   (from B1-B) provisions inside the declared boundary behind the existing approval gates.

### B. Existing Environment

1. The user selects an existing Proxmox node/cluster and registers a target.
2. The user creates an onboarding (`existing_environment`, `logical` isolation) and declares a
   **constrained boundary**. External connectivity must be deny; the boundary must be complete.
3. A preflight is recorded and must include a passing **`no_route_to_protected`** check (plus
   the base checks); the user **submits** for review.
4. A human **approves**; the user **activates** (refused on any config/scope drift).
5. SECP deploys the requested scenario **only within the declared boundary**, automatically —
   the user never hand-creates VMs, containers, networks, addresses, or storage.

## Enforceable bindings (correction pass)

Onboarding is not documentation — it is a hash-bound execution input:

- **Plan/manifest bindings.** Target-bound `DeploymentPlan`s and `ProvisioningManifest`s carry
  immutable `target_onboarding_id`, `onboarding_boundary_hash`, `approved_preflight_id`,
  `approved_preflight_evidence_hash`, and `onboarding_verification_level` (the manifest echoes
  them into immutable `content`/`content_hash`). A target-bound plan is generated only with
  exactly one active onboarding.
- **Exact agreement, fail-closed.** Manifest generation and the real worker gate require
  onboarding record → plan → manifest → recomputed approved-preflight evidence to agree, and
  refuse on boundary/evidence/level drift, target-config or scope drift, altered/stale
  evidence, or ambiguous active onboarding.
- **Simulated vs live.** Evidence carries `verification_level` + `collector_kind`. The API
  preflight route is a *request* that only ever yields `simulated` / `fake_declared_boundary`
  evidence (no caller-supplied checks/labels), so no API path forges live eligibility. Live
  real provisioning structurally requires `live_verified` evidence from a future trusted
  `provider_worker` collector; in B1-B-0 that collector is sealed and simulated evidence
  supports UX/review only.
- **Complete evidence hash.** The evidence hash covers schema version, onboarding id, boundary/
  config/scope/toolchain hashes, verification level, collector kind + identity, a monotonic
  version, and every redacted check — never secrets/endpoints/inventories.
- **One active onboarding per target.** A portable partial unique index plus service checks;
  selection fails closed on zero/multiple actives.
- **Boundary ⊆ scope.** A boundary broader than the target scope is refused; the worker executes
  only within `boundary ∩ scope` (a provider adapter seam handles future naming).

### Execution-boundary correction pass

- **Live-evidence seal.** `record_preflight_result` accepts only simulated fake evidence in
  B1-B-0; `live_verified` / `provider_worker` creation is refused everywhere by an unconditional
  code-level seal (`assert_live_evidence_unsealed_allowed`). The `provider_worker` collector
  seam exists but is inert (`SealedProviderWorkerCollector.collect` refuses). A future B1-B
  change adds a real collector under separate review.
- **Effective execution boundary.** `effective_boundary = declared boundary ∩ target scope` and
  `effective_boundary_hash` are persisted on the plan + manifest and echoed into immutable
  manifest content. Manifest generation and the worker gate recompute and require exact
  agreement for both the boundary object and hash (plan == manifest == content) and fail closed
  on empty/broadened/changed/mismatched boundaries. Manifest generation builds topology from an
  effective provisioning-policy view (preserving templates/sizing metadata while narrowing
  execution-bound fields) and runs the shared pure boundary checker before persisting. The
  worker seam `secp_worker.provisioning.boundary` delegates to the same checker and enforces
  every declared node/storage/network/CIDR/VM-ID/quota/external action before rendering, secret
  resolution, executor construction, or process calls. `apps/api` never imports the worker seam.
- **Exact approved-preflight identity.** The gate requires `approved_preflight_id` to agree
  across onboarding → plan → manifest column → immutable content (not just the evidence hash).
- **Toolchain provenance.** Bound through preflight approval → manifest generation → gate:
  preflight == onboarding-approved == plan == manifest == current active profile; a profile
  added/replaced/disabled/altered after preflight approval is refused.
- **Robust redaction.** Preflight detail text carrying a secret/credential/endpoint/inventory/
  private-key/high-entropy value is refused before persistence.

## Onboarding wizard + isolation profiles (SECP-002B-1B-0.1)

An operator-facing React/TypeScript wizard (`apps/web/src/pages/OnboardingWizard.tsx`, with
framework-free logic in `onboarding-wizard.ts`) drives the whole lifecycle against the existing
API: select target → onboarding mode → isolation model → lab network approach → isolation
profile → define & review boundary → simulated lifecycle. Two durable, provider-neutral fields
are added **inside** the hashed, immutable declared boundary (no new column; pre-0.1 boundaries
default safely):

- **`network_approach`** (`use_approved_existing_segment` | `secp_managed_dedicated_segment`).
  Segments must be within the target's approved segments for both approaches; the SECP-managed
  approach is a declaration only — **no bridge/VNet is created in this release**.
- **`isolation_profile`** — only `fully_segregated` is enabled; `internet_egress_only`,
  `controlled_service_access`, and `advanced_custom_policy` are shown as "planned, not available
  yet" in the UI **and rejected server-side** (`SUPPORTED_ISOLATION_PROFILES`).

The review screen states verbatim that SECP will automatically allocate IDs/addresses and
create scenario resources inside the boundary, and that manual per-scenario creation is not
required. The lifecycle UI is explicitly labelled **simulated** and wires only the fake
preflight → review → human approval → activate path; the B1-B-0 live-evidence seal is unchanged.

## What this slice intentionally does NOT do

No real Proxmox host/cluster/node/bridge/VLAN/storage/network/credential/endpoint is
contacted, inspected, configured, authenticated to, or mutated. Preflight is fake-only. Real
evidence collection, real provider-specific boundary verification, and the pre-existing-asset
import/adoption workflow are future work (B1-B and beyond). See the
[B1-B lab prerequisite checklist](../proxmox/b1b-lab-prerequisite-checklist.md) and the
[runtime verification](../verification/secp-002b-1b-target-onboarding-verification.md).
