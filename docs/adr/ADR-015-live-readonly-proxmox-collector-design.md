# ADR-015 — Live read-only Proxmox collector: threat model and activation design

- **Status:** Accepted (design/threat-model only — no implementation, no live access)
- **Date:** 2026-07-02
- **Milestone:** SECP-002B-1B-2 (Live Read-Only Proxmox Collector Threat Model and Activation)
- **Related:** Charter §5 (Layers 4/5/7), §6 (Invariants 6, 7, 11, 12), §13; ADR-006, ADR-007,
  ADR-008, ADR-013, ADR-014;
  [design package](../architecture/secp-002b-1b-2-live-readonly-proxmox-collector.md),
  [activation checklist](../proxmox/live-readonly-collector-activation-checklist.md)

## Context

SECP-002B-1B-1 delivered immutable, **simulated-only** target evidence, worker-owned simulated
collection, provider-neutral boundary↔evidence comparison, a full-record evidence hash, a
`target_preflight → target_evidence_record` binding, audit records, and approval gates. Live
provider evidence and the `provider_worker` collector remain **sealed**.

Before writing any real provider connector we must lock the threat model, the read-only
contract, the non-mutation enforcement, the credential/target-binding, the execution model, and
the human activation requirements. This ADR records those decisions. It changes **no runtime
behaviour**: no client/SDK/HTTP/socket/subprocess is added, no real target is contacted, no
credential/endpoint is created, and the live-evidence seal is not lifted.

## Decision

1. **The first live collector is read-only and worker-owned.** It observes an approved
   disposable/staging Proxmox target and produces the *existing* provider-neutral evidence
   payload; it reuses the B1-B-1 validate → compare → hash → persist → audit → bind pipeline
   unchanged. The only new boundary that ever touches a real target is the worker↔Proxmox
   read path.

2. **In-scope evidence is minimal:** nodes, storage, network segments, VM-ID
   availability/ranges, capacity/quotas, and read-only isolation-posture signals. Guest
   config/agent/console, tasks, backups, firewall contents, and ACL/user enumeration are out
   of scope. Provisioning/mutation is a later, separate milestone.

3. **Non-mutation by construction.** The future transport enforces, before send, a **GET-only
   method allowlist** and a **closed endpoint allowlist**; it denies unknown endpoints, does
   not follow redirects, and refuses cross-target destinations. No task/action/config/console/
   agent/backup/upload/write endpoint is ever reachable. This is proven with a fake transport
   **before** any live-capable code.

4. **Credentials stay opaque and worker-only; jobs are fully bound.** Control-plane records
   hold only an opaque `secret_ref`; the worker resolves it just-in-time into a transient
   credential and never logs/persists/hashes/returns/audits the secret. Every collection job —
   and its idempotency key — binds, at minimum, **all** of: `execution_target_id`, the target
   `config_hash`, `onboarding_id`, the onboarding `boundary_hash`, `authorization_id` **and**
   authorization expiry/version, `evidence_source` / `verification_level`, and the
   collector-contract / endpoint-allowlist version. Any mismatch, expiry, target/config/boundary
   drift, or contract-version mismatch **fails closed** and yields **no reusable passing
   result**.

5. **Durable, default-disabled execution.** Live collection runs on the durable worker path
   only (inline refused), behind a **default-disabled** feature gate, with deterministic
   idempotency, bounded timeout, capped idempotent-GET retries, cancellation, immutable
   evidence retention, and fail-closed (`unverifiable`) failure semantics.

6. **Fail closed, never infer — but note integrity ≠ truthfulness.** Missing/malformed/
   ambiguous observations are `unverifiable`; a dimension passes only on an explicit matching
   observation. The immutable full-record hash detects **post-collection alteration and binding
   drift** — it does **not** prove the response was truthful and cannot detect evidence that was
   **false at collection time**. There is **no remote attestation**: a compromised target or
   worker can return plausible false data that passes comparison; a hostile target does **not**
   necessarily fail closed. TLS identity, target/config/boundary binding, worker hardening,
   minimal collection, audit, and human review reduce — but do not remove — this residual.

7. **`fully_segregated` isolation requires specific verification.** Generic inventory, bridge/
   VNet presence, and segment names are **insufficient**. A collector may return `passed` for
   `fully_segregated` only when every required isolation assertion — dedicated lab segment
   identity, no protected-network uplink/routing, no default route / external connectivity where
   policy is `deny`, and required host-side isolation controls — is verified via approved,
   allowlisted, read-only observations and deterministic rules. Any unavailable, ambiguous,
   unsafely-observable, or out-of-scope fact is `unverifiable` and blocks approval; it is never
   inferred from incomplete inventory.

8. **Human activation gate.** A real collector may be enabled only after the
   [activation checklist](../proxmox/live-readonly-collector-activation-checklist.md) is
   completed and an explicit human authorization is recorded — in a **future** PR.

### Non-weakening

This ADR does not weaken the live-evidence seal, worker-only execution, secret references +
JIT worker resolution, immutable evidence/audit, onboarding approval gates, or the
architecture boundary that forbids `apps/api` from importing any provider/collector code.

## Consequences

**Positive**
- A reviewed, conservative, test-first path to real read-only evidence with an explicit,
  default-deny activation gate and a documented threat model.
- The existing evidence pipeline is reused, minimizing new attack surface.

**Negative / risks**
- Residual risks (over-scoped credential, read-side disclosure, TLS trust, semi-trusted
  target) remain and are accepted only behind the checklist + recorded authorization.

**Placeholder (future PRs)**
- Fake transport + allowlist tests → adapter behind a disabled gate → staging validation →
  independent security review → separate authorization to enable → (later) provisioning.

No real infrastructure, endpoint, credential, provider, SDK, HTTP client, or secret is
introduced by this ADR.
