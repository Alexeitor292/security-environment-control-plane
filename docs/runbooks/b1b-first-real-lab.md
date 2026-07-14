# Runbook skeleton — first real disposable-lab lifecycle (B1-B)

> **THIS IS A GATED SKELETON, NOT AN ACTIVATION GUIDE.** It contains **placeholders only** and **no
> runnable commands**. It gives **no** provider, SSH, OpenTofu, or Proxmox command. **Execution
> commands remain unavailable until their future reviewed implementation slices** (B1B-PR2…PR7 —
> see [ADR-020](../adr/ADR-020-first-real-disposable-lab-lifecycle.md) and the
> [implementation plan](../implementation/secp-002b-1b-plan.md)). Running this skeleton contacts or
> mutates nothing. Do not add any command that could contact or mutate a real endpoint.

**Status:** design-only skeleton. Nothing here activates or authorizes anything. Both B1-A subprocess
seals remain `True`; no real plan/apply/destroy has run; no real Proxmox host has been contacted. Every
real value (target, node, storage, bridge/VLAN, CIDR, VM-ID, credential, `secret_ref`, backend,
digest) lives **only** in the deployment-local activation dossier (ADR-020 §D), **never** here.

## Human roles (RACI)

- **Operator** — owns the activation dossier, disposable target, isolation, offline mirror, remote
  state + backup, least-privileged credential, and the emergency-stop decision.
- **Approver** — makes the exact change-set-hash approval decisions (apply and destroy, separately).
  Approval is a **decision, never execution**.
- **Reviewer** — reviews each capability unseal (a source change to a seal constant).
- **Recovery owner** — owns partial-failure recovery and manual cleanup; on standby before first apply.
- **Security owner** — owns evidence review and closeout.

No single person may hold Operator + Approver + Reviewer for the same run.

## Hold points (mandatory stops between stages)

Every stage below is a **separate, explicit** action. **Nothing auto-chains.** At each `HOLD`, work
stops until the named role signs off with captured evidence. A configuration flag never advances a
stage; each live capability requires a reviewed code unseal plus the full runtime gate.

### Stage 0 — Prerequisites

- **Entry:** the [prerequisite checklist](../proxmox/b1b-lab-prerequisite-checklist.md) is fully
  satisfied and independently reviewed; the activation dossier is reviewed.
- **Exit / HOLD (Operator + Reviewer):** all boxes checked; no real value in source control.
- **Evidence:** dossier revision/hash; approved checklist.

### Stage 1 — Toolchain attestation (capability: attest-only)

- **Entry:** real `ToolchainVerifier` available (B1B-PR2).
- **Action:** attest the on-disk toolchain (executable/version/digest/module-bundle/lockfile/offline
  mirror/renderer/CLI config/remote-state class/no-runtime-download). *(Worker-only filesystem check —
  no command is provided here; no endpoint contact.)*
- **Exit / HOLD (Reviewer):** attestation passes; execution still sealed.
- **Stop condition:** any facet mismatch → refuse.
- **Evidence:** toolchain attested/refused (redacted).

### Stage 2 — Eligibility preflight (capability: read-only)

- **Entry:** real read-only preflight available (B1B-PR3).
- **Action:** run the worker-only, **read-only** eligibility + boundary preflight. *(No command is
  provided; the worker performs read-only inspection — do not run any provider/SSH command.)*
- **Exit / HOLD (Operator):** target identity/TLS/nodes/storage/bridge-VLAN/VM-ID/CIDR/quotas/no-route/
  deny-external/least-privileged/no-drift all pass; evidence is immutable, redacted, expiry-bound.
- **Stop condition:** any check fails, or evidence expired → refuse.
- **Evidence:** preflight requested/completed/refused (redacted).

### Stage 3 — State + secret readiness (capability: validate-only)

- **Entry:** remote-state + JIT secret readiness available (B1B-PR4 / ADR-021) — **sealed by default**.
  A reviewed deployment-local composition must inject **all** of: the toolchain **filesystem
  layout**, the remote-state adapter **and its reviewed activation**, and the resolver self-test
  **and its reviewed activation**. **No configuration flag alone can activate any of them**, and a
  self-declared adapter `contract_version` is **not** provenance.
- **Prerequisite (new, security amendment):** request the worker-owned **toolchain attestation**
  first. A matching profile hash is a DECLARATION, not evidence — both readiness operations require
  the exact current durable attestation record. The attestation executes **no binary**, opens **no
  socket**, loads **no provider**, and renders **no workspace**.
- **Action:** two **SEPARATE** explicit operator actions, in order. **(1)** Request remote-state
  readiness: the worker validates backend **control metadata** only (remote-only backend class,
  transport security, server-derived namespace identity, encryption-at-rest proof, locking proof,
  backup proof, restore proof, least-privileged access, empty-or-expected namespace, no local
  fallback). **No OpenTofu state payload is created, read, written, uploaded, downloaded, restored,
  or deleted — the adapter contract has no such method. SECP performs no backup and no restore; it
  VALIDATES external proofs.** **(2)** Create → evidence → **approve** (separate permission) a
  dedicated **plan-read-only** secret authorization, then request plan-secret readiness: the worker
  proves it can AUTHENTICATE to the secret backend (a self-test that returns **no target
  credential**) and that opaque material projects into only the allowlisted environment (inert
  sentinel; **no process runs**). *(No command is provided; no plan/apply/destroy; nothing here
  advances to Stage 4.)*
- **Exit / HOLD (Operator):** both readiness records are `ready`, unexpired, and undrifted; both
  were produced under a **controlled-live** capability and a **reviewed (non-placeholder) activation
  dossier**; both bind the exact current toolchain-attestation record and the current opaque
  credential binding; and the combined current-readiness check passes. **No secret, secret reference,
  backend URL, state key, namespace name, bucket, or token is persisted, logged, audited, or
  returned — and no persisted value is a DIGEST of any of them.**
- **Credential rotation:** replacing the target's `secret_ref` **rotates its opaque credential
  binding** (enforced in the ORM *and* by a database trigger), which immediately invalidates every
  prior authorization and readiness record. Re-run readiness after any rotation. **A credential
  replacement can never be invisible.**
- **Stop condition:** any mandatory facet not explicitly proven (an absent/stale/unbound proof,
  unavailable scope evidence, an undeterminable namespace) → `unverifiable` → **refuse**. A revoked or
  expired authorization refuses immediately. Never fabricate a pass.
- **Evidence:** remote-state readiness + plan-secret readiness (immutable, redacted, expiry-bound).
- **Truth:** apply and destroy secret purposes are **unrepresentable** in this phase. **Combined
  readiness is not plan approval and launches nothing.**

### Stage 4 — Real plan (capability: plan-only)

- **Entry:** plan-only unsealed (B1B-PR5); **apply and destroy remain technically impossible**.
- **Action:** generate one real plan → canonical redacted change set → `change_set_hash`. *(Execution
  step — the plan command is unavailable outside the reviewed worker path; do not run OpenTofu here.)*
- **Exit / HOLD (Approver):** review the **redacted** change set; **approve the exact
  `change_set_hash`** (decision only).
- **Stop condition:** unexpected resources, drift, or a non-minimal shape → reject; new dry run.
- **Evidence:** real plan generated/refused; change set approved/rejected (redacted).

### Stage 5 — First apply (capability: apply, one exact plan)

- **Entry:** apply unsealed for the one approved prepared plan (B1B-PR6); recovery owner on standby.
- **Action:** the worker re-prepares a fresh plan, requires the fresh canonical hash to **exactly
  match** the approval, then applies **that same** prepared plan. *(Execution step — no command is
  provided; apply happens only inside the reviewed worker path.)*
- **Exit / HOLD (Operator + Approver):** apply completes; **do not record success yet**.
- **Stop condition:** hash mismatch, gate failure, worker crash, provider timeout → fail closed →
  `recovery_required` (no blind re-apply).
- **Evidence:** apply requested/started/completed/failed (redacted).

### Stage 6 — Verification

- **Action:** compare approved change-set resources vs remote state vs Proxmox observed inventory;
  verify VM/container/network/disk identities, boundary, reservations, quotas, isolation, no-route,
  and health/readiness. **Exit code alone is not sufficient.**
- **Exit / HOLD (Operator):** outcome is one of `verified` / `verification_failed` /
  `state_disagreement` / `isolation_failed` / `recovery_required`. Success only on `verified`.
- **Evidence:** verification completed/failed (redacted).

### Stage 7 — Destroy plan + separate approval (capability: destroy-plan)

- **Entry:** destroy readiness proven **before** first apply; destroy unsealed (B1B-PR7).
- **Action:** generate a **separate** destroy change set → its own redacted `change_set_hash`.
- **Exit / HOLD (Approver):** review and **approve the exact destroy hash** — a **separate** approval,
  never a reuse of the apply approval.
- **Evidence:** destroy planned/approved (redacted).

### Stage 8 — Destroy + zero-residue

- **Action:** apply the exact prepared **destroy** plan (idempotent/retry-safe); then independently
  re-inspect provider **and** state for **zero residue**. *(Execution step — no command provided.)*
- **Exit / HOLD (Operator + Security owner):** `zero_residue_confirmed`; **destroying resources does
  not by itself prove cleanup**.
- **Stop condition:** any residual guest/disk/network/firewall/reservation/lease/workspace/transient
  plan/state object → `zero_residue_failed` → manual containment + cleanup.
- **Evidence:** destroy started/completed/failed; zero-residue confirmed/failed (redacted).

### Stage 9 — Closeout

- **Action:** assemble the immutable audit chain; record documented recovery observations; **re-seal
  capabilities by default** (each future run re-unseals under review).
- **Exit (Security owner):** evidence review complete; STATUS updated to the real, evidenced state.

## Stop conditions (any stage)

Refuse / halt on: eligibility failure; expired evidence; toolchain drift; hash mismatch; gate failure;
worker crash; state-lock loss; provider timeout; verification/isolation failure; state/provider
disagreement; credential revocation; residue detected. **No automatic blind re-apply or blind
destroy.** Destructive recovery requires a **fresh exact approval**.

## Emergency stop and recovery escalation (ADR-020 §M/§N)

- **Prevent new work** (deterministic): stop starting new gated operations.
- **Terminate the local worker process** (best-effort): partial provider effects may remain →
  `recovery_required`.
- **Stop the Temporal workflow**: cancels the durable workflow, not necessarily an in-flight provider
  call.
- **Provider-side operations already in progress**: may complete/partially complete regardless — never
  assumed atomically cancellable.
- **Manual containment** (last resort): operator boundary action (e.g. network isolation).

The kill switch **must not** mutate approvals into success, erase evidence, enable a fake fallback, or
bypass state locking. Escalate to the recovery owner (then security owner) with the durable
operator-visible state; take no destructive recovery action without a fresh exact approval.

## Zero-residue closeout checklist

- [ ] No guests inside the declared boundary.
- [ ] No disks/volumes.
- [ ] No network attachments.
- [ ] No generated firewall entries.
- [ ] No unreleased reservations/leases.
- [ ] No workspace artifacts or transient binary plans.
- [ ] No removable state objects remain.
- [ ] `zero_residue_confirmed` recorded; state closeout complete.
