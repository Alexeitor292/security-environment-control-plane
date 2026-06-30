# ADR-004 — Deployment-plan approval gate

- **Status:** Accepted
- **Date:** 2026-06-29
- **Milestone:** SECP-001
- **Deciders:** Implementation engineering
- **Related:** Charter §3, §7, Invariants 4, 5, 10, 13; ADR-002, ADR-005

## Context

The product promise is "propose and, **after explicit approval**, create." The charter
makes approval a hard invariant: a deployment plan must be generated before execution
(Invariant 4) and **explicitly approved** before any infrastructure execution
(Invariant 5). AI may propose but may never bypass the gate (Invariant 13). This must
hold even though SECP-001 only drives the Simulator — the gate is structural, not
cosmetic.

## Decision

Model approval as an explicit, audited state transition on the `DeploymentPlan`, gating
the `apply` step of the exercise lifecycle.

- **Generation**: a `DeploymentPlan` is generated deterministically from exactly one
  immutable `EnvironmentVersion` (ADR-002). It stores the version `content_hash` and a
  human-reviewable summary of actions (networks, nodes, per team). Generation moves the
  exercise to `planned`.
- **Submission**: moves to `awaiting_approval`.
- **Decision**: an `approve` or `reject` is recorded with `decided_by` (user id),
  `decided_at`, and the `approved_content_hash`. Approval requires a role with the
  `plan:approve` permission; the API authorization layer enforces this.
- **Apply gate**: the apply path **refuses** to run unless the plan status is
  `approved` *and* the live version's `content_hash` equals the `approved_content_hash`.
  A refused apply raises `ApprovalRequiredError` and writes an audit event recording the
  refusal (who tried, when, which plan).
- **Audit**: generation, submission, approval, rejection, and refusal are all immutable
  `AuditEvent`s (Invariant 10).
- **Separation of duties (direction)**: the schema supports distinguishing the
  requester from the approver. Enforcing "approver ≠ requester" is configurable policy;
  SECP-001 records the seam and defaults to role-based gating.

## Consequences

**Positive**

- "Approve exactly what will happen" is enforceable: the plan is deterministic and
  pinned to a content hash; apply cannot drift from the approved artifact.
- Every attempt — including refused ones — is on the audit record.

**Negative / risks**

- Pinning to a content hash means a version edit would invalidate an approval. This is
  intended: versions are immutable (ADR-002), so in practice the hash is stable; the
  check is defense in depth.
- Inline-dispatch convenience (ADR-005) could tempt callers to skip the gate.
  Mitigation: the gate lives in the service layer that *both* dispatchers call, not in
  the API handler, so neither path can bypass it.

**Placeholder**

- Multi-step / multi-approver workflows, time-boxed approvals, and policy-engine
  integration are future work; SECP-001 ships single-approver role-gated approval.
