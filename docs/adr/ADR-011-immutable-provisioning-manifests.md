# ADR-011 — Immutable provisioning manifests and blast-radius policy

- **Status:** Accepted
- **Date:** 2026-06-30
- **Milestone:** SECP-002B-0
- **Related:** Charter §6 (Invariants 2–5, 10, 11, 17); ADR-002, ADR-004, ADR-006, ADR-009; ADR-012

## Context

SECP-002A made real execution targets explicit, secret-free, and auditable, and it
reserves address space — but it deliberately **refuses** any deployment to a real
target. Before SECP can ever run worker-only OpenTofu provisioning against a
disposable Proxmox lab (SECP-002B-1), we need a durable, reviewable, tamper-proof
description of *exactly* what would be created, bounded by an explicit blast-radius
policy. A plan (ADR-004) says "what will happen" at the control-plane level; a
**provisioning manifest** is the concrete, immutable, secret-free artifact a runner
would consume.

## Decision

Introduce an immutable, versioned, **secret-free** `ProvisioningManifest`.

A manifest may only be **generated** from, and is bound to:

- an **approved** `DeploymentPlan` (refused otherwise);
- the plan's **pinned** `execution_target_id` and `target_config_hash` (refused on
  drift);
- an **active** target (refused if disabled);
- **valid, finalized** CIDR reservations for the exercise/target (refused if
  missing, released, invalid, cross-org, or out of policy);
- a **validated strict provisioning scope policy** (refused if missing/invalid);
- the desired per-team topology (from the immutable environment version);
- **explicit resource limits** (from the scope policy).

Mechanics:

- The manifest stores its full **content** (JSON) plus a deterministic
  **`content_hash`** (SHA-256 over canonicalized content), and is bound to the plan
  and target.
- The manifest is **immutable after generation** — enforced in
  `secp_api.immutability` (ORM guard) plus a service layer with no update path.
- Manifest **generation and validation are audited**.
- The manifest **excludes all secrets, secret references, credentials, tokens, and
  endpoint auth material.** It records the target *id* and *config hash*, never the
  `secret_ref` value and never resolved secrets.

Generation is a pure control-plane operation: no runner, provider client, OpenTofu,
subprocess, network, or secret resolution is involved (those are worker-only, and
only for the fake runner in SECP-002B-0 — ADR-012).

## Consequences

**Positive**
- "Approve exactly what will be built" becomes verifiable: the manifest is pinned to
  the approved plan + target hash + finalized reservations + validated scope policy,
  and is immutable.
- Blast radius is bounded *before* any runner exists; the manifest cannot silently
  drift.
- Secret-free by construction; safe to store, audit, and display.

**Negative / risks**
- Another immutable entity + hash. Mitigated by reusing the established
  content-hash + ORM-immutability pattern (ADR-002, ADR-006).
- Scope policy lives in the (mutable) target `scope_policy`; a manifest captures the
  validated policy **into its immutable content** at generation time, so later target
  edits cannot weaken an existing manifest.

**Placeholder**
- SECP-002B-0 generates and validates manifests and drives only the **fake** runner
  (ADR-012). No real provisioning occurs.
