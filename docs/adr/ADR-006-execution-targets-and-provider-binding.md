# ADR-006 — Execution targets and provider binding

- **Status:** Accepted
- **Date:** 2026-06-30
- **Milestone:** SECP-002A
- **Related:** Charter §5 (Layer 7), §6 (Invariants 1–5, 9, 10), ADR-002, ADR-004; ADR-007

## Context

SECP-001 selected the execution provider implicitly: orchestration used the *first*
entry of an environment definition's `requiredPlugins` that happened to be
registered. That is unsafe for real providers — list ordering must never decide
where infrastructure is created. There is also no record of *where* a deployment is
allowed to go: no approved destination, no scope, no secret handling, no auditable
binding.

## Decision

Introduce a generic, organization-scoped **`ExecutionTarget`**: the approved
destination for a deployment. It is provider-neutral (no provider-specific table).

- Fields: `organization_id`, `display_name`, `plugin_name`, `config` (immutable
  non-secret JSON), `config_hash` (sha256 of canonical config), `secret_ref`
  (opaque pointer, never a secret), `status` (`active`|`disabled`|
  `discovery_failed`), `scope_policy` (optional generic JSON), `created_by`,
  timestamps.
- **Immutable configuration**: `config`/`config_hash`/`plugin_name` cannot change
  after creation (enforced like `EnvironmentVersion`). New configuration ⇒ new
  target record. A target is never silently edited once plans may reference it.
- **Provider binding**: the execution provider is the bound target's `plugin_name`.
  `requiredPlugins` becomes a pure *capability declaration* and never selects the
  provider by ordering. With no target, the safe inline **Simulator** path is used.
- An `Exercise` may optionally reference one `ExecutionTarget`. A `DeploymentPlan`
  pins `execution_target_id` + `target_config_hash` when present, so approval covers
  the exact destination.
- SECP-002A allows registration + read-only discovery only; an exercise may **not**
  deploy to a Proxmox target (deferred to SECP-002B).

## Consequences

**Positive:** explicit, auditable, secret-free destinations; provider selection is
deterministic and reviewable; backwards compatible with simulator exercises (no
target required).

**Negative / risks:** another immutable entity to manage. Mitigated by reusing the
established immutable-config + content-hash pattern (ADR-002).

**Placeholder:** target config *policy* schema is intentionally generic; richer
provider-specific validation arrives with each provider plugin, kept out of the core.
