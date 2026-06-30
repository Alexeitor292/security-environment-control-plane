# ADR-008 — Generic observed inventory and topology

- **Status:** Accepted
- **Date:** 2026-06-30
- **Milestone:** SECP-002A
- **Related:** Charter §8, §14, Invariant 9 (no provider-specific core columns); ADR-003

## Context

SECP-001 stored observed inventory/topology in `simulated_network`,
`simulated_node`, and `simulated_topology_edge`. The names imply the Simulator is
special, but the charter says the topology is a *generic* projection that every
provider populates (Invariant 9: no provider-specific columns in the core). Before a
real provider writes inventory, the persistence must be provider-neutral.

## Decision

Rename the tables to provider-neutral equivalents and add generic provenance
columns, preserving all existing data and Simulator behavior:

| Old | New |
| --- | --- |
| `simulated_network` | `environment_network` |
| `simulated_node` | `environment_node` |
| `simulated_topology_edge` | `environment_topology_edge` |

Generic columns: instance ownership, `provider`, optional `provider_resource_id`,
`provider_resource_type`, observed `status`, `observed_at`, `source` provenance,
`simulated` bool, generic `attributes` JSON. No Proxmox-specific columns.

- The Simulator writes `provider="simulator"`, `simulated=true`,
  `source="simulator"` — identical topology/behavior to SECP-001.
- A **data-preserving** Alembic migration renames tables (`ALTER TABLE ... RENAME`)
  and adds the new columns with safe defaults/backfill.
- `ResourcePort`, Simulator plugin, topology service, API responses, and the
  topology UI use the neutral names. The UI renders simulated exercises exactly as
  before.

Add `ProviderInventorySnapshot` + `ProviderInventoryResource` (generic) for provider
discovery output, immutable after completion, org-scoped.

## Consequences

**Positive:** the core is provider-neutral and ready for real providers without
schema churn; Invariant 9 upheld; SECP-001 behavior preserved.

**Negative / risks:** a rename migration must preserve data and FKs. Mitigated by a
RENAME-based migration (not drop/recreate), tests that assert pre/post behavior, and
PostgreSQL migration verification.

**Note:** the `simulated` boolean stays as honest provenance (the Simulator never
pretends to be real). It is descriptive metadata, not a provider-specific column.
