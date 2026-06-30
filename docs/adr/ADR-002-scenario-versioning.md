# ADR-002 — Scenario schema versioning and immutable environment versions

- **Status:** Accepted
- **Date:** 2026-06-29
- **Milestone:** SECP-001
- **Deciders:** Implementation engineering
- **Related:** Charter §9, §7 (Environment Version), Invariants 2, 3, 4; ADR-004

## Context

Two related versioning concerns:

1. **Schema versioning** — the *shape* of a declarative environment definition will
   evolve. Breaking changes must not silently invalidate existing definitions
   (Charter §9: "every breaking change must be versioned").
2. **Content versioning** — a specific environment definition, once snapshotted into
   an `EnvironmentVersion`, must be **immutable** and be the canonical source of truth
   for every deployment (Charter Invariants 2–4).

These are different axes: the schema is the grammar; the environment version is one
immutable sentence in that grammar.

## Decision

### Schema versioning

- The declarative schema is identified by `apiVersion`
  (e.g., `controlplane.security/v1alpha1`), matching the Kubernetes-style convention
  already used in the charter example.
- Each schema version is a directory under `contracts/scenario-schema/<apiVersion>/`
  containing a JSON Schema and Pydantic models. The current version is
  `v1alpha1`.
- **Backwards-compatible** additions (new optional fields) may be made within a
  version. **Breaking** changes (removing/renaming fields, tightening required fields,
  changing semantics) require a **new** `apiVersion` directory and a documented
  migration note. The validator dispatches on `apiVersion`.

### Immutable environment versions

- `EnvironmentTemplate` is mutable; `EnvironmentVersion` is an immutable snapshot of a
  template's spec at a point in time, with a monotonically increasing
  `version_number` per template.
- On creation the platform computes a **content hash**: SHA-256 over the
  canonicalized (sorted-key, normalized) JSON of the spec. The hash is stored and is
  the identity an approver and a deployment plan pin to.
- Immutability is enforced in **two layers**:
  - *Application*: there is no update path for `spec`, `content_hash`, or
    `version_number`; the service refuses such mutations with a domain error.
  - *Database*: the migration installs a guard (trigger / rule) that rejects
    `UPDATE` of those columns, so even direct SQL cannot mutate a published version.
- Every `Exercise` and every `DeploymentPlan` reference exactly one
  `EnvironmentVersion` by id, and the plan additionally records the `content_hash` so
  "approve exactly this" is verifiable.

## Consequences

**Positive**

- Definitions are reproducible and auditable; "what exactly was deployed/approved" is
  always answerable by hash.
- Schema can evolve without breaking historical definitions.

**Negative / risks**

- Two enforcement layers add a little complexity. Justified: immutability is a core
  invariant; defense in depth is appropriate.
- Content hashing requires canonicalization to be stable. Mitigation: a single
  `canonicalize()` helper is the only allowed serializer for hashing, covered by a
  test.

**Placeholder**

- Schema *migration tooling* (auto-upgrading a v1alpha1 definition to a future
  v1beta1) is out of scope for SECP-001 and recorded as future work.
