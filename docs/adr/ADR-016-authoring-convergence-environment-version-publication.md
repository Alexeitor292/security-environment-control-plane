# ADR-016 — Authoring Convergence and Environment Version Publication

- **Status:** Accepted (architecture lock / design only — no implementation)
- **Date:** 2026-07-11
- **Milestone:** SECP-B10 — Authoring Convergence & Environment Version Publication
- **Deciders:** Implementation engineering
- **Related:** Charter §5 (Layer 3), §6 Invariants 2, 3, 4, 5, 13, §7 (Environment Version); ADR-002 (scenario versioning + immutable versions + canonical hashing); ADR-004 (deployment-plan approval gate); [`docs/architecture/secp-b10-authoring-convergence-publication.md`](../architecture/secp-b10-authoring-convergence-publication.md)

## Context

The repository has grown two immutable, content-hashed, authoritative-looking objects:

1. **`EnvironmentVersion`** (`environment_version`) — immutable per-template snapshot. It stores the whole declarative `EnvironmentDefinition` object in `spec` (JSON) and its `content_hash` is `content_hash(definition)` over that **entire object** — `apiVersion`, `kind`, `metadata`, and `spec` — as `"sha256:" + sha256(json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False))`. It is allocated a per-template monotonic `version_number` under `UniqueConstraint(template_id, version_number)`, and is the **canonical input to `DeploymentPlan` generation**: a plan pins exactly one `environment_version_id` plus `version_content_hash`, and never reads any topology-authoring object. `spec`/`content_hash`/`version_number`/`api_version` are immutable (ORM `before_flush` guard + Postgres triggers).

2. **`TopologyRevision`** (`topology_revision`, SECP-B9) — immutable topology-authoring revision (`secp.topology/v1`). Its `document_content` (nodes / edges / networks / zones, with node `x`/`y` layout in-hash) and `content_hash` are frozen at creation; only `status` advances through draft → validated → submitted → approved / rejected / superseded, validated by an immutable `TopologyValidationResult` pinned to `(revision_id, content_hash)` with its own `result_hash`. **Approval is a decision only.**

These must **not** become competing deployable sources of truth (Charter §5 Layer 3: "An immutable environment version is the canonical source of truth for every deployment"). A topology revision is also **structurally insufficient** to be a complete `EnvironmentDefinition`: the versioned scenario schema (`controlplane.security/v1alpha1`) has **no topology field** and separately requires `metadata`, `spec.teams`, `spec.networks`, `spec.roles` (each requiring a non-empty `image`, a `kind`, a declared `network`, and a `count`), and `spec.requiredPlugins`, plus optional `spec.vulnerabilityPacks` / `spec.telemetry` / `spec.validation` / `spec.resetPolicy` / `spec.destroyPolicy`. Topology nodes carry no image, no plugin list, no objectives, no policies. There is today **no bridge** from an approved topology revision to an `EnvironmentVersion`. This ADR locks the architecture for that bridge — **publication** — and closes every open decision. It adds no runtime code.

## Decision

Publication is a single, permissioned, audited control-plane action that composes a **final composed `EnvironmentDefinition`** and creates a new immutable `EnvironmentVersion`. `EnvironmentVersion` remains the sole canonical deployable; `TopologyRevision` is publication input and provenance, never deployable by itself. Every decision below is concrete and final.

### D1. Non-negotiable invariants (locked)

- **EnvironmentVersion remains the sole canonical deployable definition.**
- **TopologyRevision is publication input and provenance, and is never a deployable source of truth by itself; a topology revision is never directly deployable.**
- **Approval of a topology revision does not publish anything.** Publication is a separate, permissioned, audited action.
- **Publication creates a new immutable EnvironmentVersion** and **never modifies an existing EnvironmentVersion.**
- **Publication never automatically generates, submits, or approves a DeploymentPlan**, and **publication never starts a workflow or contacts infrastructure.**
- **A DeploymentPlan continues to consume exactly one EnvironmentVersion** (unchanged: `environment_version_id` + pinned `version_content_hash`).
- **Every published version must bind the exact approved topology revision and topology content hash.**
- **Every published version must bind the exact validation-result identity and validation-result hash.**
- **All non-topology environment content used during publication must be exact, validated, and hash-bound.**
- **A caller must not be able to alter topology in the publication payload after topology approval** — the server reconstructs and embeds the exact approved topology it fetches; caller-supplied topology is refused.
- **No silent merge, heuristic mapping, fallback, or fabricated field is allowed.** Any ambiguity or missing required input **fails closed**.
- **Cross-organization references fail closed.**
- **Publication is idempotent for the exact same publication inputs.** **Different publication inputs produce a different immutable version or a closed conflict; they never overwrite a prior publication.**
- **The EnvironmentVersion content hash cryptographically covers every canonical publication input**, including the topology binding and the validation binding.

### Non-weakening

This ADR loosens no existing seal or gate and adds no runtime behavior, route, model, migration, schema, or permission in this PR. Real provisioning, the OpenTofu subprocess, worker execution, resolver activation, discovery, and every mutation path remain exactly as sealed as before (see `docs/STATUS.md`). Publication produces a control-plane record only; it is strictly upstream of, and independent from, plan generation and the plan-approval gate (ADR-004).

### D2. Selected representation and canonical environment hash

Publication composes a **final composed `EnvironmentDefinition`** and stores it as the new `EnvironmentVersion.spec`. That object contains, in one canonically-hashed structure:

1. `apiVersion` = `controlplane.security/v1alpha2` (see D4) and `kind` = `Environment`;
2. `metadata` (the definition's identity/metadata);
3. `spec` — the existing full-definition fields (`teams`, `networks`, `roles`, `requiredPlugins`, and any optional `vulnerabilityPacks` / `telemetry` / `validation` / `resetPolicy` / `destroyPolicy`), **plus**
4. `spec.topology` — the canonical topology object reconstructed from the approved `TopologyRevision` (see D3), **plus**
5. `spec.publicationProvenance` — the stable, hash-covered provenance block (see D7/D10).

**Canonical environment hash (locked):**

```
EnvironmentVersion.content_hash = content_hash(final_composed_environment_definition)
```

where `content_hash` is the existing ADR-002 scenario-schema hash
`"sha256:" + sha256(json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8"))`.
The object hashed is the **entire** `EnvironmentDefinition` — `apiVersion`, `kind`, `metadata`, and the full `spec` (existing fields ∪ `spec.topology` ∪ `spec.publicationProvenance`) — **not only the nested `spec`** block, and never only `definition["spec"]`. Because `spec.topology` and `spec.publicationProvenance` live inside the hashed object, this single hash cryptographically covers every canonical publication input, including the exact topology and the exact validation/provenance identities and hashes.

This is a composition envelope (Option D) that **embeds** the reconstructed canonical topology (the strength of Option A) and **hash-binds explicit provenance identities and hashes** (the strength of Option B), with the provenance also mirrored to immutable columns for query / uniqueness / idempotency, required to equal the embedded `spec.publicationProvenance` values.

**Alternatives rejected.** *Option A alone* (embed, no provenance columns) is not queryable and cannot enforce idempotency/uniqueness at the database. *Option B alone* (a revision reference + topology hash only, no embedding) would leave the exact approved topology outside the canonical deployable definition, so `version.spec` — what the plan consumes — would not reflect the approved topology. *Option C* (project topology into the roles/networks schema) is firmly rejected: scenario `roles` require a non-empty `image`, `kind`, and declared `network` that a topology node does not supply, so projection would fabricate them, and topology edges/zones/layout have no schema home and would be dropped — both violate the no-fabrication and no-silent-loss invariants. Introducing a second `ScenarioRevision`/competing deployable object is rejected outright: publication adds no new deployable object; the embedded topology and provenance live on the existing canonical `EnvironmentVersion`. We additionally reject any implementation where `content_hash` does not cover every canonical input, where an approved topology can be altered through a separate definition payload, where the plan generator could consume content different from what was published, or where approved layout / edges / zones silently disappear.

### D3. Canonical topology reconstruction before embedding

The publisher does **not** embed raw caller topology and does **not** depend on database JSON array order. For every publication the server:

1. fetches the immutable `TopologyRevision` server-side (the caller only names it);
2. re-validates it through the authoritative topology contract (`topology_authoring_contract.validate_document`);
3. **reconstructs the canonical topology object using the exact semantic ordering of `topology_authoring_contract.canonicalize`**: nodes ordered by `id`, edges ordered by `id`, networks ordered by `id`, zones ordered by `id`, and each zone's `member_ids` sorted;
4. recomputes the topology `content_hash` from that reconstructed canonical object;
5. requires equality of that recomputed hash with **both** the stored revision `content_hash` **and** the request's `expected_topology_content_hash` (any mismatch fails closed);
6. embeds that canonical object as `spec.topology`.

The reconstruction is never a different reordering algorithm and never a silent reorder.

**Why reconstruction is required.** The scenario-schema canonicalizer sorts object **keys** but does **not** semantically sort **arrays**, whereas the topology contract's canonicalize additionally sorts arrays by identity. If a raw or differently-ordered topology array were placed into `spec.topology`, the environment content hash — which is order-sensitive for arrays — would depend on that array order and could diverge from the authoritative topology content hash, breaking determinism and idempotency. Reconstructing the canonical topology object first makes `spec.topology` order-stable and byte-consistent with `topology_content_hash`, so the environment hash deterministically covers the exact approved topology.

### D4. Environment schema version (locked)

- `controlplane.security/v1alpha1` is **preserved unchanged** for existing versions; there is **no same-version schema drift**.
- A new `controlplane.security/v1alpha2` is introduced **for published convergence envelopes**. `v1alpha2` adds a **typed optional** `spec.topology` block and a **typed optional** `spec.publicationProvenance` block; all `v1alpha1` fields are carried forward unchanged.
- The **publication service requires both blocks on every version it creates** (schema-optional so the version validates structurally; service-required so publication is complete).
- Existing `v1alpha1` versions remain valid and plannable. There is **no automatic migration** and no mutation of old `EnvironmentVersion` rows.
- PR A implements the validator dispatch for `v1alpha1` and `v1alpha2` and the compatibility tests for both.

### D5. Shared-field consistency (locked)

Topology nodes are **logical role nodes**, not expanded per-team or per-count instances. Publication requires all of the following exactly; any failure fails closed (no case folding, slug fallback, label matching, fuzzy matching, defaulting, silent dropping, or fabricated value):

- every full-definition role has **exactly one** non-network topology node;
- topology **node id exactly equals the role name**;
- topology **node kind exactly equals the role kind**;
- topology **node network exactly equals the role network**;
- role `image` and role `count` remain full-definition-owned and are **not** copied from topology;
- topology may not add a role absent from the definition, and the definition may not contain a role absent from topology (exact one-to-one);
- every declared network has **exactly one** topology network entry **and exactly one** topology node of kind `network`;
- the topology network id and the network-node id **exactly equal** the declared `spec.networks[].name`;
- an optional topology `cidr`, when present, **exactly equals** the declared `baseCidr`;
- an optional topology `isolated`, when present, **exactly equals** the declared `isolated` value;
- every `network` edge target is **exactly** the corresponding network node;
- every host (non-network) node's `network` reference **exactly matches** its role's declared network;
- `service` and `gateway` role kinds must be supported by the future publication-capable topology schema before such definitions may publish (the current `secp.topology/v1` node kinds are `attacker`/`target`/`sensor`/`network`, so a `service`/`gateway` role cannot yet satisfy node-kind equality and cannot publish until the schema supports those kinds).

Current `secp.topology/v1` revisions may publish **only when they already satisfy every exact rule**; otherwise publication fails closed and a **new compatible revision must be authored and approved**. There is **no automatic migration** of incompatible revisions.

### D6. Future publication contract (specification, not implemented here)

A new service `publish_version(...)` behind a new API route, requiring a new `version:publish` permission (distinct from `version:create` and `topology:decide`). Publication **does not approve** topology; the topology must already be approved by a `topology:decide` holder.

**Request fields (caller-supplied):** `template_id`; `definition` (the full non-topology `EnvironmentDefinition`, which must not contain `topology` or `publicationProvenance` keys — refused if present); `topology_document_id`; `topology_revision_id`; `expected_topology_content_hash`; `validation_result_id`; `base_environment_version_id` (nullable). There is **no caller-supplied idempotency key** (see D7).

**Server-owned fields:** `id`, `organization_id`, `version_number`, `api_version` (`controlplane.security/v1alpha2`), `spec` (the composed envelope with reconstructed `spec.topology` + `spec.publicationProvenance`), `content_hash`, `publication_fingerprint`, `created_by`, `created_at`, and every provenance value + mirrored provenance column. Topology bytes are always fetched and reconstructed server-side.

**Preconditions (each independent, all fail closed with a closed refusal code):** permission (`version_publish_permission_denied`); organization ownership of template + topology document + revision + validation result + base version (`version_publish_cross_org_forbidden`); template exists (`version_publish_template_not_found`); the named revision is the document's approved head and is `approved` (`version_publish_topology_not_found` / `version_publish_topology_not_approved`); reconstructed topology hash equals the stored revision hash and the request pin (`version_publish_topology_hash_mismatch`); a passing `TopologyValidationResult` exists for `(revision_id, content_hash)` with `status ∈ {valid, valid_with_warnings}`, the supplied `validation_result_id` matches, and its recomputed `result_hash` matches (`version_publish_validation_missing` / `version_publish_validation_not_passing` / `version_publish_validation_stale`); the definition passes `validate_definition` for `v1alpha2` (`version_publish_definition_invalid`) and carries no topology/provenance keys (`version_publish_topology_in_payload_forbidden`); the D5 role/network one-to-one rules hold (`version_publish_role_topology_mismatch` / `version_publish_network_topology_mismatch` / `version_publish_unsupported_role_kind`); and the D9 base/template rules hold (`version_publish_base_version_required` / `version_publish_base_version_not_found` / `version_publish_base_version_mismatch` / `version_publish_base_version_cross_org_forbidden` / `version_publish_template_mismatch`). A fingerprint collision with disagreeing fields fails `version_publish_conflict`.

**Result:** the new immutable `EnvironmentVersion`. **Audit:** a new `version.published` `AuditAction` recording ids/hashes/version-number only. **Read-model:** the version surfaces its `spec.publicationProvenance` so the full chain is visible. **Retry / historical:** replaying the exact same inputs returns the same version; `v1alpha1` versions remain valid and are never migrated. An approved revision may be published more than once (D9); publication never changes or consumes the revision.

### D7. Idempotency (locked)

There is **no caller-supplied idempotency key**. Idempotency is a server-derived fingerprint over the final environment content:

```
final_environment_content_hash = content_hash(final_composed_environment_definition)

publication_fingerprint = "sha256:" + sha256(
    canonical UTF-8 encoding of {
      "template_id": <exact template UUID string>,
      "environment_content_hash": final_environment_content_hash
    }
)
```

The final composed definition's `spec.publicationProvenance` block includes at least: `topology_document_id`, `topology_revision_id`, `topology_content_hash`, `topology_validation_result_id`, `topology_validation_result_hash`, `base_environment_version_id` (nullable), and `publication_contract_version`. Because these identities and hashes are inside the hashed definition, `final_environment_content_hash` — and therefore `publication_fingerprint` — bind the **exact provenance identities** as well as the hashes.

`publication_fingerprint` is **server-owned and stored immutably** (a column, not part of the hashed definition, to avoid circularity). Identical exact inputs return the existing `EnvironmentVersion`. **Different `topology_revision_id` or `validation_result_id` values are different publication inputs even when their content hashes happen to match**, because the ids are inside the hashed provenance and change the environment content hash (hence the fingerprint).

### D8. Concurrency (locked)

The `(template_id, version_number)` unique constraint is **defense in depth, not the primary allocator**. The production algorithm (PostgreSQL is authoritative) is a single transaction:

1. Validate immutable input references and organization scope.
2. Lock the `EnvironmentTemplate` row with `SELECT FOR UPDATE`.
3. Re-read all relevant records inside the transaction.
4. Recompute the canonical topology, the composed definition, the environment content hash, and the publication fingerprint.
5. Query by `(template_id, publication_fingerprint)`.
6. If found and all immutable fields agree, return it idempotently.
7. If found but any field disagrees, fail `version_publish_conflict`.
8. Otherwise allocate `max(version_number) + 1` while holding the template lock.
9. Insert the immutable `EnvironmentVersion`.
10. Retain unique constraints on `(template_id, version_number)` and `(template_id, publication_fingerprint)`.

SQLite tests may exercise deterministic service behavior but do not weaken the production `SELECT FOR UPDATE` template-row lock requirement.

### D9. Source / base and reuse policy (locked)

- An approved topology revision **may be published more than once** when the final composed definition differs; an exact repeat is idempotent and returns the same version. Publication **never changes or consumes** the topology revision.
- All publications remain in the **same organization**.
- **When** the topology document/revision has a `source_environment_version_id`: `base_environment_version_id` is **required** and must equal that exact source version, and the destination template must equal the source version's template.
- **When** no source version exists: `base_environment_version_id` may be null, and the caller selects an organization-owned destination template.
- Publication to **multiple templates** is therefore allowed **only** for topology documents created without a source `EnvironmentVersion`.
- No inferred ancestor, no "latest version," and no fallback base is allowed.

### D10. Stable hash-covered provenance vs. publication event metadata (locked)

`spec.publicationProvenance` contains **only stable publication inputs and the contract version** (the D7 field list). The following are **never** placed in the hash-covered provenance block: the new `EnvironmentVersion` id, the publication timestamp, and the audit-event id. `created_by` and `created_at` remain server-owned `EnvironmentVersion` row metadata, and the immutable audit event records the publication actor and time. This separation ensures a **retry cannot alter canonical content**: because volatile values (new id, timestamp, audit id) are outside the hashed definition, identical inputs always produce the same `final_environment_content_hash` and the same `publication_fingerprint`, so the retry is idempotent rather than a new, differently-hashed version.

### D11. Content ownership matrix

| Field | Owner | Notes |
| --- | --- | --- |
| `metadata` | full-definition authoring | |
| `spec.teams` | full-definition authoring | topology cannot supply |
| `spec.networks` (declared segments) | full-definition authoring | the declared deployable network layer |
| `spec.roles` (`name`, `kind`, `network`) | full-definition authoring | node id/kind/network must equal these (D5) |
| `spec.roles[].image` | full-definition authoring | never copied from topology; never fabricated |
| `spec.roles[].count` | full-definition authoring | never copied from topology |
| `spec.requiredPlugins` / `vulnerabilityPacks` / `telemetry` / `validation` / `resetPolicy` / `destroyPolicy` | full-definition authoring | |
| topology `nodes` / `edges` / `zones` / layout (`x`/`y`) / diagram `networks` | topology authoring | reconstructed canonically and embedded as `spec.topology` (D3) |
| `spec.topology` (embedded canonical object) | publication composition | reconstructed from the approved revision; equals `topology_content_hash` |
| `spec.publicationProvenance` (stable inputs + `publication_contract_version`) | publication composition (server) | hash-covered (D7/D10) |
| `content_hash`, `version_number`, `publication_fingerprint` | server-derived | fingerprint is a column, not hashed (D10) |
| `id`, `created_by`, `created_at`, audit event | server-derived metadata | not in hash-covered provenance (D10) |

Conflicts are composed, never merged; the D5 rules are exact-equality checks and fail closed; missing required definition content (image / plugin / policy / objective) is a validation failure, never a fabricated default.

### D12. Locked state transitions (no earlier transition implies a later one)

```
local topology draft
  → saved topology revision
  → topology validation
  → topology submission
  → topology approval            (decision only — publishes nothing)
  → publication request          (separate, permissioned, audited)
  → immutable EnvironmentVersion (new; never overwrites)
  → separate exercise creation
  → separate plan generation     (binds exactly one EnvironmentVersion)
  → separate plan submission
  → separate plan approval       (ADR-004 gate)
  → separate worker execution    (sealed by default)
```

### D13. Implementation slices (recommended PR sequence after this design PR)

- **PR A — shared publication contract + schema.** Add the typed optional `spec.topology` + `spec.publicationProvenance` blocks under `controlplane.security/v1alpha2`, the validator dispatch for `v1alpha1` + `v1alpha2` with compatibility tests, and the pure canonical-topology reconstruction + envelope hashing. No persistence, no route.
- **PR B — persistence, migration, immutability, publication service.** `EnvironmentVersion` provenance columns + `publication_fingerprint` + `UniqueConstraint(template_id, publication_fingerprint)`; migration + Postgres immutability triggers; the fail-closed `publish_version` service with the D8 `SELECT FOR UPDATE` transaction and all D5/D6/D9 preconditions. No route.
- **PR C — API + read model + audit.** The publish route (permission `version:publish`), the provenance read-model, the `version.published` audit action, and the closed refusal codes.
- **PR D — frontend publication workflow.** A publish affordance bridging an approved topology revision + a chosen full definition into a published version, showing provenance and refusing silently; no auto-approve, no auto-plan.
- **PR E — planning provenance + end-to-end regression.** Surface published provenance in planning (still binding exactly one version), plus draft → publish → plan → approve regression and boundary / immutability / idempotency tests.

Each slice is independently reviewable and fail-closed.

### D14. Decision completeness

This ADR closes every decision required to lock the architecture: the canonical environment hash (D2), canonical topology reconstruction (D3), the `v1alpha2` schema version (D4), the exact shared-field consistency rules (D5), the request contract and refusal codes (D6), server-derived idempotency (D7), `SELECT FOR UPDATE` concurrency (D8), the source/base/template reuse policy (D9), and the provenance-vs-event-metadata separation (D10). **There are zero unresolved architectural ambiguities.**

## Consequences

**Positive**
- One canonical deployable object (`EnvironmentVersion`) is preserved; topology becomes hash-bound provenance plus a reconstructed canonical embedded object, not a rival.
- A single hash over the whole `EnvironmentDefinition` covers the full definition, the exact reconstructed topology, and the exact provenance identities and hashes — tamper-evident and deterministic.
- No fabrication and no silent loss; idempotency and concurrency are server-owned and fail-closed.

**Negative / risks**
- Requires the additive `controlplane.security/v1alpha2` schema (PR A); it must stay additive and versioned so `v1alpha1` versions remain valid.
- The `SELECT FOR UPDATE` template-row lock is the primary allocator; SQLite cannot fully model it, so production concurrency guarantees are validated on PostgreSQL.
- The exact one-to-one role/network rules mean some existing `secp.topology/v1` revisions cannot publish until a new compatible revision is authored and approved.

**Placeholder**
- Publication is **not implemented** in this PR. This ADR and [`docs/architecture/secp-b10-authoring-convergence-publication.md`](../architecture/secp-b10-authoring-convergence-publication.md) are the design lock; PRs A–E implement it. `docs/STATUS.md` continues to record authoring-convergence publication as not-yet-implemented, now design-locked by this ADR.
