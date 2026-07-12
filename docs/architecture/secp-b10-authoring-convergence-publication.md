# SECP-B10 — Authoring Convergence & Environment Version Publication

**Status:** design lock (documentation only — no implementation).
**Authoritative decision:** [`ADR-016`](../adr/ADR-016-authoring-convergence-environment-version-publication.md).
**Governing charter:** [`docs/PROJECT_CHARTER.md`](../PROJECT_CHARTER.md) (§5 Layer 3; §6 Invariants 2, 3, 4, 5, 13; §7).

This document explains the selected publication architecture operationally. It introduces no
runtime behavior. All values below are **placeholders**; there are no real endpoints, hosts,
IPs, fingerprints, credentials, tokens, keys, or secrets anywhere in this design.

## 1. Problem in one line

Two immutable, content-hashed objects exist — the canonical deployable `EnvironmentVersion` and
the authoring `TopologyRevision` — and they must converge without `TopologyRevision` becoming a
second deployable source of truth, and without a topology revision (which cannot supply
images / plugins / objectives / policies) being treated as a whole environment definition.

## 2. Selected architecture (summary)

**Publication** is a separate, permissioned, audited control-plane action that composes a **final
composed `EnvironmentDefinition`** into a **new immutable `EnvironmentVersion`** under a new schema
version `controlplane.security/v1alpha2`:

- the caller's **validated full non-topology definition** (`apiVersion`, `kind`, `metadata`, and the
  existing `spec` fields);
- an additive `spec.topology` block holding the **canonical topology object reconstructed** from the
  approved `TopologyRevision` via the topology contract's semantic ordering (never raw caller
  topology, never database array order);
- an additive `spec.publicationProvenance` block binding the approved topology document + revision +
  its content hash, the validation-result identity + result hash, an optional base version, and the
  publication contract version.

The `EnvironmentVersion.content_hash` is `content_hash(final_composed_environment_definition)` — the
existing ADR-002 hash over the **whole** `EnvironmentDefinition` object (`apiVersion`, `kind`,
`metadata`, and the full `spec`), **not only the nested spec**. `EnvironmentVersion` stays the sole
canonical deployable; `TopologyRevision` is input + provenance, never deployable by itself.

## 3. Trust boundaries

- **Client (untrusted for content):** proposes the non-topology `definition` and **names** an
  approved topology revision + expected topology hash + validation-result id. The client **never**
  supplies topology bytes or provenance; the server fetches, re-validates, and reconstructs.
- **Control-plane API + publication service (trusted composer):** authorizes, checks every
  precondition, reconstructs the canonical topology, composes the final definition, computes the
  content hash and the server-owned fingerprint, allocates the version number under a template-row
  lock, and records provenance + audit. It performs **no** privileged infrastructure action and
  calls **no** worker/provider/subprocess.
- **Database (system of record):** enforces immutability (ORM guard + Postgres triggers), the
  template-row `SELECT FOR UPDATE` lock, and the uniqueness constraints.
- **Worker / provider / IaC (out of scope, sealed):** publication never reaches them.

## 4. Canonical data flow

```
topology draft ─▶ saved revision ─▶ validation ─▶ submission ─▶ approval (decision only)
                                                                     │
full definition authoring ──────────────────────────────────────────┼─▶ publication request
                                                                     ▼
        server fetches + re-validates approved revision; reconstructs canonical topology
                                                                     ▼
     compose final EnvironmentDefinition { apiVersion v1alpha2, kind, metadata,
                        spec ∪ spec.topology ∪ spec.publicationProvenance }
                                                                     ▼
     content_hash = content_hash(final definition); fingerprint = f(template_id, content_hash)
                                                                     ▼
      lock template row (SELECT FOR UPDATE) ─▶ allocate version_number ─▶ INSERT immutable version
                                                                     ▼
                              NEW immutable EnvironmentVersion (+ audit: version.published)
                                                                     ▼
        (separate) exercise ─▶ (separate) plan generation ─▶ submission ─▶ approval ─▶ execution
```

No arrow is automatic beyond the one drawn.

## 5. Provenance chain

`spec.publicationProvenance` (hash-covered) contains only stable inputs and the contract version:

```
EnvironmentVersion.spec.publicationProvenance
  ├─ topology_document_id              → TopologyAuthoringDocument
  ├─ topology_revision_id              → TopologyRevision (status=approved)
  ├─ topology_content_hash             = reconstructed canonical topology hash = revision hash
  ├─ topology_validation_result_id     → TopologyValidationResult
  ├─ topology_validation_result_hash   = TopologyValidationResult.result_hash
  ├─ base_environment_version_id?      → prior EnvironmentVersion (see §11)
  └─ publication_contract_version       (publication envelope contract version)
```

Server-owned row metadata (`id`, `created_by`, `created_at`) and the server-owned
`publication_fingerprint` column are **not** inside this hashed block (§10). The reverse link (a
draft/revision derived *from* a published version) is recorded by the existing
`source_environment_version_id` fields on the authoring document and revision.

## 6. Hashing chain

Three independent `sha256:` hashes over ADR-002 canonical JSON (`sort_keys=true`,
`separators=(",",":")`, UTF-8):

1. **Topology content hash** — over the reconstructed canonical topology object. The topology
   contract additionally orders arrays by identity (nodes/edges/networks by `id`, zones by `id`,
   zone `member_ids` sorted) and keeps node `x`/`y` layout in-hash.
2. **Validation result hash** — over `{content_hash, status, findings}` of the passing validation.
3. **Environment content hash** — `content_hash(final_composed_environment_definition)` over the
   **whole** definition object (`apiVersion`, `kind`, `metadata`, full `spec` incl. `spec.topology`
   and `spec.publicationProvenance`), **not only the nested spec**.

**Why the topology must be reconstructed before embedding.** The scenario-schema canonicalizer sorts
object **keys** but does **not** semantically sort **arrays**, while the topology hash **does** sort
arrays by identity. If a raw or differently-ordered topology array were embedded, the array-sensitive
environment hash could diverge from the authoritative topology hash and break determinism. So the
publisher recomputes the topology hash from the reconstructed canonical object and requires it to
equal both the stored revision hash and the request pin before embedding. Because (1) and (2) are
inside `spec.publicationProvenance`, the environment hash (3) cryptographically covers the exact
topology and the exact validation.

## 7. Idempotency

There is **no caller-supplied idempotency key**. The server derives:

```
final_environment_content_hash = content_hash(final_composed_environment_definition)
publication_fingerprint = "sha256:" + sha256( canonical UTF-8 of
    { "template_id": <uuid>, "environment_content_hash": final_environment_content_hash } )
```

Because `topology_revision_id` and `topology_validation_result_id` are inside the hashed
`spec.publicationProvenance`, they are bound by the content hash and therefore by the fingerprint:
**different revision ids or validation-result ids are different publication inputs even when their
content hashes happen to match.** The fingerprint is a server-owned immutable column (not part of the
hashed definition, to avoid circularity) with a unique constraint `(template_id,
publication_fingerprint)`. Replaying identical inputs returns the existing version; different inputs
produce a new version or a closed `version_publish_conflict`; never an overwrite.

## 8. Concurrency

PostgreSQL is the authoritative concurrency model. Publication runs one transaction:

1. validate immutable input references + organization scope;
2. lock the `EnvironmentTemplate` row with `SELECT FOR UPDATE`;
3. re-read all relevant records inside the transaction;
4. recompute canonical topology, composed definition, environment content hash, and fingerprint;
5. query by `(template_id, publication_fingerprint)`;
6. if found and all immutable fields agree, return it idempotently;
7. if found but any field disagrees, fail `version_publish_conflict`;
8. otherwise allocate `max(version_number) + 1` while holding the template lock;
9. insert the immutable `EnvironmentVersion`;
10. retain unique constraints on `(template_id, version_number)` and `(template_id,
    publication_fingerprint)`.

The `(template_id, version_number)` unique constraint is **defense in depth**, not the primary
allocator — the template-row lock is. SQLite tests exercise deterministic service behavior but do
not weaken the production lock requirement.

## 9. Failure behavior (fail closed)

Every precondition is independent and refuses with a closed, redacted code (HTTP body is
`{"error":{"code":...}}` only). Codes:
`version_publish_permission_denied`, `version_publish_cross_org_forbidden`,
`version_publish_template_not_found`, `version_publish_topology_not_found`,
`version_publish_topology_not_approved`, `version_publish_topology_hash_mismatch`,
`version_publish_validation_missing`, `version_publish_validation_not_passing`,
`version_publish_validation_stale`, `version_publish_definition_invalid`,
`version_publish_topology_in_payload_forbidden`, `version_publish_role_topology_mismatch`,
`version_publish_network_topology_mismatch`, `version_publish_unsupported_role_kind`,
`version_publish_base_version_required`, `version_publish_base_version_not_found`,
`version_publish_base_version_mismatch`, `version_publish_base_version_cross_org_forbidden`,
`version_publish_template_mismatch`, `version_publish_conflict`. Refusals are audited with
`outcome="denied"`. There is no partial publication.

## 10. Stable provenance vs. publication event metadata

`spec.publicationProvenance` carries **only** stable publication inputs and the contract version. The
new `EnvironmentVersion` id, the publication timestamp, and the audit-event id are **never** placed in
that hash-covered block. `created_by` and `created_at` are server-owned `EnvironmentVersion` row
metadata; the immutable audit event records the actor and time. This separation is what makes a
**retry cannot alter canonical content** true: volatile values live outside the hashed definition, so
identical inputs always produce the same content hash and fingerprint, and the retry is idempotent
rather than a new, differently-hashed version.

## 11. Source / base and reuse policy

- An approved topology revision may be published more than once when the final composed definition
  differs; an exact repeat is idempotent. Publication never changes or consumes the revision.
- All publications remain in the same organization.
- When the topology document/revision has a `source_environment_version_id`,
  `base_environment_version_id` is required and must equal that exact source version, and the
  destination template must equal the source version's template.
- When no source version exists, `base_environment_version_id` may be null and the caller selects an
  organization-owned destination template.
- Publication to multiple templates is allowed only for topology documents created without a source
  `EnvironmentVersion`. No inferred ancestor, "latest version," or fallback base is allowed.

## 12. Shared-field consistency (role/network one-to-one)

Topology nodes are logical role nodes, not per-team/per-count instances. Publication requires exactly
(no case folding, slug fallback, label matching, fuzzy matching, defaulting, or fabricated value):
each role has exactly one non-network node whose `id` = role name, `kind` = role kind, and `network`
= role network; role `image` and `count` stay full-definition-owned and are never copied from
topology; the role↔node mapping is exact one-to-one both ways; each declared network has exactly one
topology network entry and one node of kind `network`, both with `id` = the declared network name;
optional topology `cidr`/`isolated`, when present, equal the declared `baseCidr`/`isolated`; every
`network` edge target is the corresponding network node; every host node's `network` matches its
role's declared network; and `service`/`gateway` role kinds are supported only once the
publication-capable topology schema adds those node kinds. Incompatible `secp.topology/v1` revisions
publish only if they already satisfy every rule; otherwise a new compatible revision must be authored
and approved. **No automatic migration.**

## 13. Security analysis

- **No content injection:** topology is fetched, re-validated, and reconstructed server-side; a
  `topology`/`publicationProvenance` key in the request payload is refused.
- **Org isolation:** template, topology document, revision, validation result, and base version must
  all belong to the actor's organization; any cross-org reference fails closed.
- **No fabrication / no silent merge:** missing required content is a validation failure; the D5/§12
  rules are exact-equality checks and conflicts fail closed.
- **Immutability:** the published version's `spec`, `content_hash`, `version_number`, `api_version`,
  fingerprint, and provenance columns are immutable (ORM guard + DB triggers); publication never
  mutates an existing version.
- **Secret hygiene:** the topology contract refuses secret-shaped keys/values; audit payloads carry
  ids/hashes/counts/codes only.
- **No privilege escalation:** publication is a control-plane record; it starts no workflow and
  contacts no infrastructure, strictly upstream of the plan-approval gate (ADR-004).

## 14. Explicit non-goals (this design PR)

This PR is documentation + static guardrail tests only. It adds **no**: migration; ORM model;
enum, permission, or schema; API route or behavior; frontend behavior; worker import; provider
import; subprocess; socket; HTTP client; OpenTofu / Terraform invocation; activation flag; package
or lockfile change; configuration; or infrastructure contact. It does **not** implement publication,
change topology-authoring behavior, generate a plan, alter the scenario schema, or unseal any path.

## 15. Migration & backward compatibility

- `controlplane.security/v1alpha1` is preserved unchanged; `controlplane.security/v1alpha2` is a new,
  additive schema version that adds the typed optional `spec.topology` + `spec.publicationProvenance`
  blocks (PR A). Existing `v1alpha1` definitions and versions stay valid and plannable; there is no
  automatic migration or mutation of old `EnvironmentVersion` rows, and no same-version schema drift.
- New provenance columns + `publication_fingerprint` on `EnvironmentVersion` are nullable/backfilled
  (PR B); publication is purely additive.
- `DeploymentPlan` generation is unchanged: it binds exactly one `environment_version_id` and pins
  `version_content_hash`. Planning may later surface provenance (PR E) but still consumes exactly one
  version.

## 16. Placeholder example (illustrative only)

A published `EnvironmentVersion.spec` (placeholders; not a real definition):

```json
{
  "apiVersion": "controlplane.security/v1alpha2",
  "kind": "Environment",
  "metadata": { "name": "example-env" },
  "spec": {
    "teams": { "count": 2, "isolationPolicy": "strict" },
    "networks": [ { "name": "net-a", "cidrStrategy": "per-team", "isolated": true } ],
    "roles": [ { "name": "target-role", "kind": "target", "image": "placeholder-image", "network": "net-a", "count": 1 } ],
    "requiredPlugins": [ "simulator" ],
    "topology": {
      "schema_version": "secp.topology/v1",
      "nodes": [
        { "id": "target-role", "kind": "target", "label": "t", "role": null, "ip": null, "network": "net-a", "x": 0, "y": 0 },
        { "id": "net-a", "kind": "network", "label": "net-a", "role": null, "ip": null, "network": null, "x": 0, "y": 0 }
      ],
      "edges": [ { "id": "e1", "source": "target-role", "target": "net-a", "kind": "network" } ],
      "networks": [ { "id": "net-a", "label": "net-a", "cidr": null, "isolated": true } ],
      "zones": []
    },
    "publicationProvenance": {
      "topology_document_id": "uuid:<document>",
      "topology_revision_id": "uuid:<revision>",
      "topology_content_hash": "sha256:<topology-hex>",
      "topology_validation_result_id": "uuid:<validation>",
      "topology_validation_result_hash": "sha256:<result-hex>",
      "base_environment_version_id": null,
      "publication_contract_version": "secp.publication/v1"
    }
  }
}
```

`EnvironmentVersion.content_hash` = `content_hash(...)` over this **entire** object; the server-owned
`publication_fingerprint` = `sha256:<fingerprint-hex>` over `{template_id, environment_content_hash}`
and is stored as a column, not inside the hashed definition.
