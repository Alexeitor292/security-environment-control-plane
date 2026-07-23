# ADR-027 — durable worker-enrollment foundation (persistence, CAS, nonce ledger, migration-head compatibility)

- **Status:** Accepted for SECP-PR5H-A. Turns the PR5G *pure* enrollment transition contract
  (ADR-026) into a **durably persisted** foundation: a PostgreSQL enrollment schema, a transactional
  revision/predecessor compare-and-swap, a single-use nonce ledger, an at-least-once step-receipt
  dedup table, and restart/crash recovery at the persistence-service layer. It delivers **no**
  network transport, **no** enrollment API, **no** UI, and **no** mutating production CLI — those are
  SECP-PR5H-B. Automated enrollment is **NOT** complete after this ADR.
- **Date:** 2026-07-22
- **Milestone:** SECP-002B-1B — **PR5H-A** (durable enrollment foundation), following PR5G
  (ADR-026: real host adapters + enrollment transition contracts).
- **Supersedes in part:** ADR-026's self-contradictory delivery claims (see *Corrections* below).

## Problem

PR5G shipped the enrollment transition contract as **pure, deterministic functions over immutable
value objects** — deliberately with no datastore, no compare-and-swap, no single-use-nonce ledger and
no restart recovery. That is honest but not yet usable: replay-uniqueness and single-use are contract
*obligations* that only hold once a persistence layer enforces them across a persisted history, and
an interrupted enrollment cannot resume. A customer must never hand-manage enrollment revisions or
recover an interrupted enrollment by hand.

PR5H-A supplies exactly that persistence foundation — and nothing that would prematurely expose a
network or browser surface.

## Corrections to ADR-026 (code is authoritative)

ADR-026 contradicts itself and the code in ways that would produce a wrong schema if followed
literally. These are corrected here and in ADR-026 itself:

1. **ADR-026 §85 vs §98-102** — §85 heads a section "durable enrollment state machine … (this PR)"
   while §98-102 correctly states there is **no** datastore/CAS/nonce ledger/restart recovery in
   PR5G. The deferral text is correct; the heading was not. PR5H-A is where durability arrives.
2. **The CAS key is `revision`, never `sequence`.** ADR-026 §96 and the module docstring say every
   transition is "sequence-chained". Empirically `refuse()` and `require_recovery()` bump **only**
   `revision` + `predecessor_digest`, leaving `sequence` unchanged: `healthy(rev 5, seq 5)`
   `--refuse-->` `(refused, rev 6, seq 5)`. A `WHERE sequence = :expected` predicate is silently
   wrong. The reviewed CAS predicate is
   `WHERE enrollment_id = :id AND revision = :expected_revision AND state_digest = :expected_digest`.
3. **`refused` is not a terminal.** `require_recovery()` short-circuits only on `recovery_required`,
   so `refused → recovery_required` is a live edge; and `refuse()` never consults the active set, so
   `healthy` can legally be flipped to `refused`. **`recovery_required` is the only absorbing
   terminal.** The database transition guard admits: the five forward edges, plus
   `{any except refused, recovery_required} → refused`, plus `{any except recovery_required} →
   recovery_required`.
4. **The state constant is `worker_bound`**, not ADR-026 §94's `worker_identity_bound`. A CHECK
   constraint written from the prose would reject every real row.
5. **Exact-retry idempotency holds only *at* the target state.** Re-delivering an identical
   controller offer *after* the state advanced raises `enrollment_wrong_state`. A network transport
   is at-least-once, so a **step-receipt dedup table is mandatory**, not optional.
6. **`EnrollmentState` is not self-sufficient.** It drops `invitation_id`, `controller_origin`,
   `controller_trust_anchor_hex` and `created_at`, so the invitation must be persisted in its own
   table joined by `enrollment_id`.
7. **Single-use needs two independent unique keys.** `enrollment_id == invitation.digest()` collapses
   only *identical* invitations; the same nonce with a different expiry yields a *different*
   `enrollment_id`. The ledger therefore carries a `UNIQUE(invitation_id)` independent of the state
   primary key.
8. **`secpctl` already ships but is permanently sealed** (the CLI builds the sealed default
   `EngineDeps`; `production_engine_deps` has no non-test caller). PR5H-B *wires* an existing
   entrypoint; it does not create one, and console scripts stay frozen at exactly three.
9. **Not every failure is a `ManagementError`.** `scan_forbidden` raises `DescriptorError` with
   colon-bearing codes; the real `verify_handoff` raises `ActivationHandoffError`. Every catch site
   must handle the full set and re-map to a bounded code.

## Decision — bounded migration-head rolling-upgrade compatibility

The Alembic head is a **validated field of the signed `ControllerOffer`**
(`controller_migration_head`). PR5H-A adds a migration, which changes the head. Replacing the pinned
value would invalidate every already-issued signed offer and force a lockstep controller upgrade, so
the pin is **widened into a bounded compatibility window** — explicitly *not* an accept-any-head
policy:

- **One code-owned compatibility definition** contains exactly two values: the legacy
  `d8f1a2b3c4e5` and the new PR5H head `b6e2f4a9c1d7`.
- **New offers emit only the new head.** Issuance is single-valued; the window exists solely for
  *validation* of already-issued PR5F offers.
- **Accepting an old signed offer never implies PR5H persistence exists.** The two concepts are kept
  strictly separate:
  - `ACCEPTED_CONTROLLER_MIGRATION_HEADS = (legacy, pr5h)` — signed-contract validation only;
  - `RUNTIME_REQUIRED_MIGRATION_HEAD = pr5h` — **every** PR5H operation (repository, CAS, nonce
    ledger, recovery, and later the transport/API/CLI) must first *independently observe* the live
    controller database head and require the new value.
- **Unknown, older, malformed, branched or future heads refuse closed.**
- Signatures remain bound to the exact declared head; a downgrade substitution is refused.
- **Removing legacy compatibility requires a later explicit deprecation PR**, once every issued PR5F
  offer has expired or been retired. The window is documented, not open-ended.

## Decision — API-side contract mirror (plane boundary preserved)

The reviewed plane boundary forbids `apps/api/secp_api` from importing **any** `secp_management`
module. That boundary is **not** weakened and `secp_management.enrollment` is **not** allowlisted.
Instead `apps/api/secp_api/worker_enrollment_contract.py` mirrors **only** the pure transition
contract the persistence service needs, following the five existing `*_contract.py` precedents. The
mirror contains only: contract/schema version constants, closed state names, permitted
transition/predecessor relationships, bounded field grammar + validation, canonical serialization,
digest derivation, the safe public projection, bounded refusal/recovery reason codes, and the pure
deterministic transition semantics. It contains **no** production composition, host adapter,
filesystem/layout helper, systemd/Compose behavior, evidence key operation, transport, or rollback
mutation.

Duplication is permitted **only** to preserve the reviewed boundary; it is not licence to duplicate
privileged management behavior. It is held safe by an exhaustive **cross-plane byte-parity corpus**
that imports both implementations from the test layer only and requires, over a deterministic corpus
of valid and invalid cases, either byte-identical canonical output **and** digest, or refusal with
the **same** bounded reason code — plus a structural test proving the mirror imports no management,
host-adapter, subprocess, filesystem, systemd, container, provider, network or secret module. Any
future contract edit fails CI until both copies and the corpus are updated together.

## Decision — `deployment_site_label` (terminology)

"Site" in PR5H is a **provider-neutral deployment-site label** that groups and binds a
controller/worker installation *inside one Organization*. It is **not** a tenant, an authorization
boundary, a physical address, a provider region, a network endpoint, or an infrastructure target.

- **Organization remains the only authorization and tenancy boundary.** PR5H introduces **no**
  per-site RBAC and **no** first-class `Site` entity; both remain future work.
- `deployment_site_label` is a closed opaque identifier: 1–120 characters of letters, numbers, dot,
  underscore and hyphen only — no slash, colon, `@`, whitespace, URL, hostname, IP, path, provider
  name, region, credential or secret reference. One shared grammar helper validates it.
- It is persisted on the invitation, the durable enrollment state, the nonce ledger, and the
  installation binding, and is **immutable after invitation issuance**.
- Lookups and mutations bind **both** the authoritative `organization_id` from the authenticated
  identity **and** the exact `deployment_site_label` from the *persisted* record. Neither value is
  ever trusted from worker transport input to select a row: rows are loaded by opaque enrollment /
  invitation identity, then their persisted organization + site binding is compared independently.
- Within one organization, cross-site substitution refuses: an invitation for site A cannot enroll a
  worker transaction bound to site B, an offer/result from A cannot advance B, and retries/recovery
  stay bound to the original deployment site.
- It is distinct from `WorkerDiscoveryNode.node_label` (which identifies one worker node); multiple
  worker nodes may belong to one deployment site.

## Decision — durable persistence, CAS, and the nonce ledger

Four provider-neutral tables in the control plane (PostgreSQL is the transactional system of record):

1. **`worker_enrollment_invitation`** — the invitation fields the state deliberately drops
   (`invitation_id`, `controller_origin`, `controller_trust_anchor_hex`, `created_at`) plus
   organization + `deployment_site_label`, with **`UNIQUE(invitation_id)`** — the single-use nonce
   key, independent of the state primary key. Consumption is one atomic conditional UPDATE
   (`WHERE invitation_id = :nonce AND consumed IS false`); a rowcount ≠ 1 is
   `enrollment_nonce_replayed`.
2. **`worker_enrollment_state`** — the head row carrying all 17 `EnrollmentState` fields **in
   declaration order**, with `revision`/`sequence` as integers and `expires_at`/`updated_at`
   persisted as **TEXT verbatim**. The canonical form embeds those raw strings and `…Z` vs `…+00:00`
   digest *differently*, so they are never round-tripped through `timestamptz`. A shadow
   `expires_at_ts` column exists **solely** to make the recovery sweep indexable, and a
   non-canonical `observed_at` records real wall-clock progress (because `refuse()` /
   `require_recovery()` legally leave `updated_at` stale). Plus a derived `state_digest`.
3. **`worker_enrollment_revision`** — append-only history, `UNIQUE(enrollment_id, revision)`.
4. **`worker_enrollment_step_receipt`** — at-least-once dedup,
   `UNIQUE(enrollment_id, step, input_digest) → resulting_revision`.

**Compare-and-swap.** Every transition is one conditional UPDATE
`WHERE enrollment_id = :id AND revision = :expected_revision AND state_digest = :expected_digest`
plus one append-only history row, in one transaction. The `state_digest` term is what makes the
predecessor chain *enforceable* rather than decorative: a row edited out of band cannot satisfy it. A
lost CAS is the closed code `enrollment_revision_conflict`. Two concurrent requests can never both
advance the same revision.

**Delegate, never pre-screen.** Check order is part of the observable contract (a wrong-signer offer
against an advanced state must yield `enrollment_controller_mismatch`, not `enrollment_wrong_state`),
so the service always loads, calls the **pure** transition, and lets it decide the code.

**Identity-based no-op detection.** The pure functions return the *same object* on an exact retry;
the service detects that and performs **no write** — writing anyway would inflate the revision and
break the chain.

**Rehydration must re-assert participant separation (repository requirement).** While mirroring the
contract we found and proved a real defect: the self-enrolment guard checked only
`worker_installation_id` against `controller_installation_id`, never the **key ids**. A worker
declaring a *different* installation id while reusing the controller's key id bound cleanly and drove
an enrollment all the way to `healthy`, collapsing both signature bindings
(`record_controller_offer` → `controller_key_id`, `record_worker_result` → `worker_key_id`) onto a
single key while every check reported success. Both planes now refuse
`worker_key_id == controller_key_id` with the existing bounded `enrollment_worker_mismatch`, at
binding time *and* on every later transition, via one pure helper
(`_assert_participants_separated`) — so a corrupted or rehydrated same-key row can neither
exact-retry a binding nor advance, verify or become healthy. `refuse()` / `require_recovery()` stay
deliberately unguarded so an operator can always drive a corrupted row to a truthful terminal.

The repository therefore inherits a **non-negotiable requirement, to be satisfied when the
persistence layer lands**: the load path must assert participant separation on the rehydrated state
*before the state is used*, alongside the existing `digest == state_digest` verification. Delegating
to the pure transition is not sufficient on its own — a row that is never transitioned (a read/status
projection, a recovery-sweep candidate, an audit emission) would otherwise be trusted without the
invariant ever being evaluated. A rehydrated row failing separation must be treated as corrupt: refuse
closed with `enrollment_worker_mismatch` and leave the row eligible for `require_recovery`, never
silently repair it.

## Decision — recovery (the database never expires a row on its own)

Expiry is evaluated **only** inside the pure transition from a caller-supplied `now`; the contract
never reads a clock. A trigger or scheduled UPDATE that flipped state would mutate the row *outside*
the digest chain and instantly break every `state_digest`. Recovery is therefore an explicit,
idempotent, restart-safe **sweep** that drives rows through the pure function under the *same* CAS as
any other transition: select active rows past expiry, rehydrate and verify `digest == state_digest`,
apply `require_recovery`, and commit under CAS. A lost CAS means a concurrent writer already moved
the row — skip silently. Exactly one audit per row, emitted only by the CAS winner. `healthy` is
deliberately **not** active and is never swept.

Restart recovery of an in-flight step whose response was lost is resolved by the **step-receipt**
table, not the sweep: the retried request hits the unique constraint, reads the recorded resulting
revision, and returns the stored head row — turning a legitimate network retry into a truthful no-op
instead of a spurious `enrollment_wrong_state`. Recovery moves a stuck enrollment to a truthful
terminal an operator can act on; it never re-drives a transport, and re-enrollment requires a **new**
invitation with a **new** nonce.

## Threat model (PR5H-A surface)

| Threat | Control |
|---|---|
| Replayed invitation / nonce reuse | `UNIQUE(invitation_id)` + atomic conditional consume; durable across restart |
| Concurrent double-advance | CAS on `(revision, state_digest)`; rowcount ≠ 1 refuses `enrollment_revision_conflict` |
| Out-of-band row edit | `state_digest` in the CAS predicate; rehydrate-and-verify on every load |
| Stale / conflicting retry | pure transition decides; step-receipt dedup distinguishes legitimate retry from conflict |
| Cross-organization access | `organization_id` bound from the authenticated identity, never from input |
| Cross-site substitution | persisted `deployment_site_label` compared independently after identity load |
| Downgrade / unknown migration head | bounded accepted-heads window for signatures; runtime head independently required |
| Secret / metadata leakage | only bounded codes, safe fingerprints and opaque labels persist or project; no raw handoff bytes, key material, endpoints, paths or free-form failure text |
| Controller enrolling as its own worker | installation-id separation **and** `worker_key_id != controller_key_id`, asserted at binding and on every later transition in both planes; rehydration must re-assert it |
| Contract fork between planes | exhaustive cross-plane byte-parity corpus + structural import guard |

## Explicitly NOT delivered by PR5H-A

No network transport (the sealed `EnrollmentTransport` stays sealed and is *not* implemented); no
enrollment API routes; no UI; no mutating supported production CLI; no host mutation reachable from a
browser; no worker network enrollment; default `EngineDeps` stays sealed. The new schema may exist
**unused** until PR5H-B. Operator activation, workflow submission, OpenTofu, provider contact and
remote root SSH remain prohibited, and PR6 stays frozen.

**Automated enrollment and one-command installation are NOT complete after PR5H-A.** PR5H-B is the
completion gate and must prove the end-to-end supported path (controller bootstrap, invitation
creation without file editing, worker bootstrap from the non-secret invitation, worker-initiated
HTTPS enrollment, durable progression, restart/lost-response recovery, verified/healthy completion,
no hand-copied offer/result files, no adapter selection, no remote root SSH, and rollback to zero
test-owned residue) before any real-host rollout.
