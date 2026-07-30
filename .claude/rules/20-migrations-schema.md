---
paths:
  - "apps/api/migrations/**"
  - "apps/api/secp_api/models.py"
  - "apps/api/secp_api/enums.py"
  - "apps/api/secp_api/worker_enrollment_schema.py"
  - "apps/deployment/secp_discovery_activation/migration_heads.py"
---

# Schema, migrations, and the head literal

## Authoring is approval-gated

A write under `apps/api/migrations/versions/` requires a single-use unlock token issued by
`scripts/program/New-MigrationUnlock.ps1`. Agents may never create, modify, copy, rename, delete
or self-issue one. See `CLAUDE.md` §6.

Approval to author is **not** approval to change the head, run the migration against a database,
deploy, or merge.

## Compute the head; never quote a document for it

One linear chain in `apps/api/migrations/versions` (36 revisions, base `09a75fd21cf8`). The head
is the revision that appears as no other revision's `down_revision`. `docs/STATUS.md` currently
names a head that is two revisions stale — this is exactly why you compute it.

## CI cannot catch a branching head

Two agents on two branches each writing the same `down_revision` produce two PRs that **both pass
CI independently**, because each branch sees exactly one head. The break appears only after the
second merge. Therefore **at most one live migration contract exists repo-wide at a time.**

## Advancing the head is an atomic ~25-file edit

The current head literal appears **55 times across 25 files** spanning four planes — control
plane, deployment plane, `infra/dev`, CI, tests and docs. Notably it is independently hardcoded
in `apps/api/secp_api/worker_enrollment_schema.py`, `migration_heads.py`,
`infra/dev/image_smoke.py`, `.github/workflows/ci.yml` and `test_pr5h_schema_parity.py`.
Any claim that one module is "the single place that definition lives" is false.

**A migration-bearing milestone is not parallelisable.** Escalate before starting one.

## Write every constraint twice, on purpose

- Migration DDL is authoritative; the ORM `__table_args__` mirrors it verbatim, same name.
  The parity guard compares CHECK constraints **by name only** — predicate text is unverified in
  both directions, so a silently divergent predicate will pass.
- Every new lifecycle table needs **both** a PostgreSQL plpgsql trigger *and* an
  `immutability.py` `before_flush` guard. Only one leaves the other write path unguarded.
- Single-active-row: use the established **partial unique index** with dual
  `sqlite_where`/`postgresql_where` (13 existing examples). A second idiom (a nullable
  `active_marker` boolean + plain UNIQUE) also exists — do not propagate it.

## Enum vocabularies are exclusive-ownership

`Permission` and `AuditAction` in `enums.py` are append-at-the-same-anchor lists: historically
every addition lands on the identical line, so two parallel agents always conflict, and CI
detects no semantic duplicate. Claim exclusive ownership before adding a member.
