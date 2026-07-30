# SECP File Ownership — the parallel-agent collision map

**Purpose.** Multiple agents will work this repository at once, some in isolated git worktrees.
A worktree isolates the *working tree* and nothing else. This document says who may touch what,
so that concurrent work does not clobber itself or silently build a second system.

**Observed at:** `e72f28f` (`main`). Churn figures are distinct non-merge commits touching the
path, measured with
`git log --no-merges --name-only --format=%H -- . | sort | uniq -c | sort -rn`.

**Read churn as a rate, not a count.** 29 of 104 commits sounds minor; 29 of the ~36 backend
milestones that could plausibly touch `enums.py` is ~80%. The rate is what predicts collision.

---

## Tier 1 — Serialised (at most one live task contract, repo-wide)

### The Alembic head literal

The current head `a1d4f7c2e9b6` appears **55 times across 25 files** spanning four planes.
Verified with `git grep -c a1d4f7c2e9b6`:

```
apps/deployment/tests/test_discovery_activation_local_adapter.py      5
.github/workflows/ci.yml                                             5   (hard-deny for agents)
apps/api/tests/test_worker_enrollment_migration_postgres.py          4
apps/api/tests/test_controller_activation_receipt_migration.py       4
tests/test_python_image_package_closure.py                           3
apps/deployment/secp_discovery_activation/migration_heads.py         3
apps/api/tests/test_worker_enrollment_migration.py                   3
apps/api/tests/test_pr5h_schema_parity.py                            3
apps/api/migrations/versions/a1d4f7c2e9b6_*.py                       3
apps/api/secp_api/worker_enrollment_schema.py                        2
apps/deployment/tests/test_migration_head_compatibility.py           2
… plus 14 further files at 1–2 occurrences each
```

Advancing the head is an **atomic, non-parallelisable** edit. Any claim that one module is "the
single place that definition lives" is false — `worker_enrollment_schema.py:31`,
`migration_heads.py`, `infra/dev/image_smoke.py:38` and `ci.yml` each hold an independent copy.

**Rule:** one live migration contract at a time, repo-wide, recorded before work starts. The
unlock minter refuses a second token while one is outstanding. Because `.github/**` is an
unconditional hard-deny for agents, a head advance **requires operator involvement** — escalate
before starting.

### Shared enum vocabularies

`apps/api/secp_api/enums.py` — `Permission` (56 members) and `AuditAction` (217 members) are
append-at-the-same-anchor lists. Historically every addition lands on the identical line, so two
parallel agents adding a member **always** textually conflict — and CI detects no *semantic*
duplicate at all. Claim exclusive ownership before adding a member.

---

## Tier 2 — Exclusive (one live task contract each)

| Path | Churn | Why it collides |
| --- | --- | --- |
| `apps/api/secp_api/enums.py` | 29 | See Tier 1 |
| `apps/api/secp_api/models.py` | 25 | Now largely a **registration manifest**; the live conflict is the tail import block (~`:2005-2061`), where each satellite model module adds a line. Two registration styles already coexist there |
| `apps/api/secp_api/main.py` | 24 | App factory: middleware order, redacted-error handler, `_REDACTED_VALIDATION_ROUTES`, and 24 `include_router` calls |
| `docs/STATUS.md` | 22 | Append-only narrative block; high-frequency low-severity text conflict sitting on a low-frequency **high-severity** coupling to `test_project_status_truthfulness.py` |
| `apps/api/secp_api/immutability.py` | 21 | One 1516-line `before_flush` listener holding the portable counterpart to every PostgreSQL trigger |
| `apps/web/src/api/client.ts` | 16 | One `api` object listing every endpoint, plus `resolveApiBase` and `buildRequestHeaders` |
| `apps/web/src/main.tsx` | 15 | The single route table (public routes + `AuthBoundary` subtree) |
| `apps/web/src/api/types.ts` | 15 | 912 lines; `Principal`/`AuthConfig` share the file with every feature DTO |
| `apps/api/secp_api/errors.py` | 14 | Error base-class contract (`redacted`, `www_authenticate`) shared by every milestone |
| `apps/worker/secp_worker/main.py` | 13 | The single worker registration point: `SHIPPED_WORKFLOWS`, `SHIPPED_ACTIVITIES`, consumer loops, the only queue binding |
| `apps/api/secp_api/config.py` | 12 | One `Settings` class and one production-refusal problems list; three `@model_validator`s already |
| `apps/web/src/App.tsx` | 11 | App shell / nav; every new surface adds an entry |
| `apps/api/secp_api/dispatch.py` | 8 | Repeatedly re-hardened safety choke point |
| `apps/worker/secp_worker/temporal_app.py` | 7 | Every activity body plus the shipped sealed default instances |
| `apps/api/tests/conftest.py` | 7 | The repo's only conftest; file-backed SQLite shared by the whole API corpus |
| `apps/management/secp_management/layout.py` | — | Code-owned production filesystem layout, unit names, forbidden roots |
| `pyproject.toml` | 8 | **Five parallel lists** must stay in sync (hatch wheel packages, uv, pytest `pythonpath`, pytest `testpaths`, `mypy_path`) plus `[project.scripts]`. `testpaths` has already drifted from `.ci/pytest-suite.json` roots |

### Guard tests — exclusive, and changing one changes an invariant

`tests/test_architecture_boundary.py` (8) · `tests/test_provisioning_boundary.py` (7) ·
`tests/test_ci_workflow.py` (7) · `tests/test_pr5h_architecture_guards.py` ·
`tests/test_discovery_boundary.py` · `tests/test_management_plane_boundary.py` ·
`tests/test_pr5f_discovery_activation_boundary.py` · `tests/test_no_real_endpoints.py` ·
`tests/test_project_status_truthfulness.py`.

Weakening a guard so a change passes is a policy violation, not a fix.

---

## Tier 3 — Operator-only (unconditional hard-deny for agents)

| Path | Reason |
| --- | --- |
| `.github/**` | CI workflow definitions; the trusted-ancestry rule must not be weakened, repaired, special-cased, skipped or warned through |
| `infra/ci/**` | The trusted-ancestry attestation is a security control |
| `apps/management/secp_management/production.py` | Production trust-root loader |
| `apps/management/secp_management/signing.py` | Release-signing trust anchor (`SHIPPED_TRUST_ROOT`) |
| `.env`, `**/*.pem`, `**/*.key` | Secrets material |
| The migration unlock directory (outside the repo) | Operator-issued tokens only |
| Any named safety seal | See `SAFETY_INVARIANTS.md` §5–§6 |

Note `.ci/pytest-suite.json` is *not* Tier 3, but adding a test **root** also requires a
`pyproject.toml` edit and a `ci.yml` edit — and `ci.yml` is Tier 3. Escalate instead.

---

## Tier 4 — Free

New files inside a single plane, owned by one task contract. Prefer adding a new module over
extending a Tier 2 file, **except** where that would create a second system — see
`CLAUDE.md` §4 and the per-plane rules in `.claude/rules/`.

---

## Shared runtime resources (not files, and worktrees do not partition them)

| Resource | Constraint |
| --- | --- |
| `infra/dev` Compose stack | Singleton: one fixed project name, fixed host ports 5432 / 7233 / 5173. One agent at a time |
| `SECP_TEST_POSTGRES_URL` | 28 modules `DROP SCHEMA IF EXISTS public CASCADE`. Concurrent agents need a **distinct database each** |
| `apps/api/tests/conftest.py` SQLite | File-backed. Never run two suites in the same checkout |
| `.venv`, `.env` | Gitignored, therefore **absent from every fresh worktree**. First step in a new worktree: `uv venv && uv pip install -e ".[dev]"` |
| `node_modules` | Same; `apps/web` needs `npm ci` in a fresh worktree |

---

## Maintenance

`tests/program/test_program_file_ownership.py` automatically fails when a new file starts
carrying the Alembic head literal without being listed in Tier 1, and when the stated carrier
count drifts from the tree — so that cluster cannot silently grow. This document is excluded from
its own census. The rest of the map is a snapshot and needs periodic re-derivation from churn.
