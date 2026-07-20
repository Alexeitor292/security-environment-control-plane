# Testing & the CI test pipeline

This project runs the **complete** backend regression corpus on every pull request, divided into
balanced parallel shards so failures surface early without dropping any coverage. The division is
machine-checked: the union of the shards is proven equal to the canonical unsharded collection.

- **Targeted commands below are for local development feedback only.**
- **All authoritative shards remain mandatory for every PR.** No changed-file selection ever
  replaces full regression.
- **PostgreSQL-gated tests are required** and run against a real PostgreSQL 16 in CI (one service
  container per shard).
- **Full-suite equivalence is machine-checked** by `scripts/ci/pytest_shards.py verify --collect`.

The canonical corpus is declared in [`.ci/pytest-suite.json`](../../.ci/pytest-suite.json): roots
(`apps/api/tests`, `tests`, `contracts/scenario-schema/tests`, `apps/commissioning/tests`,
`apps/deployment/tests`, `apps/management/tests`), the shard count (4), and two narrow exclusions
(`apps/worker/secp_worker/preflight/self_test.py` and
`apps/worker/secp_worker/readiness/self_test.py`, runtime worker modules that match the `*_test.py`
glob but are not pytest suites).

All commands are cross-platform (pure Python + `uv run`); nothing depends on bash-only behaviour.

## Everyday targeted runs (development feedback)

```bash
# one test file
uv run pytest apps/api/tests/test_environment_publication_service.py -q

# one test function / node
uv run pytest apps/api/tests/test_environment_publication_service.py::test_exact_repeat_is_idempotent -q

# publication tests (service + migration + boundary + hash compat)
uv run pytest apps/api/tests/test_environment_publication_service.py \
              apps/api/tests/test_environment_publication_migration.py \
              apps/api/tests/test_environment_publication_boundaries.py \
              apps/api/tests/test_topology_validation_result_hash_compat.py -q

# fast keyword-filtered feedback
uv run pytest apps/api/tests -k "publish and idempoten" -q
```

These are for fast iteration. They are **not** a substitute for the full sharded corpus that the
PR gate runs.

## PostgreSQL-enabled local testing

PostgreSQL-gated tests (`test_postgres_*`, migration/concurrency/immutability) `skip` unless
`SECP_TEST_POSTGRES_URL` points at a real PostgreSQL 16. Start one and export the URL:

```bash
docker run -d --name secp-pgtest \
  -e POSTGRES_USER=secp -e POSTGRES_PASSWORD=secp -e POSTGRES_DB=secptest \
  -p 5432:5432 postgres:16-alpine

export SECP_TEST_POSTGRES_URL='postgresql+psycopg://secp:secp@localhost:5432/secptest'
```

If host port 5432 is taken, map another (e.g. `-p 55432:5432`) and use `localhost:55432` in the
URL. SQLite never proves PostgreSQL trigger/`SELECT FOR UPDATE` behaviour — those tests must run
against real PostgreSQL.

## The canonical corpus and the shards

The sharding/verification tool is [`scripts/ci/pytest_shards.py`](../../scripts/ci/pytest_shards.py).

```bash
# how many shards are configured
uv run python scripts/ci/pytest_shards.py shard-count

# print the shard assignment (files, estimated weight, new/estimated files)
uv run python scripts/ci/pytest_shards.py plan

# list the files in one shard
uv run python scripts/ci/pytest_shards.py list --shard 0

# collected node count for one shard
uv run python scripts/ci/pytest_shards.py count --shard 0
```

### Run one CI shard locally

```bash
# exactly what CI shard 0 runs (real PostgreSQL required for the PG-gated files)
uv run python scripts/ci/pytest_shards.py run --shard 0 -- -q

# with JUnit output, like CI
uv run python scripts/ci/pytest_shards.py run --shard 2 -- -q --junitxml=junit-shard-2.xml
```

Everything after `--` is forwarded to pytest. Do **not** add `-x` / `--maxfail` — a shard must run
its complete slice.

### Run every shard

```bash
for s in 0 1 2 3; do
  uv run python scripts/ci/pytest_shards.py run --shard "$s" -- -q || echo "shard $s FAILED"
done
```

### The canonical unsharded full suite (one-command audit)

The complete corpus remains available as a single run — the authoritative equivalence baseline:

```bash
uv run python scripts/ci/pytest_shards.py run-all -- -q
# equivalent to:
# uv run pytest apps/api/tests tests contracts/scenario-schema/tests \
#   apps/commissioning/tests apps/deployment/tests apps/management/tests -q
```

## Inventory verification (the completeness proof)

```bash
# file-level: roots exist, every managed test file assigned exactly once, no unmanaged
# pytest file outside the roots, exclusions valid
uv run python scripts/ci/pytest_shards.py verify

# node-level: additionally prove the sharded node-ID union == the canonical collection and the
# shards are pairwise disjoint (parametrized nodes included; volatile UUID tokens canonicalized)
uv run python scripts/ci/pytest_shards.py verify --collect
```

`verify --collect` is what the `backend-test-inventory` CI job runs. It **fails closed** if a test
file is omitted, duplicated, or appears outside the managed roots without being allow-listed — so a
newly added test cannot silently disappear. A new test file placed under a canonical root is
included automatically; a pytest-shaped file added elsewhere fails the inventory until it is either
moved under a root or given a justified `exclusions` entry.

## Dedicated Linux-root gates

The canonical shards collect the root-only modules, but a normal non-root run legitimately skips
their privileged cases. CI therefore has four additive Linux jobs that execute the production
security backends under `sudo`:

- `backend-realfs-root` runs `apps/commissioning/tests/test_commissioning_realfs.py`;
- `backend-discovery-activation-root` runs
  `tests/test_pr5f_discovery_activation_root.py` against the fixed production state layout;
- `backend-deployment-root` runs the deployment manifest, pinned-executable, and real-process
  root-security modules; and
- `backend-management-root` runs `apps/management/tests/test_management_root.py`.

Each job first proves its trusted ancestor/layout preconditions and then parses its JUnit artifact.
It fails closed on a missing report, under-collection, any skip, failure, or error; a pytest exit code
alone is not accepted as proof that privileged coverage ran. These jobs are required by the stable
backend aggregate gate in addition to static checks, inventory, all four PostgreSQL-enabled shards,
and `pip-audit`.

## Timing / rebalancing

Shards are balanced by measured per-file runtime, committed in
[`.ci/pytest-timings.json`](../../.ci/pytest-timings.json). Regenerate from a JUnit run:

```bash
# 1. produce a JUnit XML for the whole canonical corpus (real PostgreSQL for full timings)
uv run python scripts/ci/pytest_shards.py run-all -- -q --junitxml=baseline.xml

# 2. regenerate the committed per-file weights
uv run python scripts/ci/pytest_shards.py weights-from-junit --junit baseline.xml

# 3. review the new balance
uv run python scripts/ci/pytest_shards.py plan
```

Assignment is a deterministic greedy longest-processing-time bin-pack: the same commit + weights
always produce the same shards. New files without a committed weight get the median weight as a
fallback estimate, so they are balanced reasonably until the next rebalance.

## Interpreting shard failures

- Each shard is an **independent** GitHub job with `fail-fast: false`; one shard going red does not
  cancel the others, so you see every failing slice in one run.
- A red shard shows its assigned file list and the normal pytest failure output. Reproduce locally
  with `run --shard N` (above).
- The **`Backend (format, lint, types, tests, schema, boundary, security)`** aggregate check is the
  branch-protection gate: it is green only if **every** backend job — static, inventory, all four
  pytest shards, and security — succeeded.
- The aggregate also requires all four dedicated Linux-root jobs described above; none is optional
  or represented by a non-root shard skip.
- If `backend-test-inventory` fails, the shards may all be green yet the corpus is
  incomplete/duplicated: read its output; it names the omitted/duplicated/unmanaged file.
- JUnit XML for each shard is uploaded as an artifact (`junit-backend-shard-N`) even on failure.

## What must never change to "make tests pass"

Do not weaken assertions, add sleeps/retries to mask races, skip slow tests, `xfail` failures, use
`continue-on-error`, add rerun-on-failure, or exclude PostgreSQL/migration/immutability/concurrency/
boundary/schema/security tests. The full PR regression gate is mandatory; nightly-only full runs are
not a substitute.
