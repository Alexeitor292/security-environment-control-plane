# SECP — Security Environment Control Platform

An enterprise control plane for creating, operating, validating, resetting and reporting on
isolated security environments. It owns desired state; infrastructure providers are execution
targets and sources of observed state, never the system of record.

Governing documents: [`docs/PROJECT_CHARTER.md`](docs/PROJECT_CHARTER.md) (intent, domain model,
the 17 architectural invariants in §6) and [`docs/adr/`](docs/adr/) (28 accepted ADRs).

---

## 1. The authority rule

**Published code and exact GitHub state are authoritative. Documentation prose is a claim to be
verified, never evidence of completion.**

This is not a stylistic preference. `docs/STATUS.md` currently calls itself the "Current
Capability Ledger" while sitting two shipped milestones behind HEAD: it names an Alembic head
that is two revisions stale and describes a transport as sealed that now exists. An audit found
30 overclaims and 43+ stale claims across STATUS, README, ADRs and docstrings.

Consequences for every session:

- Never report a capability as working because a document says so. Open the code.
- Never mark work complete from a subagent's report. Reports are input, not proof.
- A passing local test run is **not** the gate (see §5).

---

## 2. Hard boundaries — unconditional, no unlock path

Never, on any branch, for any reason:

- force push, or rewrite published history (`rebase`, `reset --hard`, `commit --amend`,
  `filter-branch`, `filter-repo`, `update-ref`, reflog deletion);
- push to `main`;
- mark a pull request ready (`gh pr ready`, or `gh pr create` without `--draft`), or merge;
- change production trust roots or release-signing anchors;
- mutate a provider, hypervisor or managed host; contact one over SSH;
- run OpenTofu/Terraform `apply` or `destroy`;
- change a safety seal (`_B1A_SUBPROCESS_SEALED`, `_PLAN_ONLY_PROCESS_SEALED`,
  `PlanExecutionGate`, `SHIPPED_TRUST_ROOT`, `SealState`/`read_seals`,
  `assert_inline_execution_allowed`);
- weaken, repair, special-case, skip or warn through the trusted-ancestry rule, or edit
  `.github/**` or `infra/ci/**`;
- commit secrets, credentials, tokens, real endpoints, or machine-specific paths.

Authoring an Alembic migration is **approval-gated**, not forbidden: it requires a single-use
operator-issued unlock token (§6). Everything above has no such path.

These are enforced by committed hooks in `.claude/hooks/`. A hook denial is a decision, not a
prompt: **stop, or choose a compliant alternative. Never wait for a human to approve past it.**

---

## 3. Plane boundaries

| Plane | Package | Owns |
| --- | --- | --- |
| Control plane API | `apps/api/secp_api` | Domain model, RBAC, publication, planning, audit, dispatch |
| Worker | `apps/worker/secp_worker` | Temporal workflows, provisioning seam, discovery, secret resolution |
| Management | `apps/management/secp_management` | `secpctl`, host bootstrap, enrollment engine |
| Commissioning / Deployment | `apps/commissioning`, `apps/deployment` | Operator packaging, discovery activation |
| Contracts / Plugins | `contracts/`, `plugins/` | Plugin capability contract, scenario schema, Simulator, Proxmox |
| Frontend | `apps/web` | React control-plane UI |

Machine-enforced import rules (breaking one fails CI, not review):

- `apps/api` must not import `subprocess`, a provider SDK, an IaC tool, or worker internals.
  `httpx` is permitted only in `oidc.py` and `oidc_preflight.py`.
  — `tests/test_architecture_boundary.py`
- `apps/api` must not import `secp_management`. — `tests/test_pr5h_architecture_guards.py`
- `apps/management` must not import `secp_api` or `secp_discovery_activation`, and must stay
  local-first (no provider/IaC/SSH/subprocess).
  — `tests/test_management_plane_boundary.py`, `tests/test_pr5f_discovery_activation_boundary.py`
- The discovery package is structurally mutation-incapable. — `tests/test_discovery_boundary.py`
- The management plane is provider-neutral: no Proxmox/K8s/AWS/Azure/GCP/VMware concept may
  appear in any management identity, release, evidence, enrollment or config surface.

The API never executes privileged infrastructure actions. Execution is dispatched — inline
(Simulator only, dev/test) or enqueued as a `WorkflowRun` + outbox row the worker publishes.

---

## 4. Reuse before you build

This repository's largest structural risk is a *second* system rather than a bug. Before adding
any seam, resolver, transport, identity model, adapter or CLI verb, search for the canonical one
and extend it. The path-scoped rules in `.claude/rules/` name the canonical system for each tree.

Known near-duplication traps: four worker-identity models already coexist; three secret-resolver
families; five worker HTTPS transports; two Compose-driving host adapters; two single-active-row
idioms; three console-script CLIs with overlapping verbs. `PR5F "creates no second enrollment
system"` is a deliberate, hard-won property — preserve it.

---

## 5. Validation tiers

| Tier | Command | Use |
| --- | --- | --- |
| Focused | `uv run pytest <paths> -q` | Edit loop |
| Affected | focused + `uv run ruff check apps contracts plugins scripts tests` + `uv run ruff format --check …` | Before pushing |
| **Gate** | exact-head CI | The only proof |

**A local green run is not the gate**, for two verified reasons:

1. `pyproject.toml` `testpaths` omits `contracts/scenario-schema/tests`, which
   `.ci/pytest-suite.json` `roots` includes. `uv run pytest` is a *narrower* corpus than CI.
2. 26 test modules skip **silently** without `SECP_TEST_POSTGRES_URL`. Absence of failure is not
   evidence of coverage.

The two required GitHub contexts are
*"Backend (format, lint, types, tests, schema, boundary, security)"* and
*"Frontend (types, lint, build, tests, security)"*.

An `infrastructure_invalid` CI classification does not block local work, commit, push, or opening
a draft PR — it blocks **mark-ready and merge**, which are Juan's alone regardless.

---

## 6. Migrations

One linear Alembic chain lives in `apps/api/migrations/versions`. Compute the head from the files
themselves — never trust a document for it.

- Authoring requires a single-use unlock token issued by
  `scripts/program/New-MigrationUnlock.ps1`. Agents may never create, modify, copy, rename,
  delete or self-issue one.
- The token binds repository, branch, base SHA, migration filename, purpose, issuer and expiry;
  max TTL 60 minutes; consumed atomically; one token can never authorise another migration or
  another branch.
- **CI cannot detect branching heads.** Two agents on two branches each writing the same
  `down_revision` produce two PRs that both pass independently; the break appears only after the
  second merge. Therefore **at most one live migration contract exists at a time.**
- Advancing the head is an atomic ~25-file edit across four planes. It is not parallelisable.
- Approval to author a migration is not approval to change the head, run it against a database,
  deploy, or merge.

---

## 7. Where project truth lives

- [`docs/program/SAFETY_INVARIANTS.md`](docs/program/SAFETY_INVARIANTS.md) — machine-enforced
  invariants, what enforces each, and how each could be silently broken.
- [`docs/program/FILE_OWNERSHIP.md`](docs/program/FILE_OWNERSHIP.md) — collision map. Consult
  before editing a shared file; it is how parallel agents avoid clobbering each other.
- [`docs/program/AGENT_OPERATING_MODEL.md`](docs/program/AGENT_OPERATING_MODEL.md) — roles, git
  authority, escalation, worktree scheduling.

The roadmap is deliberately **not** inlined here. Read the charter §17 when you need it.

---

## 8. Escalate to Juan

Architecture · migration · trust · provider authority · merge · deployment · residual risk.

Everything else: decide, act, and record why. When you escalate, state the decision needed, the
options, and your recommendation — not just the question.
