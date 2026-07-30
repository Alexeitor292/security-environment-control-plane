---
paths:
  - "tests/**"
  - "apps/api/tests/**"
  - "apps/commissioning/tests/**"
  - "apps/deployment/tests/**"
  - "apps/management/tests/**"
  - "contracts/scenario-schema/tests/**"
  - ".github/**"
  - ".ci/**"
  - "scripts/ci/**"
---

# Tests, CI, and the validation harness

## `.github/**` and `infra/ci/**` are unconditional hard-denies

The trusted-ancestry attestation is a security control. Do not weaken, repair, special-case, skip
or warn through the root-owned ancestor rule, and do not edit the workflow to route around it.
The controlled runner is separate, operator-owned work.

If CI reports `infrastructure_invalid` (exit 78), that is the control **working**. It blocks
mark-ready and merge — it does not block local implementation, commit, push, or a draft PR.

## The corpus is declared, not discovered

`.ci/pytest-suite.json` declares 6 roots, `shard_count` 4, and 2 exclusions.
`scripts/ci/pytest_shards.py` proves at pytest **node** level that the shard union equals the
canonical collection and is pairwise disjoint.

- A new test file **inside** an existing root is auto-included — no manifest edit.
- A new pytest-shaped file **outside** the roots fails the inventory closed.
- Adding a new test **root** requires editing `.ci/pytest-suite.json` *and* `pyproject.toml`
  `testpaths` — and `.github/workflows/ci.yml` is a hard-deny, so escalate.

## A local green run is not the gate

1. `pyproject.toml` `testpaths` omits `contracts/scenario-schema/tests`, which the CI manifest
   includes. `uv run pytest` is a **narrower** corpus than CI.
2. 26 modules skip **silently** without `SECP_TEST_POSTGRES_URL`. Absence of failure is not
   coverage.
3. Root-elevated jobs fail closed on skip/under-collection because the pytest exit code is not
   trusted — but `backend-pytest`, the authoritative corpus job, has no equivalent JUnit floor.

## Guard tests are load-bearing — changing one changes an invariant

`test_architecture_boundary.py` (cross-plane imports) · `test_provisioning_boundary.py` (OpenTofu
seals) · `test_discovery_boundary.py` (mutation-incapable discovery) ·
`test_management_plane_boundary.py` · `test_pr5f_discovery_activation_boundary.py` ·
`test_pr5h_architecture_guards.py` · `test_no_real_endpoints.py` ·
`test_project_status_truthfulness.py` · `test_ci_workflow.py` · `test_compose_config.py`.

`test_ci_workflow.py` pins ~54 assertions to job names, steps and the shard manifest; it must
move in lockstep with `ci.yml`. Since `ci.yml` is a hard-deny for agents, so is any change here
that assumes a workflow edit.

Weakening a guard to make a change pass is a policy violation, not a fix. Escalate instead.
