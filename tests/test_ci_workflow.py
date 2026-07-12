"""Static regression tests for .github/workflows/ci.yml (SECP CI acceleration).

These validate the workflow's *semantics* (parsed YAML), not brittle whole-file strings: complete
sharded coverage, no feature-branch push duplication, real PostgreSQL per authoritative shard,
no fail-fast / -x / --maxfail / continue-on-error / path-filtering on the required gate, a stable
aggregate gate depending on every backend job, and stable external check names.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
CI_PATH = REPO / ".github" / "workflows" / "ci.yml"
SUITE_PATH = REPO / ".ci" / "pytest-suite.json"

BACKEND_AGG_NAME = "Backend (format, lint, types, tests, schema, boundary, security)"
FRONTEND_NAME = "Frontend (types, lint, build, tests, security)"


@pytest.fixture(scope="module")
def wf() -> dict:
    return yaml.safe_load(CI_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def suite() -> dict:
    return json.loads(SUITE_PATH.read_text(encoding="utf-8"))


def _on(wf: dict) -> dict:
    # PyYAML parses the bare key `on:` as the boolean True (YAML 1.1). Accept either.
    if "on" in wf:
        return wf["on"]
    return wf[True]


def _jobs(wf: dict) -> dict:
    return wf["jobs"]


def _steps(job: dict) -> list[dict]:
    return job.get("steps", []) or []


def _run_text(job: dict) -> str:
    return "\n".join(str(s.get("run", "")) for s in _steps(job))


# --- triggers ---------------------------------------------------------------------------------


def test_pull_request_targets_main_only(wf):
    on = _on(wf)
    assert on["pull_request"]["branches"] == ["main"]


def test_push_targets_main_only_no_feature_branch_duplication(wf):
    on = _on(wf)
    assert on["push"]["branches"] == ["main"]
    # the pre-acceleration wildcard push trigger (duplicate runs per feature push) must be gone
    assert on["push"]["branches"] != ["**"]


def test_workflow_dispatch_enabled(wf):
    assert "workflow_dispatch" in _on(wf)


def test_no_path_filtering_on_required_triggers(wf):
    on = _on(wf)
    for event in ("push", "pull_request"):
        assert "paths" not in on[event], f"{event} must not use path filtering on the required gate"
        assert "paths-ignore" not in on[event]


def test_concurrency_groups_by_pr_number_or_ref(wf):
    group = wf["concurrency"]["group"]
    assert "pull_request.number" in group
    assert "github.ref" in group
    assert wf["concurrency"]["cancel-in-progress"] is True


# --- shard matrix + PostgreSQL ----------------------------------------------------------------


def test_pytest_matrix_fail_fast_is_false(wf):
    job = _jobs(wf)["backend-pytest"]
    assert job["strategy"]["fail-fast"] is False


def test_pytest_matrix_covers_all_configured_shards(wf, suite):
    shards = _jobs(wf)["backend-pytest"]["strategy"]["matrix"]["shard"]
    assert shards == [0, 1, 2, 3]
    # machine-check the workflow matrix stays in sync with the canonical shard_count
    assert len(shards) == suite["shard_count"]


def test_every_authoritative_shard_has_real_postgres(wf):
    job = _jobs(wf)["backend-pytest"]
    svc = job["services"]["postgres"]
    assert svc["image"].startswith("postgres:16")
    assert svc["env"]["POSTGRES_DB"] == "secptest"
    assert "SECP_TEST_POSTGRES_URL" in job["env"]


def test_inventory_job_shares_shard_environment(wf):
    # canonical vs. sharded collection must run in the same environment
    job = _jobs(wf)["backend-test-inventory"]
    assert "postgres" in job.get("services", {})
    assert "SECP_TEST_POSTGRES_URL" in job["env"]


# --- no suppression ---------------------------------------------------------------------------


def test_no_continue_on_error_anywhere(wf):
    for name, job in _jobs(wf).items():
        assert "continue-on-error" not in job, f"job {name} uses continue-on-error"
        for step in _steps(job):
            assert "continue-on-error" not in step, f"a step in {name} uses continue-on-error"


def test_shards_do_not_short_circuit_the_corpus(wf):
    run = _run_text(_jobs(wf)["backend-pytest"])
    assert " -x" not in run and run.strip() != "-x"
    assert "--maxfail" not in run
    assert "--exitfirst" not in run


def test_no_retry_or_rerun_plugins(wf):
    for job in _jobs(wf).values():
        text = _run_text(job)
        assert "--reruns" not in text
        assert "pytest-rerunfailures" not in text


# --- aggregate gate + stable names ------------------------------------------------------------


def test_aggregate_gate_depends_on_all_backend_jobs(wf):
    jobs = _jobs(wf)
    backend_jobs = {n for n in jobs if n.startswith("backend-")}
    needs = set(jobs["backend"]["needs"])
    assert backend_jobs <= needs, f"aggregate is missing deps: {backend_jobs - needs}"
    assert jobs["backend"]["if"] == "always()"


def test_aggregate_backend_name_is_stable(wf):
    assert _jobs(wf)["backend"]["name"] == BACKEND_AGG_NAME


def test_frontend_name_is_stable(wf):
    assert _jobs(wf)["frontend"]["name"] == FRONTEND_NAME


def test_aggregate_gate_fails_unless_all_success(wf):
    run = _run_text(_jobs(wf)["backend"])
    # every backend job result is inspected and a non-success forces exit 1
    for dep in ("backend-static", "backend-test-inventory", "backend-pytest", "backend-security"):
        assert f"needs.{dep}.result" in run
    assert "exit 1" in run


# --- security + frontend still required -------------------------------------------------------


def test_pip_audit_remains_required(wf):
    run = _run_text(_jobs(wf)["backend-security"])
    assert "pip-audit --skip-editable" in run


def test_frontend_uses_npm_ci_and_keeps_all_gates(wf):
    front = _jobs(wf)["frontend"]
    run = _run_text(front)
    assert "npm ci" in run
    assert "npm install" not in run  # deterministic install only
    for script in ("typecheck", "lint", "build", "test"):
        assert f"npm run {script}" in run
    assert "npm audit --omit=dev --audit-level=high" in run


def test_frontend_caches_on_lockfile(wf):
    front = _jobs(wf)["frontend"]
    node_step = next(
        s for s in _steps(front) if str(s.get("uses", "")).startswith("actions/setup-node")
    )
    assert node_step["with"]["cache"] == "npm"
    assert node_step["with"]["cache-dependency-path"] == "apps/web/package-lock.json"


# --- caching correctness ----------------------------------------------------------------------


def test_uv_cache_is_keyed_on_dependency_sources(wf):
    for name, job in _jobs(wf).items():
        for step in _steps(job):
            if str(step.get("uses", "")).startswith("astral-sh/setup-uv"):
                with_ = step.get("with", {})
                assert with_.get("enable-cache") is True, f"{name} setup-uv missing enable-cache"
                glob = with_.get("cache-dependency-glob", "")
                assert "uv.lock" in glob, f"{name} cache not keyed on uv.lock"
