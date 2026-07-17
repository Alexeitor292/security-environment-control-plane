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
    for dep in (
        "backend-static",
        "backend-test-inventory",
        "backend-pytest",
        "backend-realfs-root",
        "backend-security",
    ):
        assert f"needs.{dep}.result" in run
    assert "exit 1" in run


# --- production RealFilesystem root job (executes the hardened openat backend) -----------------

REALFS_MODULE = "apps/commissioning/tests/test_commissioning_realfs.py"


def test_realfs_root_job_exists(wf):
    assert "backend-realfs-root" in _jobs(wf), "the dedicated root RealFilesystem job must exist"


def test_realfs_root_job_runs_exact_module_as_root(wf):
    run = _run_text(_jobs(wf)["backend-realfs-root"])
    # runs the EXACT production RealFilesystem module, under passwordless sudo (effective UID 0),
    # through the absolute venv interpreter
    assert REALFS_MODULE in run
    assert "sudo" in run
    assert ".venv/bin/python" in run
    # it must not run any OTHER test module (the root elevation is scoped to the production backend)
    assert "test_commissioning_install.py" not in run
    assert "apps/api/tests" not in run


def test_realfs_root_job_emits_and_validates_junit(wf):
    job = _jobs(wf)["backend-realfs-root"]
    run = _run_text(job)
    assert "--junitxml=junit-realfs-root.xml" in run
    # the JUnit is uploaded even on failure
    upload = next(
        s for s in _steps(job) if str(s.get("uses", "")).startswith("actions/upload-artifact")
    )
    assert upload.get("if") == "always()"
    assert upload["with"]["path"] == "junit-realfs-root.xml"
    # and it is parsed programmatically (not just trusting pytest's exit code)
    assert "xml.etree" in run or "ElementTree" in run
    assert "junit-realfs-root.xml" in run


def test_realfs_root_job_refuses_skipped_tests(wf):
    run = _run_text(_jobs(wf)["backend-realfs-root"])
    # the gate fails closed if the module was skipped (a skipped module exits 0) or under-collected
    assert "skipped" in run
    assert "< 8" in run  # requires at least 8 production RealFilesystem tests collected
    assert "sys.exit(1)" in run  # a non-executed / failing module forces failure
    # the parse step runs even if the pytest step failed, so JUnit is always evaluated
    parse_steps = [
        s
        for s in _steps(_jobs(wf)["backend-realfs-root"])
        if "skipped" in str(s.get("run", "")) and s.get("if") == "always()"
    ]
    assert parse_steps, "the JUnit-enforcement step must run with if: always()"


def test_realfs_root_job_does_not_use_continue_on_error(wf):
    job = _jobs(wf)["backend-realfs-root"]
    assert "continue-on-error" not in job
    for step in _steps(job):
        assert "continue-on-error" not in step


def test_realfs_root_job_caches_uv_like_siblings(wf):
    step = next(
        s
        for s in _steps(_jobs(wf)["backend-realfs-root"])
        if str(s.get("uses", "")).startswith("astral-sh/setup-uv")
    )
    assert step["with"]["enable-cache"] is True
    assert "uv.lock" in step["with"]["cache-dependency-glob"]


def test_aggregate_depends_on_realfs_root_and_name_unchanged(wf):
    jobs = _jobs(wf)
    assert "backend-realfs-root" in jobs["backend"]["needs"]
    # the externally visible required aggregate check name must be byte-for-byte stable
    assert jobs["backend"]["name"] == BACKEND_AGG_NAME


def test_realfs_root_job_does_not_weaken_existing_coverage(wf, suite):
    # the dedicated root job is ADDITIVE: the sharded corpus + inventory proof are untouched, and
    # the commissioning test root stays in the authoritative corpus (so the normal shard still
    # collects the module — it merely skips it without root).
    jobs = _jobs(wf)
    assert jobs["backend-pytest"]["strategy"]["matrix"]["shard"] == [0, 1, 2, 3]
    inv_run = _run_text(jobs["backend-test-inventory"])
    assert "pytest_shards.py verify --collect" in inv_run
    assert "apps/commissioning/tests" in suite["roots"]


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
