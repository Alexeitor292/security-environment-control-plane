"""Static regression tests for .github/workflows/ci.yml (SECP CI acceleration).

These validate the workflow's *semantics* (parsed YAML), not brittle whole-file strings: complete
sharded coverage, no feature-branch push duplication, real PostgreSQL per authoritative shard,
no fail-fast / -x / --maxfail / continue-on-error / path-filtering on the required gate, a stable
aggregate gate depending on every backend job, and stable external check names.
"""

from __future__ import annotations

import json
import re
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


PR5F_POSTGRES_JOB = "backend-pr5f-postgres-finalization"
PR5F_POSTGRES_MODULE = "apps/api/tests/test_discovery_activation_rollback_migration_postgres.py"


def test_pr5f_postgres_finalization_job_runs_real_exact_module(wf):
    jobs = _jobs(wf)
    assert PR5F_POSTGRES_JOB in jobs
    job = jobs[PR5F_POSTGRES_JOB]
    assert job["services"]["postgres"]["image"].startswith("postgres:16")
    assert "SECP_TEST_POSTGRES_URL" in job["env"]
    run = _run_text(job)
    assert PR5F_POSTGRES_MODULE in run
    assert "test_discovery_activation_split_engine.py" not in run
    assert "test_pr5f_discovery_activation_root.py" not in run
    for forbidden in ("ssh ", "opentofu", "terraform", "proxmox", "secp-operator"):
        assert forbidden not in run.lower()


def test_pr5f_postgres_finalization_job_has_failclosed_no_skip_junit_gate(wf):
    job = _jobs(wf)[PR5F_POSTGRES_JOB]
    run = _run_text(job)
    assert "--junitxml=junit-pr5f-postgres-finalization.xml" in run
    assert "tests < 1" in run
    assert "skipped != 0" in run
    assert "sys.exit(1)" in run
    upload = next(
        step
        for step in _steps(job)
        if str(step.get("uses", "")).startswith("actions/upload-artifact")
    )
    assert upload.get("if") == "always()"
    assert upload["with"]["path"] == "junit-pr5f-postgres-finalization.xml"
    assert upload["with"]["if-no-files-found"] == "error"
    parse_steps = [
        step
        for step in _steps(job)
        if "skipped" in str(step.get("run", "")) and step.get("if") == "always()"
    ]
    assert parse_steps


def test_pr5f_postgres_finalization_job_is_required_additive_and_cached(wf, suite):
    jobs = _jobs(wf)
    assert PR5F_POSTGRES_JOB in jobs["backend"]["needs"]
    assert f"needs.{PR5F_POSTGRES_JOB}.result" in _run_text(jobs["backend"])
    setup = next(
        step
        for step in _steps(jobs[PR5F_POSTGRES_JOB])
        if str(step.get("uses", "")).startswith("astral-sh/setup-uv")
    )
    assert setup["with"]["enable-cache"] is True
    assert "uv.lock" in setup["with"]["cache-dependency-glob"]
    assert "apps/api/tests" in suite["roots"]
    assert jobs["backend-pytest"]["strategy"]["matrix"]["shard"] == [0, 1, 2, 3]


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
        "backend-pr5f-postgres-finalization",
        "backend-realfs-root",
        "backend-discovery-activation-root",
        "backend-deployment-root",
        "backend-management-root",
        "backend-security",
    ):
        assert f"needs.{dep}.result" in run
    assert "exit 1" in run


def test_management_root_job_exists_and_is_fail_closed(wf):
    jobs = _jobs(wf)
    assert "backend-management-root" in jobs, "the management root-security job must exist"
    job = jobs["backend-management-root"]
    run = _run_text(job)
    # runs the management root module under passwordless sudo through the absolute venv interpreter
    assert "apps/management/tests/test_management_root.py" in run
    assert "sudo" in run and ".venv/bin/python" in run
    # root-only trusted base + fail-closed ancestor preflight (uid + group/other write, sys.exit)
    assert "/root/secp-mgmt-roottest" in run and "/opt/secp-roottest" not in run
    assert "os.lstat" in run and "0o020" in run and "0o002" in run and "st_uid" in run
    assert "sys.exit(1)" in run
    # JUnit parsed programmatically; fail closed on skip / under-collection
    assert "--junitxml=junit-management-root.xml" in run
    assert "< 3" in run and "skipped" in run
    upload = next(
        s for s in _steps(job) if str(s.get("uses", "")).startswith("actions/upload-artifact")
    )
    assert upload.get("if") == "always()" and upload["with"]["if-no-files-found"] == "error"
    assert "continue-on-error" not in job
    # in the aggregate gate
    assert "backend-management-root" in jobs["backend"]["needs"]
    assert "needs.backend-management-root.result" in _run_text(jobs["backend"])


def test_management_root_job_does_not_weaken_existing_root_jobs(wf):
    jobs = _jobs(wf)
    # the deployment + realfs root jobs keep their exact modules + minimum-collection gates
    dep = _run_text(jobs["backend-deployment-root"])
    assert "apps/deployment/tests/test_deployment_root_manifest.py" in dep and "< 20" in dep
    realfs = _run_text(jobs["backend-realfs-root"])
    assert "test_commissioning_realfs.py" in realfs and "< 8" in realfs


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


# --- PR5F fixed-layout root transaction gate --------------------------------------------------

PR5F_ROOT_MODULE = "tests/test_pr5f_discovery_activation_root.py"
PR5F_ROOT_JOB = "backend-discovery-activation-root"
PR5F_STATE_PARENT = "/var/lib/secp"
PR5F_ROOT_SENTINEL = "SECP_DISCOVERY_ACTIVATION_ROOT_TEST=fixed-layout-ci-only"


def test_pr5f_root_transaction_job_exists_and_runs_only_exact_module(wf):
    jobs = _jobs(wf)
    assert PR5F_ROOT_JOB in jobs
    job = jobs[PR5F_ROOT_JOB]
    run = _run_text(job)
    assert PR5F_ROOT_MODULE in run
    assert "sudo" in run and ".venv/bin/python" in run
    assert PR5F_ROOT_SENTINEL in run
    assert "apps/api/tests" not in run
    assert "test_commissioning_realfs.py" not in run
    assert "test_deployment_root_manifest.py" not in run
    assert "services" not in job
    for forbidden_runtime in (
        "docker",
        "podman",
        "ssh ",
        "opentofu",
        "terraform",
        "run_plan_generation",
        "secp-controlled-live",
        "secp-operator",
    ):
        assert forbidden_runtime not in run.lower()


def test_pr5f_root_transaction_preflights_fixed_parent_and_absent_leaf(wf):
    steps = _steps(_jobs(wf)[PR5F_ROOT_JOB])
    job_run = _run_text(_jobs(wf)[PR5F_ROOT_JOB])
    assert "install -d" not in job_run
    assert "already exists and was left untouched" in job_run
    assert 'Path("/var/lib")' in job_run
    assert "group/other-writable" in job_run
    preflight_index = next(
        i
        for i, step in enumerate(steps)
        if "pre-existing path refuses the root gate" in str(step.get("run", ""))
    )
    pytest_index = next(
        i for i, step in enumerate(steps) if PR5F_ROOT_MODULE in str(step.get("run", ""))
    )
    assert preflight_index < pytest_index
    run = str(steps[preflight_index]["run"])
    assert PR5F_STATE_PARENT in run
    assert 'parent / "discovery-worker"' in run
    assert "lstat" in run and "S_ISLNK" in run and "S_ISDIR" in run
    assert "st_uid" in run and "st_gid" in run
    assert "0o020" in run and "0o002" in run
    assert "sys.exit(1)" in run


def test_pr5f_root_transaction_junit_gate_refuses_skip_or_undercollection(wf):
    job = _jobs(wf)[PR5F_ROOT_JOB]
    run = _run_text(job)
    assert "--junitxml=junit-discovery-activation-root.xml" in run
    assert "< 20" in run
    assert "skipped" in run and "sys.exit(1)" in run
    upload = next(
        step
        for step in _steps(job)
        if str(step.get("uses", "")).startswith("actions/upload-artifact")
    )
    assert upload.get("if") == "always()"
    assert upload["with"]["path"] == "junit-discovery-activation-root.xml"
    assert upload["with"]["if-no-files-found"] == "error"
    parse_steps = [
        step
        for step in _steps(job)
        if "skipped" in str(step.get("run", "")) and step.get("if") == "always()"
    ]
    assert parse_steps


def test_pr5f_root_transaction_job_is_required_additive_and_cached(wf, suite):
    jobs = _jobs(wf)
    assert PR5F_ROOT_JOB in jobs["backend"]["needs"]
    assert f"needs.{PR5F_ROOT_JOB}.result" in _run_text(jobs["backend"])
    assert jobs["backend"]["name"] == BACKEND_AGG_NAME
    setup = next(
        step
        for step in _steps(jobs[PR5F_ROOT_JOB])
        if str(step.get("uses", "")).startswith("astral-sh/setup-uv")
    )
    assert setup["with"]["enable-cache"] is True
    assert "uv.lock" in setup["with"]["cache-dependency-glob"]
    assert "tests" in suite["roots"]
    excluded = {entry["path"] for entry in suite.get("exclusions", [])}
    assert PR5F_ROOT_MODULE not in excluded
    assert jobs["backend-pytest"]["strategy"]["matrix"]["shard"] == [0, 1, 2, 3]


def test_static_gate_checks_pr5f_boundary_and_complete_mypy_scope(wf):
    run = _run_text(_jobs(wf)["backend-static"])
    assert "tests/test_pr5f_discovery_activation_boundary.py" in run
    assert "apps/commissioning/secp_commissioning" in run
    assert "apps/deployment/secp_discovery_activation" in run
    assert "apps/deployment/secp_operator_deployment" in run
    assert "apps/management/secp_management" in run


# --- deployment package root-security job (trusted dir-fd manifest + pinned exec) --------------

DEPLOY_ROOT_MODULES = (
    "apps/deployment/tests/test_deployment_root_manifest.py",
    "apps/deployment/tests/test_deployment_pinned_exec.py",
    "apps/deployment/tests/test_deployment_realproc.py",
)
# A genuinely root-only hierarchy: / and /root are root-owned + non-group/other-writable on a hosted
# runner. /opt has a group/other-writable ancestor and is (correctly) rejected by the trust walk.
DEPLOY_ROOT_DIR = "/root/secp-roottest"
REJECTED_ROOT_DIR = "/opt/secp-roottest"


def _deploy_root_step(wf, needle):
    return next(
        s for s in _steps(_jobs(wf)["backend-deployment-root"]) if needle in str(s.get("run", ""))
    )


def test_deployment_root_job_exists(wf):
    assert "backend-deployment-root" in _jobs(wf), "the deployment root-security job must exist"


def test_deployment_root_job_runs_exact_modules_as_root(wf):
    run = _run_text(_jobs(wf)["backend-deployment-root"])
    # runs the deployment root-security modules, under passwordless sudo (effective UID 0), through
    # the absolute venv interpreter
    for module in DEPLOY_ROOT_MODULES:
        assert module in run, f"{module} must run in the deployment root job"
    assert "sudo" in run
    assert ".venv/bin/python" in run
    # it must not elevate unrelated corpora to root
    assert "apps/api/tests" not in run
    assert "apps/commissioning/tests" not in run


def test_deployment_root_job_uses_root_only_trusted_dir(wf):
    run = _run_text(_jobs(wf)["backend-deployment-root"])
    # the fixture base is the genuinely root-only /root/secp-roottest, NOT /opt (whose ancestor is
    # group/other-writable and correctly rejected by the production trust walk)
    assert DEPLOY_ROOT_DIR in run
    assert REJECTED_ROOT_DIR not in run
    assert f"SECP_ROOT_TEST_DIR={DEPLOY_ROOT_DIR}" in run
    # explicit root:root ownership + a mode with no group/other write, and NO chmod of a broad
    # system directory (/opt, /root, or /)
    assert "chown root:root" in run
    assert "chmod 700" in run
    assert "chmod 755" not in run  # the previous group/other-readable base mode is gone
    for broad in (
        "chmod 700 /opt",
        "chmod 700 /\n",
        "chmod 777",
        "chmod 755 /opt",
        "chmod 700 /root\n",
    ):
        assert broad not in run, f"must not mutate a broad system directory: {broad!r}"


def test_deployment_root_job_has_failclosed_ancestor_preflight(wf):
    # A dedicated preflight validates the WHOLE ancestor chain of SECP_ROOT_TEST_DIR and exits
    # nonzero on any trust failure — it does not merely chmod the leaf and continue.
    step = _deploy_root_step(wf, "os.lstat")
    run = str(step["run"])
    assert f"SECP_ROOT_TEST_DIR={DEPLOY_ROOT_DIR}" in run  # the preflight validates the fixed dir
    # builds the ancestor chain from the path (not just the leaf) and iterates it
    assert ".split(" in run and "for comp in" in run
    # checks uid == 0
    assert "st_uid != 0" in run or "st_uid == 0" in run
    # checks BOTH group-write and other-write bits
    assert "0o020" in run  # group write
    assert "0o002" in run  # other write
    # rejects a symlink component (lstat, S_ISLNK) and requires a real directory
    assert "S_ISLNK" in run
    assert "S_ISDIR" in run
    # fails CLOSED (exits nonzero) rather than print-and-continue
    assert "sys.exit(1)" in run
    # the preflight runs under sudo so it can lstat the child beneath 0700 /root
    assert "sudo" in run


def test_root_pytest_uses_the_same_preflighted_trusted_dir(wf):
    # The root pytest invocation must use the SAME fixed trusted directory the preflight verified.
    pytest_step = _deploy_root_step(wf, "-m pytest")
    preflight_step = _deploy_root_step(wf, "os.lstat")
    assert f"SECP_ROOT_TEST_DIR={DEPLOY_ROOT_DIR}" in str(pytest_step["run"])
    assert f"SECP_ROOT_TEST_DIR={DEPLOY_ROOT_DIR}" in str(preflight_step["run"])


def test_root_job_cannot_regress_to_child_under_unverified_writable_ancestor(wf):
    # Regression: the job cannot silently regress to "chmod the final child + run under an
    # unverified writable ancestor". The preflight must validate EVERY component (real dir, uid 0,
    # no group/other write) and exit nonzero — so a child beneath a group/other-writable ancestor is
    # caught before any test runs. Order: the preflight step must precede the pytest step.
    steps = _steps(_jobs(wf)["backend-deployment-root"])
    preflight_idx = next(i for i, s in enumerate(steps) if "os.lstat" in str(s.get("run", "")))
    pytest_idx = next(i for i, s in enumerate(steps) if "-m pytest" in str(s.get("run", "")))
    assert preflight_idx < pytest_idx, "the ancestor preflight must run BEFORE the root tests"
    pre = str(steps[preflight_idx]["run"])
    # the preflight rejects a writable component ANYWHERE in the chain (group OR other write), not
    # just the leaf — the chain is derived from the path and every component is checked
    assert "group-writable" in pre or "0o020" in pre
    assert "other-writable" in pre or "0o002" in pre
    assert "for comp in" in pre  # iterates the whole chain


def test_deployment_root_job_emits_and_validates_junit(wf):
    job = _jobs(wf)["backend-deployment-root"]
    run = _run_text(job)
    assert "--junitxml=junit-deployment-root.xml" in run
    upload = next(
        s for s in _steps(job) if str(s.get("uses", "")).startswith("actions/upload-artifact")
    )
    assert upload.get("if") == "always()"
    assert upload["with"]["path"] == "junit-deployment-root.xml"
    assert upload["with"]["if-no-files-found"] == "error"
    # parsed programmatically (not just trusting pytest's exit code)
    assert "xml.etree" in run or "ElementTree" in run
    assert "junit-deployment-root.xml" in run


def test_deployment_root_job_refuses_skipped_tests(wf):
    job = _jobs(wf)["backend-deployment-root"]
    run = _run_text(job)
    # fails closed if a root-security test was skipped (skipped module exits 0) or under-collected
    assert "skipped" in run
    assert "< 20" in run  # requires at least 20 deployment root-security tests collected
    assert "sys.exit(1)" in run
    # the parse step runs even if the pytest step failed
    parse_steps = [
        s for s in _steps(job) if "skipped" in str(s.get("run", "")) and s.get("if") == "always()"
    ]
    assert parse_steps, "the JUnit-enforcement step must run with if: always()"


def test_deployment_root_job_no_continue_on_error(wf):
    job = _jobs(wf)["backend-deployment-root"]
    assert "continue-on-error" not in job
    for step in _steps(job):
        assert "continue-on-error" not in step


def test_deployment_root_job_caches_uv_like_siblings(wf):
    step = next(
        s
        for s in _steps(_jobs(wf)["backend-deployment-root"])
        if str(s.get("uses", "")).startswith("astral-sh/setup-uv")
    )
    assert step["with"]["enable-cache"] is True
    assert "uv.lock" in step["with"]["cache-dependency-glob"]


def test_aggregate_depends_on_deployment_root_and_inspects_its_result(wf):
    jobs = _jobs(wf)
    # the aggregate gate cannot be green without this job
    assert "backend-deployment-root" in jobs["backend"]["needs"]
    run = _run_text(jobs["backend"])
    assert "needs.backend-deployment-root.result" in run
    assert "exit 1" in run
    # the externally visible required aggregate check name is unchanged
    assert jobs["backend"]["name"] == BACKEND_AGG_NAME


def test_deployment_root_job_is_additive_not_weakening(wf, suite):
    # the dedicated root job is ADDITIVE: the sharded corpus is untouched and the deployment test
    # root stays in the authoritative corpus (so the normal shards still collect the modules — they
    # merely skip the root-only tests without root).
    jobs = _jobs(wf)
    assert jobs["backend-pytest"]["strategy"]["matrix"]["shard"] == [0, 1, 2, 3]
    assert "apps/deployment/tests" in suite["roots"]


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


# --- production Python image smoke job (SECP-PR5F.2) -------------------------------------------


def test_python_image_smoke_job_exists_and_is_required(wf):
    jobs = _jobs(wf)
    assert "backend-python-image-smoke" in jobs, "the dedicated image smoke job must exist"
    assert "backend-python-image-smoke" in jobs["backend"]["needs"]
    assert "needs.backend-python-image-smoke.result" in _run_text(jobs["backend"])


def test_python_image_smoke_builds_the_exact_repo_dockerfile(wf):
    run = _run_text(_jobs(wf)["backend-python-image-smoke"])
    assert "docker build -f infra/dev/Dockerfile.python -t secp-python-image-smoke:ci ." in run


def test_python_image_smoke_container_is_fully_locked_down(wf):
    run = _run_text(_jobs(wf)["backend-python-image-smoke"])
    for flag in (
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--tmpfs /tmp",
    ):
        assert flag in run, f"image smoke must run with {flag}"
    # the check script is fed over stdin (never bind-mounted); no volume/socket/env-file
    assert "python - < infra/dev/image_smoke.py" in run
    assert "-v " not in run
    assert "--volume" not in run
    assert "docker.sock" not in run
    assert "--env-file" not in run


def test_python_image_smoke_is_fail_closed_on_skip_or_failure(wf):
    run = _run_text(_jobs(wf)["backend-python-image-smoke"])
    assert "junit-python-image-smoke.xml" in run
    assert "tests < 5" in run
    assert "skipped != 0" in run
    assert "failures != 0" in run


# --- real device flow against a disposable Keycloak (SECP-PR5H-B2 WS-C deployment) --------------

DEVICE_FLOW_JOB = "backend-keycloak-device-flow"
DEVICE_FLOW_MODULE = "apps/management/tests/test_keycloak_device_flow_integration.py"


def test_device_flow_job_exists_and_is_required(wf):
    jobs = _jobs(wf)
    assert DEVICE_FLOW_JOB in jobs
    assert DEVICE_FLOW_JOB in jobs["backend"]["needs"]
    assert f"needs.{DEVICE_FLOW_JOB}.result" in _run_text(jobs["backend"])


def test_device_flow_job_opts_into_the_real_grant(wf):
    job = _jobs(wf)[DEVICE_FLOW_JOB]
    # The module skips itself unless this is set, so the job that must NOT skip has to set it.
    assert job["env"]["SECP_TEST_KEYCLOAK_DEVICE_FLOW"] == "1"
    assert DEVICE_FLOW_MODULE in _run_text(job)


def test_device_flow_job_refuses_a_skipped_or_miscollected_run(wf):
    run = _run_text(_jobs(wf)[DEVICE_FLOW_JOB])
    assert "junit-keycloak-device-flow.xml" in run
    # An EXACT collection count, not a floor: a floor would let a deleted proof pass unnoticed.
    assert "EXPECTED_TESTS = 17" in run
    assert "tests != EXPECTED_TESTS" in run
    assert "skipped != 0" in run
    assert "failures != 0" in run
    assert "errors != 0" in run


def test_device_flow_job_proves_the_disposable_provider_was_destroyed(wf):
    run = _run_text(_jobs(wf)[DEVICE_FLOW_JOB])
    assert 'docker ps -a --filter "name=secp-cli-device-flow-"' in run


def test_device_flow_job_does_not_use_continue_on_error(wf):
    job = _jobs(wf)[DEVICE_FLOW_JOB]
    assert "continue-on-error" not in job
    for step in _steps(job):
        assert "continue-on-error" not in step


def test_device_flow_job_caches_uv_like_siblings(wf):
    steps = _steps(_jobs(wf)[DEVICE_FLOW_JOB])
    uv = [s for s in steps if str(s.get("uses", "")).startswith("astral-sh/setup-uv")]
    assert len(uv) == 1
    assert uv[0]["with"]["enable-cache"] is True


# --- the optional `worker` extra must be installed where the shared corpus EXECUTES -------------
#
# `temporalio` is declared only in the `worker` extra (pyproject.toml). Every install site in the
# workflow used `.[dev]`, so seven tests reached `pytest.importorskip("temporalio")` and SKIPPED in
# CI while passing on any developer machine -- among them a fail-closed worker guard and the
# regression for a startup-fatal import bug. The shard jobs have no no-skip enforcement, so nothing
# surfaced it. These proofs stop the extra being dropped again in silence.
#
# SEVEN, counted rather than estimated: `test_temporal_sandbox_validation.py` gates 1 test at its
# own `importorskip`, `test_worker_fail_closed.py` gates 2 (two separate test bodies), and
# `test_worker_readiness_timing.py` gates 4 (one `importorskip` in the shared `_install_common`
# helper, which four of its five tests call). Six sites in this file and in ci.yml previously said
# "eight" against ci.yml's own "seven"; the JUnit from a run without the extra reports exactly 7
# skips whose reason is `could not import 'temporalio'`, and no other module gates on it.

WORKER_EXTRA_TESTS = (
    "apps/api/tests/test_temporal_sandbox_validation.py",
    "apps/api/tests/test_worker_fail_closed.py",
    "apps/api/tests/test_worker_readiness_timing.py",
)


def test_the_shard_job_installs_the_worker_extra(wf):
    """The job that executes the shared corpus must have `temporalio` available."""
    run = _run_text(_jobs(wf)["backend-pytest"])
    assert "--extra worker" in run, (
        "backend-pytest executes the shared corpus, so it must install the worker extra or the "
        "temporalio-gated tests silently skip"
    )


def test_the_shard_job_proves_the_worker_extra_is_present(wf):
    """Installing it is not enough: dropping `--extra worker` must FAIL the job rather than restore
    the skip. The import step is what makes that true."""
    run = _run_text(_jobs(wf)["backend-pytest"])
    assert "import temporalio" in run, (
        "backend-pytest must prove temporalio is importable, otherwise dropping the extra silently "
        "re-skips seven tests"
    )


def test_the_temporalio_gated_modules_are_in_the_authoritative_corpus(suite):
    """The extra only helps if these modules are actually collected by the sharded corpus."""
    assert "apps/api/tests" in suite["roots"]


def test_the_worker_extra_is_not_quietly_added_everywhere(wf):
    """The placement is deliberate: the job that EXECUTES the corpus, and the job that CERTIFIES it.

    Recorded as a test so the choice is visible if someone later widens it -- widening is not
    forbidden, but it should be a decision rather than a drift.

    This set was widened from `{backend-pytest}` deliberately. `backend-test-inventory` ran on `dev`
    alone while claiming an environment identical to the shards, and
    `tests/test_queue_contract_integration.py` gates on `temporalio` at MODULE level, so its nodes
    were dropped at COLLECTION time from both sides of that job's canonical-vs-sharded comparison.
    Both sides agreed and the proof passed, over a corpus smaller than the one the shards execute.
    An install-site count cannot see that, which is why
    `test_the_inventory_job_installs_the_same_extras_as_the_shards` states the coupling directly."""
    jobs = _jobs(wf)
    with_extra = {name for name, job in jobs.items() if "--extra worker" in _run_text(job)}
    assert with_extra == {"backend-pytest", "backend-test-inventory"}, (
        f"the worker extra is installed in {sorted(with_extra)}; if that is intended, update this "
        "test deliberately"
    )


def test_the_inventory_job_installs_the_same_extras_as_the_shards(wf):
    """The fail-closed proof must certify the corpus the shards actually run.

    Keyed on equality of the extras the two jobs request, NOT on `worker` by name: a future extra
    that carries another module-level `importorskip` would reopen the same hole, and a
    `worker`-specific assertion would still pass while it did. The failure this closes was silent in
    exactly that way -- both sides of the comparison shrank together, so the proof stayed green."""

    def extras(job_name: str) -> set[str]:
        return set(re.findall(r"--extra\s+([A-Za-z0-9_-]+)", _run_text(_jobs(wf)[job_name])))

    inventory, shards = extras("backend-test-inventory"), extras("backend-pytest")
    assert inventory, "backend-test-inventory requests no extras at all"
    assert inventory == shards, (
        f"backend-test-inventory installs {sorted(inventory)} but backend-pytest installs "
        f"{sorted(shards)}; the inventory proof would certify a corpus that differs from the one "
        "the shards execute, and a module-level importorskip makes that gap invisible"
    )


# --- every install site must install from uv.lock ---------------------------------------------
#
# `uv pip install -e ".[dev]"` is uv's PIP-COMPATIBLE interface and IGNORES uv.lock by design. Every
# install site in both workflows used it, `uv sync` appeared nowhere, and `pyproject.toml` declares
# `fastapi>=0.115` — an open floor. So every job re-resolved FastAPI on every run and drifted to
# whatever was newest, while uv.lock recorded 0.138.2 and nothing consulted it.
#
# That is not hypothetical. The resolution reached fastapi 0.141.1, which relocated
# `Dependant.is_gen_callable` to a module-level function, and `tests/test_api_commit_boundary.py`
# — the guard that five real commit-ordering defects were found through — failed 4 of its 7 nodes
# on EVERY branch simultaneously, for a reason no branch had introduced. Measured both ways at the
# time: `uv sync --frozen --extra dev` -> fastapi 0.138.2, guard 7/7; `uv pip install -e ".[dev]"`
# -> fastapi 0.141.1, guard 4 failed.
#
# These proofs keep the lock load-bearing. They cover `acceptance.yml` as well as `ci.yml`, because
# a job that ignores the lock is exactly as unreproducible in either file, and the conversion is
# only worth anything if the next copy-pasted job cannot quietly reintroduce the old form.

ACCEPTANCE_PATH = REPO / ".github" / "workflows" / "acceptance.yml"
WORKFLOW_PATHS = (CI_PATH, ACCEPTANCE_PATH)

# Floor, not an exact count: 14 jobs in ci.yml and 2 in acceptance.yml build an environment today.
# It exists only so an empty or collapsed walk cannot pass as "no offenders found".
MIN_ENVIRONMENT_BUILDING_JOBS = 16


def _jobs_by_run_text() -> dict[str, str]:
    """``"<workflow>:<job>" -> concatenated run: text``, across BOTH workflow files."""
    out = {}
    for path in WORKFLOW_PATHS:
        assert path.is_file(), f"{path} is missing; this walk would silently find nothing"
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        jobs = workflow.get("jobs") or {}
        assert jobs, f"{path.name} parsed with no jobs; the walk would prove nothing"
        for name, job in jobs.items():
            out[f"{path.name}:{name}"] = _run_text(job)
    return out


def test_no_workflow_job_installs_with_uv_pip_install():
    """The pip-compatible interface ignores the lock, so it may not appear in either workflow."""
    corpus = _jobs_by_run_text()
    assert len(corpus) >= MIN_ENVIRONMENT_BUILDING_JOBS, (
        f"only {len(corpus)} job(s) reached across both workflows; the walk is not engaging"
    )
    offenders = sorted(name for name, run in corpus.items() if "uv pip install" in run)
    assert not offenders, (
        f"{len(offenders)} job(s) install with `uv pip install`, which ignores uv.lock and "
        f"re-resolves every open floor in pyproject.toml: {offenders}. Use "
        "`uv sync --frozen --extra dev` (plus whatever extras the job needs)."
    )


def test_every_environment_building_job_syncs_from_the_frozen_lock():
    """Absence of `uv pip install` is not enough — the job must positively sync from the lock.

    A job that creates a venv and never syncs it is the same unreproducible install by omission,
    and would satisfy the check above while installing nothing at all.
    """
    corpus = _jobs_by_run_text()
    building = {name: run for name, run in corpus.items() if "uv venv" in run}
    assert len(building) >= MIN_ENVIRONMENT_BUILDING_JOBS, (
        f"only {len(building)} environment-building job(s) found, expected at least "
        f"{MIN_ENVIRONMENT_BUILDING_JOBS}; this check is not engaging and its silence means nothing"
    )
    unsynced = sorted(name for name, run in building.items() if "uv sync --frozen" not in run)
    assert not unsynced, (
        f"{len(unsynced)} job(s) create a venv without installing from the lock: {unsynced}"
    )


def _sync_commands() -> dict[str, list[str]]:
    """``"<workflow>:<job>" -> the `uv sync` COMMAND lines`` (shell comments excluded)."""
    out = {}
    for name, run in _jobs_by_run_text().items():
        commands = [
            line.strip()
            for line in run.splitlines()
            if "uv sync" in line and not line.strip().startswith("#")
        ]
        if commands:
            out[name] = commands
    return out


def test_every_sync_pins_both_the_interpreter_and_the_dev_extra():
    """`uv sync` alone is not the repair. Both flags are load-bearing, and both were MEASURED.

    On this project, in a directory with no environment already created:

        uv sync --frozen                  -> CPython 3.12.13, and pytest/ruff/mypy ABSENT
        uv sync --frozen --extra dev      -> CPython 3.12.13, toolchain present
        uv venv --python 3.11, then sync  -> CPython 3.11.15, toolchain present

    Two separate traps. `dev` is an `[project.optional-dependencies]` EXTRA rather than a
    dependency group, so a plain sync installs no test or lint toolchain at all — and a job whose
    `uv run pytest` finds no pytest fails in a way that looks nothing like its cause. And
    `requires-python = ">=3.11"` lets uv select the newest interpreter it can find, which is not
    the one any of this is tested against.

    The `uv venv --python 3.11` line above each sync already pins the interpreter — measured, the
    converted steps land on 3.11.15. But that makes each sync depend on its NEIGHBOUR surviving,
    and neighbours do not survive refactors. The flag is therefore repeated on the sync itself, so
    the step is self-contained, and pinned here so it cannot quietly decay back.
    """
    commands = _sync_commands()
    assert len(commands) >= MIN_ENVIRONMENT_BUILDING_JOBS, (
        f"only {len(commands)} job(s) run `uv sync`, expected at least "
        f"{MIN_ENVIRONMENT_BUILDING_JOBS}; this check is not engaging"
    )
    problems = []
    for name, lines in sorted(commands.items()):
        for line in lines:
            missing = [
                flag for flag in ("--frozen", "--extra dev", "--python 3.11") if flag not in line
            ]
            if missing:
                problems.append(f"{name}: {line!r} is missing {missing}")
    assert not problems, (
        f"{len(problems)} `uv sync` invocation(s) do not pin the lock, the dev extra and the "
        f"interpreter: {problems}"
    )


def test_the_lock_is_proven_in_step_with_pyproject(wf):
    """`--frozen` uses the lock as-is; it does not notice a lock that fell behind pyproject.toml.

    Checked once, in the fast static job, so a dependency added to `pyproject.toml` but never locked
    fails there with its actual cause rather than as an ImportError somewhere unrelated.
    """
    assert "uv lock --check" in _run_text(_jobs(wf)["backend-static"]), (
        "nothing verifies uv.lock against pyproject.toml, so a stale lock would be installed "
        "faithfully and silently"
    )


# --- shard skip accounting: absence must not read as coverage ---------------------------------
#
# The shard jobs were the ONLY pytest jobs with no skip accounting. Every dedicated fence refuses a
# skip outright, but the shards cannot -- ~80 tests are legitimately gated on POSIX/root/docker/
# systemd a normal runner lacks -- so a genuinely missing dependency (`temporalio`) sat in the
# corpus reading as coverage. The enforcement keys on the skip REASON, never on test identity.


def _shard_enforcement(wf):
    steps = [
        s
        for s in _steps(_jobs(wf)["backend-pytest"])
        if "platform-gated" in str(s.get("name", "")) or "PLATFORM_GATED" in str(s.get("run", ""))
    ]
    assert len(steps) == 1, f"expected exactly one shard skip-accounting step, found {len(steps)}"
    return steps[0]


def _shard_skip_classifier(wf):
    """Execute only the repository-owned classifier definitions, never the JUnit gate body."""
    run = str(_shard_enforcement(wf)["run"])
    definitions = run[run.index("import re") : run.index("problems = []")]
    namespace: dict[str, object] = {}
    exec(definitions, namespace)  # noqa: S102 - the parsed repository workflow is the test subject
    return namespace


def test_the_shard_job_accounts_for_every_skip(wf):
    step = _shard_enforcement(wf)
    run = str(step["run"])
    assert "sys.exit(1)" in run, "the skip accounting must fail the job, not merely report"
    assert step.get("continue-on-error") in (None, False)
    assert "if" not in step, "a conditional skip gate stops nothing"


def test_the_shard_skip_accounting_keys_on_reason_not_on_test_names(wf):
    """An enumerated allowlist of test names decays silently the moment a test is renamed. A
    capability shape does not, and a newly added root-gated test needs no maintenance."""
    run = str(_shard_enforcement(wf)["run"])
    for capability in ("posix", "root", "docker", "systemctl", "systemd", "postgres"):
        assert capability in run, f"the reason matcher must recognise {capability}"
    # it must classify the message, not the identity
    assert "message" in run and "classname" not in run.split("unexplained")[0]


def test_the_shard_skip_accounting_accepts_only_the_exact_keystore_reasons(wf):
    """Keystore skips stay skips, and generic uses of their words remain unexplained failures."""
    namespace = _shard_skip_classifier(wf)
    exact = frozenset(
        {
            "Windows Credential Manager only",
            "no OS keystore binding on this host",
        }
    )
    assert namespace["PLATFORM_GATED_EXACT"] == exact

    platform_gated = namespace["platform_gated"]
    assert callable(platform_gated)
    for reason in exact:
        assert platform_gated(reason), reason
    for reason in (
        "Windows",
        "host",
        "credential",
        "keystore",
        "platform",
        "dependency unavailable",
        "could not import 'temporalio': No module named 'temporalio'",
        "requires Windows Credential Manager only",
        "Windows Credential Manager only on this host",
        "expected no OS keystore binding on this host",
        "no OS keystore binding on this host today",
    ):
        assert not platform_gated(reason), reason


def test_the_shard_skip_accounting_is_not_vacuous(wf):
    """A matcher broadened to accept everything would pass while checking nothing, so the step
    proves in-process that it still discriminates: a known missing-dependency reason must be
    refused and a known platform-gated reason accepted, or the step fails."""
    run = str(_shard_enforcement(wf)["run"])
    assert "MUST_REFUSE" in run and "MUST_ACCEPT" in run
    assert "temporalio" in run, "the anti-vacuity sample must be the real defect it exists to catch"
    assert "PLATFORM_GATED is empty" in run, "an empty pattern set must fail, not accept everything"
    assert "no testcases at all" in run, "an empty corpus must fail rather than pass vacuously"
    assert "missing" in run, "a missing report must fail rather than pass vacuously"


# --- PostgreSQL + real-socket API regression gate ----------------------------------------------
#
# The defect that motivated this job (a create answered 201 before its transaction committed)
# survived because no gate exercised PostgreSQL and a real HTTP socket at the same time: 88
# `TestClient` references and no live-server harness anywhere. `TestClient` drives the ASGI app to
# completion in-process, so the request exit stack always closes before the assertion.
#
# The module is deliberately OUTSIDE the sharded corpus, which means exactly one job runs it. These
# proofs tie the three parts together — the exclusion, the job, and the module's own marker — so
# that no single edit can leave the gate excluded from the corpus and run by nothing.

SOCKET_GATE_JOB = "backend-api-socket-gate"
SOCKET_GATE_MODULE = "apps/api/socket_gate_tests/test_api_read_after_write_over_socket.py"
SOCKET_GATE_TEST = "test_a_created_template_is_readable_by_the_immediately_following_request"


def test_socket_gate_module_is_excluded_from_the_corpus_and_names_its_job(suite):
    """The exclusion is what keeps the inventory fail-closed for a pytest file outside `roots`.

    It must also record WHICH job runs the module, so the pairing below is not folklore.
    """
    entries = {entry["path"]: entry for entry in suite.get("exclusions", [])}
    assert SOCKET_GATE_MODULE in entries, (
        "the socket gate lives outside the canonical roots, so it must be an explicit exclusion or "
        "the inventory proof fails closed"
    )
    entry = entries[SOCKET_GATE_MODULE]
    assert entry["job"] == SOCKET_GATE_JOB
    assert entry["reason"].strip(), "an exclusion without a justification is not a decision"
    # It is genuinely outside the roots: an excluded file *inside* a root would be collected by the
    # canonical directory-level collection and missing from every shard, failing `verify --collect`.
    assert not any(
        SOCKET_GATE_MODULE == root or SOCKET_GATE_MODULE.startswith(root + "/")
        for root in suite["roots"]
    )


def test_socket_gate_job_runs_the_exact_module_against_real_postgres(wf):
    jobs = _jobs(wf)
    assert SOCKET_GATE_JOB in jobs, "the excluded module must have exactly one job that runs it"
    job = jobs[SOCKET_GATE_JOB]
    assert job["services"]["postgres"]["image"].startswith("postgres:16")
    assert job["env"]["SECP_TEST_POSTGRES_URL"].startswith("postgresql+psycopg://")
    run = _run_text(job)
    assert SOCKET_GATE_MODULE in run
    # scoped to the gate: it does not elevate or re-run any other corpus
    assert "apps/api/tests" not in run
    assert "pytest_shards.py" not in run
    # it contacts no deployment infrastructure; the only listener is loopback inside the runner
    for forbidden in ("ssh ", "opentofu", "terraform", "proxmox", "secp-operator"):
        assert forbidden not in run.lower()


def test_socket_gate_job_accounting_is_xfail_aware_and_refuses_a_plain_skip(wf):
    """A strict xfail is recorded in JUnit as `<skipped type="pytest.xfail">`.

    So the accounting must discriminate on that type: an expected failure is the pending state, a
    plain skip means PostgreSQL was absent and the gate never executed. Collapsing the two would
    let an unrun gate read as a passing one — the exact failure this whole job exists to prevent.
    """
    job = _jobs(wf)[SOCKET_GATE_JOB]
    run = _run_text(job)
    assert "--junitxml=junit-api-socket-gate.xml" in run
    assert "pytest.xfail" in run, "the accounting must tell an expected failure from a real skip"
    assert "plain_skipped" in run and "SKIPPED outright" in run
    assert "STATE=PENDING" in run and "STATE=FIXED" in run, (
        "the job must name which of the two acceptable states it observed, rather than being "
        "silently green in both"
    )
    assert "tests != EXPECTED_TESTS" in run, "an exact count, never a floor"
    assert "sys.exit(1)" in run
    upload = next(
        step
        for step in _steps(job)
        if str(step.get("uses", "")).startswith("actions/upload-artifact")
    )
    assert upload.get("if") == "always()"
    assert upload["with"]["path"] == "junit-api-socket-gate.xml"
    assert upload["with"]["if-no-files-found"] == "error"
    parse_steps = [
        step
        for step in _steps(job)
        if "plain_skipped" in str(step.get("run", "")) and step.get("if") == "always()"
    ]
    assert parse_steps, "the JUnit-enforcement step must run with if: always()"


def test_socket_gate_job_is_required_and_cached_like_its_siblings(wf):
    jobs = _jobs(wf)
    assert SOCKET_GATE_JOB in jobs["backend"]["needs"]
    assert f"needs.{SOCKET_GATE_JOB}.result" in _run_text(jobs["backend"])
    assert jobs["backend"]["name"] == BACKEND_AGG_NAME
    setup = next(
        step
        for step in _steps(jobs[SOCKET_GATE_JOB])
        if str(step.get("uses", "")).startswith("astral-sh/setup-uv")
    )
    assert setup["with"]["enable-cache"] is True
    assert "uv.lock" in setup["with"]["cache-dependency-glob"]


def test_socket_gate_job_is_additive_and_changes_no_existing_coverage(wf, suite):
    """Adding the gate must not shrink anything: same roots, same shards, same sibling fences."""
    jobs = _jobs(wf)
    assert jobs["backend-pytest"]["strategy"]["matrix"]["shard"] == [0, 1, 2, 3]
    assert len(jobs["backend-pytest"]["strategy"]["matrix"]["shard"]) == suite["shard_count"]
    for root in ("apps/api/tests", "tests", "apps/commissioning/tests", "apps/deployment/tests"):
        assert root in suite["roots"]
    assert "pytest_shards.py verify --collect" in _run_text(jobs["backend-test-inventory"])
    # the sibling PostgreSQL fences keep their own no-skip accounting untouched
    assert "skipped != 0" in _run_text(jobs["backend-pr5f-postgres-finalization"])
    assert "expected 0 skipped" in _run_text(jobs["backend-pr5h-postgres-enrollment"])


def _socket_gate_module():
    from socket_gate_tests import test_api_read_after_write_over_socket as gate

    return gate


def _marks(owner) -> list:
    """Normalize a `pytestmark` attribute to a list of marks.

    A module-level `pytestmark = pytest.mark.skipif(...)` is a single MarkDecorator; marks applied
    to a function are collected into a list of Mark objects. Both expose `.name` and `.kwargs`.
    """
    marks = getattr(owner, "pytestmark", [])
    return list(marks) if isinstance(marks, (list, tuple)) else [marks]


def test_socket_gate_carries_no_expected_failure_marker():
    """Checked on the LOADED marker object, not on source text.

    This test used to require exactly one `strict=True, raises=ReadAfterWriteViolation` marker,
    because the defect was still present and the marker was how the gate stayed honest about it.
    The defect is fixed — every session resolution now goes through `secp_api.deps.DB_SESSION` with
    `scope="function"` — so the marker is gone, and its ABSENCE is now the property under test.

    It is asserted rather than merely deleted because re-adding an expected failure is exactly how
    a reintroduced defect would be made to look green again. With no marker, a regression fails the
    gate outright, and the CI job's accounting prints `STATE=FIXED` only when zero expected
    failures are reported.
    """
    from socket_gate_tests.live_api_server import LiveServerError

    gate = _socket_gate_module()
    target = getattr(gate, SOCKET_GATE_TEST)
    # BOTH scopes. `pytestmark` on the FUNCTION is the obvious place, but a module-level
    # `pytestmark = [..., pytest.mark.xfail(strict=True)]` applies to every test in the file and
    # would leave a function-only check green while the gate's result was being absorbed exactly as
    # before. The CI job's `xfailed == 0` accounting backstops this, but a test asserting the
    # absence of a marker should not itself be defeated by where the marker was written.
    xfails = [mark for owner in (target, gate) for mark in _marks(owner) if mark.name == "xfail"]
    assert not xfails, (
        f"the read-after-write gate carries {len(xfails)} expected-failure marker(s) (function- or "
        f"module-level): {[mark.kwargs for mark in xfails]}. The defect is fixed; a marker here "
        "can only be absorbing a regression."
    )

    # The gate's ability to REFUSE an unmeasurable run is unchanged by the fix and is still the
    # thing that keeps a green result meaningful, so it is still asserted here.
    assert issubclass(gate.ReadAfterWriteViolation, AssertionError)
    assert not issubclass(gate.LiveGateInconclusive, gate.ReadAfterWriteViolation)
    # A harness failure is not even an AssertionError, so no expected-failure marker could take it.
    assert not issubclass(LiveServerError, AssertionError)


def test_socket_gate_declares_its_engine_scope_and_refuses_anything_else():
    """The gate runs only where its CI accounting was calibrated, and says so.

    NOT because other engines hide the defect. An earlier version of this test asserted that
    "SQLite serialises the race away at its database-level write lock"; that is wrong and was never
    measured. SQLite's write lock serialises *writers* — it does not block a reader against an
    uncommitted writer, and `create_template` only flushes, so the follow-up read checks out a
    second pooled connection and misses the pending row. Measured: 110/110 violations and 0
    inconclusives running this gate's own body on SQLite (50 serial + 60 at 4-way concurrency),
    corroborated by 5/5 from the PR #77 reviewer and 40/40 on the enrollment revoke path from the
    PR #72 reviewer.

    What the scoping buys is narrower and still real: a mis-set ``SECP_TEST_POSTGRES_URL`` cannot
    silently run the gate somewhere the job's JUnit accounting was not calibrated for.
    """
    gate = _socket_gate_module()
    reasons = [mark.kwargs.get("reason", "") for mark in _marks(gate) if mark.name == "skipif"]
    assert any("SECP_TEST_POSTGRES_URL" in reason for reason in reasons), (
        "the skip must say out loud which capability is missing, so an absent gate is visible"
    )
    import sqlalchemy

    sqlite = sqlalchemy.create_engine("sqlite+pysqlite:///:memory:")
    try:
        with pytest.raises(gate.LiveGateInconclusive):
            gate._require_postgresql(sqlite)
    finally:
        sqlite.dispose()


def test_socket_gate_job_expects_exactly_the_module_s_test_count(wf):
    """Couple the workflow's exact count to the module, so neither can drift alone."""
    import re

    run = _run_text(_jobs(wf)[SOCKET_GATE_JOB])
    declared = re.search(r"EXPECTED_TESTS\s*=\s*(\d+)", run)
    assert declared, "the socket-gate job must declare an exact expected test count"
    gate = _socket_gate_module()
    defined = [
        name for name in dir(gate) if name.startswith("test_") and callable(getattr(gate, name))
    ]
    assert int(declared.group(1)) == len(defined), (
        f"the job expects {declared.group(1)} tests but the module defines {len(defined)}: "
        f"{sorted(defined)}"
    )
    assert SOCKET_GATE_TEST in defined
