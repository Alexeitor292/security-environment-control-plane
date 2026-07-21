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
