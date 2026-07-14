"""B1B-PR4 — readiness boundary + seal lock (ADR-021 §R).

Proves, by AST/text scan and by runtime assertion, that the readiness subsystem cannot execute
anything, and that every pre-existing execution seal is untouched.

No readiness module may import ``OpenTofuRunner``, a process executor, a renderer, a provider
mutation client, or the provisioning activation module; call a subprocess, ``os.system``, or
``os.popen``; mint a ``RealLabActivationGrant``; render a workspace; or read/mutate ``os.environ``.
Both B1-A subprocess seals remain exactly and effectively ``True``.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[3]
READINESS_PKG = ROOT / "apps" / "worker" / "secp_worker" / "readiness"
API_PKG = ROOT / "apps" / "api" / "secp_api"

# The API-side readiness modules. They may never import a worker module, an adapter, a resolver,
# SecretMaterial, an OpenBao client, HTTP, or a subprocess.
API_READINESS_FILES = (
    "readiness_contract.py",
    "readiness_binding.py",
    "readiness_models.py",
    "credential_binding.py",
    "schemas_readiness.py",
    "services/readiness.py",
    "services/plan_secret_authorization.py",
    "routers/readiness.py",
)

# B1B-PR4 §1 — the ONLY sanctioned crossing into the provisioning package, and the exact files it is
# permitted in. The readiness-only attestation path must use the REVIEWED PR2 verifier, so a narrow,
# EXPLICIT allowlist is safer than banning the import outright and re-implementing verification.
#
# The allowlist is deliberately tiny and exact: one module, three names, two files. Nothing else in
# ``secp_worker.provisioning`` (the runner, the executor, the renderer, the activation grant) may be
# imported by ANY readiness module, and ``RealToolchainVerifier`` still appears in NO execution
# path.
ATTESTATION_MODULE = "secp_worker.provisioning.toolchain_verify"
ATTESTATION_NAMES = frozenset(
    {"RealToolchainVerifier", "ToolchainFilesystemLayout", "ATTESTATION_POLICY_VERSION"}
)
ATTESTATION_FILES = frozenset({"composition.py", "toolchain_attestation.py"})

# Modules/symbols the WORKER readiness package may never import.
FORBIDDEN_WORKER_IMPORT_ROOTS = frozenset(
    {
        "subprocess",
        "socket",
        "httpx",
        "requests",
        "aiohttp",
        "paramiko",
        "asyncssh",
        "proxmoxer",
        "docker",
        "boto3",
        "botocore",
        "azure",
        "kubernetes",
    }
)
FORBIDDEN_WORKER_MODULES = (
    "secp_worker.provisioning",
    "secp_plugin_proxmox",
    "opentofu",
    "terraform",
)
FORBIDDEN_WORKER_NAMES = frozenset(
    {
        "OpenTofuRunner",
        "ProcessExecutor",
        "FakeProcessExecutor",
        "SubprocessProcessExecutor",
        "WorkspaceRenderer",
        "RealLabActivationGrant",
        "grant_real_lab_activation",
        "build_process_executor",
        "build_process_env",
        "build_lab_secret_env",
        "run_real_provisioning",
        "run_provisioning",
        "RealToolchainVerifier",
        "PreparedOpenTofuPlan",
        "apply_prepared",
        "destroy_prepared",
    }
)

# Every OpenTofu/Terraform subcommand the readiness package must never name as an operation.
FORBIDDEN_TOFU_SUBCOMMANDS = (
    "init",
    "plan",
    "show",
    "apply",
    "destroy",
    "import",
    "refresh",
    "output",
    "force-unlock",
    "workspace",
    "providers",
    "console",
)


def _worker_files() -> list[pathlib.Path]:
    return sorted(p for p in READINESS_PKG.rglob("*.py") if "__pycache__" not in p.parts)


def _api_files() -> list[pathlib.Path]:
    return [API_PKG / name for name in API_READINESS_FILES]


def test_the_readiness_package_exists_and_was_scanned():
    files = _worker_files()
    assert len(files) >= 8
    for path in _api_files():
        assert path.exists(), path


@pytest.mark.parametrize("path", _worker_files(), ids=lambda p: p.name)
def test_no_readiness_module_imports_an_execution_or_transport_module(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        modules: list[str] = []
        names: list[str] = []
        if isinstance(node, ast.Import):
            modules += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                modules.append(node.module)
            names += [a.name for a in node.names]
        # The ONE sanctioned crossing: the reviewed PR2 toolchain verifier, in exactly the two files
        # that own the readiness-only attestation seam, importing exactly the three allowed names.
        sanctioned = (
            path.name in ATTESTATION_FILES
            and modules == [ATTESTATION_MODULE]
            and set(names) <= ATTESTATION_NAMES
        )
        for module in modules:
            root = module.split(".")[0]
            assert root not in FORBIDDEN_WORKER_IMPORT_ROOTS, f"{path.name}: {module}"
            low = module.lower()
            for forbidden in FORBIDDEN_WORKER_MODULES:
                if sanctioned and forbidden == "secp_worker.provisioning":
                    continue
                assert forbidden not in low, f"{path.name}: {module}"
        for name in names:
            if sanctioned and name in ATTESTATION_NAMES:
                continue
            assert name not in FORBIDDEN_WORKER_NAMES, f"{path.name}: {name}"


def test_the_attestation_import_allowlist_is_exactly_two_files_and_three_names():
    """The sanctioned crossing is exhaustively enumerated — nothing else may reach provisioning."""
    crossers: dict[str, set[str]] = {}
    for path in _worker_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = None
            names: list[str] = []
            if isinstance(node, ast.Import):
                module = next(
                    (a.name for a in node.names if a.name.startswith("secp_worker.provisioning")),
                    None,
                )
            elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                "secp_worker.provisioning"
            ):
                module = node.module
                names = [a.name for a in node.names]
            if module is not None:
                assert module == ATTESTATION_MODULE, f"{path.name}: {module}"
                crossers.setdefault(path.name, set()).update(names)

    assert set(crossers) == set(ATTESTATION_FILES)
    for name_set in crossers.values():
        assert name_set <= ATTESTATION_NAMES, name_set


def _code_attributes(tree: ast.AST) -> set[str]:
    """Every dotted attribute EXPRESSION in the module's code (docstrings/comments excluded)."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            parts: list[str] = []
            cur: ast.AST = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
                found.add(".".join(reversed(parts)))
    return found


def _code_names(tree: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}


def _string_literals(tree: ast.AST) -> list[str]:
    """String literals in CODE — excluding module/class/function docstrings."""
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstrings.add(id(body[0].value))
    return [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings
    ]


@pytest.mark.parametrize("path", _worker_files(), ids=lambda p: p.name)
def test_no_readiness_module_calls_a_subprocess_or_shell(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    attrs = _code_attributes(tree)
    names = _code_names(tree)
    assert "subprocess" not in names
    assert not any(a.startswith("subprocess.") for a in attrs), attrs
    for forbidden in ("os.system", "os.popen", "os.spawnl", "os.spawnv", "os.execv", "pty.spawn"):
        assert forbidden not in attrs, f"{path.name}: {forbidden}"
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "shell":
            raise AssertionError(f"{path.name}: shell= keyword")


@pytest.mark.parametrize("path", _worker_files(), ids=lambda p: p.name)
def test_no_readiness_module_reads_or_mutates_os_environ(path):
    """AST-level: no ``os.environ`` EXPRESSION exists in the readiness code (prose is not code)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    attrs = _code_attributes(tree)
    for forbidden in ("os.environ", "os.putenv", "os.unsetenv", "os.getenv", "os.environb"):
        assert forbidden not in attrs, f"{path.name}: {forbidden}"
    assert "environ" not in _code_names(tree), path.name


@pytest.mark.parametrize("path", _worker_files(), ids=lambda p: p.name)
def test_no_readiness_module_renders_a_workspace_or_mints_a_grant(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                called.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                called.add(fn.attr)
    for forbidden in (
        "grant_real_lab_activation",
        "RealLabActivationGrant",
        "RenderedWorkspace",
        "WorkspaceRenderer",
        "materialize",
        "canonicalize_plan_json",
        "change_set_hash",
        "build_process_executor",
        "build_process_env",
        "build_lab_secret_env",
        "prepare",
        "apply_prepared",
        "destroy_prepared",
    ):
        assert forbidden not in called, f"{path.name}: {forbidden}()"


def test_no_readiness_module_names_an_opentofu_operation_as_a_command():
    """The readiness package builds no argv and names no OpenTofu subcommand as an operation."""
    for path in _worker_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        literals = {s.strip().lower() for s in _string_literals(tree)}
        for sub in FORBIDDEN_TOFU_SUBCOMMANDS:
            assert f"-{sub}" not in literals
            assert f"tofu {sub}" not in literals
            assert f"terraform {sub}" not in literals
        assert "tofu" not in literals, path.name
        assert "terraform" not in literals, path.name


# --- the API boundary
# ------------------------------------------------------------------------------


@pytest.mark.parametrize("path", _api_files(), ids=lambda p: p.name)
def test_the_api_readiness_modules_import_no_worker_or_secret_code(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        modules: list[str] = []
        names: list[str] = []
        if isinstance(node, ast.Import):
            modules += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                modules.append(node.module)
            names += [a.name for a in node.names]
        for module in modules:
            root = module.split(".")[0]
            assert root != "secp_worker", f"{path.name} imports {module}"
            assert root not in {"httpx", "requests", "subprocess", "socket"}, f"{path.name}"
        for name in names:
            assert name not in {
                "SecretMaterial",
                "OpenBaoWorkerSecretResolver",
                "OpenBaoHttpClient",
                "WorkerSecretResolver",
                "RemoteStateReadinessAdapter",
                "build_plan_secret_env",
                "run_remote_state_readiness",
                "run_plan_secret_readiness",
                "record_remote_state_readiness",
                "record_plan_secret_readiness",
                "build_readiness_composition",
            }, f"{path.name} imports {name}"


@pytest.mark.parametrize("path", _api_files(), ids=lambda p: p.name)
def test_the_api_readiness_modules_reference_no_worker_symbol_in_code(path):
    """AST-level: no worker symbol is NAMED, CALLED, or STRING-REFERENCED in API code."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden = {
        "SecretMaterial",
        "RemoteStateReadinessAdapter",
        "run_remote_state_readiness",
        "run_plan_secret_readiness",
        "record_remote_state_readiness",
        "record_plan_secret_readiness",
        "build_plan_secret_env",
        "build_readiness_composition",
        "OpenBaoWorkerSecretResolver",
        "WorkerSecretResolver",
    }
    assert not (_code_names(tree) & forbidden), path.name
    assert not ({a.split(".")[-1] for a in _code_attributes(tree)} & forbidden), path.name
    for literal in _string_literals(tree):
        assert "secp_worker" not in literal, f"{path.name}: {literal!r}"
    assert "os" not in _code_names(tree) or "os.system" not in _code_attributes(tree)


def test_the_api_cannot_import_the_worker_recorder_or_any_worker_module():
    """The recorder lives in the worker package; the architecture lock forbids the import."""
    for name in API_READINESS_FILES:
        tree = ast.parse((API_PKG / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] != "secp_worker", name
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] != "secp_worker", name


# --- durable models carry no secret-bearing column
# ---------------------------------------------------


def test_no_readiness_model_has_a_secret_bearing_column():
    from secp_api.models import (
        PlanSecretReadinessAuthorization,
        PlanSecretReadinessEvidence,
        PlanSecretReadinessRecord,
        PlanSecretResolutionLease,
        RemoteStateReadinessRecord,
    )

    forbidden_fragments = (
        "secret",
        "token",
        "password",
        "credential_reference",
        "secret_ref",
        "endpoint",
        "url",
        "bucket",
        "container",
        "object_key",
        "state_key",
        "state_path",
        "namespace_name",
        "access_key",
        "account_id",
        "response",
        "body",
        "exception",
        "stack",
    )
    allowed = {
        # A bounded PURPOSE class, a bounded SCHEME token, and opaque digests — never a value.
        "secret_purpose",
        "credential_reference_scheme",
        "self_test_proof_id",
        "self_test_policy_version",
    }
    for model in (
        RemoteStateReadinessRecord,
        PlanSecretReadinessAuthorization,
        PlanSecretReadinessEvidence,
        PlanSecretResolutionLease,
        PlanSecretReadinessRecord,
    ):
        for column in model.__table__.columns:  # type: ignore[attr-defined]
            name = column.name
            if name in allowed:
                continue
            for fragment in forbidden_fragments:
                assert fragment not in name, f"{model.__tablename__}.{name}"  # type: ignore[attr-defined]


def test_no_readiness_model_stores_a_secret_reference_hash():
    """A hash of a secret reference is itself forbidden (ADR-021 §L)."""
    from secp_api.models import PlanSecretReadinessAuthorization, PlanSecretReadinessRecord

    for model in (PlanSecretReadinessAuthorization, PlanSecretReadinessRecord):
        names = {c.name for c in model.__table__.columns}  # type: ignore[attr-defined]
        assert "credential_reference_hash" not in names
        assert "secret_ref_hash" not in names


# --- the B1-A seals are untouched
# ---------------------------------------------------------------------


def test_both_b1a_subprocess_seals_remain_exactly_and_effectively_true():
    import re

    from secp_worker.provisioning import activation as act
    from secp_worker.provisioning import process_executor as pe

    assert pe._B1A_SUBPROCESS_SEALED is True
    assert act._B1A_SUBPROCESS_SEALED is True

    for module in (pe, act):
        text = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        assigns = re.findall(r"(?m)^_B1A_SUBPROCESS_SEALED\s*=.*$", text)
        assert len(assigns) == 1
        assert assigns[0].split("=", 1)[1].strip() == "True"


def test_the_subprocess_executor_still_cannot_be_constructed():
    from secp_worker.provisioning.process_executor import (
        ProcessExecutionError,
        SubprocessProcessExecutor,
    )

    with pytest.raises(ProcessExecutionError, match="SEALED"):
        SubprocessProcessExecutor()
    with pytest.raises(ProcessExecutionError, match="SEALED"):
        SubprocessProcessExecutor(armed=True)


def test_the_process_executor_factory_still_returns_the_fake():
    from secp_api.config import Settings
    from secp_worker.provisioning.activation import (
        RealLabActivationGrant,
        build_process_executor,
    )
    from secp_worker.provisioning.process_executor import FakeProcessExecutor

    settings = Settings(app_env="test", enable_opentofu_subprocess=True)
    grant = RealLabActivationGrant(manifest_id="m", _nonce="n")
    assert isinstance(build_process_executor(settings, grant=grant), FakeProcessExecutor)


def test_the_real_toolchain_verifier_remains_unwired_into_execution():
    """PR4 runs the REAL verifier for READINESS ONLY. No execution path is wired to it.

    ``OpenTofuRunner`` and ``run_real_provisioning`` still default to ``FakeToolchainVerifier``; the
    readiness attestation seam is the sole construction site outside tests, and it runs no OpenTofu.
    """
    import inspect

    from secp_worker.provisioning import execution, opentofu

    runner_src = inspect.getsource(opentofu.OpenTofuRunner.__init__)
    assert "FakeToolchainVerifier()" in runner_src
    assert "RealToolchainVerifier" not in inspect.getsource(opentofu)
    exec_src = inspect.getsource(execution.run_real_provisioning)
    assert "FakeToolchainVerifier()" in exec_src
    assert "RealToolchainVerifier" not in inspect.getsource(execution)

    # It is CONSTRUCTED in exactly one readiness module — the readiness-only attestation seam.
    constructing = [
        path.name
        for path in _worker_files()
        if "RealToolchainVerifier(" in path.read_text(encoding="utf-8")
    ]
    assert constructing == ["toolchain_attestation.py"]

    # ... and that seam names no runner, no executor, no renderer, and no activation grant in CODE
    # (docstrings are excluded: the module documents exactly what it must never do).
    tree = ast.parse((READINESS_PKG / "toolchain_attestation.py").read_text(encoding="utf-8"))
    identifiers = {
        node.id if isinstance(node, ast.Name) else node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Name | ast.Attribute)
    }
    for forbidden in (
        "OpenTofuRunner",
        "ProcessExecutor",
        "SubprocessProcessExecutor",
        "WorkspaceRenderer",
        "RealLabActivationGrant",
        "subprocess",
        "environ",
        "system",
        "popen",
    ):
        assert forbidden not in identifiers, forbidden


def test_the_attestation_policy_version_agrees_across_the_boundary():
    from secp_api.readiness_binding import TOOLCHAIN_ATTESTATION_POLICY_VERSION
    from secp_worker.provisioning.toolchain_verify import ATTESTATION_POLICY_VERSION

    assert TOOLCHAIN_ATTESTATION_POLICY_VERSION == ATTESTATION_POLICY_VERSION


def test_readiness_never_dispatches_a_plan_apply_or_destroy():
    """No readiness module dispatches a workflow, and no readiness workflow chains to another."""
    for path in _worker_files():
        text = path.read_text(encoding="utf-8")
        for token in (
            "dispatch_deploy",
            "dispatch_destroy",
            "dispatch_reset",
            "get_dispatcher",
            "WorkflowDispatchOutbox",
            "ProvisioningChangeSetApproval",
        ):
            assert token not in text, f"{path.name}: {token}"


def test_the_readiness_workflows_are_registered_only_in_the_worker():
    worker_main = (ROOT / "apps" / "worker" / "secp_worker" / "main.py").read_text(encoding="utf-8")
    assert "RemoteStateReadinessWorkflow" in worker_main
    assert "PlanSecretReadinessWorkflow" in worker_main
    assert "remote_state_readiness_activity" in worker_main
    assert "plan_secret_readiness_activity" in worker_main

    for path in sorted(API_PKG.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert "remote_state_readiness_activity" not in text, path.name
        assert "plan_secret_readiness_activity" not in text, path.name


# --- the inert readiness canary ------------------------------------------------------------------


def test_the_readiness_canary_is_inert_and_locally_generated():
    """The ONE place PR4 constructs SecretMaterial. It is NOT a credential: it is local randomness.

    The SECP-B2-2 design lock (``tests/test_live_secret_resolver_design.py``) additionally asserts
    that this module imports nothing capable of reading a backend, a database, a file, or the
    environment, and that its only source of material is ``secrets.token_hex``.
    """
    from secp_worker.preflight.secret_resolution import SecretMaterial
    from secp_worker.readiness.canary import INERT_CANARY_PREFIX, inert_canary_material

    first = inert_canary_material()
    second = inert_canary_material()
    assert isinstance(first, SecretMaterial)
    assert first.reveal_secret().startswith(INERT_CANARY_PREFIX)
    assert first.reveal_secret() != second.reveal_secret()  # fresh randomness every time
    assert INERT_CANARY_PREFIX not in repr(first)  # still redacted


def test_only_the_canary_module_constructs_secret_material_in_the_readiness_package():
    canary = READINESS_PKG / "canary.py"
    for path in _worker_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        constructs = any(
            isinstance(n, ast.Call)
            and (n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", ""))
            == "SecretMaterial"
            for n in ast.walk(tree)
        )
        if path != canary:
            assert not constructs, f"{path.name} constructs SecretMaterial"
