"""Proofs #10, #11 — the API cannot import or invoke the provisioning runner /
OpenTofu / provider clients / subprocess.

Complements ``test_architecture_boundary.py`` with provisioning-specific, focused
assertions. Static (AST) scan of ``apps/api/secp_api``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

API_PKG = Path(__file__).resolve().parents[1] / "apps" / "api" / "secp_api"

# Import module roots / substrings the API must never import.
FORBIDDEN_IMPORT_SUBSTRINGS = (
    "secp_worker.provisioning",
    "secp_worker.secrets",
    "fake_opentofu",
    "opentofu",
    "terraform",
    "tofu",
    "subprocess",
    "secp_plugin_proxmox",
    "httpx",
    "paramiko",
    # SECP-002B-1A: process executor, adapters, and workspace rendering are worker-only.
    "process_executor",
    "provisioning.adapters",
    "provisioning.rendering",
)

# Symbols that name a runner / executor / renderer / secret resolver; the API must not
# import them (SECP-002B-1A adds the real OpenTofu seam symbols).
FORBIDDEN_IMPORT_NAMES = {
    "ProvisioningRunner",
    "FakeOpenTofuRunner",
    "run_provisioning",
    "run_real_provisioning",
    "OpenTofuRunner",
    "ProcessExecutor",
    "FakeProcessExecutor",
    "SubprocessProcessExecutor",
    "WorkspaceRenderer",
    "EnvSecretResolver",
    "SecretResolver",
}


def _py_files():
    return [p for p in API_PKG.rglob("*.py") if "__pycache__" not in p.parts]


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: list[str] = []
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules.append(node.module or "")
            names += [a.name for a in node.names]
    return modules, names


@pytest.mark.parametrize("path", _py_files(), ids=lambda p: p.name)
def test_api_never_imports_runner_or_iac(path: Path):
    modules, names = _imports(path)
    for mod in modules:
        low = mod.lower()
        for bad in FORBIDDEN_IMPORT_SUBSTRINGS:
            assert bad not in low, f"{path.name} imports forbidden module '{mod}'"
    bad_names = FORBIDDEN_IMPORT_NAMES & set(names)
    assert not bad_names, f"{path.name} imports runner symbol(s) {bad_names}"


def test_runner_lives_only_in_worker():
    # The runner/execution/executor/adapter/rendering modules must exist under the
    # worker, not the API (SECP-002B-0/1A).
    worker = Path(__file__).resolve().parents[1] / "apps" / "worker" / "secp_worker"
    prov = worker / "provisioning"
    for rel in (
        "runner.py",
        "fake_opentofu.py",
        "execution.py",
        "opentofu.py",
        "process_executor.py",
        "rendering.py",
        "change_set.py",
        "activation.py",
        "adapters/proxmox.py",
    ):
        assert (prov / rel).exists(), f"missing worker module {rel}"
    # And there is no runner / executor / adapter / rendering module under the API.
    assert not (API_PKG / "provisioning").exists()


def test_subprocess_executor_defined_only_in_worker():
    """Proof #2 — SubprocessProcessExecutor exists only in the worker boundary."""
    worker = Path(__file__).resolve().parents[1] / "apps" / "worker" / "secp_worker"
    src = (worker / "provisioning" / "process_executor.py").read_text(encoding="utf-8")
    assert "class SubprocessProcessExecutor" in src
    # It must NOT be defined or imported anywhere in the API package.
    for path in _py_files():
        text = path.read_text(encoding="utf-8")
        assert "SubprocessProcessExecutor" not in text, (
            f"{path.name} references SubprocessProcessExecutor (worker-only)"
        )


def test_api_provisioning_modules_have_no_shell_or_http():
    for name in (
        "services/manifests.py",
        "services/provisioning.py",
        "services/toolchain.py",
        "services/approvals.py",
        "provisioning_scope.py",
        "toolchain_profile.py",
    ):
        src = (API_PKG / name).read_text(encoding="utf-8")
        for forbidden in ("import subprocess", "os.system(", "import httpx", "subprocess."):
            assert forbidden not in src, f"{name} contains '{forbidden}'"
