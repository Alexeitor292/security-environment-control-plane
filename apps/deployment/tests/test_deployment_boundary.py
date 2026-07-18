"""Automation + purity boundary proofs for the deployment package (SECP-PR5D)."""

from __future__ import annotations

import ast
import pathlib

import pytest

_DEPLOY_PKG = pathlib.Path(__file__).resolve().parents[1] / "secp_operator_deployment"
_COMMISSIONING_PKG = (
    pathlib.Path(__file__).resolve().parents[3] / "apps" / "commissioning" / "secp_commissioning"
)
_DEPLOY_FILES = sorted(_DEPLOY_PKG.glob("*.py"))

# The single module allowed to spawn a subprocess (the hardened command seam).
_SUBPROCESS_ALLOWED = {"host_process.py"}
# temporalio must NEVER be imported anywhere in this package (the runner is sealed; the entrypoint
# is disabled) — controlled-live activation constructs no Worker here.
_ALWAYS_FORBIDDEN = frozenset({"temporalio"})


def _imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


@pytest.mark.parametrize("path", _DEPLOY_FILES, ids=lambda p: p.name)
def test_no_temporalio_imports_anywhere(path):
    assert not (_imports(path) & _ALWAYS_FORBIDDEN), f"{path.name} imports temporalio"


@pytest.mark.parametrize("path", _DEPLOY_FILES, ids=lambda p: p.name)
def test_subprocess_isolated_to_the_command_seam(path):
    roots = _imports(path)
    if path.name in _SUBPROCESS_ALLOWED:
        return
    assert "subprocess" not in roots, f"{path.name} must not import subprocess"


def test_runner_and_compositions_never_construct_a_worker():
    for name in ("runner.py", "compositions.py"):
        text = (_DEPLOY_PKG / name).read_text(encoding="utf-8")
        assert "Worker(" not in text
        assert "run_plan_generation" not in text


def test_no_activate_command_in_the_package():
    for path in _DEPLOY_FILES:
        text = path.read_text(encoding="utf-8")
        assert '"activate"' not in text
        assert "def activate" not in text


def test_no_real_endpoint_or_credential_in_source():
    import re

    ipv4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    ok = ("192.0.2.", "198.51.100.", "203.0.113.", "127.0.0.", "0.0.0.")
    creds = (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"(?i)\bvault:secret/[a-z0-9]"),
    )
    for path in _DEPLOY_FILES:
        text = path.read_text(encoding="utf-8")
        for m in ipv4.finditer(text):
            assert m.group(0).startswith(ok), f"{path.name}: {m.group(0)}"
        for rx in creds:
            assert not rx.search(text), path.name


# --- the commissioning engine must stay decoupled from this package + privileged libs -------------


def test_commissioning_never_imports_the_deployment_package_or_privileged_libs():
    forbidden = {
        "secp_operator_deployment",
        "temporalio",
        "subprocess",
        "secp_worker",
        "secp_api",
    }
    scanned = 0
    for path in sorted(_COMMISSIONING_PKG.glob("*.py")):
        scanned += 1
        bad = _imports(path) & forbidden
        assert not bad, f"secp_commissioning/{path.name} imports {sorted(bad)}"
    assert scanned >= 10  # guard: the scan actually matched the package


# --- the reviewed seals remain exactly as required by PR5D ----------------------------------------


def test_all_seals_remain_as_required():
    from secp_operator_deployment import runner
    from secp_worker.plan_gen import process_boundary as pb
    from secp_worker.provisioning import activation as act
    from secp_worker.provisioning import process_executor as pe

    assert runner._OPERATOR_ACTIVATION_SEALED is True  # PR5D operator-activation seal
    assert pb._PLAN_ONLY_PROCESS_SEALED is False  # plan-only seal unchanged
    assert act._B1A_SUBPROCESS_SEALED is True  # both B1-A subprocess seals unchanged
    assert pe._B1A_SUBPROCESS_SEALED is True
