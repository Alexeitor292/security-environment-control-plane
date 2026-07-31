"""Automation + purity boundary proofs for the deployment package (SECP-PR5D)."""

from __future__ import annotations

import ast
import pathlib

import pytest

_DEPLOY_PKG = pathlib.Path(__file__).resolve().parents[1] / "secp_operator_deployment"
_COMMISSIONING_PKG = (
    pathlib.Path(__file__).resolve().parents[3] / "apps" / "commissioning" / "secp_commissioning"
)


def _package_sources(pkg: pathlib.Path) -> list[pathlib.Path]:
    """Every ``.py`` under ``pkg`` at ANY depth (WS-E).

    This was ``glob("*.py")`` — top level only. The package is flat, so it was green while covering
    everything, and would have gone on being green the moment a subpackage appeared: a future
    ``secp_operator_deployment/adapters/*.py`` would have escaped both the subprocess-isolation and
    the temporalio-import checks silently. That matters more here than in the sibling case, because
    these two guards are what close the one seam the provenance tripwires cannot see — a direct
    ``subprocess`` bypassing ``host_process`` entirely.

    Proven recursive by :func:`test_the_boundary_scan_reaches_into_subpackages`, not assumed.
    """
    return sorted(p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts)


_DEPLOY_FILES = _package_sources(_DEPLOY_PKG)


def _rel(path: pathlib.Path) -> str:
    return path.relative_to(_DEPLOY_PKG).as_posix()


# The single module allowed to spawn a subprocess (the hardened command seam). Keyed on the
# package-RELATIVE path, not the basename: with a recursive scan, a basename match would allow a
# nested ``adapters/host_process.py`` to import subprocess purely by being named the same thing —
# a hole the recursion fix would otherwise have opened while closing another.
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


@pytest.mark.parametrize("path", _DEPLOY_FILES, ids=_rel)
def test_no_temporalio_imports_anywhere(path):
    assert not (_imports(path) & _ALWAYS_FORBIDDEN), f"{_rel(path)} imports temporalio"


@pytest.mark.parametrize("path", _DEPLOY_FILES, ids=_rel)
def test_subprocess_isolated_to_the_command_seam(path):
    roots = _imports(path)
    if _rel(path) in _SUBPROCESS_ALLOWED:
        return
    assert "subprocess" not in roots, f"{_rel(path)} must not import subprocess"


def test_the_boundary_scan_reaches_into_subpackages(tmp_path):
    """Prove the scan's COVERAGE, not just that it was changed to ``rglob``.

    A recursive glob with no test proving it reaches a subpackage is the version worth catching in
    review: it looks fixed and is unverified. This builds the tree that defeated the old scan and
    requires the production helper to return that specific nested path.
    """
    pkg = tmp_path / "secp_operator_deployment"
    (pkg / "adapters").mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    nested = pkg / "adapters" / "systemd.py"
    nested.write_text("import subprocess\nimport temporalio\n", encoding="utf-8")

    sources = _package_sources(pkg)
    assert nested in sources, "the boundary scan does not reach subpackages"
    # And the checks themselves would fire on it, rather than merely the file being listed.
    assert _imports(nested) & _ALWAYS_FORBIDDEN
    assert "subprocess" in _imports(nested)


def test_a_nested_module_cannot_inherit_the_subprocess_exemption_by_basename():
    """The exemption is keyed on the package-relative path. A nested ``adapters/host_process.py``
    must NOT be exempt just for sharing a basename with the real command seam — the hole the
    recursion fix would otherwise have opened."""
    assert "host_process.py" in _SUBPROCESS_ALLOWED
    assert "adapters/host_process.py" not in _SUBPROCESS_ALLOWED
    # The real seam is still exempt, so the check has not simply been tightened into a failure.
    assert _rel(_DEPLOY_PKG / "host_process.py") in _SUBPROCESS_ALLOWED


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
    # Recursive for the same reason as the deployment scan above. This one was NOT named in the
    # finding, but it is the identical defect two functions down in the same file: a
    # ``secp_commissioning/adapters/*.py`` importing subprocess or secp_worker would have escaped
    # it silently. Fixing the reported instance and leaving its twin is the letter of the finding
    # against its point.
    scanned = 0
    for path in _package_sources(_COMMISSIONING_PKG):
        scanned += 1
        rel = path.relative_to(_COMMISSIONING_PKG).as_posix()
        bad = _imports(path) & forbidden
        assert not bad, f"secp_commissioning/{rel} imports {sorted(bad)}"
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
