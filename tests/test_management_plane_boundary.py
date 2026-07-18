"""Management-plane protection boundary (SECP-PR5E §12).

Static (AST) guardrails proving lower planes cannot reach into the management-plane bootstrap:

* scenario-plane plugins and the control-plane API (which drive scenario provision/reset/destroy)
  must
  NOT import ``secp_management`` at all — they can never receive the bootstrap filesystem/service
  MUTATION capabilities (the write engine, the hardened layout writer, the systemd renderer);
* the management-bootstrap package must NOT import a provider/IaC/SSH/subprocess module or a
  scenario
  plugin — it is a local-first installer, never a remote deployment service or a scenario actor;
* a management-plane installation can never be selected as a scenario deployment target.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MGMT_PKG = REPO / "apps" / "management" / "secp_management"
# The bootstrap MUTATION surface: importing any of these grants filesystem/service write capability.
BOOTSTRAP_WRITE_MODULES = {
    "secp_management",
    "secp_management.engine",
    "secp_management.layout",
    "secp_management.systemd",
}
# Lower-plane code roots that must never import the management plane.
LOWER_PLANE_ROOTS = (
    REPO / "plugins",
    REPO / "apps" / "api" / "secp_api",
)
# The management installer itself must never import these (local-first; no remote/provider/IaC).
MGMT_FORBIDDEN = {
    "subprocess",
    "paramiko",
    "fabric",
    "asyncssh",
    "ansible",
    "proxmoxer",
    "boto3",
    "kubernetes",
    "opentofu",
    "terraform",
    "secp_plugin_proxmox",
    "secp_plugin_simulator",
    "requests",
    "aiohttp",
}


def _imports(path: Path) -> set[str]:
    """Every module named by a static OR dynamic import — ``import``/``from``, plus the string
    argument of ``__import__(...)`` and ``importlib.import_module(...)`` — so a dynamic-import
    evasion
    cannot smuggle a forbidden module past the boundary."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.Call):
            target = node.func
            dynamic = isinstance(target, ast.Name) and target.id == "__import__"
            dynamic = dynamic or (
                isinstance(target, ast.Attribute) and target.attr == "import_module"
            )
            if dynamic and node.args and isinstance(node.args[0], ast.Constant):
                arg = node.args[0].value
                if isinstance(arg, str):
                    names.add(arg)
    return names


def _py_files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*.py") if "__pycache__" not in p.parts] if root.exists() else []


@pytest.mark.parametrize(
    "path",
    [p for root in LOWER_PLANE_ROOTS for p in _py_files(root)],
    ids=lambda p: str(p.relative_to(REPO)),
)
def test_lower_plane_cannot_import_bootstrap_write_adapters(path: Path):
    imported = _imports(path)
    offending = {
        mod for mod in imported if mod == "secp_management" or mod.startswith("secp_management.")
    }
    assert not offending, (
        f"{path.relative_to(REPO)} imports the management bootstrap {offending}; a lower plane "
        "may never receive bootstrap filesystem/service mutation capabilities"
    )


@pytest.mark.parametrize("path", _py_files(MGMT_PKG), ids=lambda p: p.name)
def test_management_installer_is_local_first(path: Path):
    imported = _imports(path)
    offending = {mod for mod in imported if mod.split(".")[0] in MGMT_FORBIDDEN}
    assert not offending, f"{path.name} imports a forbidden remote/provider/IaC module {offending}"


def test_management_identity_cannot_be_a_scenario_target():
    import sys

    sys.path.insert(0, str(REPO / "apps" / "management"))
    from secp_management import ManagementError
    from secp_management.planes import Plane, assert_not_scenario_target

    with pytest.raises(ManagementError):
        assert_not_scenario_target(Plane.MANAGEMENT)
    assert_not_scenario_target(Plane.SCENARIO)  # a scenario object is a legitimate target


def test_scan_found_lower_plane_files():
    total = sum(len(_py_files(root)) for root in LOWER_PLANE_ROOTS)
    assert total >= 10


def test_import_scan_catches_dynamic_evasion(tmp_path):
    # A dynamic-import evasion must not slip a forbidden module past the boundary scan.
    evader = tmp_path / "evader.py"
    evader.write_text(
        "import importlib\n"
        "__import__('subprocess').run(['x'])\n"
        "importlib.import_module('secp_management.engine')\n"
        "__import__('secp_management.layout')\n",
        encoding="utf-8",
    )
    found = _imports(evader)
    assert "subprocess" in found
    assert "secp_management.engine" in found
    assert "secp_management.layout" in found
