"""secpctl enrollment plane-boundary guards (SECP-PR5H-B1, Phase 4).

Prove the controller/worker enrollment commands stay management-plane and cannot bypass the
supported API: secpctl never imports ``secp_api`` (ORM/services/DB/Principal), opens no database for
enrollment commands, invokes no enrollment service function, and the controller client reaches ONLY
the allowlisted enrollment HTTPS paths. The reverse (``secp_api`` must not import
``secp_management``) is already governed by ``test_management_plane_boundary``; asserted here too.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MGMT_PKG = REPO / "apps" / "management" / "secp_management"
API_PKG = REPO / "apps" / "api" / "secp_api"

#: The Phase 4 secpctl enrollment surface (management plane).
SECPCTL_ENROLLMENT_MODULES = (
    MGMT_PKG / "cli.py",
    MGMT_PKG / "enrollment_cli.py",
    MGMT_PKG / "enrollment_controller_client.py",
    MGMT_PKG / "controller_api_locator.py",
    MGMT_PKG / "operator_auth.py",
    MGMT_PKG / "worker_enroller.py",
)


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(path: Path) -> tuple[set[str], set[str]]:
    """(module names, imported symbol names) incl. dynamic ``__import__``/``import_module`` args."""
    modules: set[str] = set()
    symbols: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            modules.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                modules.add(node.module)
            symbols.update(a.name for a in node.names)
        elif isinstance(node, ast.Call):
            target = node.func
            dynamic = isinstance(target, ast.Name) and target.id == "__import__"
            dynamic = dynamic or (
                isinstance(target, ast.Attribute) and target.attr == "import_module"
            )
            if dynamic and node.args and isinstance(node.args[0], ast.Constant):
                if isinstance(node.args[0].value, str):
                    modules.add(node.args[0].value)
    return modules, symbols


def test_secpctl_enrollment_modules_do_not_import_the_api_plane() -> None:
    for path in SECPCTL_ENROLLMENT_MODULES:
        modules, symbols = _imports(path)
        offending = {m for m in modules if m == "secp_api" or m.startswith("secp_api.")}
        assert not offending, f"{path.name} imports the API plane {sorted(offending)}"
        # never a Principal or a service/repository symbol smuggled in
        assert "Principal" not in symbols, f"{path.name} imports a Principal"


def test_secpctl_enrollment_modules_open_no_database() -> None:
    """The enrollment commands operate ONLY over the HTTPS API — never a direct DB connection."""
    db = {"sqlalchemy", "psycopg", "psycopg2", "asyncpg", "aiopg"}
    for path in SECPCTL_ENROLLMENT_MODULES:
        modules, _symbols = _imports(path)
        offending = {m for m in modules if m.split(".")[0] in db}
        assert not offending, f"{path.name} opens a database {sorted(offending)}"


def test_secpctl_enrollment_modules_invoke_no_enrollment_service() -> None:
    for path in SECPCTL_ENROLLMENT_MODULES:
        modules, _symbols = _imports(path)
        offending = {
            m
            for m in modules
            if "worker_enrollment_repository" in m
            or m.endswith("services.worker_enrollment")
            or m.endswith("services.worker_enrollment_recovery")
        }
        assert not offending, f"{path.name} reaches the enrollment service/repository {offending}"


def test_secp_api_does_not_import_the_management_plane() -> None:
    for path in API_PKG.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        modules, _symbols = _imports(path)
        offending = {m for m in modules if m.split(".")[0] == "secp_management"}
        assert not offending, (
            f"{path.relative_to(REPO)} imports secp_management {sorted(offending)}"
        )


def test_controller_client_reaches_only_allowlisted_https_paths() -> None:
    """The client's only enrollment paths are ``/invitations``, ``/{id}`` and ``/{id}/revoke`` under
    the fixed ``/api/v1/enrollment`` prefix — no arbitrary path literal, no embedded origin."""
    import sys

    sys.path.insert(0, str(REPO / "apps" / "management"))
    from secp_management import enrollment_controller_client as client_mod

    assert client_mod._API_PREFIX == "/api/v1/enrollment"
    tree = _tree(MGMT_PKG / "enrollment_controller_client.py")
    # collect the 2nd positional arg of every self._request(method, path, ...) call
    paths: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_request"
            and len(node.args) >= 2
        ):
            arg = node.args[1]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                paths.add(arg.value)
            elif isinstance(arg, ast.JoinedStr):  # an f-string path template
                literal = "".join(
                    p.value if isinstance(p, ast.Constant) and isinstance(p.value, str) else "{}"
                    for p in arg.values
                )
                paths.add(literal)
    assert paths == {"/invitations", "/{}", "/{}/revoke"}, paths
    # no scheme/origin literal is baked into the client (origin comes only from the locator)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert "http://" not in node.value and "https://" not in node.value
