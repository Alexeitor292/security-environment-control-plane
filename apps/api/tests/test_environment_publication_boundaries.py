"""Architecture / boundary tests for SECP-B10 / ADR-016 PR B.

The publication service is control-plane DB logic only. It must not be externally reachable
(no router/route/API schema), must not import workers/providers/transports/secret
resolvers/subprocess/socket/HTTP clients/OpenTofu/Terraform, and must not create an
exercise, generate a deployment plan, or dispatch a workflow.
"""

from __future__ import annotations

import ast
from pathlib import Path

API_DIR = Path(__file__).resolve().parents[1]
SERVICE = API_DIR / "secp_api" / "services" / "environment_publication.py"
CONTRACT = API_DIR / "secp_api" / "environment_publication_contract.py"

# Import roots (first dotted segment) the publication layer must never pull in.
FORBIDDEN_ROOTS = {
    "subprocess",
    "socket",
    "http",
    "httpx",
    "requests",
    "urllib",
    "urllib3",
    "aiohttp",
    "websockets",
    "paramiko",
    "asyncssh",
    "secp_worker",
    "docker",
}
# Substrings that must not appear in any imported module path (infra/transport/secret surfaces).
FORBIDDEN_SUBSTRINGS = (
    "terraform",
    "opentofu",
    "provider",
    "transport",
    "secret",
    "resolver",
    "worker",
    "dispatch",
)


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                modules.add(node.module)
    return modules


def _assert_clean_imports(path: Path) -> None:
    modules = _imported_modules(path)
    for module in modules:
        root = module.split(".")[0]
        assert root not in FORBIDDEN_ROOTS, f"{path.name} imports forbidden root {module!r}"
        lowered = module.lower()
        for needle in FORBIDDEN_SUBSTRINGS:
            assert needle not in lowered, f"{path.name} imports forbidden module {module!r}"


def test_service_imports_are_control_plane_only():
    _assert_clean_imports(SERVICE)


def test_contract_imports_are_control_plane_only():
    _assert_clean_imports(CONTRACT)


def test_service_does_not_create_exercise_plan_or_dispatch_workflow():
    source = SERVICE.read_text(encoding="utf-8").lower()
    # docstring may *describe* the prohibition; strip it before scanning identifiers.
    tree = ast.parse(SERVICE.read_text(encoding="utf-8"))
    body_wo_docstring = ast.get_docstring(tree)
    if body_wo_docstring:
        source = source.replace(body_wo_docstring.lower(), "")
    for banned in ("deploymentplan", "create_exercise", "generate_plan", "dispatch", "exercise("):
        assert banned not in source, f"service references {banned!r}"


def test_no_publication_router_module_exists():
    routers = API_DIR / "secp_api" / "routers"
    for path in routers.glob("*.py"):
        assert "publication" not in path.name


def test_publication_service_is_not_wired_into_any_route():
    # No route handler should import the publication service (it is not externally reachable).
    routers = API_DIR / "secp_api" / "routers"
    for path in routers.glob("*.py"):
        modules = _imported_modules(path)
        assert "secp_api.services.environment_publication" not in modules, path.name


def test_main_registers_no_publication_router():
    main_src = (API_DIR / "secp_api" / "main.py").read_text(encoding="utf-8").lower()
    assert "environment_publication" not in main_src
    assert "publication" not in main_src


def test_service_module_exposes_only_publish_version_publicly():
    tree = ast.parse(SERVICE.read_text(encoding="utf-8"))
    public_funcs = [
        n.name for n in tree.body if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")
    ]
    assert public_funcs == ["publish_version"], public_funcs
