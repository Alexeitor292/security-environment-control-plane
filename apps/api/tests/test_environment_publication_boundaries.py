"""Architecture / security boundary tests for EnvironmentVersion publication.

PR B kept publication as control-plane DB logic only; PR C (ADR-016) makes it reachable through
exactly ONE audited route. These tests pin both: the service and route import no
worker/provider/transport/subprocess/socket/HTTP-client/secret-resolver/OpenTofu/Terraform code and
create no exercise/plan/workflow; the route reaches the publication service (never the ORM
constructor) and cannot bypass its preconditions; the request schema carries no caller
idempotency/fingerprint/topology; every closed error code has an explicit HTTP status; and the
audit payloads are allowlisted.
"""

from __future__ import annotations

import ast
from pathlib import Path

from secp_api.enums import EnvironmentPublicationErrorCode
from secp_api.errors import EnvironmentPublicationError
from secp_api.schemas_environment_publication import EnvironmentPublicationRequest

API_DIR = Path(__file__).resolve().parents[1]
SERVICE = API_DIR / "secp_api" / "services" / "environment_publication.py"
CONTRACT = API_DIR / "secp_api" / "environment_publication_contract.py"
ROUTER = API_DIR / "secp_api" / "routers" / "environment_publication.py"
REQUEST_SCHEMA = API_DIR / "secp_api" / "schemas_environment_publication.py"

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
# Downstream service modules the publication route must never import (no auto-triggering).
FORBIDDEN_DOWNSTREAM = (
    "secp_api.services.plans",
    "secp_api.services.planning",
    "secp_api.services.exercises",
    "secp_api.services.provisioning",
    "secp_api.services.staging_labs",
    "secp_api.services.staging_deployments",
)


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
    return modules


def _assert_clean_imports(path: Path) -> None:
    for module in _imported_modules(path):
        root = module.split(".")[0]
        assert root not in FORBIDDEN_ROOTS, f"{path.name} imports forbidden root {module!r}"
        lowered = module.lower()
        for needle in FORBIDDEN_SUBSTRINGS:
            assert needle not in lowered, f"{path.name} imports forbidden module {module!r}"


# --- service + contract stay control-plane only (PR B, still enforced) -------------------------


def test_service_imports_are_control_plane_only():
    _assert_clean_imports(SERVICE)


def test_contract_imports_are_control_plane_only():
    _assert_clean_imports(CONTRACT)


def test_service_does_not_create_exercise_plan_or_dispatch_workflow():
    tree = ast.parse(SERVICE.read_text(encoding="utf-8"))
    source = SERVICE.read_text(encoding="utf-8").lower()
    doc = ast.get_docstring(tree)
    if doc:
        source = source.replace(doc.lower(), "")
    for banned in ("deploymentplan", "create_exercise", "generate_plan", "dispatch", "exercise("):
        assert banned not in source, f"service references {banned!r}"


def test_service_exposes_only_publish_functions():
    tree = ast.parse(SERVICE.read_text(encoding="utf-8"))
    public = [
        n.name for n in tree.body if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")
    ]
    assert set(public) == {"publish_version", "publish_version_with_result"}, public


# --- the route is reachable but bounded (PR C) -------------------------------------------------


def test_router_imports_are_control_plane_only():
    _assert_clean_imports(ROUTER)


def test_router_does_not_import_downstream_services():
    modules = _imported_modules(ROUTER)
    for forbidden in FORBIDDEN_DOWNSTREAM:
        assert forbidden not in modules, f"router imports downstream {forbidden!r}"


def test_router_calls_service_not_the_orm_constructor():
    source = ROUTER.read_text(encoding="utf-8")
    # the route delegates to the publication service; it never constructs the version itself
    assert "publish_version_with_result" in source
    assert "EnvironmentVersion(" not in source
    # and never computes hashes / fingerprints / reconstructs topology itself
    for banned in ("content_hash(", "compose_published_definition(", "_next_version_number"):
        assert banned not in source


def test_exactly_one_publication_route_post_only():
    from secp_api.main import create_app

    schema = create_app().openapi()
    publish_paths = [p for p in schema["paths"] if p.endswith("/environment-versions/publish")]
    assert publish_paths == ["/api/v1/environment-versions/publish"], publish_paths
    assert set(schema["paths"]["/api/v1/environment-versions/publish"]) == {"post"}


# --- request schema carries no server-owned / caller-forbidden inputs --------------------------


def test_request_schema_forbids_extra_and_owns_no_server_fields():
    fields = set(EnvironmentPublicationRequest.model_fields)
    assert fields == {
        "template_id",
        "definition",
        "topology_document_id",
        "topology_revision_id",
        "expected_topology_content_hash",
        "validation_result_id",
        "base_environment_version_id",
    }
    for forbidden in ("idempotency_key", "publication_fingerprint", "topology", "provenance"):
        assert forbidden not in fields
    assert EnvironmentPublicationRequest.model_config.get("extra") == "forbid"


# --- closed error mapping + redaction ----------------------------------------------------------


def test_every_error_code_has_explicit_http_status():
    enum_values = {c.value for c in EnvironmentPublicationErrorCode}
    assert set(EnvironmentPublicationError._STATUS) == enum_values
    for code in EnvironmentPublicationErrorCode:
        assert EnvironmentPublicationError(code).http_status in {403, 404, 409, 422, 500}


def test_error_is_redacted():
    assert EnvironmentPublicationError.redacted is True


def test_request_validation_is_redacted_in_main():
    main_src = (API_DIR / "secp_api" / "main.py").read_text(encoding="utf-8")
    assert "invalid_environment_publication_input" in main_src
    assert "/api/v1/environment-versions/publish" in main_src


# --- audit payload keys are allowlisted --------------------------------------------------------

_SUCCESS_KEYS = {
    "template_id",
    "environment_version_id",
    "version_number",
    "environment_content_hash",
    "publication_fingerprint",
    "topology_document_id",
    "topology_revision_id",
    "topology_content_hash",
    "topology_validation_result_id",
    "topology_validation_result_hash",
    "base_environment_version_id",
    "publication_contract_version",
}
_REFUSAL_KEYS = {
    "refusal_code",
    "template_id",
    "topology_document_id",
    "topology_revision_id",
    "expected_topology_content_hash",
    "validation_result_id",
    "base_environment_version_id",
}


def _audit_keys(func_name: str) -> set[str]:
    """The literal dict keys returned by an audit-payload builder in the router (static parse)."""
    tree = ast.parse(ROUTER.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == func_name)
    for node in ast.walk(fn):
        if isinstance(node, ast.Dict):
            keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
            if keys:
                return keys
    return set()


def test_success_audit_payload_keys_are_allowlisted():
    assert _audit_keys("_success_audit_data") == _SUCCESS_KEYS


def test_refusal_audit_payload_keys_are_allowlisted():
    assert _audit_keys("_refusal_audit_data") == _REFUSAL_KEYS


def _function_source(func_name: str) -> str:
    """Unparsed body of a router function, EXCLUDING its docstring (which may name the words we
    are asserting never appear in the actual code)."""
    tree = ast.parse(ROUTER.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == func_name)
    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    return "\n".join(ast.unparse(node) for node in body)


def test_audit_builders_do_not_reference_definition_or_spec():
    # The route legitimately forwards body.definition to the SERVICE; the AUDIT builders must not.
    for builder in ("_success_audit_data", "_refusal_audit_data"):
        src = _function_source(builder)
        for banned in ("definition", ".spec", "findings"):
            assert banned not in src, f"{builder} references {banned!r}"
