"""Architecture / security boundary tests for planning (ADR-016 PR E, deliverable 13).

The plan binds ONE EnvironmentVersion via ``environment_version_id`` + ``version_content_hash`` and
NOTHING more: the plan never becomes a second topology-publication envelope. These pin that the
planning service + plans router never import or query topology-authoring records; the DeploymentPlan
model carries no publication/topology provenance columns (so no migration is needed); plan
generation consumes the immutable ``version.spec``; no lifecycle transition auto-triggers the next;
plan approval deploys nothing; the binding verifier consults no audit data; and the exact
EnvironmentVersion read endpoint is read-only.
"""

from __future__ import annotations

import ast
from pathlib import Path

from secp_api.models import DeploymentPlan

API_DIR = Path(__file__).resolve().parents[1]
PLANNING = API_DIR / "secp_api" / "services" / "planning.py"
PLANS_ROUTER = API_DIR / "secp_api" / "routers" / "plans.py"
CATALOG_ROUTER = API_DIR / "secp_api" / "routers" / "catalog.py"

# Transport / infra / secret roots + substrings the planning layer must never pull in.
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
FORBIDDEN_SUBSTRINGS = ("terraform", "opentofu", "transport", "secret", "resolver")
# Topology-authoring modules the planning layer must never touch (the plan consumes the immutable
# version.spec, never a TopologyRevision / TopologyValidationResult / authoring document).
TOPOLOGY_AUTHORING_MODULES = (
    "secp_api.topology_authoring_models",
    "secp_api.schemas_topology_authoring",
    "secp_api.services.topology_authoring",
)
# Names that would indicate a plan reading topology-authoring rows directly.
TOPOLOGY_AUTHORING_NAMES = (
    "TopologyRevision",
    "TopologyValidationResult",
    "TopologyAuthoringDocument",
    "topology_authoring",
)


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
    return modules


def _source_no_docstrings(path: Path) -> str:
    """Module source with every docstring removed (so words we assert never appear in CODE are not
    matched inside explanatory prose)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    src = path.read_text(encoding="utf-8")
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            doc = ast.get_docstring(node)
            if doc:
                src = src.replace(doc, "")
    return src


def _function_source(path: Path, func_name: str) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == func_name)
    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    return "\n".join(ast.unparse(node) for node in body)


# --- imports stay control-plane, no topology-authoring -----------------------------------------


def test_planning_service_imports_no_transport_or_infra():
    for module in _imported_modules(PLANNING):
        assert module.split(".")[0] not in FORBIDDEN_ROOTS, module
        lowered = module.lower()
        for needle in FORBIDDEN_SUBSTRINGS:
            assert needle not in lowered, f"planning.py imports forbidden {module!r}"


def test_planning_service_does_not_import_topology_authoring():
    modules = _imported_modules(PLANNING)
    for forbidden in TOPOLOGY_AUTHORING_MODULES:
        assert forbidden not in modules, f"planning.py imports {forbidden!r}"


def test_plans_router_does_not_import_topology_authoring():
    modules = _imported_modules(PLANS_ROUTER)
    for forbidden in TOPOLOGY_AUTHORING_MODULES:
        assert forbidden not in modules, f"plans.py imports {forbidden!r}"


def test_planning_service_never_names_topology_authoring_records():
    src = _source_no_docstrings(PLANNING)
    for name in TOPOLOGY_AUTHORING_NAMES:
        assert name not in src, f"planning.py references topology-authoring name {name!r}"


def test_plans_router_never_names_topology_authoring_records():
    src = _source_no_docstrings(PLANS_ROUTER)
    for name in TOPOLOGY_AUTHORING_NAMES:
        assert name not in src, f"plans.py references topology-authoring name {name!r}"


# --- the plan model carries NO publication/topology provenance columns (no migration) ----------


def test_deployment_plan_has_no_publication_provenance_columns():
    columns = set(DeploymentPlan.__table__.columns.keys())
    forbidden = {
        "source_topology_document_id",
        "source_topology_revision_id",
        "topology_content_hash",
        "topology_validation_result_id",
        "topology_validation_result_hash",
        "base_environment_version_id",
        "publication_contract_version",
        "publication_fingerprint",
        "topology_document_id",
        "topology_revision_id",
    }
    assert not (columns & forbidden), columns & forbidden
    # the ONLY canonical version binding is exactly these two columns.
    assert "environment_version_id" in columns
    assert "version_content_hash" in columns


# --- plan generation consumes the immutable version.spec ---------------------------------------


def test_plan_generation_consumes_version_spec():
    src = _function_source(PLANNING, "generate_plan")
    assert "version.spec" in src


# --- no transition auto-triggers the next; approval deploys nothing -----------------------------


def test_lifecycle_functions_do_not_auto_chain():
    # No plan lifecycle function may invoke another transition service or start execution.
    for func in ("generate_plan", "submit_plan", "approve_plan", "reject_plan"):
        src = _function_source(PLANNING, func)
        for banned in (
            "start_exercise",
            "deploy_exercise",
            "dispatch",
            "WorkflowRun(",
            "generate_manifest",
        ):
            assert banned not in src, f"{func} references {banned!r}"


def test_approve_plan_does_not_deploy():
    src = _function_source(PLANNING, "approve_plan").lower()
    # Deployment/provisioning ACTIONS (not the "deployment_plan" resource type / table name).
    for banned in (
        "workflowrun",
        "manifest",
        "dispatch",
        "provider.",
        "deploy_exercise",
        "deploy_started",
        "provisioning_apply",
        "start_exercise",
    ):
        assert banned not in src, f"approve_plan references {banned!r}"


# --- the binding verifier never reads audit data, and folds all corruption to the closed 409 ---


def test_binding_verifier_does_not_consult_audit():
    # Neither the verifier nor its category helper reads audit data — the binding decision is a pure
    # function of the immutable plan/exercise/version rows.
    for func in ("require_plan_version_binding", "_binding_disagreement_category"):
        assert "audit" not in _function_source(PLANNING, func).lower(), func


def test_binding_verifier_uses_raw_session_get_not_user_facing_helpers():
    # The verifier loads the referenced Exercise + EnvironmentVersion with the raw, org-unaware
    # session.get — NEVER the user-facing get_version/get_exercise helpers — so a dangling or
    # cross-org internal reference folds into the closed 409 instead of leaking a 404/403.
    verifier = _function_source(PLANNING, "require_plan_version_binding")
    assert "session.get" in verifier
    assert "get_version(" not in verifier
    assert "get_exercise(" not in verifier
    # the recompute (defense-in-depth) lives in the category helper.
    assert "content_hash" in _function_source(PLANNING, "_binding_disagreement_category")


# --- the exact version read endpoint is read-only ----------------------------------------------


def test_get_environment_version_endpoint_is_read_only():
    src = _function_source(CATALOG_ROUTER, "get_environment_version")
    for banned in ("audit", ".add(", "commit", "delete", "flush", "= "):
        assert banned not in src, f"read endpoint performs a mutation-like op {banned!r}"
    assert "catalog.get_version" in src


def test_read_endpoint_is_get_only_in_openapi():
    from secp_api.main import create_app

    schema = create_app().openapi()
    path = "/api/v1/environment-versions/{version_id}"
    assert path in schema["paths"], schema["paths"].keys()
    assert set(schema["paths"][path]) == {"get"}, schema["paths"][path]


def test_openapi_plan_response_binding_shape():
    # Deliverable 14: the plan response carries the typed one-version binding (all fields) + typed
    # provenance, and NO full environment spec.
    from secp_api.main import create_app

    comps = create_app().openapi()["components"]["schemas"]
    plan = comps["PlanOut"]["properties"]
    assert "environment_version_binding" in plan
    assert "spec" not in plan  # the plan response never embeds the full environment spec
    binding = comps["PlanEnvironmentVersionBindingOut"]["properties"]
    assert set(binding) == {
        "environment_version_id",
        "template_id",
        "version_number",
        "api_version",
        "content_hash",
        "publication_provenance",
    }
    provenance = comps["VersionPublicationProvenanceOut"]["properties"]
    assert set(provenance) == {
        "topology_document_id",
        "topology_revision_id",
        "topology_content_hash",
        "topology_validation_result_id",
        "topology_validation_result_hash",
        "base_environment_version_id",
        "publication_contract_version",
        "publication_fingerprint",
    }
