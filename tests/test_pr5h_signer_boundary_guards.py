"""SECP-PR5H-B1 Phase 3 — root privilege-boundary guards for the evidence-driven exchange.

These prove the security invariants of the signer boundary as GUARDS (not behaviour), so a future
refactor cannot silently give the NON-ROOT controller API the ability to read the enrollment key,
run as root, instantiate the concrete root signer, or reach a generic root capability:

* the controller API container runs NON-ROOT and neither contains nor mounts the enrollment key;
* no API module imports the concrete root filesystem signer, the hardened ``RealFilesystem``, the
  key lifecycle, or the management-plane broker;
* ONLY the management-plane broker composition instantiates the concrete signer;
* the shipped API signer client is SEALED by default (fails closed) and the exchange is inert;
* the HTTP exchange requests expose NO key / socket / path / domain / signer selector;
* the broker + its identity provider carry no generic execution / shell / subprocess capability, and
  the worker driver reaches no provider / OpenTofu / operator / controlled-live capability.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
API_PKG = REPO / "apps" / "api" / "secp_api"


def _py_files(root: Path) -> list[Path]:
    return [
        p for p in root.rglob("*.py") if "__pycache__" not in p.parts and "tests" not in p.parts
    ]


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _import_modules_and_symbols(path: Path) -> tuple[set[str], set[str]]:
    """Every imported module name AND every imported symbol name (incl. dynamic ``__import__`` /
    ``importlib.import_module`` string args), so a forbidden name cannot slip past."""
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


# --- 1. the API runs non-root and never holds the enrollment key ---------------------------------


def test_api_container_runs_non_root() -> None:
    dockerfile = (REPO / "infra" / "dev" / "Dockerfile.python").read_text(encoding="utf-8")
    users = [ln.split()[1] for ln in dockerfile.splitlines() if ln.strip().startswith("USER ")]
    assert users, "the API Dockerfile must set a USER"
    assert users[-1] == "secp", f"the API container must end NON-ROOT, got USER {users[-1]}"
    assert "USER root" not in dockerfile.splitlines()[-1:], "must not end as root"


def test_api_image_and_infra_never_contain_or_mount_the_enrollment_key() -> None:
    import sys

    sys.path.insert(0, str(REPO / "apps" / "commissioning"))
    from secp_commissioning.controller_enrollment_signer import CONTROLLER_ENROLLMENT_KEY_PATH

    key_basename = CONTROLLER_ENROLLMENT_KEY_PATH.rsplit("/", 1)[-1]
    infra = REPO / "infra"
    offenders = []
    for path in infra.rglob("*"):
        if (
            path.is_file()
            and path.suffix.lower() in {".yml", ".yaml", ".env", ""}
            or (path.is_file() and path.name.startswith("Dockerfile"))
        ):
            text = path.read_text(encoding="utf-8", errors="ignore")
            if key_basename in text or CONTROLLER_ENROLLMENT_KEY_PATH in text:
                offenders.append(str(path.relative_to(REPO)))
    assert not offenders, f"the enrollment key is referenced by infra (never mount it): {offenders}"


# --- 2. no API module imports the concrete root signer / filesystem / broker ---------------------

_FORBIDDEN_API_SYMBOLS = {
    "ControllerEnrollmentOfferSigner",  # the concrete root signer (only the broker builds it)
    "RealFilesystem",  # the hardened root filesystem reader
    "prepare_controller_enrollment_key",
    "rotate_controller_enrollment_key",
    "_read_root_key",
}
_FORBIDDEN_API_MODULES = {
    "secp_management.enrollment_signer_broker",
    "secp_management.enrollment_signer_identity",
}


def test_no_api_module_imports_the_concrete_root_signer_or_broker() -> None:
    offenders = []
    for path in _py_files(API_PKG):
        modules, symbols = _import_modules_and_symbols(path)
        bad_syms = symbols & _FORBIDDEN_API_SYMBOLS
        bad_mods = {m for m in modules if m in _FORBIDDEN_API_MODULES}
        # the whole management plane is already fenced off, but assert the broker modules explicitly
        bad_mods |= {m for m in modules if m.split(".")[0] == "secp_management"}
        if bad_syms or bad_mods:
            offenders.append((path.name, sorted(bad_syms | bad_mods)))
    assert not offenders, offenders


def test_only_the_broker_composition_instantiates_the_concrete_signer() -> None:
    """A ``ControllerEnrollmentOfferSigner(...)`` construction may appear in exactly ONE production
    module — the management-plane broker composition. Nothing in the API (or elsewhere) may build
    it."""
    builders = []
    for root in (REPO / "apps", REPO / "plugins"):
        if not root.exists():
            continue
        for path in _py_files(root):
            for node in ast.walk(_tree(path)):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "ControllerEnrollmentOfferSigner"
                ):
                    builders.append(str(path.relative_to(REPO)).replace("\\", "/"))
    assert builders == ["apps/management/secp_management/enrollment_signer_broker.py"], builders


# --- 3. the API signer client is sealed by default; the exchange is inert -------------------------


def test_the_api_signer_client_default_is_sealed() -> None:
    import sys

    sys.path.insert(0, str(REPO / "apps" / "api"))
    from secp_api.config import Settings
    from secp_api.enrollment_signer_client import (
        SealedEnrollmentOfferSignerClient,
        build_enrollment_offer_signer,
    )

    assert Settings(app_env="dev").enrollment_signer_socket_path == ""
    signer = build_enrollment_offer_signer(Settings(app_env="dev"))
    assert isinstance(signer, SealedEnrollmentOfferSignerClient)


# --- 4. HTTP cannot select a key / socket / path / domain / signer identity -----------------------


def test_the_exchange_requests_expose_no_privileged_selector() -> None:
    import sys

    sys.path.insert(0, str(REPO / "apps" / "api"))
    from secp_api.schemas_enrollment import BindExchangeRequest, ResultExchangeRequest

    forbidden = ("socket", "controller_key", "signer", "key_path", "private", "domain", "root")
    for model in (BindExchangeRequest, ResultExchangeRequest):
        assert model.model_config.get("extra") == "forbid", model.__name__
        for field in model.model_fields:
            low = field.lower()
            assert not any(token in low for token in forbidden), (model.__name__, field)


# --- 5. no generic root/execution capability in the broker; driver stays inert --------------------

_FORBIDDEN_EXEC_CALLS = {"system", "popen", "spawn", "exec", "eval", "run", "check_output", "call"}
_FORBIDDEN_EXEC_MODULES = {"subprocess", "shutil", "pty", "ctypes"}


def test_the_broker_has_no_generic_execution_or_shell_capability() -> None:
    for name in ("enrollment_signer_broker.py", "enrollment_signer_identity.py"):
        path = REPO / "apps" / "management" / "secp_management" / name
        modules, _symbols = _import_modules_and_symbols(path)
        assert not (modules & _FORBIDDEN_EXEC_MODULES), (name, modules & _FORBIDDEN_EXEC_MODULES)
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.Call):
                parts = node.func
                attr = parts.attr if isinstance(parts, ast.Attribute) else None
                root = None
                if isinstance(parts, ast.Attribute) and isinstance(parts.value, ast.Name):
                    root = parts.value.id
                if root in {"os", "subprocess"} and attr in _FORBIDDEN_EXEC_CALLS:
                    raise AssertionError(f"{name} calls {root}.{attr}")


def test_the_worker_driver_reaches_no_provider_operator_or_iac_capability() -> None:
    driver = REPO / "apps" / "worker" / "secp_worker" / "enrollment_driver.py"
    modules, symbols = _import_modules_and_symbols(driver)
    forbidden = {
        "opentofu",
        "terraform",
        "python_tofu",
        "temporalio",
        "proxmoxer",
        "boto3",
        "kubernetes",
        "subprocess",
        "docker",
        "secp_operator_deployment",
    }
    hits = {m for m in modules if m.split(".")[0] in forbidden}
    assert not hits, hits
    # no provider/operator/controlled-live token in an imported symbol or module either
    blob = " ".join(sorted(modules | symbols)).lower()
    for token in ("opentofu", "terraform", "operator", "controlled_live", "provider", "proxmox"):
        assert token not in blob, token
