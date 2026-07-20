"""PR5F deployment, seal, packaging, and forbidden-value architecture proofs.

These tests are intentionally static or pure.  They never construct a host adapter, open a network
connection, submit a workflow, or execute a process.  The fixed-layout POSIX transaction is covered
separately by ``test_pr5f_discovery_activation_root.py`` under its dedicated opt-in root CI gate.
"""

from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ACTIVATION_PACKAGE = REPO / "apps" / "deployment" / "secp_discovery_activation"
PYPROJECT = REPO / "pyproject.toml"
SUITE_CONFIG = REPO / ".ci" / "pytest-suite.json"

_LOWER_OR_UNRELATED_ROOTS = (
    REPO / "apps" / "api" / "secp_api",
    REPO / "apps" / "worker" / "secp_worker",
    REPO / "apps" / "commissioning" / "secp_commissioning",
    REPO / "apps" / "management" / "secp_management",
    REPO / "apps" / "deployment" / "secp_operator_deployment",
    REPO / "plugins",
    REPO / "contracts",
)

# PR5F is a local deployment package.  It may reuse hardened filesystem/pinned-process seams, but
# it must never acquire infrastructure-provider, workflow, generic subprocess, remote-shell, plan,
# apply, destroy, or operator-start authority.
_FORBIDDEN_IMPORT_PREFIXES = (
    "subprocess",
    "requests",
    "aiohttp",
    "paramiko",
    "asyncssh",
    "fabric",
    "pexpect",
    "docker",
    "proxmoxer",
    "temporalio",
    "opentofu",
    "terraform",
    "secp_plugin_proxmox",
    "secp_worker.plan_gen",
    "secp_worker.provisioning",
    "secp_operator_deployment.runner",
    "secp_operator_deployment.compositions",
)

_FORBIDDEN_CALL_LEAVES = {
    "run_plan_generation",
    "run_operator_worker",
    "apply",
    "destroy",
    "reset",
    "ssh",
    "exec",
    "eval",
}

_REAL_DEPLOYMENT_VALUES = {
    "secp-" + "control-01",
    "secp-site-" + "worker-01",
    "5c0ade6e35838038f9" + "f4f0ac5e7e8cf299556e65",
    "secp-python:63440c93957a" + "fd3f4d106115f19aee2924df9c68",
}


def _py_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def _repository_text_files() -> list[Path]:
    roots = (
        REPO / "apps",
        REPO / "contracts",
        REPO / "plugins",
        REPO / "docs",
        REPO / "infra",
        REPO / "scripts",
        REPO / "tests",
        REPO / ".ci",
        REPO / ".github",
    )
    suffixes = {".py", ".md", ".toml", ".json", ".yml", ".yaml", ".ts", ".tsx", ".sh"}
    files = [REPO / "pyproject.toml", REPO / "README.md"]
    for root in roots:
        files.extend(
            path
            for path in root.rglob("*")
            if path.is_file()
            and path.suffix in suffixes
            and "node_modules" not in path.parts
            and "__pycache__" not in path.parts
        )
    return sorted(set(files))


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _imports(tree: ast.AST) -> set[str]:
    """Collect direct imports and constant-string dynamic imports."""

    result: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            result.add(node.module)
        elif isinstance(node, ast.Call):
            target = _dotted(node.func)
            if target in {"__import__", "importlib.import_module"} and node.args:
                argument = node.args[0]
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    result.add(argument.value)
    return result


def _is_forbidden_import(module: str) -> bool:
    return any(
        module == prefix or module.startswith(prefix + ".") for prefix in _FORBIDDEN_IMPORT_PREFIXES
    )


@pytest.mark.parametrize(
    "path",
    _py_files(ACTIVATION_PACKAGE),
    ids=lambda path: path.name,
)
def test_activation_package_has_no_remote_provider_workflow_or_generic_process_authority(
    path: Path,
) -> None:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    forbidden_imports = sorted(module for module in _imports(tree) if _is_forbidden_import(module))
    forbidden_calls: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = _dotted(node.func)
        leaf = target.rsplit(".", 1)[-1]
        if leaf in _FORBIDDEN_CALL_LEAVES:
            forbidden_calls.append(target)
        if target == "os.system" or target == "os.popen" or target.startswith("os.spawn"):
            forbidden_calls.append(target)
        if target.startswith("subprocess."):
            forbidden_calls.append(target)
        for keyword in node.keywords:
            if (
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):
                forbidden_calls.append(target + "(shell=True)")
    assert not forbidden_imports, f"{path.name}: forbidden imports {forbidden_imports}"
    assert not forbidden_calls, f"{path.name}: forbidden calls {sorted(forbidden_calls)}"


def test_http_client_is_confined_to_the_closed_internal_proxy() -> None:
    users: dict[str, set[str]] = {}
    for path in _py_files(ACTIVATION_PACKAGE):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported = {
            module for module in _imports(tree) if module == "httpx" or module.startswith("httpx.")
        }
        if imported:
            users[path.name] = imported
    assert users == {"proxy.py": {"httpx"}}
    proxy_source = (ACTIVATION_PACKAGE / "proxy.py").read_text(encoding="utf-8")
    assert "trust_env=False" in proxy_source
    assert "follow_redirects=False" in proxy_source
    proxy_tree = ast.parse(proxy_source)
    stream_calls = [
        node
        for node in ast.walk(proxy_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "client"
        and node.func.attr == "stream"
    ]
    assert len(stream_calls) == 1
    assert stream_calls[0].args
    assert isinstance(stream_calls[0].args[0], ast.Constant)
    assert stream_calls[0].args[0].value == "POST"


def test_raw_socket_is_confined_to_the_strict_local_tls_probe() -> None:
    users: set[str] = set()
    for path in _py_files(ACTIVATION_PACKAGE):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if any(module == "socket" or module.startswith("socket.") for module in _imports(tree)):
            users.add(path.name)
    assert users <= {"local_adapter.py", "admission_tls_probe.py"}
    adapter_path = ACTIVATION_PACKAGE / "local_adapter.py"
    if adapter_path.exists():
        assert "local_adapter.py" in users
        source = adapter_path.read_text(encoding="utf-8")
        for required in (
            "ssl.PROTOCOL_TLS_CLIENT",
            "ssl.CERT_REQUIRED",
            "check_hostname",
            "load_verify_locations",
            "server_hostname",
            "settimeout",
        ):
            assert required in source
    worker_probe = REPO / "apps" / "worker" / "secp_worker" / "admission_tls_probe.py"
    if worker_probe.exists():
        source = worker_probe.read_text(encoding="utf-8")
        for required in (
            "ssl.PROTOCOL_TLS_CLIENT",
            "ssl.CERT_REQUIRED",
            "check_hostname",
            "load_verify_locations",
            "server_hostname",
            "settimeout",
        ):
            assert required in source


def test_activation_boundary_scan_is_not_vacuous() -> None:
    files = _py_files(ACTIVATION_PACKAGE)
    assert len(files) >= 7
    assert {"layout.py", "profile.py", "render.py", "state.py", "status.py", "tls.py"} <= {
        path.name for path in files
    }


def test_lower_planes_and_operator_package_cannot_import_pr5f_root_authority() -> None:
    offenders: dict[str, list[str]] = {}
    scanned = 0
    for root in _LOWER_OR_UNRELATED_ROOTS:
        for path in _py_files(root):
            scanned += 1
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imported = sorted(
                module
                for module in _imports(tree)
                if module == "secp_discovery_activation"
                or module.startswith("secp_discovery_activation.")
            )
            if imported:
                offenders[str(path.relative_to(REPO))] = imported
    assert scanned >= 50
    assert not offenders, (
        f"PR5F root deployment authority leaked into a lower/unrelated plane: {offenders}"
    )


def test_activation_layout_is_fixed_and_worker_private() -> None:
    from secp_discovery_activation.layout import PRODUCTION_LAYOUT

    expected = {
        "profile_path": "/etc/secp/discovery-activation/profile.json",
        "worker_compose_override_path": (
            "/etc/secp/discovery-activation/worker-compose.override.yaml"
        ),
        "proxy_contract_path": "/etc/secp/discovery-activation/admission-proxy.json",
        "controller_compose_override_path": (
            "/etc/secp/discovery-activation/controller-compose.override.yaml"
        ),
        "ca_certificate_path": "/etc/secp/discovery-activation/tls/admission-ca.pem",
        "server_certificate_path": "/etc/secp/discovery-activation/tls/admission-server.pem",
        "server_private_key_path": "/etc/secp/discovery-activation/tls/admission-server.key",
        "worker_state_host_path": "/var/lib/secp/discovery-worker",
        "worker_state_container_path": "/var/run/secp",
        "worker_keys_container_path": "/var/run/secp/worker-keys",
        "discovery_bundle_container_path": "/var/run/secp/discovery-bundle",
        "worker_ca_container_path": "/etc/secp/admission-ca.pem",
        "journal_path": "/var/lib/secp/discovery-activation/transaction.json",
        "evidence_path": "/var/lib/secp/discovery-activation/evidence.json",
    }
    for field, value in expected.items():
        assert getattr(PRODUCTION_LAYOUT, field) == value
    assert PRODUCTION_LAYOUT.worker_keys_container_path.startswith(
        PRODUCTION_LAYOUT.worker_state_container_path + "/"
    )
    assert PRODUCTION_LAYOUT.discovery_bundle_container_path.startswith(
        PRODUCTION_LAYOUT.worker_state_container_path + "/"
    )


def test_profile_cannot_redirect_privileged_writes_or_mounts() -> None:
    from secp_discovery_activation.profile import DeploymentProfile

    fields = set(DeploymentProfile.model_fields)
    forbidden_path_knobs = {
        "profile_path",
        "worker_compose_override_path",
        "proxy_contract_path",
        "controller_compose_override_path",
        "ca_certificate_path",
        "server_certificate_path",
        "server_private_key_path",
        "worker_state_host_path",
        "worker_state_container_path",
        "journal_path",
        "evidence_path",
    }
    assert not fields & forbidden_path_knobs
    # The only caller-supplied paths are independently pinned executable identities, not write or
    # mount destinations.
    assert {name for name in fields if name.endswith("_executable")} == {
        "container_runtime_executable",
        "compose_executable",
    }


def test_worker_state_mount_is_rendered_only_by_the_ordinary_worker_overlay() -> None:
    path = ACTIVATION_PACKAGE / "render.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    containing_functions: list[str] = []
    for function in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)):
        if any(
            isinstance(node, ast.Attribute) and node.attr == "worker_state_host_path"
            for node in ast.walk(function)
        ):
            containing_functions.append(function.name)
    assert containing_functions == ["render_worker_compose_override"]


def test_exact_status_taxonomy_and_flags_alone_never_report_ready() -> None:
    from secp_discovery_activation.status import (
        ALL_STATES,
        DISABLED,
        PREPARED,
        ActivationObservation,
        derive_status,
    )

    assert ALL_STATES == (
        "disabled",
        "prepared",
        "TLS-ready",
        "worker-recreation-required",
        "worker-starting",
        "keys-generated",
        "public-node-published",
        "awaiting-finalization",
        "awaiting-bootstrap-session",
        "awaiting-proof",
        "awaiting-authorization",
        "awaiting-bundle",
        "bundle-ready",
        "discovery-contacted",
        "recovery-required",
    )
    # A missing/incoherent observation can never be interpreted as proof of no effects.
    assert derive_status(ActivationObservation()).state == "recovery-required"
    assert derive_status(ActivationObservation(coherent=True)).state == DISABLED
    flags_only = ActivationObservation(
        coherent=True,
        activation_enabled=True,
        b8_flags_enabled=True,
    )
    assert derive_status(flags_only).state == PREPARED


def test_pr5f_preserves_generic_and_plan_only_seals() -> None:
    from secp_worker.plan_gen import process_boundary
    from secp_worker.provisioning import activation, process_executor

    assert activation._B1A_SUBPROCESS_SEALED is True
    assert process_executor._B1A_SUBPROCESS_SEALED is True
    assert process_boundary._PLAN_ONLY_PROCESS_SEALED is False


def test_shipped_activation_adapter_is_mutation_sealed() -> None:
    from secp_discovery_activation.adapters import (
        ActivationAdapterError,
        SealedActivationAdapter,
    )

    adapter = SealedActivationAdapter()
    receipt = adapter.receipt()
    assert receipt.transaction_id == "sealed"
    assert receipt.journal_present is False
    assert receipt.effects_started is False
    assert receipt.worker_recreated is False
    with pytest.raises(ActivationAdapterError) as error:
        adapter.recreate_worker(object())  # type: ignore[arg-type]
    assert error.value.reason_code == "activation_adapter_not_provisioned"


def test_engine_exposes_only_the_closed_eight_operation_surface() -> None:
    from secp_discovery_activation import engine

    operations = {name for name in engine.__all__ if name.endswith("_operation")}
    assert operations == {
        "inspect_operation",
        "plan_operation",
        "render_operation",
        "install_operation",
        "verify_operation",
        "status_operation",
        "rollback_operation",
        "evidence_operation",
    }
    assert not {"activate", "exec", "shell", "apply", "destroy"} & set(engine.__all__)
    gate = engine.WriteGate()
    assert gate.refusal_reason() == "write_authority_required"
    assert engine.WriteGate(write=True).refusal_reason() == "explicit_confirmation_required"
    assert engine.WriteGate(write=True, confirm=True).refusal_reason() is None


def test_authenticated_evidence_schema_requires_absence_of_forbidden_effects() -> None:
    from secp_discovery_activation.evidence import ActivationEvidence

    fields = set(ActivationEvidence.model_fields)
    assert {
        "operator_service_present",
        "operator_queue_polled",
        "generic_activation_subprocess_sealed",
        "generic_executor_subprocess_sealed",
        "plan_only_process_sealed",
        "real_provisioning_enabled",
        "forbidden_infrastructure_contacts_performed",
        "workflows_submitted",
        "run_plan_generation_called",
        "opentofu_executed",
        "proxmox_contacted",
    } <= fields
    source = (ACTIVATION_PACKAGE / "evidence.py").read_text(encoding="utf-8")
    assert "if getattr(self, field_name) is not False:" in source


def test_package_source_contains_no_operator_queue_or_plan_activation_hook() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in _py_files(ACTIVATION_PACKAGE))
    assert "SECP_TEMPORAL_OPERATOR_TASK_QUEUE" not in source
    assert "secp-controlled-live-v1" not in source
    assert "run_plan_generation(" not in source
    assert "run_operator_worker(" not in source


def test_no_real_deployment_identity_or_literal_ip_is_committed_to_pr5f_surface() -> None:
    paths = [
        *_py_files(ACTIVATION_PACKAGE),
        REPO / "docs" / "runbooks" / "pr5f-b8-production-activation.md",
        REPO / "infra" / "production" / "README.md",
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    repository_source = b"\n".join(path.read_bytes() for path in _repository_text_files())
    for forbidden in _REAL_DEPLOYMENT_VALUES:
        assert forbidden.encode("ascii") not in repository_source
    package_source = "\n".join(
        path.read_text(encoding="utf-8") for path in _py_files(ACTIVATION_PACKAGE)
    )
    ip_literals = re.findall(
        r"(?<![A-Za-z0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9])", package_source
    )
    # The sole literal is the proxy process's container-internal bind. Host publication is bound to
    # the validated deployment-local private listener address by the Compose renderer.
    assert ip_literals == ["0.0.0.0"]
    assert 'host="0.0.0.0"' in package_source
    # Parser marker strings are expected; an actual embedded PEM payload is not.
    assert re.search(r"-----BEGIN [^-]*PRIVATE KEY-----\s*\n[A-Za-z0-9+/]{40,}", combined) is None
    assert re.search(r"-----BEGIN CERTIFICATE-----\s*\n[A-Za-z0-9+/]{40,}", combined) is None


def test_wheel_scripts_and_canonical_inventory_include_only_stable_pr5f_surfaces() -> None:
    from secp_discovery_activation.layout import ADMISSION_PROXY_EXECUTABLE

    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    packages = project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    assert "apps/deployment/secp_discovery_activation" in packages
    # Both PR5F executables have fixed reviewed surfaces: the private proxy and the explicit,
    # write-gated host activation CLI. Neither accepts a filesystem path or generic command.
    scripts = project["project"].get("scripts", {})
    assert scripts == {
        "secpctl": "secp_management.cli:main",
        "secp-admission-proxy": "secp_discovery_activation.proxy:main",
        "secp-discovery-activation": "secp_discovery_activation.cli:main",
    }
    assert Path(ADMISSION_PROXY_EXECUTABLE).name in scripts

    suite = json.loads(SUITE_CONFIG.read_text(encoding="utf-8"))
    assert "tests" in suite["roots"]
    excluded = {entry["path"] for entry in suite.get("exclusions", [])}
    assert "tests/test_pr5f_discovery_activation_boundary.py" not in excluded
    assert "tests/test_pr5f_discovery_activation_root.py" not in excluded
