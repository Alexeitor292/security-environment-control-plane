"""SECP-B2-0 — structural + static safety guardrails for the read-only preflight.

Proves: the API cannot import/execute the Proxmox transport/collector or the worker preflight
consumer; the worker preflight package (apart from the injected collection seam) contains no
HTTP/socket/subprocess/secret-manager code; and no concrete infrastructure value is committed.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
API_PKG = REPO_ROOT / "apps" / "api" / "secp_api"
WORKER_PREFLIGHT = REPO_ROOT / "apps" / "worker" / "secp_worker" / "preflight"


def _py(pkg: Path) -> list[Path]:
    return [p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts]


# Modules/symbols the API must never import (provider contact + preflight run are worker-only).
_API_FORBIDDEN_IMPORT_PREFIXES = ("secp_plugin_proxmox", "secp_worker.preflight")
_API_FORBIDDEN_SYMBOLS = {
    "run_readonly_preflight",
    "claim_and_process_one",
    "process_all_queued",
    "run_consumer_loop",
    "SealedSecretResolver",
    "LiveReadOnlyProxmoxCollector",
    "HttpxReadOnlyTransport",
    # SECP-B2-1: the worker-only secret-resolution contract is never importable by the API.
    "SealedUnavailableResolver",
    "WorkerSecretResolver",
    "TrustedResolutionRequest",
    "SecretMaterial",
    "TrustedCredentialReference",
    "build_trusted_resolution_request",
    "build_resolution_contract",
    "ResolutionContract",
    # SECP-B2-3: the worker-only lease/identity/activation-gate internals are never API-importable.
    "acquire_lease",
    "begin_attempt",
    "mark_consumed",
    "OperationKey",
    "WorkerIdentityVerifier",
    "DenyingWorkerIdentityVerifier",
    "ResolutionActivationGate",
    "SealedActivationGate",
    # SECP-B2-4: the worker-only OpenBao adapter, its client seam, and the reverifier are never
    # importable by the API.
    "OpenBaoWorkerSecretResolver",
    "OpenBaoHttpClient",
    "ResolverSelfTest",
    "SealedResolverSelfTest",
    "AuthoritativeReverifier",
    "DbAuthoritativeReverifier",
    "ReverifiedAuthority",
    # SECP-B2-4.2: the worker-only activation-capability verifier (now wired into the sealed
    # preflight chain) and the offline preflight wiring self-test are never API-importable.
    "load_and_verify_activation_capability",
    "ResolverActivationCapability",
    "ActivationAuthorizationRefused",
    "run_preflight_wiring_self_test",
    "PreflightSelfTestResult",
}


def test_api_never_imports_plugin_or_preflight_worker():
    for path in _py(API_PKG):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(_API_FORBIDDEN_IMPORT_PREFIXES), (
                        f"{path.name} imports {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert not module.startswith(_API_FORBIDDEN_IMPORT_PREFIXES), (
                    f"{path.name} imports from {module}"
                )
                for alias in node.names:
                    assert alias.name not in _API_FORBIDDEN_SYMBOLS, (
                        f"{path.name} imports {alias.name}"
                    )


def test_api_makes_no_preflight_execution_calls():
    forbidden = {"run_readonly_preflight", "claim_and_process_one", "process_all_queued"}
    for path in _py(API_PKG):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                assert name not in forbidden, f"{path.name} calls {name}"


def test_worker_preflight_has_no_network_or_secret_manager_code():
    forbidden = (
        "import httpx",
        "from httpx",
        "import requests",
        "import aiohttp",
        "import socket",
        "from socket",
        "import subprocess",
        "from subprocess",
        "import ssl",
        "import paramiko",
        "EnvSecretResolver",  # the sealed resolver never reads env / a real backend
        "os.environ",
        "run_live_readonly_collection",  # the sealed path is not reached in this PR
    )
    for path in _py(WORKER_PREFLIGHT):
        src = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"{path.name} must not reference `{token}`"


def test_worker_preflight_makes_no_transport_or_subprocess_calls():
    forbidden_calls = {"Popen", "urlopen", "create_connection", "getaddrinfo", "connect", "socket"}
    for path in _py(WORKER_PREFLIGHT):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                assert name not in forbidden_calls, f"{path.name} calls {name}"


def test_worker_secret_resolution_has_no_backend_or_network_client():
    # SECP-B2-1: the sealed secret-resolution contract introduces NO secret-backend/provider/
    # network/subprocess client. It resolves nothing and contacts nothing.
    forbidden = (
        "import hvac",  # HashiCorp Vault client library (a bundled backend client is forbidden)
        "from hvac",
        "import openbao",  # the OpenBao ADAPTER is allowed; a bundled client LIBRARY is not
        "from openbao",
        "import vault",
        "from vault",
        "boto3",
        "botocore",
        "azure",
        "googleapiclient",
        "keyring",
        "import httpx",
        "from httpx",
        "import requests",
        "import aiohttp",
        "import socket",
        "from socket",
        "import subprocess",
        "from subprocess",
        "import ssl",
        "os.environ",
        "os.getenv",
        "getpass",
        "EnvSecretResolver",
    )
    for path in _py(WORKER_PREFLIGHT):
        src = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"{path.name} must not reference `{token}`"


def test_worker_secret_resolution_defines_no_orm_or_persistence():
    # No secret material may be storable: the preflight package defines no ORM model / column /
    # table (secret material lives only in an in-memory, non-serializable wrapper).
    forbidden = ("mapped_column", "Column(", "Table(", "declarative_base", "__tablename__")
    for path in _py(WORKER_PREFLIGHT):
        src = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"{path.name} must not define persistence (`{token}`)"


def test_only_worker_code_constructs_a_trusted_resolution_request():
    # The trusted request builder + type are referenced ONLY under the worker (and tests) — never
    # in API application code or the frontend. A caller elsewhere cannot construct a trust anchor.
    needles = ("build_trusted_resolution_request", "TrustedResolutionRequest(")
    for path in _py(API_PKG):
        src = path.read_text(encoding="utf-8")
        for needle in needles:
            assert needle not in src, f"API file {path.name} references `{needle}`"
    web_src = REPO_ROOT / "apps" / "web" / "src"
    for path in list(web_src.rglob("*.ts")) + list(web_src.rglob("*.tsx")):
        if ".mypy_cache" in path.parts or "node_modules" in path.parts:
            continue
        src = path.read_text(encoding="utf-8")
        for needle in needles:
            assert needle not in src, f"frontend file {path.name} references `{needle}`"


def test_frontend_has_no_credential_entry_field_or_secret_resolution_route():
    # SECP-B2-1: the UI must never collect/transmit a literal credential, and must not expose a
    # secret-resolution route. No password inputs; no credential-entry/secret-resolution endpoints.
    web_src = REPO_ROOT / "apps" / "web" / "src"
    forbidden = (
        'type="password"',
        "type='password'",
        "/secrets",
        "/credentials",
        "secret-resolution",
        "resolveSecret",
        "uploadCredential",
        "submitCredential",
        "enterCredential",
        "SecretMaterial",
        "reveal_secret",
    )
    scanned = 0
    for path in list(web_src.rglob("*.ts")) + list(web_src.rglob("*.tsx")):
        if ".mypy_cache" in path.parts or "node_modules" in path.parts:
            continue
        scanned += 1
        src = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"frontend file {path.name} references `{token}`"
    assert scanned >= 5  # guard against the scan silently matching nothing


def test_no_concrete_infrastructure_values_in_new_sources():
    import re

    new_sources = (
        _py(API_PKG / "services")
        + [API_PKG / "live_read_contract.py", API_PKG / "schemas_readonly_preflight.py"]
        + [API_PKG / "routers" / "readonly_preflight.py"]
        + _py(WORKER_PREFLIGHT)
    )
    forbidden = re.compile(
        r"(?:\d{1,3}\.){3}\d{1,3}"  # IPv4
        r"|https?://[a-z0-9]"  # URL with host
        r"|:\d{4,5}\b"  # port
        r"|PVEAPIToken|@pam|@pve|vmbr\d|vlan\s*\d",
        re.IGNORECASE,
    )
    for path in new_sources:
        text = path.read_text(encoding="utf-8")
        m = forbidden.search(text)
        assert m is None, f"{path.name} contains a concrete infrastructure value: {m.group(0)!r}"
