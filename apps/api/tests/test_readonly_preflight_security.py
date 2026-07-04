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
