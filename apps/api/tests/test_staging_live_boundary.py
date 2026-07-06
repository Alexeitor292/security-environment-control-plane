"""SECP-B2-5-pre — static/architecture guardrails for the sealed staging-live package.

Proves, WITHOUT importing or running the staging-live adapters against anything real, that:

* no normal runtime module (API package, worker main/temporal/consumer/orchestration/runtime, legacy
  discovery) imports ``secp_worker.staging_live`` or any concrete live adapter;
* the staging-live sources add no network/socket/subprocess/env-reading code and commit no concrete
  endpoint / IP / port / token / certificate / vault path;
* the defaults (sealed transport / sealed mTLS material) refuse offline, constructing nothing
  and contacting nothing;
* the legacy discovery / Temporal / EnvSecretResolver path is neither imported nor modified by the
  staging-live package.
"""

from __future__ import annotations

import ast
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
API_PKG = REPO_ROOT / "apps" / "api" / "secp_api"
WORKER_PKG = REPO_ROOT / "apps" / "worker" / "secp_worker"
STAGING_LIVE = WORKER_PKG / "staging_live"
# The SECP-B4 deployment engine is a PEER sealed, worker-only, unwired layer (not normal runtime);
# it legitimately builds on the staging-live primitives, so it is excluded here exactly like
# staging_live itself. Its own guard test asserts normal runtime never imports IT.
DEPLOYMENT = WORKER_PKG / "deployment"


def _py(pkg: Path) -> list[Path]:
    return [p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts]


def _normal_runtime_sources() -> list[Path]:
    """Every worker + API source EXCEPT the sealed staging-live/deployment layers (and caches)."""
    out: list[Path] = []
    for p in _py(WORKER_PKG):
        if STAGING_LIVE in p.parents or DEPLOYMENT in p.parents:
            continue
        out.append(p)
    out.extend(_py(API_PKG))
    return out


_CONCRETE_LIVE_SYMBOLS = frozenset(
    {
        "build_staging_live_composition",
        "StagingLiveComposition",
        "ConcreteOpenBaoClient",
        "PoPVerifiedAttestationSource",
        "run_openbao_readiness_canary",
        "run_proxmox_transport_canary",
        "LiveProxmoxProvider",
        "render_host_command",
        "ownership_namespace",
        "EphemeralBootstrapCredential",
    }
)


def test_no_normal_runtime_module_imports_the_staging_live_package():
    for path in _normal_runtime_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert "staging_live" not in module, f"{path} imports {module}"
                for alias in node.names:
                    assert alias.name not in _CONCRETE_LIVE_SYMBOLS, (
                        f"{path} imports concrete live symbol {alias.name}"
                    )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert "staging_live" not in alias.name, f"{path} imports {alias.name}"


def test_worker_entrypoints_do_not_wire_live_adapters():
    for rel in ("main.py", "temporal_app.py", "preflight/consumer.py", "preflight/runtime.py"):
        src = (WORKER_PKG / rel).read_text(encoding="utf-8")
        assert "staging_live" not in src, f"{rel} references staging_live"
        for symbol in _CONCRETE_LIVE_SYMBOLS:
            assert symbol not in src, f"{rel} wires {symbol}"


def test_staging_live_sources_add_no_network_or_env_code():
    forbidden = (
        "import httpx",
        "from httpx",
        "import requests",
        "from requests",
        "import socket",
        "from socket",
        "import subprocess",
        "from subprocess",
        "import ssl",
        "os.environ",
        "os.getenv",
        "hvac",
    )
    for path in _py(STAGING_LIVE):
        src = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"{path.name} must not reference `{token}`"


def test_staging_live_sources_commit_no_concrete_infrastructure_values():
    forbidden = re.compile(
        r"(?:\d{1,3}\.){3}\d{1,3}|https?://[a-z0-9]|:\d{4,5}\b|PVEAPIToken|@pam|-----BEGIN"
        r"|vault:[a-z]",
        re.IGNORECASE,
    )
    for path in _py(STAGING_LIVE):
        m = forbidden.search(path.read_text(encoding="utf-8"))
        assert m is None, f"{path.name} contains a concrete value: {m.group(0)!r}"


def test_staging_live_package_does_not_import_legacy_discovery_or_temporal():
    # The legacy discovery / Temporal / EnvSecretResolver path is out of scope and must never be
    # reused or imported by the staging-live package.
    forbidden_modules = ("discovery", "temporal", "EnvSecretResolver", "live_readonly")
    for path in _py(STAGING_LIVE):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for bad in forbidden_modules:
                    assert bad not in module, f"{path.name} imports {module}"
                for alias in node.names:
                    assert alias.name != "EnvSecretResolver", f"{path.name} imports {alias.name}"


def test_sealed_defaults_refuse_offline_and_construct_nothing():
    # Constructing + invoking the shipped sealed defaults contacts nothing and fails closed.
    from secp_worker.staging_live.mtls_pop import (
        DeploymentSignerUnavailable,
        SealedDeploymentLocalSigner,
    )
    from secp_worker.staging_live.openbao_client import (
        OpenBaoClientError,
        SealedOpenBaoBackendTransport,
    )

    now = datetime.now(UTC)
    sealed_bao = SealedOpenBaoBackendTransport()
    with pytest.raises(OpenBaoClientError):
        sealed_bao.authenticate(now=now)
    with pytest.raises(OpenBaoClientError):
        sealed_bao.read(locator="x", now=now)

    # The sealed deployment-local signer refuses to expose an anchor or sign — no material, no I/O.
    sealed_signer = SealedDeploymentLocalSigner()
    with pytest.raises(DeploymentSignerUnavailable):
        sealed_signer.public_anchor()
    with pytest.raises(DeploymentSignerUnavailable):
        sealed_signer.sign(b"challenge")


def test_composition_and_canaries_import_without_touching_infrastructure():
    # Importing the package must not open a socket, read env, or construct a live client. If any
    # module contacted infrastructure at import time, this import (already done at collection) would
    # have failed; we assert the public surface is present and inert.
    import secp_worker.staging_live.canaries as canaries
    import secp_worker.staging_live.composition as composition

    assert callable(composition.build_staging_live_composition)
    assert callable(canaries.run_openbao_readiness_canary)
    assert callable(canaries.run_proxmox_transport_canary)
