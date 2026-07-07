"""SECP-B6 MB-1 item-1 — the worker/control-plane admission BOUNDARY is architectural, not a shim.

The live worker must cross a real control-plane boundary to be admitted: it must NOT import or call
the admission SERVICE (``secp_api.services.worker_admission``) in-process, and its admission client
must NOT accept a DB ``Session``. These tests fail closed if a future change reintroduces the
in-process shortcut (e.g. a ``SignedWorkerAdmissionClient`` that imports the service and calls it
with the engine's session).

They statically scan the ``secp_worker.target_discovery`` package source (AST) for a forbidden
import, and reflectively check the admission client's method signatures + the constructed live
composition's client type.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

_WORKER_ROOT = Path(__file__).resolve().parents[3] / "apps" / "worker" / "secp_worker"
_TARGET_DISCOVERY = _WORKER_ROOT / "target_discovery"

# The admission DECISION service is control-plane only; the worker package must never import it.
_FORBIDDEN_IMPORT_PREFIXES = ("secp_api.services.worker_admission",)
# No worker discovery module may import a DB-session-bearing admission service surface either.
_FORBIDDEN_SERVICE_ROOTS = ("secp_api.services",)


def _module_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            # Resolve only absolute imports (the package uses absolute imports throughout).
            mods.add(node.module)
    return mods


def test_target_discovery_never_imports_admission_service() -> None:
    offenders: list[str] = []
    for path in sorted(_TARGET_DISCOVERY.rglob("*.py")):
        for mod in _module_imports(path):
            if mod.startswith(_FORBIDDEN_IMPORT_PREFIXES):
                offenders.append(f"{path.name} imports {mod}")
    assert not offenders, (
        "worker discovery must cross the control-plane admission BOUNDARY, not import the "
        f"admission service in-process: {offenders}"
    )


def test_no_target_discovery_module_imports_any_services_module() -> None:
    # Defense in depth: the whole discovery package stays free of the API service layer (it may only
    # use pure contracts + models). This prevents smuggling the admission decision back in-process
    # through a sibling service.
    offenders: list[str] = []
    for path in sorted(_TARGET_DISCOVERY.rglob("*.py")):
        for mod in _module_imports(path):
            if mod.startswith(_FORBIDDEN_SERVICE_ROOTS):
                offenders.append(f"{path.name} imports {mod}")
    assert not offenders, offenders


def test_admission_client_methods_take_no_session() -> None:
    from secp_worker.target_discovery.admission_client import (
        HttpWorkerAdmissionClient,
        SealedWorkerAdmissionClient,
        WorkerAdmissionClient,
    )

    checked = 0
    for cls in (WorkerAdmissionClient, SealedWorkerAdmissionClient, HttpWorkerAdmissionClient):
        for name in ("admit", "assert_valid", "consume"):
            method = getattr(cls, name)
            sig = inspect.signature(method)
            for pname, param in sig.parameters.items():
                assert pname != "session", f"{cls.__name__}.{name} accepts a Session parameter"
                anno = param.annotation
                assert "Session" not in str(anno), (
                    f"{cls.__name__}.{name}({pname}) is annotated with a DB Session ({anno})"
                )
                assert pname not in ("now",), (
                    f"{cls.__name__}.{name} accepts a client-supplied clock ({pname}); the control "
                    "plane must own admission time"
                )
            checked += 1
    assert checked == 9  # 3 classes x 3 methods, all verified


def test_live_composition_uses_http_admission_client_over_endpoint(tmp_path) -> None:
    # The CONFIGURED live runtime (endpoint + Ed25519 material present) must build the real HTTP
    # client pointed at the internal admission endpoint — not a sealed or in-process client.
    from secp_api.config import Settings
    from secp_worker.target_discovery.admission_client import (
        HttpWorkerAdmissionClient,
        HttpxAdmissionTransport,
    )
    from secp_worker.target_discovery.composition import _build_admission_client

    key = tmp_path / "id.key"
    anchor = tmp_path / "id.anchor"
    key.write_text("aa" * 32)
    anchor.write_text("bb" * 32)
    settings = Settings(
        discovery_controlled_integration_enabled=True,
        discovery_admission_endpoint="https://control-plane.internal:8443",
        discovery_worker_identity_key=str(key),
        discovery_worker_identity_anchor=str(anchor),
        discovery_admission_ca=str(tmp_path / "ca.pem"),
    )
    client = _build_admission_client(settings)
    assert isinstance(client, HttpWorkerAdmissionClient)
    transport = client._transport
    assert isinstance(transport, HttpxAdmissionTransport)
    assert transport.base_url == "https://control-plane.internal:8443"


def test_live_composition_sealed_without_endpoint_or_material(tmp_path) -> None:
    from secp_api.config import Settings
    from secp_worker.target_discovery.admission_client import SealedWorkerAdmissionClient
    from secp_worker.target_discovery.composition import _build_admission_client

    # Endpoint set but no identity material → sealed (fails closed).
    s1 = Settings(
        discovery_controlled_integration_enabled=True,
        discovery_admission_endpoint="https://control-plane.internal:8443",
    )
    assert isinstance(_build_admission_client(s1), SealedWorkerAdmissionClient)
    # Material present but no endpoint → sealed.
    key = tmp_path / "id.key"
    anchor = tmp_path / "id.anchor"
    key.write_text("aa" * 32)
    anchor.write_text("bb" * 32)
    s2 = Settings(
        discovery_controlled_integration_enabled=True,
        discovery_worker_identity_key=str(key),
        discovery_worker_identity_anchor=str(anchor),
    )
    assert isinstance(_build_admission_client(s2), SealedWorkerAdmissionClient)


def test_no_signed_in_process_admission_client_symbol() -> None:
    # The in-process, service-importing client is GONE; a reintroduction must trip this test.
    import secp_worker.target_discovery.admission_client as ac

    assert not hasattr(ac, "SignedWorkerAdmissionClient")


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
