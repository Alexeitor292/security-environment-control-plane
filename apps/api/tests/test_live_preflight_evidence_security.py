"""SECP-B2-4.5 — static/architecture guardrails for the live-preflight evidence boundary.

Proves: the API/web never CONSTRUCT a live-evidence row or import the worker-only writers; no
runtime path (consumer/orchestration/runtime/main) constructs the durable writer; the schema/writer
add no network/secret/target code; and no concrete infrastructure value is committed.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
API_PKG = REPO_ROOT / "apps" / "api" / "secp_api"
WEB_SRC = REPO_ROOT / "apps" / "web" / "src"
PREFLIGHT = REPO_ROOT / "apps" / "worker" / "secp_worker" / "preflight"
WRITER = PREFLIGHT / "live_evidence_writer.py"


def _py(pkg: Path) -> list[Path]:
    return [p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts]


_FORBIDDEN_API_SYMBOLS = frozenset(
    {
        "DurableLivePreflightEvidenceWriter",
        "SealedLivePreflightEvidenceWriter",
        "LivePreflightEvidenceWriter",
        "LivePreflightEvidenceContext",
    }
)


def test_api_does_not_import_the_live_evidence_writer():
    for path in _py(API_PKG):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert "live_evidence_writer" not in module, f"{path.name} imports {module}"
                assert not module.startswith("secp_worker.preflight"), (
                    f"{path.name} imports {module}"
                )
                for alias in node.names:
                    assert alias.name not in _FORBIDDEN_API_SYMBOLS, (
                        f"{path.name} imports {alias.name}"
                    )


def test_api_never_constructs_a_live_evidence_row():
    # The API may import the MODEL (for the immutability guard) but must never CONSTRUCT one — only
    # the worker-only durable writer creates live evidence.
    for path in _py(API_PKG):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                assert name != "LivePreflightEvidence", (
                    f"{path.name} constructs LivePreflightEvidence"
                )


def test_shipped_runtime_never_constructs_the_durable_writer():
    for name in ("consumer.py", "orchestration.py", "runtime.py"):
        src = (PREFLIGHT / name).read_text(encoding="utf-8")
        assert "DurableLivePreflightEvidenceWriter" not in src, f"{name} wires the durable writer"
        assert "live_evidence_writer" not in src, f"{name} imports the writer seam"
    worker_main = (REPO_ROOT / "apps/worker/secp_worker/main.py").read_text(encoding="utf-8")
    assert "DurableLivePreflightEvidenceWriter" not in worker_main


def test_frontend_has_no_live_evidence_interface():
    forbidden = ("live_preflight_evidence", "LivePreflightEvidence", "live-preflight-evidence")
    scanned = 0
    for path in list(WEB_SRC.rglob("*.ts")) + list(WEB_SRC.rglob("*.tsx")):
        if ".mypy_cache" in path.parts or "node_modules" in path.parts:
            continue
        scanned += 1
        src = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"frontend {path.name} references `{token}`"
    assert scanned >= 5


def test_writer_and_schema_add_no_network_or_secret_code():
    forbidden = (
        "import httpx",
        "from httpx",
        "import requests",
        "import socket",
        "from socket",
        "import subprocess",
        "from subprocess",
        "hvac",
        "openbao",
        "os.environ",
        "os.getenv",
    )
    for path in (WRITER, API_PKG / "live_preflight_evidence_schema.py"):
        src = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"{path.name} must not reference `{token}`"


def test_no_concrete_infrastructure_values_in_new_sources():
    import re

    new_sources = [
        API_PKG / "live_preflight_evidence_schema.py",
        WRITER,
        REPO_ROOT / "apps/api/migrations/versions/f3b8d1c6a4e9_live_preflight_evidence.py",
    ]
    forbidden = re.compile(
        r"(?:\d{1,3}\.){3}\d{1,3}|https?://[a-z0-9]|:\d{4,5}\b|PVEAPIToken|@pam|-----BEGIN|vault:[a-z]",
        re.IGNORECASE,
    )
    for path in new_sources:
        m = forbidden.search(path.read_text(encoding="utf-8"))
        assert m is None, f"{path.name} contains a concrete value: {m.group(0)!r}"
