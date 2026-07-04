"""SECP-B2-2 — static guard for the live secret-resolver ACTIVATION DESIGN PR.

This milestone is documentation/static-contract only. These checks prove the activation design +
checklist docs exist and are secret-free, that the ADR records every SECP-B2-1 review obligation,
that the shipped default resolver still fails closed, and that this PR introduces NO live resolver,
secret backend, secret-manager client, activation flag, or runtime/environment switch that could
enable resolution.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

ADR = REPO / "docs/adr/ADR-015-live-readonly-proxmox-collector-design.md"
DESIGN = REPO / "docs/architecture/secp-b2-2-live-secret-resolver-activation.md"
CHECKLIST = REPO / "docs/proxmox/live-secret-resolver-activation-checklist.md"
NEW_DOCS = (DESIGN, CHECKLIST)

API_PKG = REPO / "apps" / "api" / "secp_api"
WORKER_PKG = REPO / "apps" / "worker" / "secp_worker"
PREFLIGHT_PKG = WORKER_PKG / "preflight"


def _py(pkg: Path) -> list[Path]:
    return [p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts]


def _normalized(path: Path) -> str:
    """Lowercased text with whitespace runs collapsed (markdown wraps phrases across lines)."""
    return " ".join(path.read_text(encoding="utf-8").lower().split())


# --- Docs exist and are structured ---------------------------------------------------------------


def test_activation_design_docs_exist():
    for p in NEW_DOCS:
        assert p.is_file(), f"missing activation doc: {p}"


def test_design_doc_has_required_sections():
    text = DESIGN.read_text(encoding="utf-8")
    for marker in (
        "## 1. Purpose and scope",
        "## 2. Trust model: a TrustedResolutionRequest is not a capability",
        "## 3. Authoritative trust anchors and source of truth",
        "## 4. Credential-reference three-way binding",
        "## 5. Replay, retry, and resolution-lease model",
        "## 6. Worker identity and backend access policy",
        "## 7. Fail-closed ordering",
        "## 8. Activation evidence package",
        "## 9. Formal activation gates",
        "## 10. Rollback and kill-switch sequence",
        "## 11. Future implementation plan",
    ):
        assert marker in text, f"design doc missing section: {marker}"


def test_checklist_has_required_gates():
    text = _normalized(CHECKLIST)
    for marker in (
        "trusted request is not a capability",
        "authoritative trust anchors",
        "credential-reference three-way binding",
        "replay and resolution-lease review",
        "worker identity and backend policy",
        "activation evidence package (closed set)",
        "formal activation gates",
        "rollback / kill-switch sequence tested",
    ):
        assert marker in text, f"checklist missing gate: {marker!r}"


def test_evidence_package_is_a_closed_set():
    text = _normalized(CHECKLIST)
    for marker in (
        "isolated staging-control-plane identity proof",
        "worker-only network-path proof",
        "backend access-policy review",
        "reference-grammar review",
        "redaction / log / audit verification",
        "transport remains get-only and canonicalized",
        "no production or shared target",
        "rollback / kill-switch drill",
        "independent adversarial review",
        "explicit, time-bound human approval recorded",
    ):
        assert marker in text, f"evidence package missing item: {marker!r}"
    assert "no item in this package may be waived" in text


# --- ADR records every B2-1 review obligation ----------------------------------------------------


def test_adr_includes_b2_1_review_obligations():
    text = _normalized(ADR)
    for marker in (
        "a trusted request is not a capability",
        "no self-referential trust anchor",
        "independent source of truth",
        "credential-reference three-way binding",
        "constant-time equality",
        "replay and single-use resolution lease",
        "secret-free",
        "worker identity and backend policy",
        "formal activation gates",
        "none alone sufficient",
    ):
        assert marker in text, f"ADR missing B2-1 obligation: {marker!r}"


def test_design_doc_addresses_both_b2_1_review_findings():
    text = _normalized(DESIGN)
    # Finding 1: self-referential expectation.
    assert "self-referential" in text
    assert "independent of the request" in text
    # Finding 2: object seal is best-effort; request is not a bearer credential.
    assert "best-effort" in text
    assert "never proof of authorization" in text
    assert "dataclasses.replace" in text


# --- Docs/tests are secret-free ------------------------------------------------------------------

# A secret-bearing value = a secret WORD immediately followed by ':'/'=' and a value, a private
# key block, or a high-entropy token. Generic prose ("no tokens/keys/passwords") is not flagged.
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|credential)"
    r"\s*[:=]\s*\S"
)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----")
_HIGH_ENTROPY_RE = re.compile(r"\b(?=[A-Za-z0-9]*[0-9])[A-Za-z0-9]{24,}\b")


@pytest.mark.parametrize("path", (*NEW_DOCS, Path(__file__)), ids=lambda p: p.name)
def test_activation_docs_and_test_are_secret_free(path: Path):
    text = path.read_text(encoding="utf-8")
    assert not _SECRET_ASSIGN_RE.search(text), f"{path.name}: secret-like assignment present"
    assert not _PRIVATE_KEY_RE.search(text), f"{path.name}: private key block present"
    assert not _HIGH_ENTROPY_RE.search(text), f"{path.name}: high-entropy token present"


def test_no_real_endpoint_or_reference_values_in_new_docs():
    forbidden = re.compile(
        r"(?:\d{1,3}\.){3}\d{1,3}"  # IPv4
        r"|https?://[a-z0-9]"  # URL with host
        r"|:\d{4,5}\b"  # port
        r"|PVEAPIToken|@pam|@pve|vmbr\d|vlan\s*\d",
        re.IGNORECASE,
    )
    for path in NEW_DOCS:
        m = forbidden.search(path.read_text(encoding="utf-8"))
        assert m is None, f"{path.name} contains a concrete value: {m.group(0)!r}"


# --- No live resolver / backend code introduced --------------------------------------------------

# External secret-backend / provider / secret-source modules that production code must not import.
_FORBIDDEN_BACKEND_MODULES = frozenset(
    {
        "hvac",  # HashiCorp Vault client
        "openbao",
        "boto3",
        "botocore",
        "azure",
        "googleapiclient",
        "keyring",
        "getpass",
    }
)


def _imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            roots.add((node.module or "").split(".")[0])
    return roots


def test_no_production_code_imports_an_external_secret_backend():
    for pkg in (API_PKG, WORKER_PKG):
        for path in _py(pkg):
            roots = _imported_roots(path)
            bad = roots & _FORBIDDEN_BACKEND_MODULES
            assert not bad, f"{path.relative_to(REPO)} imports secret-backend module(s): {bad}"


def test_shipped_default_resolver_remains_sealed_and_constructs_no_material():
    # The shipped default is still the sealed unavailable resolver; no production code constructs
    # SecretMaterial (only the class's own redacted repr strings mention it).
    from secp_worker.preflight.sealed_secret_resolver import SealedSecretResolver
    from secp_worker.preflight.secret_resolution import SealedUnavailableResolver

    assert issubclass(SealedSecretResolver, SealedUnavailableResolver)

    offenders: list[str] = []
    for path in _py(WORKER_PKG) + _py(API_PKG):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name == "SecretMaterial":
                    offenders.append(str(path.relative_to(REPO)))
    assert not offenders, f"production code constructs SecretMaterial: {offenders}"


def test_preflight_package_has_no_backend_or_network_client():
    forbidden = (
        "hvac",
        "openbao",
        "import vault",
        "from vault",
        "boto3",
        "botocore",
        "azure",
        "googleapiclient",
        "keyring",
        "getpass",
        "import httpx",
        "import requests",
        "import socket",
        "import subprocess",
        "os.environ",
        "os.getenv",
    )
    for path in _py(PREFLIGHT_PKG):
        src = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"{path.name} must not reference `{token}`"


# --- No activation flag / environment switch can enable a resolver -------------------------------


def test_settings_expose_no_resolver_activation_flag():
    from secp_api.config import Settings

    fields = set(Settings.model_fields)
    bad = {
        f
        for f in fields
        if re.search(r"resolver|secret[_-]?backend|secret[_-]?manager|vault|openbao", f, re.I)
    }
    assert not bad, f"Settings expose a resolver-activation field: {bad}"


def test_no_resolver_activation_switch_in_code_or_compose():
    switch = re.compile(
        r"(?i)(?:enable|activate|turn[_-]?on)[_-]?(?:live[_-]?)?"
        r"(?:secret[_-]?)?resolver"
        r"|resolver[_-]?(?:enabled|active|live)"
        r"|LIVE_SECRET_RESOLVER"
    )
    targets = _py(API_PKG) + _py(WORKER_PKG)
    compose = REPO / "infra" / "dev" / "docker-compose.yml"
    if compose.exists():
        targets.append(compose)
    for path in targets:
        text = path.read_text(encoding="utf-8")
        m = switch.search(text)
        assert m is None, (
            f"{path.relative_to(REPO)} defines a resolver-activation switch: {m.group(0)!r}"
        )


def test_scan_actually_covered_files():
    # Guard against a scan silently matching nothing.
    assert len(_py(API_PKG)) >= 10
    assert len(_py(WORKER_PKG)) >= 5
    assert len(_py(PREFLIGHT_PKG)) >= 4
