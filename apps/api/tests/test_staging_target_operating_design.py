"""SECP-002B-1B-7 — static guardrails for the disposable staging target operating design.

Documentation-only PR guards. These tests prove that the operating-design document exists with
every required safety section; that the live-read documents contain no real infrastructure
value (endpoint, host, IP, port, VLAN id, certificate material, token, credential or secret
reference); and that no code path, environment switch, or infrastructure wiring references a
staging live-read activation. They execute no network, subprocess, provider, transport,
resolver, collector, or authorization code.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DOCS = REPO_ROOT / "docs"
DESIGN_DOC = DOCS / "proxmox" / "disposable-staging-target-operating-design.md"
ACTIVATION_CHECKLIST = DOCS / "proxmox" / "live-readonly-collector-activation-checklist.md"
ADR_015 = DOCS / "adr" / "ADR-015-live-readonly-proxmox-collector-design.md"

# Production source trees that must never grow a staging live-read switch or wiring.
PRODUCTION_TREES = (
    REPO_ROOT / "apps" / "api" / "secp_api",
    REPO_ROOT / "apps" / "worker" / "secp_worker",
    REPO_ROOT / "plugins",
    REPO_ROOT / "contracts",
    REPO_ROOT / "infra",
)


def _live_read_docs() -> list[Path]:
    """Every live-read/staging document that must stay free of real infrastructure values."""
    docs = sorted((DOCS / "proxmox").glob("*.md"))
    docs.append(ADR_015)
    assert DESIGN_DOC in docs
    return docs


# (name, compiled pattern) — each must have zero matches in every guarded document.
_FORBIDDEN_VALUE_PATTERNS = (
    ("ipv4 address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("url with host", re.compile(r"https?://[A-Za-z0-9\[]")),
    ("numeric port", re.compile(r":\d{4,5}\b")),
    ("vlan id", re.compile(r"(?i)\bvlan[\s_-]*\d")),
    ("certificate/mac fingerprint", re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5,}[0-9a-f]{2}\b")),
    ("long hex value", re.compile(r"\b[0-9a-fA-F]{32,}\b")),
    ("token-like base64 run", re.compile(r"[A-Za-z0-9+=]{48,}")),
    ("proxmox api token", re.compile(r"PVEAPIToken")),
    ("certificate/key block", re.compile(r"BEGIN (?:[A-Z ]*PRIVATE KEY|CERTIFICATE)")),
    ("realm user account", re.compile(r"(?i)\broot@|@pam\b|@pve\b|@pbs\b")),
    ("concrete secret reference", re.compile(r"env:SECP_|vault:[A-Za-z0-9]")),
    ("live-read/staging env switch", re.compile(r"SECP_(?:LIVE_READ|STAGING)[A-Z_]*")),
)


def test_operating_design_doc_exists_with_required_sections():
    assert DESIGN_DOC.is_file(), "SECP-002B-1B-7 operating design document is missing"
    text = DESIGN_DOC.read_text(encoding="utf-8")
    for heading in (
        "# Disposable Staging Target — Operating Design and Readiness Contract",
        "## 1. Staging target eligibility",
        "## 2. Reference topology (placeholders only)",
        "## 3. Least-privilege Proxmox identity design",
        "## 4. Certificate trust and target identity",
        "## 5. Readiness evidence checklist (completed outside Git)",
        "## 6. Rollback and kill-switch plan",
        "## 7. Separation of responsibilities",
        "## 8. Explicit future activation entry criteria",
    ):
        assert heading in text, f"operating design is missing section: {heading}"


def test_operating_design_doc_states_required_controls():
    text = DESIGN_DOC.read_text(encoding="utf-8").lower()
    for control in (
        # eligibility
        "disposable or recoverable",
        "known-clean",
        "no production workload dependency",
        "no shared credentials",
        "rollback",
        "no participant access",
        "exactly one approved target",
        "exactly one approved onboarding",
        "exactly one time-bound authorization",
        # topology
        "default-deny worker egress",
        "no dns-based widening",
        "no proxy inheritance",
        "tls verification required",
        "redirects disabled",
        "management plane segmentation",
        "break-glass rule removal",
        # identity
        "read-only",
        "no console",
        "no shell",
        "no task execution",
        "no upload/download",
        "no backup/restore",
        "no token management",
        "never committed to source control",
        # certificate identity
        "independent verification channel",
        "explicit refusal",
        # kill switch
        "revoke the authorization",
        "remove the worker egress rule",
        "revoke the target credential",
        "preserve the audit trail",
        # separation + entry criteria
        "no single layer can activate collection alone",
        "no unresolved blocker",
    ):
        assert control in text, f"operating design is missing required control: {control}"


def test_operating_design_topology_uses_placeholders_only():
    text = DESIGN_DOC.read_text(encoding="utf-8")
    assert "<staging-target-host>:<api-port>" in text
    # The design document must not name any concrete environment switch either.
    assert not re.search(r"\bSECP_[A-Z_]+\b", text), (
        "operating design must not name environment switches"
    )


def test_live_read_documents_contain_no_real_infrastructure_values():
    for doc in _live_read_docs():
        text = doc.read_text(encoding="utf-8")
        for name, pattern in _FORBIDDEN_VALUE_PATTERNS:
            match = pattern.search(text)
            assert match is None, (
                f"{doc.relative_to(REPO_ROOT)} contains a forbidden {name}: {match.group(0)!r}"
            )


def test_activation_checklist_and_adr_reference_the_operating_design():
    checklist = ACTIVATION_CHECKLIST.read_text(encoding="utf-8")
    adr = ADR_015.read_text(encoding="utf-8")
    assert "disposable-staging-target-operating-design.md" in checklist
    assert "SECP-002B-1B-7" in checklist
    assert "SECP-002B-1B-7" in adr
    assert "documentation-only" in adr.lower()


def test_no_staging_live_read_switch_or_wiring_in_production_code_or_infra():
    """No code path, config, route, dispatcher, workflow, or env switch references a staging
    live-read activation anywhere in the production trees (tests excluded)."""
    forbidden = re.compile(
        r"SECP_LIVE_READ|SECP_STAGING|LIVE_READ_ENABLED|STAGING_TARGET_HOST"
        r"|staging_activation|disposable_staging|activate_live_read"
    )
    scanned = 0
    for tree in PRODUCTION_TREES:
        assert tree.exists(), f"expected production tree is missing: {tree}"
        for path in tree.rglob("*"):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts or "tests" in path.parts:
                continue
            allowed = {".py", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".example", ".sh", ""}
            if path.suffix not in allowed:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, PermissionError):
                continue
            scanned += 1
            match = forbidden.search(text)
            assert match is None, (
                f"{path.relative_to(REPO_ROOT)} wires a staging live-read switch: "
                f"{match.group(0)!r}"
            )
    assert scanned > 0, "guardrail scanned no files; check PRODUCTION_TREES"
