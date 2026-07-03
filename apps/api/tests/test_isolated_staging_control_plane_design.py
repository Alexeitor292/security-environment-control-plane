"""SECP-002B-1B-8 — static guardrails for the isolated staging control-plane topology correction.

Documentation-only PR guards. These tests prove that the correction document exists with every
required section; that it mandates a self-contained staging API/database/worker with no
production control-plane or production-database dependency; that it requires an offline
bootstrap; that it does not claim physical/hypervisor isolation or zero-consequence destruction
for the nested design; and that no real infrastructure value or activation code/config was
introduced. They execute no network, subprocess, provider, transport, resolver, collector, or
authorization code.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DOCS = REPO_ROOT / "docs"
CORRECTION_DOC = DOCS / "proxmox" / "isolated-staging-control-plane-design.md"
PRIOR_DESIGN_DOC = DOCS / "proxmox" / "disposable-staging-target-operating-design.md"
ADR_015 = DOCS / "adr" / "ADR-015-live-readonly-proxmox-collector-design.md"

# Production source trees that must never grow a staging live-read switch or wiring.
PRODUCTION_TREES = (
    REPO_ROOT / "apps" / "api" / "secp_api",
    REPO_ROOT / "apps" / "worker" / "secp_worker",
    REPO_ROOT / "plugins",
    REPO_ROOT / "contracts",
    REPO_ROOT / "infra",
)

# Real-infrastructure-value patterns; each must have zero matches in the corrected documents.
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
    ("environment switch", re.compile(r"\bSECP_[A-Z_]+\b")),
)


def test_correction_doc_exists_with_required_sections():
    assert CORRECTION_DOC.is_file(), "SECP-002B-1B-8 correction document is missing"
    text = CORRECTION_DOC.read_text(encoding="utf-8")
    for heading in (
        "# Isolated SECP Staging Control-Plane — Topology Correction",
        "## 1. What is being corrected",
        "## 2. Isolated SECP staging control-plane VM",
        "## 3. Authority path",
        "## 4. Two-plane topology",
        "## 5. Offline bootstrap requirement",
        "## 6. Corrected scope language",
        "## 7. Updated readiness checklist",
        "## 8. Guardrails in this repository",
    ):
        assert heading in text, f"correction is missing section: {heading}"


def test_correction_requires_self_contained_staging_control_plane():
    text = CORRECTION_DOC.read_text(encoding="utf-8").lower()
    for phrase in (
        "isolated secp staging control-plane vm",
        "staging-only api",
        "staging database",
        "staging worker",
        "self-contained",
        "loaded from the isolated staging\n  database",  # authority path, wrapped
    ):
        # Normalize wrapping for the multi-line authority phrase.
        needle = phrase.replace("\n  ", " ")
        assert needle in re.sub(r"\s+", " ", text), f"correction missing required phrase: {needle}"


def test_correction_forbids_production_control_plane_dependency():
    text = re.sub(r"\s+", " ", CORRECTION_DOC.read_text(encoding="utf-8").lower())
    assert "must never use the production secp database" in text
    assert "production control-plane" in text
    # The authority path must be local to the staging control plane.
    assert "no caller-supplied records can substitute for the staging database" in text
    assert "authoritative only for this isolated staging" in text


def test_correction_requires_local_control_plane_and_single_target_path():
    text = re.sub(r"\s+", " ", CORRECTION_DOC.read_text(encoding="utf-8").lower())
    assert "loopback" in text
    assert "internal container network" in text
    assert "one isolated nic" in text
    assert "one approved api flow" in text
    for absent_route in (
        "no default gateway",
        "no dns",
        "no lan",
        "no wan",
        "no production-control-plane route",
    ):
        assert absent_route in text, f"topology missing required negation: {absent_route}"


def test_correction_requires_offline_bootstrap():
    text = re.sub(r"\s+", " ", CORRECTION_DOC.read_text(encoding="utf-8").lower())
    assert "operator-controlled offline process" in text
    assert "never download dependencies after isolation" in text
    assert "provenance and integrity are verified outside git" in text
    assert "no real artifact locations or checksums enter the repository" in text


def test_correction_does_not_overclaim_isolation_or_zero_consequence():
    """The nested design must not be described as physical/hypervisor isolation, and the
    withdrawn 'consequence-free' language must be gone from the corrected documents."""
    correction = CORRECTION_DOC.read_text(encoding="utf-8").lower()
    prior = PRIOR_DESIGN_DOC.read_text(encoding="utf-8").lower()

    # The honest disclaimer must be present.
    assert "not equivalent to dedicated-hardware or hypervisor-level isolation" in correction
    assert "must not execute untrusted workloads" in correction
    assert "bounded, reversible staging resources" in correction

    # Zero-consequence / affirmative-isolation overclaims must be absent from BOTH documents.
    for doc_name, doc_text in (("correction", correction), ("prior design", prior)):
        for overclaim in (
            "consequence-free",
            "zero consequence",
            "zero-consequence",
            "physically isolated",
            "hardware-isolated",
            "provides hypervisor-level isolation",
            "provides physical isolation",
        ):
            assert overclaim not in doc_text, f"{doc_name} overclaims: {overclaim!r}"


def test_corrected_documents_contain_no_real_infrastructure_values():
    for doc in (CORRECTION_DOC, PRIOR_DESIGN_DOC, ADR_015):
        text = doc.read_text(encoding="utf-8")
        for name, pattern in _FORBIDDEN_VALUE_PATTERNS:
            match = pattern.search(text)
            assert match is None, (
                f"{doc.relative_to(REPO_ROOT)} contains a forbidden {name}: {match.group(0)!r}"
            )


def test_adr_records_the_correction():
    adr = ADR_015.read_text(encoding="utf-8")
    assert "SECP-002B-1B-8" in adr
    assert "isolated-staging-control-plane-design.md" in adr
    assert "documentation-only" in adr.lower()


def test_no_staging_control_plane_wiring_in_production_code_or_infra():
    """No code path, config, route, dispatcher, workflow, or env switch references a staging
    control-plane or live-read activation anywhere in the production trees (tests excluded)."""
    forbidden = re.compile(
        # Activation-shaped tokens only. SECP-002B-1B-9 legitimately implements the staging
        # control-plane concept in application-owned, fake-only code (e.g. the compiler resource
        # kind ``self_contained_staging_control_plane``); the concept name is not an activation
        # switch, so it is intentionally not forbidden here — only real activation/enable
        # switches and target-host wiring are.
        r"SECP_LIVE_READ|SECP_STAGING|LIVE_READ_ENABLED|STAGING_TARGET_HOST"
        r"|staging_activation|activate_live_read|activate_staging|real_provisioning_enabled"
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
                f"{path.relative_to(REPO_ROOT)} wires a staging control-plane switch: "
                f"{match.group(0)!r}"
            )
    assert scanned > 0, "guardrail scanned no files; check PRODUCTION_TREES"
