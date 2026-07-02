"""SECP-002B-1B-2 — static guard for the live read-only Proxmox collector DESIGN PR.

This milestone is documentation/design only. These checks prove the design, threat-model, and
activation-checklist docs exist and are secret-free, that no Proxmox SDK was added anywhere,
and that the B1-B-1 live-evidence seal is unchanged (no live collector is implemented/enabled).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

ADR = REPO / "docs/adr/ADR-015-live-readonly-proxmox-collector-design.md"
DESIGN = REPO / "docs/architecture/secp-002b-1b-2-live-readonly-proxmox-collector.md"
CHECKLIST = REPO / "docs/proxmox/live-readonly-collector-activation-checklist.md"
NEW_DOCS = (ADR, DESIGN, CHECKLIST)


def test_design_docs_exist():
    for p in NEW_DOCS:
        assert p.is_file(), f"missing design doc: {p}"


def test_design_doc_has_required_sections():
    text = DESIGN.read_text(encoding="utf-8")
    for marker in (
        "## 1. Threat model",
        "## 2. Read-only collector contract",
        "## 3. Non-mutation enforcement design",
        "## 4. Credential and target-binding design",
        "## 5. Execution model",
        "## 6. Human activation checklist",
        "## 7. Future implementation plan",
    ):
        assert marker in text, f"design doc missing section: {marker}"


def test_checklist_has_required_gates():
    text = CHECKLIST.read_text(encoding="utf-8").lower()
    for marker in (
        "disposable/staging target approval",
        "restricted read-only identity reviewed",
        "certificate identity verified out of band",
        "egress allowlist approved",
        "secret storage approved",
        "rollback",
        "manual test plan approved",
        "explicit user authorization recorded",
    ):
        assert marker in text, f"checklist missing gate: {marker}"


# A secret-bearing value = a secret WORD immediately followed by ':'/'=' and a value, a private
# key block, or a high-entropy token. Generic prose ("no tokens/keys/passwords") is not flagged.
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|credential)"
    r"\s*[:=]\s*\S"
)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----")
_HIGH_ENTROPY_RE = re.compile(r"\b(?=[A-Za-z0-9]*[0-9])[A-Za-z0-9]{24,}\b")


@pytest.mark.parametrize("path", NEW_DOCS, ids=lambda p: p.name)
def test_design_docs_are_secret_free(path: Path):
    text = path.read_text(encoding="utf-8")
    assert not _SECRET_ASSIGN_RE.search(text), f"{path.name}: secret-like assignment present"
    assert not _PRIVATE_KEY_RE.search(text), f"{path.name}: private key block present"
    assert not _HIGH_ENTROPY_RE.search(text), f"{path.name}: high-entropy token present"


def test_no_proxmox_sdk_added_anywhere():
    for base in ("apps/api/secp_api", "apps/worker/secp_worker"):
        for p in (REPO / base).rglob("*.py"):
            if "__pycache__" in p.parts:
                continue
            assert "proxmoxer" not in p.read_text(encoding="utf-8"), f"proxmoxer import in {p}"


def test_live_evidence_seal_is_unchanged():
    from secp_api.errors import LiveEvidenceSealedError
    from secp_api.onboarding import B1B0_LIVE_EVIDENCE_SEALED
    from secp_worker.onboarding.target_evidence import SealedProviderTargetEvidenceCollector

    assert B1B0_LIVE_EVIDENCE_SEALED is True
    with pytest.raises(LiveEvidenceSealedError):
        SealedProviderTargetEvidenceCollector().collect(declared_boundary={})


def _normalized(path: Path) -> str:
    """Lowercased text with all whitespace runs collapsed to single spaces.

    Markdown wraps phrases across lines, so substring checks must be newline-insensitive.
    """
    return " ".join(path.read_text(encoding="utf-8").lower().split())


def test_integrity_vs_truthfulness_is_documented():
    """Correction 1: the hash proves integrity/binding, not truthfulness; no remote attestation."""
    text = _normalized(DESIGN)
    for marker in (
        "evidence integrity vs. evidence truthfulness",
        "post-collection alteration",
        "binding drift",
        "prove the provider response was truthful",
        "remote attestation",
        "false at the moment of collection",
    ):
        assert marker in text, f"design doc missing integrity/truthfulness statement: {marker!r}"
    # The over-strong claim that a hostile target necessarily fails closed must be gone.
    assert "can only feed misleading" not in text
    assert "never a silent pass" not in text
    adr = _normalized(ADR)
    assert "no remote attestation" in adr
    assert "post-collection alteration and binding drift" in adr


def test_complete_job_binding_is_documented():
    """Correction 2: live jobs + idempotency key bind the full identity and fail closed."""
    text = _normalized(DESIGN)
    for marker in (
        "execution_target_id",
        "config_hash",
        "onboarding_id",
        "boundary_hash",
        "authorization_id",
        "expiry/version",
        "verification_level",
        "endpoint_allowlist_version",
        "no reusable passing result",
        "fails closed",
    ):
        assert marker in text, f"design doc missing job-binding element: {marker!r}"


def test_fully_segregated_verification_is_documented():
    """Correction 3: generic inventory is insufficient; required facts verified or unverifiable."""
    text = _normalized(DESIGN)
    for marker in (
        "insufficient",
        "dedicated lab segment identity",
        "no protected-network uplink",
        "no default route",
        "host-side isolation controls",
        "inferred from incomplete inventory",
        "unverifiable",
    ):
        assert marker in text, f"design doc missing fully_segregated safeguard: {marker!r}"
