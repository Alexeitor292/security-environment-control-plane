"""SECP-B2-5-pre — guardrails for the staging-live bootstrap readiness package.

Documentation + machine-checkable-checklist guards. They prove the operator readiness doc exists
with every required section, the machine-checkable evidence checklist covers every required trust
root and is entirely secret-free (no item records a concrete value), and neither artifact commits a
real infrastructure value. They execute no network, subprocess, provider, or authorization code.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DOC = REPO_ROOT / "docs" / "proxmox" / "staging-live-activation-readiness.md"
CHECKLIST = REPO_ROOT / "docs" / "proxmox" / "staging-live-bootstrap-evidence-checklist.json"

_REQUIRED_SECTIONS = (
    "# SECP Staging Live Activation Readiness",
    "## 1. Purpose and non-goals",
    "## 2. Isolated staging control plane",
    "## 3. Disposable nested Proxmox target",
    "## 4. Network isolation and egress",
    "## 5. Trust roots and identity material",
    "## 6. OpenBao authentication and policy",
    "## 7. Least-privilege staging read credential",
    "## 8. Revocation and kill-switch drill",
    "## 9. Evidence recorded in SECP",
    "## 10. Canary and preflight order",
    "## 11. What must never enter Git",
)

_REQUIRED_CHECK_IDS = frozenset(
    {
        "isolated_staging_control_plane_vm",
        "isolated_staging_database",
        "isolated_staging_api",
        "isolated_staging_worker",
        "disposable_nested_proxmox_target",
        "no_home_corp_prod_public_route",
        "no_default_gateway_on_target_plane",
        "no_dns_on_target_plane",
        "private_staging_ca",
        "deployment_local_worker_key",
        "short_lived_worker_certificate",
        "openbao_mtls_authentication",
        "openbao_least_privilege_policy",
        "synthetic_canary_secret",
        "least_privilege_staging_read_credential",
        "default_deny_egress",
        "revocation_kill_switch_drill",
        "trust_root_evidence_recorded",
    }
)

# Real-infrastructure-value patterns; each must have zero matches in the readiness artifacts.
_FORBIDDEN_VALUE_PATTERNS = (
    ("ipv4 address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("url with host", re.compile(r"https?://[A-Za-z0-9\[]")),
    ("numeric port", re.compile(r":\d{4,5}\b")),
    ("certificate/mac fingerprint", re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5,}[0-9a-f]{2}\b")),
    ("long hex value", re.compile(r"\b[0-9a-fA-F]{32,}\b")),
    ("token-like base64 run", re.compile(r"[A-Za-z0-9+=]{48,}")),
    ("proxmox api token", re.compile(r"PVEAPIToken")),
    ("certificate/key block", re.compile(r"BEGIN (?:[A-Z ]*PRIVATE KEY|CERTIFICATE)")),
    ("realm user account", re.compile(r"(?i)\broot@|@pam\b|@pve\b|@pbs\b")),
    ("concrete secret reference", re.compile(r"env:SECP_[A-Z]|vault:[A-Za-z0-9]")),
)


def test_readiness_doc_exists_with_required_sections():
    assert DOC.is_file(), "staging-live readiness doc is missing"
    text = DOC.read_text(encoding="utf-8")
    for heading in _REQUIRED_SECTIONS:
        assert heading in text, f"readiness doc missing section: {heading}"


def test_readiness_doc_states_the_hard_invariants():
    text = re.sub(r"\s+", " ", DOC.read_text(encoding="utf-8").lower())
    for phrase in (
        "no default gateway and no dns",
        "egress is default-deny",
        "never use the production secp database",
        "private staging certificate authority",
        "deployment-local private key material",
        "without reading or returning any secret",
        "no proxmox contact can occur before openbao authentication",
        "no commands, real endpoints",
    ):
        assert phrase in text, f"readiness doc missing invariant phrase: {phrase!r}"


def test_checklist_covers_every_required_trust_root_and_is_secret_free():
    data = json.loads(CHECKLIST.read_text(encoding="utf-8"))
    assert data.get("secret_free") is True
    assert data.get("records_no_values") is True
    items = data["items"]
    ids = {item["id"] for item in items}
    assert ids == _REQUIRED_CHECK_IDS, f"checklist id mismatch: {ids ^ _REQUIRED_CHECK_IDS}"
    allowed_keys = {"id", "requirement", "evidence", "secret_free", "records_value"}
    for item in items:
        assert set(item) == allowed_keys, f"{item['id']} has unexpected keys: {set(item)}"
        assert item["secret_free"] is True, f"{item['id']} is not marked secret_free"
        assert item["records_value"] is False, f"{item['id']} claims to record a value"
        # No item may carry a value-bearing field (endpoint/host/ip/token/credential/secret).
        for key in ("value", "endpoint", "host", "ip", "port", "token", "credential", "secret_ref"):
            assert key not in item, f"{item['id']} carries a value field: {key}"


def test_readiness_artifacts_contain_no_real_infrastructure_values():
    for artifact in (DOC, CHECKLIST):
        text = artifact.read_text(encoding="utf-8")
        for name, pattern in _FORBIDDEN_VALUE_PATTERNS:
            match = pattern.search(text)
            assert match is None, (
                f"{artifact.relative_to(REPO_ROOT)} contains a forbidden {name}: {match.group(0)!r}"
            )
