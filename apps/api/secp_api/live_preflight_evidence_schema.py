"""Strict, secret-free schema + deterministic hash for durable live-preflight evidence (B2-4.5).

This schema is SEPARATE from the simulated target-evidence schema and does not weaken it. A live
evidence payload may contain ONLY a closed outcome/status, safe booleans, bounded counts, closed
check/finding codes, and approved schema/version labels. It can NEVER carry an endpoint/base-URL/
hostname/IP/port, a node/storage/network name, a raw Proxmox/OpenBao response or error, a
certificate value/fingerprint, a credential/token/secret reference, arbitrary free text, or raw
exception text — the validator rejects any key/value that is not a closed code, boolean, or bounded
integer. The deterministic ``sha256:`` hash is computed over the canonical payload.
"""

from __future__ import annotations

import hashlib
import json

from secp_api.enums import (
    LivePreflightCheckCode,
    LivePreflightEvidenceStatus,
    LivePreflightFactCode,
    LivePreflightFindingStatus,
)

LIVE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION = "secp-b2-4.5/live-preflight-evidence/v1"

# A generous upper bound on any count fact; a count outside [0, bound] is rejected as unbounded.
_MAX_COUNT = 10_000_000

# Which fact codes are booleans vs bounded counts (closed classification).
_BOOL_FACTS = frozenset(
    {
        LivePreflightFactCode.api_reachable.value,
        LivePreflightFactCode.readonly_policy_enforced.value,
        LivePreflightFactCode.tls_verified.value,
    }
)
_COUNT_FACTS = frozenset(
    {
        LivePreflightFactCode.node_count.value,
        LivePreflightFactCode.storage_count.value,
        LivePreflightFactCode.network_segment_count.value,
    }
)
_ALL_FACT_CODES = _BOOL_FACTS | _COUNT_FACTS
_CHECK_CODES = frozenset(c.value for c in LivePreflightCheckCode)
_FINDING_STATUSES = frozenset(s.value for s in LivePreflightFindingStatus)
_EVIDENCE_STATUSES = frozenset(s.value for s in LivePreflightEvidenceStatus)


class LiveEvidencePayloadError(ValueError):
    """Raised when a proposed live-evidence payload is not a strict closed, secret-free structure.

    Never echoes an offending value — only a closed reason describing the structural violation.
    """


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise LiveEvidencePayloadError(reason)


def build_live_evidence_payload(
    *,
    status: object,
    facts: object,
    checks: object,
) -> dict:
    """Validate + canonicalize a live-evidence payload into a deterministic, secret-free structure.

    ``status`` — a :class:`LivePreflightEvidenceStatus` value; ``facts`` — a mapping of closed fact
    codes to booleans / bounded counts; ``checks`` — a list of ``{code, status}`` closed items;
    any unknown key, non-closed code, non-bool/non-bounded value, string, duplicate check,
    or extra field is rejected. Returns the canonical payload (sorted, closed) — never raw input.
    """
    status_value = getattr(status, "value", status)
    _require(status_value in _EVIDENCE_STATUSES, "status is not a closed live-preflight status")

    _require(isinstance(facts, dict), "facts must be a mapping")
    assert isinstance(facts, dict)
    canonical_facts: dict[str, object] = {}
    for key, value in facts.items():
        code = getattr(key, "value", key)
        _require(
            isinstance(code, str) and code in _ALL_FACT_CODES, "unknown or non-closed fact key"
        )
        assert isinstance(code, str)  # narrowed by the closed-set check above
        if code in _BOOL_FACTS:
            # A strict bool — reject ints (incl. 0/1) and everything else.
            _require(isinstance(value, bool), "boolean fact must be a real bool")
            canonical_facts[code] = value
        else:  # count fact
            _require(
                isinstance(value, int) and not isinstance(value, bool),
                "count fact must be an integer",
            )
            assert isinstance(value, int)
            _require(0 <= value <= _MAX_COUNT, "count fact is out of the bounded range")
            canonical_facts[code] = value

    _require(isinstance(checks, list), "checks must be a list")
    assert isinstance(checks, list)
    canonical_checks: list[dict[str, str]] = []
    seen_codes: set[str] = set()
    for item in checks:
        _require(isinstance(item, dict), "each check must be a mapping")
        _require(set(item.keys()) == {"code", "status"}, "check must have exactly code + status")
        code = getattr(item["code"], "value", item["code"])
        st = getattr(item["status"], "value", item["status"])
        _require(isinstance(code, str) and code in _CHECK_CODES, "unknown or non-closed check code")
        _require(isinstance(st, str) and st in _FINDING_STATUSES, "non-closed finding status")
        _require(code not in seen_codes, "duplicate check code")
        seen_codes.add(code)
        canonical_checks.append({"code": code, "status": st})

    return {
        "schema_version": LIVE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
        "status": status_value,
        "facts": dict(sorted(canonical_facts.items())),
        "checks": sorted(canonical_checks, key=lambda c: c["code"]),
    }


def compute_live_evidence_hash(canonical_payload: dict) -> str:
    """Deterministic ``sha256:`` hash over the canonical live-evidence payload (secret-free)."""
    encoded = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
