"""Provider-neutral read-only target evidence contract (SECP-002B-1B-1).

Pure data validation, canonical hashing, and declared-boundary comparison. This module
does not import worker, provider, transport, subprocess, or secret-resolution code.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from secp_scenario_schema import content_hash

from secp_api.enums import EvidenceStatus, IsolationProfile, VerificationLevel
from secp_api.errors import ValidationFailedError
from secp_api.onboarding import OnboardingBoundarySpec

TARGET_EVIDENCE_SCHEMA_VERSION = "secp-002b-1b-1/target-evidence/v1"
SIMULATED_EVIDENCE_SOURCE = "simulated_target_evidence"
FINDING_PASS = EvidenceStatus.passed.value
FINDING_FAIL = EvidenceStatus.failed.value
FINDING_UNVERIFIABLE = EvidenceStatus.unverifiable.value

CHECK_NODES = "nodes"
CHECK_STORAGE = "storage"
CHECK_NETWORK_SEGMENTS = "network_segments"
CHECK_CIDRS = "cidr_reservations"
CHECK_VMID_RANGE = "vmid_range"
CHECK_QUOTAS = "quotas"
CHECK_ISOLATION = "fully_segregated_isolation"
COMPARISON_CHECKS = (
    CHECK_NODES,
    CHECK_STORAGE,
    CHECK_NETWORK_SEGMENTS,
    CHECK_CIDRS,
    CHECK_VMID_RANGE,
    CHECK_QUOTAS,
    CHECK_ISOLATION,
)

_SECRET_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|credential)",
    re.IGNORECASE,
)


def _list(value: object) -> list[str] | None:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        return None
    return list(value)


def _finding(check: str, status: str, detail: str) -> dict:
    return {"check": check, "status": status, "detail": detail}


def _status_for_findings(findings: list[dict]) -> EvidenceStatus:
    statuses = {str(f.get("status")) for f in findings}
    if FINDING_UNVERIFIABLE in statuses:
        return EvidenceStatus.unverifiable
    if FINDING_FAIL in statuses:
        return EvidenceStatus.failed
    return EvidenceStatus.passed


def _contains_secret_token(value: object) -> bool:
    if isinstance(value, str):
        return bool(_SECRET_RE.search(value))
    if isinstance(value, dict):
        return any(_contains_secret_token(k) or _contains_secret_token(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_contains_secret_token(v) for v in value)
    return False


def _cidr_within_any(cidr: str, observed: Iterable[str]) -> bool | None:
    try:
        net = ipaddress.ip_network(cidr, strict=True)
    except ValueError:
        return None
    matched = False
    for item in observed:
        try:
            block = ipaddress.ip_network(item, strict=True)
        except ValueError:
            return None
        if net.version == block.version and net.subnet_of(block):  # type: ignore[arg-type]
            matched = True
    return matched


def build_simulated_evidence_payload(boundary: dict) -> dict:
    """Build a deterministic simulated observed-target payload from a declared boundary.

    It is evidence-shaped but not live evidence: no real target is contacted and no
    endpoint, credential, or provider-specific inventory is inspected.
    """
    spec = OnboardingBoundarySpec.model_validate(boundary)
    return {
        "schema_version": TARGET_EVIDENCE_SCHEMA_VERSION,
        "evidence_source": SIMULATED_EVIDENCE_SOURCE,
        "verification_level": VerificationLevel.simulated.value,
        "observed": {
            "nodes": sorted(spec.nodes),
            "storage": sorted(spec.storage),
            "network_segments": sorted(spec.network_segments),
            "cidr_reservations": sorted(spec.cidrs),
            "vmid_range": spec.vmid_range.model_dump(mode="json"),
            "quotas": spec.quotas.model_dump(mode="json"),
            "isolation": {
                "profile": spec.isolation_profile.value,
                "external_connectivity_policy": spec.external_connectivity.policy,
                "route_to_protected": False,
            },
        },
    }


def validate_target_evidence_payload(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValidationFailedError("target evidence payload must be an object")
    if payload.get("schema_version") != TARGET_EVIDENCE_SCHEMA_VERSION:
        raise ValidationFailedError("unsupported target evidence schema version")
    if payload.get("evidence_source") != SIMULATED_EVIDENCE_SOURCE:
        raise ValidationFailedError("only simulated target evidence is accepted in SECP-002B-1B-1")
    if payload.get("verification_level") != VerificationLevel.simulated.value:
        raise ValidationFailedError("only simulated target evidence is accepted in SECP-002B-1B-1")
    observed = payload.get("observed")
    if not isinstance(observed, dict):
        raise ValidationFailedError("target evidence observed section is missing")
    if _contains_secret_token(payload):
        raise ValidationFailedError("target evidence must not contain secret-like material")
    return payload


def compare_boundary_to_evidence(boundary: dict, payload: dict | None) -> list[dict]:
    """Compare a declared boundary to observed target evidence.

    Findings are explicit and fail closed: malformed or missing evidence yields
    ``unverifiable`` for each comparison dimension.
    """
    try:
        spec = OnboardingBoundarySpec.model_validate(boundary)
    except Exception:
        return missing_evidence_findings("declared boundary is malformed")
    if payload is None:
        return missing_evidence_findings("target evidence is missing")
    try:
        validated = validate_target_evidence_payload(payload)
    except Exception:
        return missing_evidence_findings("target evidence is malformed or unavailable")

    observed = validated["observed"]
    findings: list[dict] = []

    for check, expected, key, label in (
        (CHECK_NODES, spec.nodes, "nodes", "nodes"),
        (CHECK_STORAGE, spec.storage, "storage", "storage"),
        (
            CHECK_NETWORK_SEGMENTS,
            spec.network_segments,
            "network_segments",
            "network segments",
        ),
    ):
        values = _list(observed.get(key))
        if values is None:
            findings.append(_finding(check, FINDING_UNVERIFIABLE, f"observed {label} missing"))
        elif set(expected) <= set(values):
            findings.append(_finding(check, FINDING_PASS, f"declared {label} are observed"))
        else:
            findings.append(_finding(check, FINDING_FAIL, f"declared {label} are not observed"))

    observed_cidrs = _list(observed.get("cidr_reservations"))
    if observed_cidrs is None:
        findings.append(
            _finding(CHECK_CIDRS, FINDING_UNVERIFIABLE, "observed CIDR reservations missing")
        )
    else:
        cidr_results = [_cidr_within_any(cidr, observed_cidrs) for cidr in spec.cidrs]
        if any(result is None for result in cidr_results):
            findings.append(
                _finding(CHECK_CIDRS, FINDING_UNVERIFIABLE, "CIDR evidence is malformed")
            )
        elif all(cidr_results):
            findings.append(
                _finding(CHECK_CIDRS, FINDING_PASS, "declared CIDR reservations are observed")
            )
        else:
            findings.append(
                _finding(CHECK_CIDRS, FINDING_FAIL, "declared CIDR reservations are not observed")
            )

    observed_vmid = observed.get("vmid_range")
    if not isinstance(observed_vmid, dict) or not all(
        isinstance(observed_vmid.get(k), int) for k in ("start", "end")
    ):
        findings.append(_finding(CHECK_VMID_RANGE, FINDING_UNVERIFIABLE, "VM-ID evidence missing"))
    elif (
        observed_vmid["start"] <= spec.vmid_range.start
        and spec.vmid_range.end <= observed_vmid["end"]
    ):
        findings.append(_finding(CHECK_VMID_RANGE, FINDING_PASS, "declared VM-ID range observed"))
    else:
        findings.append(
            _finding(CHECK_VMID_RANGE, FINDING_FAIL, "declared VM-ID range is not observed")
        )

    observed_quotas = observed.get("quotas")
    quota_keys = set(spec.quotas.model_dump(mode="json"))
    if not isinstance(observed_quotas, dict) or not all(
        isinstance(observed_quotas.get(k), int) for k in quota_keys
    ):
        findings.append(_finding(CHECK_QUOTAS, FINDING_UNVERIFIABLE, "quota evidence missing"))
    elif all(observed_quotas[k] >= spec.quotas.model_dump(mode="json")[k] for k in quota_keys):
        findings.append(_finding(CHECK_QUOTAS, FINDING_PASS, "declared quotas are observed"))
    else:
        findings.append(_finding(CHECK_QUOTAS, FINDING_FAIL, "declared quotas are not observed"))

    isolation = observed.get("isolation")
    if not isinstance(isolation, dict):
        findings.append(
            _finding(CHECK_ISOLATION, FINDING_UNVERIFIABLE, "isolation evidence missing")
        )
    elif (
        spec.isolation_profile == IsolationProfile.fully_segregated
        and spec.external_connectivity.policy == "deny"
        and isolation.get("profile") == IsolationProfile.fully_segregated.value
        and isolation.get("external_connectivity_policy") == "deny"
        and isolation.get("route_to_protected") is False
    ):
        findings.append(
            _finding(CHECK_ISOLATION, FINDING_PASS, "fully segregated isolation is observed")
        )
    else:
        findings.append(
            _finding(CHECK_ISOLATION, FINDING_FAIL, "fully segregated isolation is not observed")
        )

    return findings


def missing_evidence_findings(detail: str) -> list[dict]:
    return [_finding(check, FINDING_UNVERIFIABLE, detail) for check in COMPARISON_CHECKS]


def target_evidence_package(payload: dict, findings: list[dict]) -> dict:
    validated = validate_target_evidence_payload(payload)
    if _contains_secret_token(findings):
        raise ValidationFailedError(
            "target evidence findings must not contain secret-like material"
        )
    return {
        "schema_version": TARGET_EVIDENCE_SCHEMA_VERSION,
        "evidence_source": validated["evidence_source"],
        "verification_level": validated["verification_level"],
        "evidence_payload": validated,
        "findings": sorted(
            (
                {
                    "check": str(item["check"]),
                    "status": str(item["status"]),
                    "detail": str(item.get("detail", "")),
                }
                for item in findings
            ),
            key=lambda item: item["check"],
        ),
    }


def target_evidence_hash(payload: dict, findings: list[dict]) -> str:
    return content_hash(target_evidence_package(payload, findings))


def summarize_findings(findings: list[dict]) -> EvidenceStatus:
    return _status_for_findings(findings)


def findings_pass(findings: list[dict]) -> bool:
    return summarize_findings(findings) == EvidenceStatus.passed
