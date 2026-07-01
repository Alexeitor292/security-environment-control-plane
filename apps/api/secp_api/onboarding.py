"""Provider-neutral target onboarding contract (SECP-002B-1B-0, ADR-014).

Two isolation models are valid: ``physical`` (a dedicated host/cluster — the recommended
secure preset) and ``logical`` (a shared environment behind an explicitly declared,
enforceable, auditable, independently verifiable boundary). This module validates the
provider-neutral *declared boundary*, the redacted *preflight evidence*, and the onboarding
*lifecycle*. Proxmox-specific validation belongs in the worker adapter/plugin layer, never
here.

Nothing in this module inspects, connects to, or mutates any real target — it validates
data submitted through the control plane. Fixtures/fakes use clearly non-routable values.
"""

from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from secp_api.enums import IsolationModel, OnboardingMode, PreflightCheckStatus
from secp_api.enums import OnboardingStatus as S
from secp_api.errors import InvalidTransitionError, ValidationFailedError

# Tokens that would broaden an allowlist into an unsafe wildcard.
_WILDCARD_TOKENS = {"*", "any", "all", "", "0.0.0.0/0", "::/0", "0/0"}
_MAX_VMID_WIDTH = 100_000
# A secret must never appear in submitted preflight evidence details.
_SECRET_RE = re.compile(
    r"(pass|passwd|password|secret|token|api[_-]?key|apikey|private[_-]?key|credential)",
    re.IGNORECASE,
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _no_wildcards(values: list[str], field: str) -> list[str]:
    if not values:
        raise ValueError(f"{field} must be a non-empty allowlist")
    for item in values:
        if not isinstance(item, str) or item.strip().lower() in _WILDCARD_TOKENS:
            raise ValueError(f"{field} must not contain wildcards or empty entries")
    return values


class BoundaryVmidRange(_Strict):
    start: int = Field(ge=100)
    end: int = Field(ge=100)

    @field_validator("end")
    @classmethod
    def _end_after_start(cls, v: int, info) -> int:
        start = info.data.get("start")
        if start is not None and v <= start:
            raise ValueError("vmid_range.end must be greater than vmid_range.start")
        if start is not None and (v - start) > _MAX_VMID_WIDTH:
            raise ValueError(f"vmid_range width must not exceed {_MAX_VMID_WIDTH}")
        return v


class BoundaryQuotas(_Strict):
    max_teams: int = Field(ge=1)
    max_vms: int = Field(ge=1)
    max_containers: int = Field(ge=0)
    max_total_vcpu: int = Field(ge=1)
    max_total_memory_mb: int = Field(ge=1)
    max_total_disk_gb: int = Field(ge=1)


class BoundaryExternalConnectivity(_Strict):
    # Deny-by-default; nothing permissive is accepted at onboarding time.
    policy: str = "deny"

    @field_validator("policy")
    @classmethod
    def _only_deny(cls, v: str) -> str:
        if v != "deny":
            raise ValueError(
                "external_connectivity.policy must be 'deny'; permissive external "
                "connectivity is refused at onboarding"
            )
        return v


class OnboardingBoundarySpec(_Strict):
    """Provider-neutral declared boundary. Enforceable + auditable, no provider specifics.

    ``network_segments`` is a generic allowlist of bridges / VNets / VLANs / segments;
    ``nodes`` and ``storage`` are generic allowlists. ``credential_scope`` is an opaque,
    non-secret label describing the least-privilege posture (e.g. ``least_privilege``) —
    never a credential or secret.
    """

    nodes: list[str]
    storage: list[str]
    network_segments: list[str]
    cidrs: list[str]
    vmid_range: BoundaryVmidRange
    quotas: BoundaryQuotas
    external_connectivity: BoundaryExternalConnectivity
    credential_scope: str = Field(min_length=1)

    @field_validator("nodes", "storage", "network_segments")
    @classmethod
    def _allowlists_no_wildcards(cls, v: list[str], info) -> list[str]:
        return _no_wildcards(v, info.field_name)

    @field_validator("cidrs")
    @classmethod
    def _cidrs_valid(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("cidrs must be a non-empty allowlist")
        for cidr in v:
            if not isinstance(cidr, str) or cidr.strip().lower() in _WILDCARD_TOKENS:
                raise ValueError("cidrs must not contain wildcards")
            try:
                net = ipaddress.ip_network(cidr, strict=True)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR '{cidr}': {exc}") from exc
            if net.prefixlen == 0:
                raise ValueError(f"unrestricted CIDR '{cidr}' is refused")
        return v

    @field_validator("credential_scope")
    @classmethod
    def _credential_scope_is_a_label(cls, v: str) -> str:
        if _SECRET_RE.search(v) and "=" in v:
            raise ValueError("credential_scope must be an opaque label, never a secret value")
        return v


def validate_onboarding_boundary(
    boundary: dict | None,
    *,
    mode: OnboardingMode,
    isolation_model: IsolationModel,
) -> OnboardingBoundarySpec:
    """Strictly validate a declared boundary. Raise on any problem.

    Both ``clean_server`` and ``existing_environment`` require a complete, enforceable
    boundary — SECP deploys only inside a declared boundary. ``mode``/``isolation_model``
    are accepted for future model-specific rules and to keep the seam explicit.
    """
    if not isinstance(boundary, dict):
        raise ValidationFailedError("declared boundary is missing or not an object")
    try:
        return OnboardingBoundarySpec.model_validate(boundary)
    except ValidationError as exc:
        raise ValidationFailedError(
            "invalid declared boundary",
            errors=[f"{'/'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()],
        ) from exc


def onboarding_boundary_hash(boundary: dict) -> str:
    """Deterministic SHA-256 of a validated declared boundary."""
    from secp_scenario_schema import content_hash

    return content_hash(boundary)


# --- Preflight evidence -------------------------------------------------------

CHECK_NODES_IN_ALLOWLIST = "nodes_in_allowlist"
CHECK_STORAGE_IN_ALLOWLIST = "storage_in_allowlist"
CHECK_NETWORK_IN_BOUNDARY = "network_in_boundary"
CHECK_CIDR_NON_OVERLAPPING = "cidr_non_overlapping"
CHECK_VMID_NON_OVERLAPPING = "vmid_non_overlapping"
CHECK_CAPACITY_WITHIN_QUOTA = "capacity_within_quota"
CHECK_EXTERNAL_CONNECTIVITY_DENY = "external_connectivity_deny"
CHECK_NO_ROUTE_TO_PROTECTED = "no_route_to_protected"
CHECK_TLS_POSTURE = "tls_posture_acceptable"
CHECK_CREDENTIAL_LEAST_PRIVILEGE = "credential_least_privilege"
CHECK_REMOTE_STATE_PRESENT = "remote_state_present"
CHECK_PINNED_TOOLCHAIN_PRESENT = "pinned_toolchain_present"

# Checks required for ANY activation.
BASE_REQUIRED_CHECKS = frozenset(
    {
        CHECK_NODES_IN_ALLOWLIST,
        CHECK_STORAGE_IN_ALLOWLIST,
        CHECK_NETWORK_IN_BOUNDARY,
        CHECK_CIDR_NON_OVERLAPPING,
        CHECK_VMID_NON_OVERLAPPING,
        CHECK_CAPACITY_WITHIN_QUOTA,
        CHECK_EXTERNAL_CONNECTIVITY_DENY,
        CHECK_TLS_POSTURE,
        CHECK_CREDENTIAL_LEAST_PRIVILEGE,
        CHECK_REMOTE_STATE_PRESENT,
        CHECK_PINNED_TOOLCHAIN_PRESENT,
    }
)
# Additional check required for logical isolation (shared environment).
LOGICAL_REQUIRED_CHECKS = frozenset({CHECK_NO_ROUTE_TO_PROTECTED})


class PreflightCheck(_Strict):
    """A single, redacted, structured preflight check result (safe for API display)."""

    check: str = Field(min_length=1)
    status: PreflightCheckStatus
    detail: str = ""

    @field_validator("detail")
    @classmethod
    def _detail_is_redacted(cls, v: str) -> str:
        # Defense-in-depth: preflight details are for human review and must never carry a
        # secret. (Real values are redacted by the worker collector; this rejects leaks.)
        if _SECRET_RE.search(v) and (":" in v or "=" in v):
            raise ValueError("preflight detail must be redacted; it must not contain a secret")
        return v


def validate_preflight_evidence(checks: list[dict] | None) -> list[PreflightCheck]:
    """Validate submitted preflight evidence (structure + redaction). Raise on problems."""
    if not isinstance(checks, list) or not checks:
        raise ValidationFailedError("preflight evidence must be a non-empty list of checks")
    out: list[PreflightCheck] = []
    seen: set[str] = set()
    try:
        for item in checks:
            pc = PreflightCheck.model_validate(item)
            if pc.check in seen:
                raise ValidationFailedError(f"duplicate preflight check '{pc.check}'")
            seen.add(pc.check)
            out.append(pc)
    except ValidationError as exc:
        raise ValidationFailedError(
            "invalid preflight evidence",
            errors=[f"{'/'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()],
        ) from exc
    return out


def preflight_evidence_hash(checks: list[dict]) -> str:
    from secp_scenario_schema import content_hash

    canonical = sorted(
        ({"check": c["check"], "status": c["status"]} for c in checks),
        key=lambda c: c["check"],
    )
    return content_hash({"checks": canonical})


def required_checks_passed(
    checks: list[PreflightCheck], *, isolation_model: IsolationModel
) -> tuple[bool, list[str]]:
    """Return (ok, missing_or_failed) for the checks required by the isolation model."""
    required = set(BASE_REQUIRED_CHECKS)
    if isolation_model == IsolationModel.logical:
        required |= set(LOGICAL_REQUIRED_CHECKS)
    passed = {c.check for c in checks if c.status == PreflightCheckStatus.passed}
    missing = sorted(required - passed)
    return (not missing, missing)


# --- Onboarding lifecycle -----------------------------------------------------

ONBOARDING_TRANSITIONS: dict[S, frozenset[S]] = {
    S.draft: frozenset({S.preflight_pending, S.rejected, S.retired}),
    S.preflight_pending: frozenset({S.ready_for_review, S.draft, S.rejected, S.retired}),
    S.ready_for_review: frozenset({S.approved, S.rejected, S.draft, S.retired}),
    S.approved: frozenset({S.active, S.rejected, S.retired}),
    S.active: frozenset({S.retired}),
    S.rejected: frozenset({S.draft, S.retired}),
    S.retired: frozenset(),  # terminal
}


def is_permitted(current: S, target: S) -> bool:
    if current == target:
        return False
    return target in ONBOARDING_TRANSITIONS.get(current, frozenset())


def transition(current: S, target: S) -> S:
    if not is_permitted(current, target):
        raise InvalidTransitionError(
            f"illegal onboarding transition {current.value} -> {target.value}"
        )
    return target
