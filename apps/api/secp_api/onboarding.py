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

from secp_api.enums import (
    CollectorKind,
    IsolationModel,
    IsolationProfile,
    NetworkApproach,
    OnboardingMode,
    PreflightCheckStatus,
    VerificationLevel,
)
from secp_api.enums import OnboardingStatus as S
from secp_api.errors import (
    InvalidTransitionError,
    LiveEvidenceSealedError,
    ValidationFailedError,
)

# Tokens that would broaden an allowlist into an unsafe wildcard.
_WILDCARD_TOKENS = {"*", "any", "all", "", "0.0.0.0/0", "::/0", "0/0"}
_MAX_VMID_WIDTH = 100_000
# Isolation profiles enabled in this release. Only fully-segregated is available; the roadmap
# profiles are rejected server-side (SECP-002B-1B-0.1) — never merely hidden in the UI.
SUPPORTED_ISOLATION_PROFILES = frozenset({IsolationProfile.fully_segregated})
# A secret must never appear in submitted preflight evidence details.
_SECRET_RE = re.compile(
    r"(pass|passwd|password|secret|token|api[_-]?key|apikey|private[_-]?key|credential)",
    re.IGNORECASE,
)

# --- Robust redaction of preflight detail text (correction pass, ADR-014 §5) ---
# Preflight details are review-only strings. They must never carry a secret, endpoint,
# credential, or raw-inventory VALUE. These patterns reject secret-bearing text robustly
# (not only the colon/equals form) while leaving generic, value-free descriptions valid.
_SECRET_WORD = (
    r"(?:pass(?:word|wd)?|secret|token|api[_-]?key|apikey|private[_-]?key|"
    r"credentials?|bearer|authorization|session[_-]?id)"
)
# A secret keyword directly followed by a value (":", "=", or a following token).
_SECRET_ASSIGNMENT_RE = re.compile(rf"{_SECRET_WORD}\s*[:=]\s*\S", re.IGNORECASE)
_SECRET_VALUE_RE = re.compile(rf"{_SECRET_WORD}\s+\S{{6,}}", re.IGNORECASE)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----", re.IGNORECASE)
# Endpoint-like: URL schemes, IPv4 (with optional CIDR/port), or multi-label hostnames.
_URL_RE = re.compile(r"[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HOSTNAME_RE = re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+){2,}\b", re.IGNORECASE)
# Raw-inventory-like: provider node/storage/bridge/VNet/VLAN tokens.
_INVENTORY_RE = re.compile(
    r"\bvmbr\d+\b|\bpve-node-?\d+\b|\blocal-lvm\b|\blocal-zfs\b|\bvnet\d+\b|\bvlan\d+\b",
    re.IGNORECASE,
)
# High-entropy token-like run (16+ alphanumerics containing at least one digit).
_HIGH_ENTROPY_RE = re.compile(r"\b(?=[A-Za-z0-9]*[0-9])[A-Za-z0-9]{16,}\b")

_REDACTION_REJECT_RES = (
    _PRIVATE_KEY_RE,
    _SECRET_ASSIGNMENT_RE,
    _SECRET_VALUE_RE,
    _URL_RE,
    _IPV4_RE,
    _HOSTNAME_RE,
    _INVENTORY_RE,
    _HIGH_ENTROPY_RE,
)


def detail_is_secret_bearing(text: str) -> bool:
    """True when a preflight detail string carries a secret/endpoint/inventory value.

    Robust redaction check: rejects secret keywords with a value, private keys, URLs,
    IPv4/CIDR, multi-label hostnames, provider inventory tokens, and high-entropy tokens.
    Generic value-free descriptions (the simulated details) are accepted.
    """
    return any(rx.search(text) for rx in _REDACTION_REJECT_RES)


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
    # Provider-neutral operator declarations (SECP-002B-1B-0.1). Optional with safe,
    # backward-compatible defaults so pre-0.1 boundaries validate unchanged. Both are part of
    # the hashed, immutable declared boundary.
    network_approach: NetworkApproach = NetworkApproach.use_approved_existing_segment
    isolation_profile: IsolationProfile = IsolationProfile.fully_segregated

    @field_validator("isolation_profile")
    @classmethod
    def _isolation_profile_supported(cls, v: IsolationProfile) -> IsolationProfile:
        # Reject roadmap profiles server-side (not merely disabled in the UI). No NAT/gateway/
        # firewall/egress behaviour exists in this release.
        if v not in SUPPORTED_ISOLATION_PROFILES:
            raise ValueError(
                f"isolation profile '{v.value}' is planned but not available yet; only "
                f"'{IsolationProfile.fully_segregated.value}' is supported in this release"
            )
        return v

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
        # secret, credential, endpoint, or raw inventory value. (Real values are redacted by
        # the worker collector; this rejects any leak robustly — not only ":"/"=" forms.)
        if detail_is_secret_bearing(v):
            raise ValueError(
                "preflight detail must be redacted; it must not contain a secret, "
                "credential, endpoint, or raw inventory value"
            )
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


# --- Complete, hash-bound preflight evidence package (ADR-014 §3) -------------

EVIDENCE_SCHEMA_VERSION = "secp-002b-1b-0/preflight-evidence/v1"

# Generic, redacted, review-safe descriptions for simulated evidence. No real
# hostnames/IPs/nodes/storage/bridges/CIDRs/VM-IDs.
_SIMULATED_DETAILS = {
    CHECK_NODES_IN_ALLOWLIST: "all selected nodes are within the declared node allowlist",
    CHECK_STORAGE_IN_ALLOWLIST: "all selected storage is within the declared storage allowlist",
    CHECK_NETWORK_IN_BOUNDARY: "requested network segments are within the declared boundary",
    CHECK_CIDR_NON_OVERLAPPING: "declared CIDR ranges are non-overlapping",
    CHECK_VMID_NON_OVERLAPPING: "declared VM-ID range is non-overlapping",
    CHECK_CAPACITY_WITHIN_QUOTA: "requested capacity is within the declared quotas",
    CHECK_EXTERNAL_CONNECTIVITY_DENY: "external connectivity policy is deny by default",
    CHECK_NO_ROUTE_TO_PROTECTED: "no route to management/home/corporate/public network classes",
    CHECK_TLS_POSTURE: "TLS posture is acceptable (trusted CA / pinning)",
    CHECK_CREDENTIAL_LEAST_PRIVILEGE: "credential scope is least privilege (opaque reference)",
    CHECK_REMOTE_STATE_PRESENT: "remote state backend prerequisite is present",
    CHECK_PINNED_TOOLCHAIN_PRESENT: "pinned toolchain prerequisite is present",
}


def simulate_boundary_checks(
    boundary: dict,
    isolation_model: IsolationModel,
    *,
    fail: set[str] | None = None,
    omit: set[str] | None = None,
) -> list[dict]:
    """Deterministically derive SIMULATED checks from a declared boundary.

    This is not infrastructure inspection — it derives review-safe evidence from
    already-declared data. Used by both the control-plane simulated-preflight path and
    the worker ``FakePreflightCollector``. Every detail is generic and redacted.
    """
    fail = set(fail or ())
    omit = set(omit or ())
    required = set(BASE_REQUIRED_CHECKS) | {CHECK_NO_ROUTE_TO_PROTECTED}
    checks: list[dict] = []
    for name in sorted(required):
        if name in omit:
            continue
        if name in fail:
            status = PreflightCheckStatus.failed
        elif name == CHECK_NO_ROUTE_TO_PROTECTED and isolation_model != IsolationModel.logical:
            status = PreflightCheckStatus.skipped
        else:
            status = PreflightCheckStatus.passed
        checks.append(
            {"check": name, "status": status.value, "detail": _SIMULATED_DETAILS.get(name, "check")}
        )
    return checks


def build_evidence_package(
    *,
    onboarding_id: str,
    boundary_hash: str,
    target_config_hash: str,
    scope_policy_hash: str,
    toolchain_profile_id: str | None,
    toolchain_profile_hash: str | None,
    verification_level: str,
    collector_kind: str,
    collector_identity: str,
    evidence_version: int,
    checks: list[dict],
    target_evidence_id: str | None = None,
    target_evidence_hash: str | None = None,
) -> dict:
    """Assemble the canonical, redacted evidence package that the evidence hash covers.

    Includes schema version, onboarding id, all binding hashes + provenance, trust level,
    collector identity, monotonic evidence version, and every redacted check field. It
    contains NO secrets, endpoints, credentials, raw inventories, or unredacted output.
    """
    canonical_checks = sorted(
        (
            {"check": c["check"], "status": c["status"], "detail": c.get("detail", "")}
            for c in checks
        ),
        key=lambda c: c["check"],
    )
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "onboarding_id": onboarding_id,
        "boundary_hash": boundary_hash,
        "target_config_hash": target_config_hash,
        "scope_policy_hash": scope_policy_hash,
        "toolchain_profile_id": toolchain_profile_id,
        "toolchain_profile_hash": toolchain_profile_hash,
        "verification_level": verification_level,
        "collector_kind": collector_kind,
        "collector_identity": collector_identity,
        "evidence_version": evidence_version,
        "target_evidence_id": target_evidence_id,
        "target_evidence_hash": target_evidence_hash,
        "checks": canonical_checks,
    }


def evidence_package_hash(package: dict) -> str:
    from secp_scenario_schema import content_hash

    return content_hash(package)


def validate_collector_and_level(collector_kind: str, verification_level: str) -> None:
    """Reject arbitrary collector labels and unsafe collector/level combinations."""
    if collector_kind not in {c.value for c in CollectorKind}:
        raise ValidationFailedError(f"unknown collector_kind '{collector_kind}'")
    if verification_level not in {v.value for v in VerificationLevel}:
        raise ValidationFailedError(f"unknown verification_level '{verification_level}'")
    # A fake/declared-boundary collector can only ever produce simulated evidence; only the
    # trusted worker provider collector may produce live_verified evidence.
    if (
        collector_kind == CollectorKind.fake_declared_boundary.value
        and verification_level != VerificationLevel.simulated.value
    ):
        raise ValidationFailedError(
            "fake_declared_boundary collector may only produce 'simulated' evidence"
        )
    if (
        verification_level == VerificationLevel.live_verified.value
        and collector_kind != CollectorKind.provider_worker.value
    ):
        raise ValidationFailedError(
            "live_verified evidence may only be produced by the provider_worker collector"
        )


# --- B1-B-0 live-evidence seal (correction pass) -----------------------------
#
# Live-verified preflight evidence is a FUTURE B1-B capability that requires a real,
# separately-reviewed ``provider_worker`` collector. In SECP-002B-1B-0 NO code path may
# create ``live_verified`` evidence or use the ``provider_worker`` collector: the seam
# exists (the ``PreflightCollector`` protocol and the enum values) but its implementation
# is unavailable/inert. This is a deliberate, UNCONDITIONAL code-level seal — not a
# configuration setting — lifted only by a separately reviewed B1-B change that adds a real
# collector. ``record_preflight_result`` therefore accepts only simulated fake evidence in
# this release.
B1B0_LIVE_EVIDENCE_SEALED = True


def assert_live_evidence_unsealed_allowed(collector_kind: str, verification_level: str) -> None:
    """Refuse any attempt to create live_verified / provider_worker evidence in B1-B-0.

    Raises :class:`LiveEvidenceSealedError` while :data:`B1B0_LIVE_EVIDENCE_SEALED` holds.
    """
    if not B1B0_LIVE_EVIDENCE_SEALED:  # pragma: no cover - only a reviewed B1-B change lifts this
        return
    if (
        verification_level == VerificationLevel.live_verified.value
        or collector_kind == CollectorKind.provider_worker.value
    ):
        raise LiveEvidenceSealedError(
            "live_verified onboarding evidence cannot be created in SECP-002B-1B-0; the "
            "provider_worker collector is a sealed future B1-B seam and only simulated fake "
            "evidence is permitted. Lifting this seal requires a separately reviewed B1-B change."
        )


# --- Boundary <-> target scope compatibility (ADR-014 §5) --------------------


def boundary_from_scope(scope_policy: dict) -> dict:
    """Derive a provider-neutral declared boundary from a provisioning scope policy.

    The derived boundary is exactly the scope's boundary-relevant fields, so it is always
    equal to (⊆) the scope. Useful for UX ("suggest a boundary") and tests.
    """
    prov = (scope_policy or {}).get("provisioning", scope_policy) or {}
    return {
        "nodes": list(prov.get("allowed_nodes", [])),
        "storage": list(prov.get("allowed_storage", [])),
        "network_segments": list(prov.get("allowed_bridges", [])),
        "cidrs": list(prov.get("allowed_cidr_reservations", [])),
        "vmid_range": dict(prov.get("vmid_range", {})),
        "quotas": {
            "max_teams": prov.get("max_teams"),
            "max_vms": prov.get("max_vms"),
            "max_containers": prov.get("max_containers"),
            "max_total_vcpu": prov.get("max_total_vcpu"),
            "max_total_memory_mb": prov.get("max_total_memory_mb"),
            "max_total_disk_gb": prov.get("max_total_disk_gb"),
        },
        "external_connectivity": dict(prov.get("external_connectivity", {"policy": "deny"})),
        "credential_scope": "least_privilege",
    }


def _cidr_within_any(cidr: str, allowed: list[str]) -> bool:
    net = ipaddress.ip_network(cidr, strict=True)
    for a in allowed:
        block = ipaddress.ip_network(a, strict=True)
        if net.version == block.version and net.subnet_of(block):  # type: ignore[arg-type]
            return True
    return False


def validate_boundary_within_scope(boundary: OnboardingBoundarySpec, scope_policy: dict) -> None:
    """Refuse a declared boundary that is broader than the target provisioning scope.

    Provider-neutral: names are compared as opaque strings. Provider-specific naming
    normalization is a worker adapter concern (a seam, not implemented here).
    """
    prov = (scope_policy or {}).get("provisioning")
    if not isinstance(prov, dict) or not prov:
        raise ValidationFailedError(
            "target has no provisioning scope policy; a scope policy is required before "
            "an onboarding boundary can be validated"
        )
    problems: list[str] = []
    if not set(boundary.nodes) <= set(prov.get("allowed_nodes", [])):
        problems.append("nodes exceed the target allowed_nodes")
    if not set(boundary.storage) <= set(prov.get("allowed_storage", [])):
        problems.append("storage exceeds the target allowed_storage")
    if not set(boundary.network_segments) <= set(prov.get("allowed_bridges", [])):
        problems.append("network_segments exceed the target allowed_bridges")
    allowed_cidrs = prov.get("allowed_cidr_reservations", [])
    if not all(_cidr_within_any(c, allowed_cidrs) for c in boundary.cidrs):
        problems.append("cidrs exceed the target allowed_cidr_reservations")
    srange = prov.get("vmid_range", {})
    if not (
        srange.get("start", 0) <= boundary.vmid_range.start
        and boundary.vmid_range.end <= srange.get("end", 0)
    ):
        problems.append("vmid_range exceeds the target vmid_range")
    q = boundary.quotas
    for field, scope_key in (
        ("max_teams", "max_teams"),
        ("max_vms", "max_vms"),
        ("max_containers", "max_containers"),
        ("max_total_vcpu", "max_total_vcpu"),
        ("max_total_memory_mb", "max_total_memory_mb"),
        ("max_total_disk_gb", "max_total_disk_gb"),
    ):
        if getattr(q, field) > prov.get(scope_key, 0):
            problems.append(f"quota {field} exceeds the target {scope_key}")
    if boundary.external_connectivity.policy != prov.get("external_connectivity", {}).get(
        "policy", "deny"
    ):
        problems.append("external_connectivity policy disagrees with the target scope")
    if problems:
        raise ValidationFailedError(
            "declared boundary is broader than the target provisioning scope", errors=problems
        )


def boundary_scope_intersection(boundary: OnboardingBoundarySpec, scope_policy: dict) -> dict:
    """The provider-neutral effective boundary = boundary ∩ target scope policy.

    The worker must later execute only within this intersection. When the boundary is
    within scope (enforced at onboarding) the intersection equals the declared boundary.
    """
    prov = (scope_policy or {}).get("provisioning", {}) or {}
    return {
        "nodes": sorted(set(boundary.nodes) & set(prov.get("allowed_nodes", []))),
        "storage": sorted(set(boundary.storage) & set(prov.get("allowed_storage", []))),
        "network_segments": sorted(
            set(boundary.network_segments) & set(prov.get("allowed_bridges", []))
        ),
        "cidrs": [
            c
            for c in boundary.cidrs
            if _cidr_within_any(c, prov.get("allowed_cidr_reservations", []))
        ],
        "vmid_range": {
            "start": max(boundary.vmid_range.start, prov.get("vmid_range", {}).get("start", 0)),
            "end": min(boundary.vmid_range.end, prov.get("vmid_range", {}).get("end", 0)),
        },
    }


# --- Effective execution boundary (correction pass, ADR-014 §2) --------------

EFFECTIVE_BOUNDARY_SCHEMA_VERSION = "secp-002b-1b-0/effective-boundary/v1"


def effective_boundary(boundary: OnboardingBoundarySpec, scope_policy: dict) -> dict:
    """Canonical effective execution boundary = declared boundary ∩ target scope policy.

    Deterministic and provider-neutral. Extends :func:`boundary_scope_intersection` with the
    min-of quotas and the (deny) external-connectivity policy so it is the *complete* set of
    resources the worker may act within. When the declared boundary is within scope (enforced
    at onboarding) the allowlist/CIDR/VM-ID parts equal the declared boundary. An empty
    allowlist or an inverted VM-ID range denotes an *empty* boundary (refused upstream).
    """
    prov = (scope_policy or {}).get("provisioning", {}) or {}
    inter = boundary_scope_intersection(boundary, scope_policy)
    q = boundary.quotas
    quotas = {
        "max_teams": min(q.max_teams, prov.get("max_teams", q.max_teams)),
        "max_vms": min(q.max_vms, prov.get("max_vms", q.max_vms)),
        "max_containers": min(q.max_containers, prov.get("max_containers", q.max_containers)),
        "max_total_vcpu": min(q.max_total_vcpu, prov.get("max_total_vcpu", q.max_total_vcpu)),
        "max_total_memory_mb": min(
            q.max_total_memory_mb, prov.get("max_total_memory_mb", q.max_total_memory_mb)
        ),
        "max_total_disk_gb": min(
            q.max_total_disk_gb, prov.get("max_total_disk_gb", q.max_total_disk_gb)
        ),
    }
    return {
        "schema_version": EFFECTIVE_BOUNDARY_SCHEMA_VERSION,
        "nodes": inter["nodes"],
        "storage": inter["storage"],
        "network_segments": inter["network_segments"],
        "cidrs": inter["cidrs"],
        "vmid_range": inter["vmid_range"],
        "quotas": quotas,
        # External connectivity is always deny within the effective boundary.
        "external_connectivity": {"policy": "deny"},
    }


def effective_boundary_is_empty(eb: dict) -> bool:
    """True when the effective boundary permits nothing (fail-closed sentinel)."""
    if not eb:
        return True
    vr = eb.get("vmid_range", {}) or {}
    start, end = vr.get("start"), vr.get("end")
    if start is None or end is None or start > end:
        return True
    return not (
        eb.get("nodes") and eb.get("storage") and eb.get("network_segments") and eb.get("cidrs")
    )


def effective_boundary_hash(eb: dict) -> str:
    """Deterministic SHA-256 of a canonical effective boundary."""
    from secp_scenario_schema import content_hash

    return content_hash(eb)


def cidr_within_allowed(cidr: str, allowed: list[str]) -> bool:
    """True when ``cidr`` is a subnet of any allowed CIDR (public helper for the worker seam)."""
    return _cidr_within_any(cidr, allowed)


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
