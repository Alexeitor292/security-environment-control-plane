"""Strict provisioning scope policy — blast-radius enforcement (ADR-011, §2).

Validated ONLY at provisioning-manifest generation (and future provisioning paths).
SECP-002A discovery scope keys (e.g. ``resource_types``, ``nodes``) are untouched;
provisioning bounds live at ``ExecutionTarget.scope_policy["provisioning"]``.

Rejects empty lists, wildcards, unrestricted ranges, unsupported keys, or missing
required limits. External connectivity defaults to deny and nothing permissive is
accepted in SECP-002B-0.
"""

from __future__ import annotations

import ipaddress

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from secp_api.errors import ValidationFailedError

# Tokens that would broaden an allowlist into an unsafe wildcard.
_WILDCARD_TOKENS = {"*", "any", "all", "", "0.0.0.0/0", "::/0", "0/0"}
# A conservative cap so a VM-ID range cannot be effectively unbounded.
_MAX_VMID_WIDTH = 100_000


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VmidRange(_Strict):
    start: int = Field(ge=100)  # Proxmox reserves VM IDs < 100
    end: int = Field(ge=100)

    @field_validator("end")
    @classmethod
    def _end_after_start(cls, v: int, info) -> int:
        start = info.data.get("start")
        if start is not None and v <= start:
            raise ValueError("vmid_range.end must be greater than vmid_range.start")
        if start is not None and (v - start) > _MAX_VMID_WIDTH:
            raise ValueError(
                f"vmid_range width must not exceed {_MAX_VMID_WIDTH} (unbounded range refused)"
            )
        return v


class ExternalConnectivity(_Strict):
    # SECP-002B-0 permits only an explicit default-deny posture.
    policy: str = "deny"

    @field_validator("policy")
    @classmethod
    def _only_deny(cls, v: str) -> str:
        if v != "deny":
            raise ValueError(
                "external_connectivity.policy must be 'deny' in SECP-002B-0; "
                "permissive external connectivity is refused"
            )
        return v


class NodeSizing(_Strict):
    """Per-image/template resource sizing (vcpu, memory_mb, disk_gb).

    Captured in the approved scope policy so every node's resources come from
    an immutable approved input.  No silent defaults: a missing image fails closed.
    """

    vcpu: int = Field(ge=1)
    memory_mb: int = Field(ge=128)
    disk_gb: int = Field(ge=1)


def _no_wildcards(values: list[str], field: str) -> list[str]:
    if not values:
        raise ValueError(f"{field} must be a non-empty allowlist")
    for item in values:
        if not isinstance(item, str) or item.strip().lower() in _WILDCARD_TOKENS:
            raise ValueError(f"{field} must not contain wildcards or empty entries")
    return values


class ProvisioningScopePolicy(_Strict):
    """Explicit allowlists + hard bounds for a would-be Proxmox provisioning."""

    allowed_nodes: list[str]
    allowed_storage: list[str]
    allowed_bridges: list[str]
    allowed_templates: list[str]
    vmid_range: VmidRange
    max_teams: int = Field(ge=1)
    max_vms: int = Field(ge=1)
    max_containers: int = Field(ge=0)
    max_total_vcpu: int = Field(ge=1)
    max_total_memory_mb: int = Field(ge=1)
    max_total_disk_gb: int = Field(ge=1)
    allowed_cidr_reservations: list[str]
    external_connectivity: ExternalConnectivity
    # Required per-image sizing profile.  No defaults — missing image fails closed.
    node_sizing: dict[str, NodeSizing]

    @field_validator("allowed_nodes", "allowed_storage", "allowed_bridges", "allowed_templates")
    @classmethod
    def _allowlists_no_wildcards(cls, v: list[str], info) -> list[str]:
        return _no_wildcards(v, info.field_name)

    @field_validator("node_sizing")
    @classmethod
    def _node_sizing_non_empty(cls, v: dict) -> dict:
        if not v:
            raise ValueError("node_sizing must have at least one entry")
        return v

    @field_validator("allowed_cidr_reservations")
    @classmethod
    def _cidrs_valid_and_bounded(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("allowed_cidr_reservations must be a non-empty allowlist")
        for cidr in v:
            if not isinstance(cidr, str) or cidr.strip().lower() in _WILDCARD_TOKENS:
                raise ValueError("allowed_cidr_reservations must not contain wildcards")
            try:
                net = ipaddress.ip_network(cidr, strict=True)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR '{cidr}': {exc}") from exc
            if net.prefixlen == 0:
                raise ValueError(f"unrestricted CIDR '{cidr}' is refused")
        return v


def validate_provisioning_scope(scope_policy: dict | None) -> ProvisioningScopePolicy:
    """Validate ``scope_policy['provisioning']`` strictly. Raise on any problem."""
    if not isinstance(scope_policy, dict):
        raise ValidationFailedError("target scope_policy is missing or not an object")
    section = scope_policy.get("provisioning")
    if not isinstance(section, dict):
        raise ValidationFailedError(
            "target scope_policy.provisioning is missing; a strict provisioning "
            "scope policy is required to generate a manifest"
        )
    try:
        return ProvisioningScopePolicy.model_validate(section)
    except ValidationError as exc:
        raise ValidationFailedError(
            "invalid provisioning scope policy",
            errors=[f"{'/'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()],
        ) from exc
