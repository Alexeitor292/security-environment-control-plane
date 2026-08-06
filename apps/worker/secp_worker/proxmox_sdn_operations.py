"""Typed HTTPS SDN discovery operations, on the same engine as everything else.

No second discovery engine, no second signer, no second verifier. These operations append to the
same canonical manifest and produce the same observation states; the only thing that differs is what
they ask for.

**Two Proxmox behaviours shape every design choice here**, and both were established from the API
source rather than assumed:

* a privilege-denied SDN **index** read returns HTTP **200 with an empty list**, because the
  handlers are declared ``user => 'all'`` and skip rows via ``check_any(..., noerr=1)``. So an empty
  zones list means "no zones" or "not allowed to see zones", and nothing at the wire distinguishes
  them. ``GET /cluster/sdn`` is the tiebreaker: it is a declarative permission check and 403s
  outright, so it is the authority preflight rather than a convenience;
* the pending state lives under ``?pending=1``, and for an object with ``state: "new"`` **only
  ``type`` and ``vnet`` are hoisted to the top level** — every other value sits under a nested
  ``pending`` object. Top-level-only parsing sees an almost-empty record and reads it as a
  near-empty change, which is the opposite of the truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from secp_worker.proxmox_discovery_operations import validated_segment

#: Same identity scheme as the non-SDN operations, and deliberately the same families: these run on
#: the same engine, so their evidence must be readable by the same reviewer without a second
#: vocabulary to learn.
_PARSER = "secp.proxmox-discovery.parser"
_NORMALIZER = "secp.proxmox-discovery.normalizer"

#: The families whose pending state must ALL be enumerated before any pending claim is made.
#: There is no read-only "does anything pend" boolean in the API, so completeness is the only way to
#: know, and a partial enumeration is an unknown rather than a smaller answer.
SDN_PENDING_FAMILIES: tuple[str, ...] = ("zones", "vnets", "subnets", "controllers")


@dataclass(frozen=True)
class GetSdnRootOperation:
    """``GET /cluster/sdn`` — the authority preflight.

    Declared ``check => ['perm','/sdn',['SDN.Audit']]``, so it CANNOT return 200-with-empty for a
    permission reason. A 200 here is the only thing that licenses reading an empty index as absence.
    """

    operation_code: ClassVar[str] = "sdn_root_authority"
    not_found_meaning: ClassVar[str] = "capability_absent"
    required_privilege: ClassVar[str] = "SDN.Audit"
    path_template: ClassVar[str] = "/cluster/sdn"
    parser_implementation_id: ClassVar[str] = f"{_PARSER}.sdn-root-authority/v1"
    normalizer_implementation_id: ClassVar[str] = f"{_NORMALIZER}.sdn-root-authority/v1"
    observation_field_codes: ClassVar[tuple[str, ...]] = ("sdn_read_authority",)

    def rendered_path(self) -> str:
        return self.path_template

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


@dataclass(frozen=True)
class GetEffectivePermissionsOperation:
    """``GET /access/permissions`` — self-scoped, and callable by a privsep token with no privilege.

    Deliberately sent with NO ``userid`` parameter. The handler defaults to the caller's own authid
    and only requires ``Sys.Audit`` on ``/access`` when asked about somebody else, so omitting the
    parameter is what keeps this within a read-only grant.
    """

    operation_code: ClassVar[str] = "effective_permissions"
    not_found_meaning: ClassVar[str] = "capability_absent"
    required_privilege: ClassVar[str] = ""
    path_template: ClassVar[str] = "/access/permissions"
    parser_implementation_id: ClassVar[str] = f"{_PARSER}.effective-permissions/v1"
    normalizer_implementation_id: ClassVar[str] = f"{_NORMALIZER}.effective-permissions/v1"
    #: Guest read authority comes from the SAME self-scoped read. There is no VM.Audit equivalent of
    #: GET /cluster/sdn — no declarative endpoint that 403s rather than filtering — so the effective
    #: permission map is the only evidence, and it must be read rather than inferred.
    observation_field_codes: ClassVar[tuple[str, ...]] = (
        "sdn_read_authority",
        "guest_read_authority",
    )

    def rendered_path(self) -> str:
        return self.path_template

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


@dataclass(frozen=True)
class GetSdnZonesOperation:
    """``GET /cluster/sdn/zones?pending=1``."""

    operation_code: ClassVar[str] = "sdn_zones_pending"
    not_found_meaning: ClassVar[str] = "capability_absent"
    required_privilege: ClassVar[str] = "SDN.Audit"
    path_template: ClassVar[str] = "/cluster/sdn/zones"
    parser_implementation_id: ClassVar[str] = f"{_PARSER}.sdn-zones-pending/v1"
    normalizer_implementation_id: ClassVar[str] = f"{_NORMALIZER}.sdn-zones-pending/v1"
    observation_field_codes: ClassVar[tuple[str, ...]] = (
        "existing_sdn_zones",
        "pending_sdn_state",
        "existing_vlan_use",
    )

    def rendered_path(self) -> str:
        return self.path_template

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return (("pending", "1"),)


@dataclass(frozen=True)
class GetSdnVnetsOperation:
    """``GET /cluster/sdn/vnets?pending=1``. Also the source of every vnet id used below."""

    operation_code: ClassVar[str] = "sdn_vnets_pending"
    not_found_meaning: ClassVar[str] = "capability_absent"
    required_privilege: ClassVar[str] = "SDN.Audit"
    path_template: ClassVar[str] = "/cluster/sdn/vnets"
    parser_implementation_id: ClassVar[str] = f"{_PARSER}.sdn-vnets-pending/v1"
    normalizer_implementation_id: ClassVar[str] = f"{_NORMALIZER}.sdn-vnets-pending/v1"
    observation_field_codes: ClassVar[tuple[str, ...]] = (
        "existing_vnets",
        "pending_sdn_state",
        "existing_vlan_use",
    )

    def rendered_path(self) -> str:
        return self.path_template

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return (("pending", "1"),)


@dataclass(frozen=True)
class GetSdnSubnetsOperation:
    """``GET /cluster/sdn/vnets/{vnet}/subnets?pending=1``.

    There is no cluster-wide subnet index, so enumeration is O(vnets) and each ``vnet`` MUST come
    from a validated vnets response. This endpoint is also hard-gated rather than silently filtered,
    so a 403 here is an unambiguous denial — unlike the indexes above.
    """

    vnet: str
    sourced_from: str = ""

    operation_code: ClassVar[str] = "sdn_subnets_pending"
    not_found_meaning: ClassVar[str] = "inventory_stale"
    required_privilege: ClassVar[str] = "SDN.Audit"
    path_template: ClassVar[str] = "/cluster/sdn/vnets/{vnet}/subnets"
    parser_implementation_id: ClassVar[str] = f"{_PARSER}.sdn-subnets-pending/v1"
    normalizer_implementation_id: ClassVar[str] = f"{_NORMALIZER}.sdn-subnets-pending/v1"
    observation_field_codes: ClassVar[tuple[str, ...]] = (
        "existing_subnets",
        "pending_sdn_state",
    )

    def __post_init__(self) -> None:
        validated_segment(self.vnet, field="vnet", sourced_from=self.sourced_from)

    def rendered_path(self) -> str:
        return f"/cluster/sdn/vnets/{self.vnet}/subnets"

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return (("pending", "1"),)


@dataclass(frozen=True)
class GetSdnControllersOperation:
    """``GET /cluster/sdn/controllers?pending=1``."""

    operation_code: ClassVar[str] = "sdn_controllers_pending"
    not_found_meaning: ClassVar[str] = "capability_absent"
    required_privilege: ClassVar[str] = "SDN.Audit"
    path_template: ClassVar[str] = "/cluster/sdn/controllers"
    parser_implementation_id: ClassVar[str] = f"{_PARSER}.sdn-controllers-pending/v1"
    normalizer_implementation_id: ClassVar[str] = f"{_NORMALIZER}.sdn-controllers-pending/v1"
    observation_field_codes: ClassVar[tuple[str, ...]] = ("pending_sdn_state",)

    def rendered_path(self) -> str:
        return self.path_template

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return (("pending", "1"),)


@dataclass(frozen=True)
class GetSdnIpamStatusOperation:
    """``GET /cluster/sdn/ipams/pve/status`` — allocated CIDRs and IPs, for overlap reasoning.

    ``pve`` is fixed: the handler dies for any other ipam id, so a caller-supplied one could only
    ever fail, and accepting one would be a caller-controlled path segment for no benefit.
    """

    operation_code: ClassVar[str] = "sdn_ipam_status"
    not_found_meaning: ClassVar[str] = "capability_absent"
    required_privilege: ClassVar[str] = "SDN.Audit"
    path_template: ClassVar[str] = "/cluster/sdn/ipams/pve/status"
    parser_implementation_id: ClassVar[str] = f"{_PARSER}.sdn-ipam-status/v1"
    normalizer_implementation_id: ClassVar[str] = f"{_NORMALIZER}.sdn-ipam-status/v1"
    observation_field_codes: ClassVar[tuple[str, ...]] = ("existing_subnets",)

    def rendered_path(self) -> str:
        return self.path_template

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


@dataclass(frozen=True)
class GetSdnFabricsOperation:
    """``GET /cluster/sdn/fabrics/all?pending=1`` — PVE 9.0+; absent on 8.x.

    A 501 or 404 is recorded as ``observed_unsupported`` rather than as a failure: the target
    answered, and "this version has no fabrics" is a fact about the target.
    """

    operation_code: ClassVar[str] = "sdn_fabrics"
    not_found_meaning: ClassVar[str] = "capability_absent"
    required_privilege: ClassVar[str] = "SDN.Audit"
    path_template: ClassVar[str] = "/cluster/sdn/fabrics/all"
    parser_implementation_id: ClassVar[str] = f"{_PARSER}.sdn-fabrics/v1"
    normalizer_implementation_id: ClassVar[str] = f"{_NORMALIZER}.sdn-fabrics/v1"
    observation_field_codes: ClassVar[tuple[str, ...]] = ("pending_sdn_state",)

    def rendered_path(self) -> str:
        return self.path_template

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return (("pending", "1"),)


@dataclass(frozen=True)
class GetNodeSdnZonesOperation:
    """``GET /nodes/{node}/sdn/zones`` — per-node runtime zone status.

    Its schema documents an ``SDN.Audit`` filter that the handler does not implement, so it returns
    the unfiltered set. That makes it the unfiltered side of the partial-visibility differential:
    a zone visible here and absent from the cluster index proves per-object filtering.
    """

    node: str
    sourced_from: str = ""

    operation_code: ClassVar[str] = "node_sdn_zones"
    not_found_meaning: ClassVar[str] = "inventory_stale"
    required_privilege: ClassVar[str] = "SDN.Audit"
    path_template: ClassVar[str] = "/nodes/{node}/sdn/zones"
    parser_implementation_id: ClassVar[str] = f"{_PARSER}.node-sdn-zones/v1"
    normalizer_implementation_id: ClassVar[str] = f"{_NORMALIZER}.node-sdn-zones/v1"
    observation_field_codes: ClassVar[tuple[str, ...]] = ("existing_sdn_zones",)

    def __post_init__(self) -> None:
        validated_segment(self.node, field="node", sourced_from=self.sourced_from)

    def rendered_path(self) -> str:
        return f"/nodes/{self.node}/sdn/zones"

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


@dataclass(frozen=True)
class GetNodeSdnBridgesOperation:
    """``GET /nodes/{node}/sdn/zones/{zone}/bridges`` — observed VLAN materialisation.

    PVE 9.1+ only, and added days before the 9.1 release, so absence is expected on anything older
    and is recorded as unsupported rather than as a gap.
    """

    node: str
    zone: str
    sourced_from: str = ""

    operation_code: ClassVar[str] = "node_sdn_bridges"
    not_found_meaning: ClassVar[str] = "ambiguous"
    required_privilege: ClassVar[str] = "SDN.Audit"
    path_template: ClassVar[str] = "/nodes/{node}/sdn/zones/{zone}/bridges"
    parser_implementation_id: ClassVar[str] = f"{_PARSER}.node-sdn-bridges/v1"
    normalizer_implementation_id: ClassVar[str] = f"{_NORMALIZER}.node-sdn-bridges/v1"
    observation_field_codes: ClassVar[tuple[str, ...]] = (
        "bridge_vlan_awareness",
        "existing_vlan_use",
    )

    def __post_init__(self) -> None:
        validated_segment(self.node, field="node", sourced_from=self.sourced_from)
        validated_segment(self.zone, field="zone", sourced_from=self.sourced_from)

    def rendered_path(self) -> str:
        return f"/nodes/{self.node}/sdn/zones/{self.zone}/bridges"

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


SDN_OPERATIONS: tuple[type, ...] = (
    GetSdnRootOperation,
    GetEffectivePermissionsOperation,
    GetSdnZonesOperation,
    GetSdnVnetsOperation,
    GetSdnSubnetsOperation,
    GetSdnControllersOperation,
    GetSdnIpamStatusOperation,
    GetSdnFabricsOperation,
    GetNodeSdnZonesOperation,
    GetNodeSdnBridgesOperation,
)


# --- pending-state parsing
# --------------------------------------------------------------------------

SDN_STATE_NEW = "new"
SDN_STATE_CHANGED = "changed"
SDN_STATE_DELETED = "deleted"


def parse_pending_objects(family: str, payload: object) -> tuple[dict, ...]:
    """Extract pending SDN objects from a ``?pending=1`` response.

    The nested-``pending`` rule is the whole point. Proxmox's ``pending_config`` hoists only
    ``type``
    and ``vnet`` to the top level for a ``new`` object; every other value — tag, bridge, nodes,
    cidr — lives under ``pending``. So the merged view reads nested values FIRST and falls back to
    the top level, rather than the other way round.

    For a ``changed`` object the top level holds the RUNNING values and ``pending`` holds the new
    ones, so the same precedence gives the state that activation would produce, which is what
    collision reasoning needs.
    """
    if not isinstance(payload, list):
        raise ValueError("sdn_pending_payload_not_a_list")

    out: list[dict] = []
    for row in payload:
        if not isinstance(row, dict):
            raise ValueError("sdn_pending_row_not_an_object")
        state = row.get("state")
        if state not in (SDN_STATE_NEW, SDN_STATE_CHANGED, SDN_STATE_DELETED):
            # No state annotation means this object is identical in both configs — not pending.
            continue
        nested = row.get("pending")
        merged = dict(row)
        if isinstance(nested, dict):
            for key, value in nested.items():
                # The literal string 'deleted' marks a key removed by the pending change.
                merged[key] = None if value == "deleted" else value
        merged.pop("pending", None)
        merged["family"] = family
        merged["state"] = state
        out.append(merged)
    return tuple(out)


# Completeness across the families is decided by
# ``secp_api.discovery_fact_projection._pending_sdn_completeness``, the production path and the only
# one. A ``pending_families_complete(dict[str, bool])`` helper lived here and was reached by
# nothing: it could not express the rule that actually matters — subnets have no cluster-wide index,
# so completeness means every OBSERVED VNET was walked, which a flat family→bool map cannot say.
# Two functions answering "was the pending state fully enumerated" is how the weaker one ends up
# deciding, so the weaker one is gone rather than kept for convenience.
