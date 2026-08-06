"""Typed HTTPS discovery operations. One type per exact reviewed request.

There is no ``get(path)`` on this surface. Orchestration selects an operation TYPE; the type renders
its own path from a reviewed template, and a caller has nowhere to put a path, a query parameter or
a method. That is the difference between a request that cannot be misdirected and one that is
checked for misdirection.

First-MVP scope is deliberately one operation. ``/version`` is the right one to establish the seam
with: it needs no privilege at all, it is side-effect-free, and it carries the exact patch version
that provider compatibility is decided on — so the vertical slice proves the whole path while asking
the target for the least it can.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

#: Bound into signed evidence so a snapshot names the code that interpreted it. A parse produced by
#: a different implementation is a different observation even from identical bytes.
VERSION_PARSER_IMPLEMENTATION_ID = "secp.proxmox-discovery.version-parser/v1"
VERSION_NORMALIZER_IMPLEMENTATION_ID = "secp.proxmox-discovery.version-normalizer/v1"


@dataclass(frozen=True)
class GetVersionOperation:
    """``GET /version`` — the Proxmox API's own view of its version.

    Takes no parameters, so there is nothing a caller can influence. The path template and the
    rendered path are identical here precisely because it interpolates nothing; operations that do
    take a segment will differ, and both are signed so a reviewer sees the permitted shape as well
    as the instance.
    """

    operation_code: ClassVar[str] = "api_version"
    path_template: ClassVar[str] = "/version"
    observation_field_codes: ClassVar[tuple[str, ...]] = (
        "pve_version_full",
        "pve_version_major",
        "pve_version_minor",
        "pve_version_patch",
        "pve_release",
        "pve_repoid",
    )

    def rendered_path(self) -> str:
        return self.path_template

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


class OperationParameterError(ValueError):
    """A dynamic identifier was not sourced from a prior validated response, or is malformed."""


#: Dynamic path segments must look like this and nothing else. Proxmox node, storage, vnet and zone
#: identifiers are short safe tokens; anything carrying a slash, a dot-dot, a query or an encoded
#: character is refused rather than escaped, because escaping is a decision and refusal is not.
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")

#: How many dynamic identifiers one enumeration may expand into. A cluster reporting ten thousand
#: nodes is a malformed or hostile answer, not a large cluster, and an unbounded expansion turns one
#: read into a stampede.
MAX_DYNAMIC_EXPANSION = 64


def validated_segment(value: object, *, field: str, sourced_from: str) -> str:
    """Validate one dynamic identifier taken from a PRIOR validated response.

    ``sourced_from`` is required and recorded in the refusal, because the rule being enforced is
    provenance and not merely shape: a well-formed node name a caller invented is exactly as
    unacceptable as a malformed one, and only the call site knows which response it came from.
    """
    if not sourced_from:
        raise OperationParameterError(f"dynamic_identifier_unsourced:{field}")
    if not isinstance(value, str) or not _SAFE_SEGMENT.match(value):
        raise OperationParameterError(f"dynamic_identifier_unsafe:{field}")
    return value


def bounded_identifiers(values: object, *, field: str, sourced_from: str) -> tuple[str, ...]:
    """Validate and bound a list of dynamic identifiers from a prior response."""
    if not isinstance(values, (list, tuple)):
        raise OperationParameterError(f"dynamic_identifier_list_malformed:{field}")
    if len(values) > MAX_DYNAMIC_EXPANSION:
        raise OperationParameterError(f"dynamic_identifier_list_too_large:{field}")
    return tuple(validated_segment(v, field=field, sourced_from=sourced_from) for v in values)


@dataclass(frozen=True)
class GetClusterStatusOperation:
    """``GET /cluster/status`` — cluster identity, membership and quorum."""

    operation_code: ClassVar[str] = "cluster_status"
    path_template: ClassVar[str] = "/cluster/status"
    observation_field_codes: ClassVar[tuple[str, ...]] = ("cluster_identity", "node_names")

    def rendered_path(self) -> str:
        return self.path_template

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


@dataclass(frozen=True)
class GetNodesOperation:
    """``GET /nodes`` — the node index, and the source of every node identifier used below."""

    operation_code: ClassVar[str] = "node_index"
    path_template: ClassVar[str] = "/nodes"
    observation_field_codes: ClassVar[tuple[str, ...]] = ("node_names", "node_online_state")

    def rendered_path(self) -> str:
        return self.path_template

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


@dataclass(frozen=True)
class GetNodeStatusOperation:
    """``GET /nodes/{node}/status`` — capacity, running kernel and boot posture."""

    node: str
    sourced_from: str = ""

    operation_code: ClassVar[str] = "node_status"
    path_template: ClassVar[str] = "/nodes/{node}/status"
    observation_field_codes: ClassVar[tuple[str, ...]] = (
        "node_capacity",
        "kernel_version",
        "node_versions",
    )

    def __post_init__(self) -> None:
        validated_segment(self.node, field="node", sourced_from=self.sourced_from)

    def rendered_path(self) -> str:
        return f"/nodes/{self.node}/status"

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


@dataclass(frozen=True)
class GetNodeVersionOperation:
    """``GET /nodes/{node}/version`` — the per-node package version. No privilege required."""

    node: str
    sourced_from: str = ""

    operation_code: ClassVar[str] = "node_version"
    path_template: ClassVar[str] = "/nodes/{node}/version"
    observation_field_codes: ClassVar[tuple[str, ...]] = ("node_versions",)

    def __post_init__(self) -> None:
        validated_segment(self.node, field="node", sourced_from=self.sourced_from)

    def rendered_path(self) -> str:
        return f"/nodes/{self.node}/version"

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


@dataclass(frozen=True)
class GetNodeAptVersionsOperation:
    """``GET /nodes/{node}/apt/versions`` — the package inventory replacing ``pveversion -v``."""

    node: str
    sourced_from: str = ""

    operation_code: ClassVar[str] = "node_package_inventory"
    path_template: ClassVar[str] = "/nodes/{node}/apt/versions"
    observation_field_codes: ClassVar[tuple[str, ...]] = (
        "raw_host_package_version",
        "release_build_identifier",
    )

    def __post_init__(self) -> None:
        validated_segment(self.node, field="node", sourced_from=self.sourced_from)

    def rendered_path(self) -> str:
        return f"/nodes/{self.node}/apt/versions"

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


@dataclass(frozen=True)
class GetNodeNetworkOperation:
    """``GET /nodes/{node}/network`` — bridges, their VLAN-awareness and management interfaces."""

    node: str
    sourced_from: str = ""

    operation_code: ClassVar[str] = "node_network"
    path_template: ClassVar[str] = "/nodes/{node}/network"
    observation_field_codes: ClassVar[tuple[str, ...]] = (
        "bridges",
        "bridge_vlan_awareness",
        "management_bridges",
        "management_cidrs",
    )

    def __post_init__(self) -> None:
        validated_segment(self.node, field="node", sourced_from=self.sourced_from)

    def rendered_path(self) -> str:
        return f"/nodes/{self.node}/network"

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


@dataclass(frozen=True)
class GetNodeStorageOperation:
    """``GET /nodes/{node}/storage`` — storage ids, types, content capability and free space."""

    node: str
    sourced_from: str = ""

    operation_code: ClassVar[str] = "node_storage"
    path_template: ClassVar[str] = "/nodes/{node}/storage"
    observation_field_codes: ClassVar[tuple[str, ...]] = (
        "storage_ids",
        "storage_types",
        "allowed_storage_content",
        "available_capacity",
    )

    def __post_init__(self) -> None:
        validated_segment(self.node, field="node", sourced_from=self.sourced_from)

    def rendered_path(self) -> str:
        return f"/nodes/{self.node}/storage"

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


@dataclass(frozen=True)
class GetStorageContentOperation:
    """``GET /nodes/{node}/storage/{storage}/content`` — ISO and container-template availability."""

    node: str
    storage: str
    sourced_from: str = ""

    operation_code: ClassVar[str] = "storage_content"
    path_template: ClassVar[str] = "/nodes/{node}/storage/{storage}/content"
    observation_field_codes: ClassVar[tuple[str, ...]] = (
        "iso_and_container_template_availability",
        "templates",
    )

    def __post_init__(self) -> None:
        validated_segment(self.node, field="node", sourced_from=self.sourced_from)
        validated_segment(self.storage, field="storage", sourced_from=self.sourced_from)

    def rendered_path(self) -> str:
        return f"/nodes/{self.node}/storage/{self.storage}/content"

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


@dataclass(frozen=True)
class GetClusterResourcesOperation:
    """``GET /cluster/resources?type=vm`` — the guest inventory.

    ``type`` is a FIXED value on a closed enum, not a caller parameter: it is the difference between
    a query the operation type owns and one a caller can widen.
    """

    operation_code: ClassVar[str] = "cluster_resources_vm"
    path_template: ClassVar[str] = "/cluster/resources"
    observation_field_codes: ClassVar[tuple[str, ...]] = ("existing_vm_ids", "existing_lxc_ids")

    def rendered_path(self) -> str:
        return self.path_template

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return (("type", "vm"),)


@dataclass(frozen=True)
class GetClusterFirewallOptionsOperation:
    """``GET /cluster/firewall/options`` — whether the cluster firewall can enforce anything."""

    operation_code: ClassVar[str] = "cluster_firewall_options"
    path_template: ClassVar[str] = "/cluster/firewall/options"
    observation_field_codes: ClassVar[tuple[str, ...]] = ("firewall_capability",)

    def rendered_path(self) -> str:
        return self.path_template

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


@dataclass(frozen=True)
class GetClusterFirewallGroupsOperation:
    """``GET /cluster/firewall/groups`` — existing security groups, for ownership and collision."""

    operation_code: ClassVar[str] = "cluster_firewall_groups"
    path_template: ClassVar[str] = "/cluster/firewall/groups"
    observation_field_codes: ClassVar[tuple[str, ...]] = ("firewall_capability",)

    def rendered_path(self) -> str:
        return self.path_template

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


#: Every operation the first-MVP production composition may execute. Orchestration picks from this
#: set; it cannot construct a request outside it.
FIRST_MVP_OPERATIONS: tuple[type, ...] = (
    GetVersionOperation,
    GetClusterStatusOperation,
    GetNodesOperation,
    GetNodeStatusOperation,
    GetNodeVersionOperation,
    GetNodeAptVersionsOperation,
    GetNodeNetworkOperation,
    GetNodeStorageOperation,
    GetStorageContentOperation,
    GetClusterResourcesOperation,
    GetClusterFirewallOptionsOperation,
    GetClusterFirewallGroupsOperation,
)
