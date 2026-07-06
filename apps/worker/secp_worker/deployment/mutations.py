"""Closed, typed provider mutation intents (SECP-B4 corrective).

Replaces the previous ``apply_owned(method, path, owner_tag, body)`` surface — which accepted a
hardcoded path + an arbitrary dict body + a caller tag — with a CLOSED set of typed operations. Each
op derives its canonical route and a typed, scalar-only body FROM its locator (an exact discovered
provider object), so there is no hardcoded node/VMID/bridge/endpoint, no arbitrary body key, and no
fallback path anywhere. Every create carries this deployment's ownership marker in a provider field
so a later fresh read can prove ownership; every delete renders from the recorded observed
locator. Unknown operations do not exist in the type — an unmapped kind/inverse raises before any
request is built.

Route templates and the provider-visible marker field are PROVISIONAL and validated only against the
disposable isolated staging target during the controlled integration phase; nothing here contacts a
host (the mutation transport + ownership observer are sealed, fail-closed seams).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from secp_api.enums import DeploymentInverseOp, DeploymentResourceKind

from secp_worker.deployment.locators import (
    BridgeLocator,
    FirewallGroupLocator,
    GuestLocator,
    ResourceLocator,
    ScopedTokenLocator,
    ServiceIdentityLocator,
)


@dataclass(frozen=True)
class MutationRequest:
    """One canonical, closed request derived from a typed op. ``body`` is a flat scalar-only mapping
    (never an arbitrary caller dict). The concrete route is built from validated locator fields."""

    method: str
    path: str
    body: Mapping[str, str | int | bool] | None = None


# --- create operations ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CreateServiceIdentity:
    locator: ServiceIdentityLocator
    owner_marker: str
    resource_kind = DeploymentResourceKind.proxmox_service_identity

    def request(self) -> MutationRequest:
        return MutationRequest(
            "POST",
            "/access/users",
            {"userid": self.locator.userid, "comment": self.owner_marker, "enable": 1},
        )

    def inverse(self) -> RevokeServiceIdentity:
        return RevokeServiceIdentity(self.locator, self.owner_marker)


@dataclass(frozen=True)
class CreateScopedToken:
    locator: ScopedTokenLocator
    owner_marker: str
    resource_kind = DeploymentResourceKind.proxmox_service_identity

    def request(self) -> MutationRequest:
        return MutationRequest(
            "POST",
            f"/access/users/{self.locator.userid}/token/{self.locator.tokenid}",
            {"comment": self.owner_marker, "privsep": 1},
        )

    def inverse(self) -> RevokeScopedToken:
        return RevokeScopedToken(self.locator, self.owner_marker)


@dataclass(frozen=True)
class CreateIsolatedBridge:
    locator: BridgeLocator
    owner_marker: str
    resource_kind = DeploymentResourceKind.isolated_bridge

    def request(self) -> MutationRequest:
        return MutationRequest(
            "POST",
            f"/nodes/{self.locator.node}/network",
            {
                "iface": self.locator.iface,
                "type": "bridge",
                "autostart": 1,
                # Owner marker stamped into a provider-visible field for later fresh-read proof.
                "comments": self.owner_marker,
            },
        )

    def inverse(self) -> RemoveOwnedBridge:
        return RemoveOwnedBridge(self.locator, self.owner_marker)


@dataclass(frozen=True)
class CreateFirewallBoundary:
    """Creates a NEW SECP-owned cluster firewall GROUP object (never edits existing policy)."""

    locator: FirewallGroupLocator
    owner_marker: str
    resource_kind = DeploymentResourceKind.host_firewall_boundary

    def request(self) -> MutationRequest:
        return MutationRequest(
            "POST",
            "/cluster/firewall/groups",
            {"group": self.locator.group, "comment": self.owner_marker},
        )

    def inverse(self) -> RemoveOwnedFirewall:
        return RemoveOwnedFirewall(self.locator, self.owner_marker)


@dataclass(frozen=True)
class CreateControlPlaneVM:
    locator: GuestLocator
    owner_marker: str
    resource_kind = DeploymentResourceKind.control_plane_vm

    def request(self) -> MutationRequest:
        return MutationRequest(
            "POST",
            f"/nodes/{self.locator.node}/qemu",
            {"vmid": self.locator.vmid, "description": self.owner_marker},
        )

    def inverse(self) -> DestroyOwnedVM:
        return DestroyOwnedVM(self.locator, self.owner_marker)


@dataclass(frozen=True)
class CreateNestedTargetVM:
    locator: GuestLocator
    owner_marker: str
    resource_kind = DeploymentResourceKind.nested_target_vm

    def request(self) -> MutationRequest:
        return MutationRequest(
            "POST",
            f"/nodes/{self.locator.node}/qemu",
            {"vmid": self.locator.vmid, "description": self.owner_marker},
        )

    def inverse(self) -> DestroyOwnedVM:
        return DestroyOwnedVM(self.locator, self.owner_marker)


# --- inverse (delete/revoke) operations ----------------------------------------------------------


@dataclass(frozen=True)
class RevokeServiceIdentity:
    locator: ServiceIdentityLocator
    owner_marker: str
    inverse_op = DeploymentInverseOp.revoke_service_identity

    def request(self) -> MutationRequest:
        return MutationRequest("DELETE", f"/access/users/{self.locator.userid}")


@dataclass(frozen=True)
class RevokeScopedToken:
    locator: ScopedTokenLocator
    owner_marker: str
    inverse_op = DeploymentInverseOp.revoke_service_identity

    def request(self) -> MutationRequest:
        return MutationRequest(
            "DELETE", f"/access/users/{self.locator.userid}/token/{self.locator.tokenid}"
        )


@dataclass(frozen=True)
class RemoveOwnedBridge:
    locator: BridgeLocator
    owner_marker: str
    inverse_op = DeploymentInverseOp.remove_owned_bridge

    def request(self) -> MutationRequest:
        return MutationRequest("DELETE", f"/nodes/{self.locator.node}/network/{self.locator.iface}")


@dataclass(frozen=True)
class RemoveOwnedFirewall:
    locator: FirewallGroupLocator
    owner_marker: str
    inverse_op = DeploymentInverseOp.remove_owned_firewall

    def request(self) -> MutationRequest:
        return MutationRequest("DELETE", f"/cluster/firewall/groups/{self.locator.group}")


@dataclass(frozen=True)
class DestroyOwnedVM:
    locator: GuestLocator
    owner_marker: str
    inverse_op = DeploymentInverseOp.destroy_owned_guest

    def request(self) -> MutationRequest:
        return MutationRequest("DELETE", f"/nodes/{self.locator.node}/qemu/{self.locator.vmid}")


TypedCreate = (
    CreateServiceIdentity
    | CreateScopedToken
    | CreateIsolatedBridge
    | CreateFirewallBoundary
    | CreateControlPlaneVM
    | CreateNestedTargetVM
)
TypedInverse = (
    RevokeServiceIdentity
    | RevokeScopedToken
    | RemoveOwnedBridge
    | RemoveOwnedFirewall
    | DestroyOwnedVM
)


def locator_of(op: TypedCreate | TypedInverse) -> ResourceLocator:
    return op.locator
