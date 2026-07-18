"""The three SECP planes + the closed management-plane role model (SECP-PR5E).

SECP is organized into three strict planes:

* **management** — controller hosts, site-worker hosts, management databases/API/UI/Temporal/MinIO/
  Keycloak, the ordinary worker, and the sealed controlled-live operator. SECP operates FROM here.
* **infrastructure** — Proxmox, vCenter, Kubernetes, cloud accounts, future managed targets.
* **scenario** — lab VMs/LXCs, scenario networks, vulnerable workloads, offensive tools, scoring.

The load-bearing invariant: a LOWER plane may never create, mutate, reset, adopt, or destroy an
object in a HIGHER plane (management > infrastructure > scenario). SECP's management plane
orchestrates
the lower planes (it provisions scenario labs on the infrastructure plane); the reverse is
forbidden.
The controller and workers are MANAGEMENT-plane objects even when physically hosted on the same
Proxmox cluster a customer uses for scenarios — they are never scenario resources or deployment
targets.
"""

from __future__ import annotations

from enum import Enum

from secp_management import ManagementError


class Plane(str, Enum):
    """The closed set of SECP planes, ranked so a lower plane can never mutate a higher one."""

    MANAGEMENT = "management"
    INFRASTRUCTURE = "infrastructure"
    SCENARIO = "scenario"


class Role(str, Enum):
    """The closed set of management-plane installation roles. No other role is valid."""

    CONTROLLER = "controller"
    WORKER = "worker"


# management (2) > infrastructure (1) > scenario (0). Higher rank = higher plane.
_PLANE_RANK: dict[Plane, int] = {
    Plane.MANAGEMENT: 2,
    Plane.INFRASTRUCTURE: 1,
    Plane.SCENARIO: 0,
}

# Reason codes are closed; a caller-supplied string is never echoed.
_VALID_ROLES = frozenset(r.value for r in Role)


def parse_role(value: object) -> Role:
    """Parse a role string into the closed :class:`Role`, or fail closed with a bounded reason."""
    if not isinstance(value, str) or value not in _VALID_ROLES:
        raise ManagementError("role_invalid")
    return Role(value)


def other_role(role: Role) -> Role:
    return Role.WORKER if role is Role.CONTROLLER else Role.CONTROLLER


def may_mutate(actor: Plane, target: Plane) -> bool:
    """True iff an actor in ``actor`` plane may create/mutate/reset/adopt/destroy an object in
    ``target`` plane. A lower plane may NEVER mutate a higher one; equal or higher may."""
    return _PLANE_RANK[actor] >= _PLANE_RANK[target]


def assert_may_mutate(actor: Plane, target: Plane) -> None:
    """Fail closed (``plane_violation``) if ``actor`` may not mutate ``target``."""
    if not may_mutate(actor, target):
        raise ManagementError("plane_violation")


def assert_not_scenario_target(plane: object) -> None:
    """Refuse to treat a MANAGEMENT-plane object as a scenario deployment target. A scenario target
    must be strictly below the management plane; a management-plane installation can never be
    one."""
    if plane == Plane.MANAGEMENT or plane == Plane.MANAGEMENT.value:
        raise ManagementError("management_plane_not_a_scenario_target")
