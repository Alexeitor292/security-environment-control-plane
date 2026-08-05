"""The two logical worker roles, and the capability separation that makes running both safe (P1).

A worker host in the Proxmox management environment runs ONE of two logical roles:

* ``ordinary`` — non-privileged jobs. It holds NO infrastructure mutation credential, NO
  provisioning (OpenTofu) execution authority, NO host-network mutation capability, and NO access
  to the controlled-live queue.
* ``infrastructure_operator`` — the ONLY consumer of the controlled-live queue: credentialed
  discovery, OpenTofu init/plan/apply, post-apply observation, isolation verification, reset and
  destroy.

WHY THE VOCABULARY IS PROVIDER-NEUTRAL WHEN THE DELIVERABLE IS PROXMOX
----------------------------------------------------------------------
The role is named ``infrastructure_operator``, not ``proxmox_operator``, and its capabilities are
``infrastructure_mutation_credentials`` / ``provisioning_execution`` rather than Proxmox- and
OpenTofu-specific names. That is not squeamishness about naming: the management plane is required
to stay provider-neutral so the same identities, release trust, enrollment and evidence work
unchanged against Kubernetes / AWS / VMware later, and
``tests/../test_provider_neutrality.py`` enforces it structurally over every field name and
serialized dict key in this package.

Proxmox is the PROVIDER INSTANCE this role is deployed against, and that binding belongs in the
deployment profile and the worker plane — not in the management plane's typed vocabulary. Prose
like this docstring names Proxmox freely; the serialized surface does not.

WHY QUEUE SEPARATION IS A SAFETY PROPERTY AND NOT PACKAGING
-----------------------------------------------------------
Temporal LOAD-BALANCES across the pollers on a task queue. Two workers polling one queue therefore
split the work between them by chance, so a worker that cannot serve a controlled-live operation
still wins roughly half the polls and takes work it has no credential, no OpenTofu authority, and no
provider reach to complete. The operation is then STRANDED: accepted by a worker that can never
finish it, and never offered to the one that could.

That is not a degraded mode to recover from — it is a defect re-created BY CONSTRUCTION, every
time, the moment the two roles share a queue. No amount of care inside either worker prevents it,
because the mistake is made by the dispatcher before either worker's code runs. So a shared queue is
refused HERE, at plan time, before anything is installed — never diagnosed afterwards from a
stalled operation.

WHY THE CAPABILITY TABLE IS INVERTED
------------------------------------
:data:`ROLE_CAPABILITIES` is checked as *every role in the live enum must carry an approved
capability row*, not as *the approved set contains these roles*. A closed set written the other way
around passes unchanged when a third role is added and silently exempts it — the guard keeps
reporting green while covering less than it claims. Adding a member to :class:`WorkerRole` without a
row here fails :func:`require_role_capability_separation` immediately.

Pure and secret-free: this module holds role/capability metadata and queue NAMES only. It reads no
file, contacts nothing, and never touches credential material.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum

from secp_management import ManagementError


class WorkerRoleError(ManagementError):
    """A role/capability separation invariant was violated (bounded reason code, never a value)."""


class WorkerRole(str, Enum):
    """The two logical worker roles. The value is the stable on-the-wire/CLI token."""

    ordinary = "ordinary"
    infrastructure_operator = "infrastructure_operator"


@dataclass(frozen=True)
class RoleCapabilities:
    """The privileged capabilities a role is authorized to hold.

    Every field is a PRIVILEGED capability and every field defaults to ``False``: a capability a
    role does not explicitly claim is one it does not have. ``queue_kind`` is not a capability — it
    names which of the two task queues the role polls, and is validated separately.
    """

    queue_kind: str
    infrastructure_mutation_credentials: bool = False
    provisioning_execution: bool = False
    host_network_mutation: bool = False
    controlled_live_queue: bool = False


#: The queue kinds, as they appear in the deployment profile's two queue fields.
QUEUE_ORDINARY = "ordinary"
QUEUE_CONTROLLED_LIVE = "controlled_live"


#: The authoritative role -> capability table. The ordinary row is all-``False`` BY CONSTRUCTION
#: (every privileged field defaults to ``False``, so the row cannot acquire one by omission).
ROLE_CAPABILITIES: dict[WorkerRole, RoleCapabilities] = {
    WorkerRole.ordinary: RoleCapabilities(queue_kind=QUEUE_ORDINARY),
    WorkerRole.infrastructure_operator: RoleCapabilities(
        queue_kind=QUEUE_CONTROLLED_LIVE,
        infrastructure_mutation_credentials=True,
        provisioning_execution=True,
        host_network_mutation=True,
        controlled_live_queue=True,
    ),
}


def privileged_capability_names() -> tuple[str, ...]:
    """Every privileged capability field on :class:`RoleCapabilities`, derived from the DATACLASS.

    Derived rather than listed so a capability added to the dataclass is covered by the ordinary
    worker's must-hold-nothing check automatically. A hand-maintained tuple here would go on
    passing while a newly added capability sat outside it — exactly the coverage-vanishing shape
    this codebase has been bitten by before.
    """
    return tuple(f.name for f in fields(RoleCapabilities) if f.name != "queue_kind")


def parse_worker_role(value: object) -> WorkerRole:
    """Parse an operator-supplied role token, refusing anything not in the authorized set."""
    if isinstance(value, WorkerRole):
        return value
    if not isinstance(value, str):
        raise WorkerRoleError("installer_role_not_authorized")
    try:
        return WorkerRole(value)
    except ValueError:
        raise WorkerRoleError("installer_role_not_authorized") from None


def capabilities_for(role: WorkerRole) -> RoleCapabilities:
    """The approved capability row for ``role``; a role with no row is refused, never defaulted."""
    caps = ROLE_CAPABILITIES.get(role)
    if caps is None:
        raise WorkerRoleError("installer_role_not_authorized")
    return caps


def require_role_capability_separation() -> None:
    """Fail closed unless the live capability table still expresses the separation P1 depends on.

    Checked as an invariant over the LIVE enum and the LIVE dataclass, so it cannot be satisfied by
    a stale approved-set literal:

    1. every :class:`WorkerRole` member has a capability row (no role is silently uncovered);
    2. the ordinary role holds NO privileged capability, over every privileged field the dataclass
       currently declares;
    3. exactly one role may consume the controlled-live queue;
    4. the two roles poll DIFFERENT queue kinds.
    """
    if set(ROLE_CAPABILITIES) != set(WorkerRole):
        raise WorkerRoleError("installer_role_table_incomplete")

    ordinary = ROLE_CAPABILITIES[WorkerRole.ordinary]
    for name in privileged_capability_names():
        if getattr(ordinary, name) is not False:
            raise WorkerRoleError("installer_ordinary_role_over_privileged")

    consumers = [r for r, c in ROLE_CAPABILITIES.items() if c.controlled_live_queue]
    if consumers != [WorkerRole.infrastructure_operator]:
        raise WorkerRoleError("installer_controlled_live_consumer_invalid")

    kinds = [c.queue_kind for c in ROLE_CAPABILITIES.values()]
    if len(set(kinds)) != len(kinds):
        raise WorkerRoleError("installer_role_queues_not_separated")


def resolve_role_queue(
    role: WorkerRole, *, ordinary_task_queue: str, operator_task_queue: str
) -> str:
    """The task queue ``role`` polls, refusing a configuration where the two queues coincide.

    Takes the two queue names explicitly rather than reading a deployment profile: this module
    stays pure and free of a cross-package import, and the caller keeps the job of sourcing the
    names from the root-controlled profile that already binds them to independent trusted pins.

    The equality refusal is the load-bearing one — see the module docstring. It is applied for BOTH
    roles, not only the operator: a shared queue strands operations whichever role asked.
    """
    require_role_capability_separation()
    for name in (ordinary_task_queue, operator_task_queue):
        if not isinstance(name, str) or not name.strip():
            raise WorkerRoleError("installer_queue_not_configured")
    if ordinary_task_queue == operator_task_queue:
        raise WorkerRoleError("installer_role_queues_not_separated")
    caps = capabilities_for(role)
    return operator_task_queue if caps.controlled_live_queue else ordinary_task_queue


__all__ = [
    "QUEUE_CONTROLLED_LIVE",
    "QUEUE_ORDINARY",
    "ROLE_CAPABILITIES",
    "RoleCapabilities",
    "WorkerRole",
    "WorkerRoleError",
    "capabilities_for",
    "parse_worker_role",
    "privileged_capability_names",
    "require_role_capability_separation",
    "resolve_role_queue",
]
