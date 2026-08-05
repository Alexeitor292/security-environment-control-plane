"""Enumerations for the range lifecycle, provider resources, and the competition core.

Kept in their own module rather than appended to :mod:`secp_api.enums` because the range slice is a
self-contained product surface with its own vocabulary, and ``enums.py`` is already the shared
vocabulary of the provisioning/discovery planes.

The one term that carries real weight here is :class:`ResidueVerdict.unproven` and its siblings on
:class:`RangeOperationStatus` and :class:`RangeResourceState`. ``unproven`` is a THIRD outcome, not
a shade of failure and never a shade of success: it is what an observation reports when it could
not be made at all. The distinction exists because a teardown probe whose removal step and whose
"is it actually gone?" step share a failure mode (the Docker daemon being unreachable) will report
"nothing found" for the same reason it failed to remove anything. That negative is not evidence of
absence. Anywhere this codebase would be tempted to write ``clean`` from a probe that could not
run, it writes ``unproven`` instead and the range lands in
:class:`RangeState.recovery_required`.
"""

from __future__ import annotations

from enum import Enum


class RangeState(str, Enum):
    """The authoritative range-instance lifecycle.

    ``recovery_required`` is NOT ``failed``. ``failed`` means an operation was observed to go
    wrong; ``recovery_required`` means resources may or may not still exist and only a human
    looking at the provider can settle it.
    """

    draft = "draft"
    deploying = "deploying"
    ready = "ready"
    active = "active"
    resetting = "resetting"
    recovery_required = "recovery_required"
    failed = "failed"
    destroying = "destroying"
    destroyed = "destroyed"


#: States from which a range still owns (or may still own) provider resources.
RANGE_STATES_WITH_RESOURCES: frozenset[RangeState] = frozenset(
    {
        RangeState.deploying,
        RangeState.ready,
        RangeState.active,
        RangeState.resetting,
        RangeState.recovery_required,
        RangeState.failed,
        RangeState.destroying,
    }
)

#: Terminal states: no operation may start from these.
RANGE_TERMINAL_STATES: frozenset[RangeState] = frozenset({RangeState.destroyed})


class RangeOperationKind(str, Enum):
    deploy = "deploy"
    reset = "reset"
    destroy = "destroy"


class RangeOperationStatus(str, Enum):
    pending = "pending"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    #: The operation ran but its outcome could not be observed. Never rendered as either
    #: success or failure.
    unproven = "unproven"


class RangeStepStatus(str, Enum):
    pending = "pending"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    unproven = "unproven"


class RangeResourceKind(str, Enum):
    network = "network"
    container = "container"
    # SECP-PROXMOX — the object kinds a Proxmox range owns. Stored via the VARCHAR-backed
    # EnumType, so these values are additive (no migration). They are listed here rather than in a
    # provider-local enum because the resource table is provider-neutral: the lifecycle, the
    # residue verdict and the teardown proof all key on this one vocabulary, and a provider that
    # invented its own would fall outside the ``unproven`` accounting that makes teardown honest.
    virtual_machine = "virtual_machine"
    lxc_container = "lxc_container"
    sdn_zone = "sdn_zone"
    vnet = "vnet"
    subnet = "subnet"
    firewall_group = "firewall_group"
    ip_set = "ip_set"
    egress_gateway = "egress_gateway"


class RangeResourceState(str, Enum):
    pending = "pending"
    creating = "creating"
    created = "created"
    #: Observed to be doing its job — for a container, an actual response was received from it.
    #: Never set from "the create call returned 0".
    verified = "verified"
    removing = "removing"
    #: Observed to be absent by a probe that was itself demonstrably working.
    removed = "removed"
    #: Could not be observed. May or may not exist.
    unproven = "unproven"
    failed = "failed"


class ResidueVerdict(str, Enum):
    """The answer to "did we leave anything behind?"."""

    #: Every owned resource was confirmed absent by a working probe.
    clean = "clean"
    #: At least one owned resource was confirmed still present.
    residue = "residue"
    #: The probe could not run, so absence was not proved. NOT a success.
    unproven = "unproven"


class RangeEventLevel(str, Enum):
    info = "info"
    warning = "warning"
    error = "error"


class CompetitionState(str, Enum):
    draft = "draft"
    running = "running"
    stopped = "stopped"


class SubmissionVerdict(str, Enum):
    #: First correct solve for this team on this challenge — the only verdict that awards points.
    accepted = "accepted"
    incorrect = "incorrect"
    #: This team already submitted this exact value before.
    duplicate = "duplicate"
    #: Correct, but this team already holds the solve. Awards zero — no duplicate credit.
    already_solved = "already_solved"
    not_open = "not_open"
    attempts_exhausted = "attempts_exhausted"


class ComponentRole(str, Enum):
    target = "target"
    scoring = "scoring"
    support = "support"
