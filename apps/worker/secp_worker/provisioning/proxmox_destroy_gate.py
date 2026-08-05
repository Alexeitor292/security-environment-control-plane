"""The Proxmox destroy gate — a separate operation with a separate authorization. Worker-only.

:mod:`secp_worker.provisioning.proxmox_apply_gate` decides whether an approved plan may be
*applied*. This module decides whether an approved plan may be *destroyed*, and the two are
deliberately not the same decision made twice.

**AN APPLY APPROVAL MUST NEVER AUTHORIZE A DESTROY.** That is the whole reason this file exists,
and it is enforced twice, independently:

1. :class:`DestroyApproval` refuses at construction to hold anything whose ``operation_kind`` is
   not ``destroy``. An apply approval cannot be turned into a destroy approval by passing it to a
   different function — there is no constructor that accepts it.
2. :func:`evaluate_destroy_gate` separately checks that the regenerated change set's own ``kind``
   field says ``destroy``. A plan that creates resources cannot be authorised by a destroy
   approval either, so the mistake is refused from both directions.

The second check is not redundant with the first. The first binds the APPROVAL to a destroy; the
second binds the PLAN to a destroy. An operator approving "destroy this range" against a change set
that in fact creates twelve VMs is the failure the pair prevents, and neither check alone catches
it.

WHY DESTROY DEMANDS FRESHNESS THAT APPLY DOES NOT
--------------------------------------------------
An apply against stale discovery creates resources in the wrong place. A destroy against stale
discovery *deletes the wrong thing*. So this gate additionally requires:

``ownership_verified``  a fresh ownership pass ran against live observation, tags read back off
                        every object. Not "we checked at deploy time" — ownership is re-established
                        immediately before deletion, because an object can change hands between
                        deploy and destroy and a name has never been proof of anything.
``deletion_set_hash``   the exact set of resources approved for deletion. The change-set hash binds
                        the ACTIONS; this binds WHAT they act on. A regenerated destroy plan that
                        would delete one resource more than the operator reviewed produces a
                        different deletion-set hash and is refused, even where the canonical change
                        set happens to match.

WHY A DESTROY APPROVAL IS ONE-SHOT
-----------------------------------
A destroy approval that can be replayed is a standing authorization to delete a range. It is
consumed by the operation it authorises, and a second presentation is refused with
:attr:`DestroyRefusalCode.approval_already_consumed` rather than quietly succeeding as a no-op —
because "it was already destroyed" and "someone is replaying an approval" look identical from the
outside, and only one of them is fine.

This module performs NO privileged execution: no subprocess, no socket, no provider client, no
database session. Every refusal is a pure decision over already-loaded records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from secp_worker.provisioning.proxmox_apply_gate import INFRASTRUCTURE_OPERATOR_ROLE, WorkerIdentity

#: The one operation kind this gate authorises. Compared as a literal against both the approval and
#: the regenerated change set, which is why it lives here rather than being spelled twice.
DESTROY_OPERATION_KIND = "destroy"


class DestroyRefusalCode(str, Enum):
    """Every way this gate can refuse. Closed set — there is no generic "other"."""

    #: An approval was presented whose operation kind is not ``destroy``.
    approval_is_not_for_destroy = "proxmox.destroy.approval_is_not_for_destroy"
    #: No destroy approval was presented at all.
    no_destroy_approval = "proxmox.destroy.no_destroy_approval"
    #: This destroy approval was already consumed by an earlier operation.
    approval_already_consumed = "proxmox.destroy.approval_already_consumed"
    #: The regenerated plan's canonical change set is not the approved one.
    destroy_change_set_hash_mismatch = "proxmox.destroy.change_set_hash_mismatch"
    #: The regenerated plan's own ``kind`` says it is not a destroy plan.
    prepared_plan_is_not_a_destroy_plan = "proxmox.destroy.prepared_plan_is_not_a_destroy_plan"
    #: The binary destroy plan on disk is gone, or is not the one whose hash was approved.
    stale_binary_destroy_plan = "proxmox.destroy.stale_binary_destroy_plan"
    #: The set of resources that would be deleted differs from the reviewed set.
    deletion_set_mismatch = "proxmox.destroy.deletion_set_mismatch"
    #: Ownership was never re-verified against live observation immediately before deletion.
    ownership_not_verified = "proxmox.destroy.ownership_not_verified"
    #: Discovery is older than the freshness window a destroy requires.
    discovery_stale = "proxmox.destroy.discovery_stale"
    #: The ownership scope of what would be deleted differs from the approved scope.
    ownership_scope_mismatch = "proxmox.destroy.ownership_scope_mismatch"
    #: This worker is not the enrolled worker the operation is bound to.
    worker_identity_mismatch = "proxmox.destroy.worker_identity_mismatch"
    #: This worker's release differs from the one the destroy was approved against.
    worker_release_mismatch = "proxmox.destroy.worker_release_mismatch"
    #: The target this worker would act on is not the approved target.
    target_mismatch = "proxmox.destroy.target_mismatch"
    #: The remote-state lock could not be acquired.
    remote_state_lock_unavailable = "proxmox.destroy.remote_state_lock_unavailable"
    #: The operation-specific credential could not be resolved.
    credential_unresolvable = "proxmox.destroy.credential_unresolvable"
    #: An ordinary worker reached the controlled-live path at all.
    ordinary_worker_on_controlled_live_path = (
        "proxmox.destroy.ordinary_worker_on_controlled_live_path"
    )


class DestroyRefused(Exception):
    """A coded refusal. Carries the code separately from the human-readable detail."""

    def __init__(self, code: DestroyRefusalCode, detail: str) -> None:
        super().__init__(f"[{code.value}] {detail}")
        self.code = code
        self.detail = detail


class DestroyApprovalError(ValueError):
    """A destroy approval was constructed from something that is not a destroy approval."""


@dataclass(frozen=True)
class DestroyApproval:
    """What a human approved, specifically and only for a destroy.

    ``operation_kind`` is validated at construction rather than checked by the gate alone. The
    difference matters: a value checked only inside the gate can be bypassed by any other caller
    that reads the same record, while a value validated here means an apply approval never becomes
    a ``DestroyApproval`` object anywhere in the process.
    """

    operation_kind: str
    #: Canonical hash of the DESTROY change set the operator reviewed.
    change_set_hash: str
    #: Hash of the exact set of resource addresses approved for deletion. Binds WHAT, not just
    #: which actions — see the module docstring.
    deletion_set_hash: str
    plan_document_hash: str
    ownership_scope: tuple[str, str, str, int]
    target_id: str
    cluster_fingerprint: str
    worker_id: str
    worker_release: str
    #: Opaque id of this approval, so its consumption can be recorded and replay refused.
    approval_id: str

    def __post_init__(self) -> None:
        if self.operation_kind != DESTROY_OPERATION_KIND:
            raise DestroyApprovalError(
                f"operation kind {self.operation_kind!r} is not {DESTROY_OPERATION_KIND!r}; an "
                "approval for another operation can never authorize a destroy, and this type "
                "cannot be constructed to hold one"
            )
        if not self.approval_id:
            raise DestroyApprovalError(
                "a destroy approval needs an id; without one its consumption cannot be recorded "
                "and it could be replayed indefinitely"
            )


@dataclass(frozen=True)
class RegeneratedDestroyPlan:
    """What regenerating the destroy plan from authoritative state right now produced."""

    #: The change set's own ``kind`` field, straight off the canonical change set.
    kind: str
    change_set_hash: str
    deletion_set_hash: str
    #: The resource addresses this plan would delete, for the refusal message only.
    deletion_addresses: tuple[str, ...]
    ownership_scope: tuple[str, str, str, int]
    target_id: str
    cluster_fingerprint: str
    #: True only when the binary destroy plan the hash refers to is still the prepared one.
    binary_plan_present: bool = True


@dataclass(frozen=True)
class DestroyPreconditions:
    """Facts reloaded immediately before the destroy.

    Every field is ``| None`` where "not checked" is distinguishable from "checked and false".
    ``None`` refuses — this gate never reads an unmade check as a passed one.
    """

    #: A fresh ownership pass ran against live observation, tags read back off every object.
    ownership_verified: bool | None = None
    discovery_fresh: bool | None = None
    remote_state_lock_held: bool | None = None
    credential_resolved: bool | None = None
    #: True when this approval id has already been consumed by an earlier operation.
    approval_already_consumed: bool = False


@dataclass(frozen=True)
class DestroyAuthorization:
    """The gate's positive result. Holds no handle to anything executable."""

    change_set_hash: str
    deletion_set_hash: str
    ownership_scope: tuple[str, str, str, int]
    approval_id: str
    checks_passed: tuple[str, ...] = field(default_factory=tuple)


def _refuse(code: DestroyRefusalCode, detail: str) -> None:
    raise DestroyRefused(code, detail)


def deletion_set_hash(addresses: tuple[str, ...]) -> str:
    """Hash the exact set of resource addresses a destroy would delete.

    Sorted and de-duplicated first, so the hash describes the SET rather than the order a
    particular run happened to enumerate it in. Two plans that would delete the same resources hash
    the same; a plan that would delete one more does not, which is the entire point.
    """
    from secp_scenario_schema import content_hash

    return content_hash({"deletion_set": sorted(set(addresses))})


def evaluate_destroy_gate(
    *,
    worker: WorkerIdentity,
    approval: DestroyApproval | None,
    regenerated: RegeneratedDestroyPlan | None,
    preconditions: DestroyPreconditions,
    controlled_live_queue: str,
) -> DestroyAuthorization:
    """Decide whether this destroy may proceed. Returns an authorization or raises.

    The order is deliberate. Authority first, so an unauthorized caller learns nothing about what
    would be deleted from the refusal it receives. Then the approval's own identity and freshness.
    Then the plan-to-approval bindings, of which the deletion-set binding is the one that makes
    "approve this destroy" mean "delete exactly these resources".
    """
    passed: list[str] = []

    # -- 1. authority ------------------------------------------------------------------
    if worker.queue == controlled_live_queue and worker.role != INFRASTRUCTURE_OPERATOR_ROLE:
        _refuse(
            DestroyRefusalCode.ordinary_worker_on_controlled_live_path,
            f"worker role {worker.role!r} consumed the controlled-live queue; only "
            f"{INFRASTRUCTURE_OPERATOR_ROLE!r} may",
        )
    passed.append("authority")

    # -- 2. the approval exists, is FOR a destroy, and has not been used ----------------
    if approval is None:
        _refuse(
            DestroyRefusalCode.no_destroy_approval,
            "no destroy approval was presented; an apply approval does not authorize a destroy, "
            "and a destroy with no approval of its own is not authorized at all",
        )
    assert approval is not None  # narrowed for type checkers; _refuse never returns

    # Belt to the constructor's braces. The constructor makes an apply approval unconstructable as
    # a DestroyApproval; this catches a record mutated or deserialized around it.
    if approval.operation_kind != DESTROY_OPERATION_KIND:
        _refuse(
            DestroyRefusalCode.approval_is_not_for_destroy,
            f"the presented approval is for {approval.operation_kind!r}, not "
            f"{DESTROY_OPERATION_KIND!r}",
        )
    if preconditions.approval_already_consumed:
        _refuse(
            DestroyRefusalCode.approval_already_consumed,
            f"destroy approval {approval.approval_id!r} was already consumed; a replayable "
            "approval is a standing authorization to delete this range",
        )
    passed.append("destroy_approval")

    if worker.worker_id != approval.worker_id:
        _refuse(
            DestroyRefusalCode.worker_identity_mismatch,
            "this worker is not the worker the destroy approval is bound to",
        )
    if worker.release != approval.worker_release:
        _refuse(
            DestroyRefusalCode.worker_release_mismatch,
            f"worker release {worker.release!r} differs from the approved "
            f"{approval.worker_release!r}",
        )
    passed.append("worker_identity")

    # -- 3. freshness. A destroy against stale facts deletes the wrong thing. -----------
    if preconditions.ownership_verified is not True:
        _refuse(
            DestroyRefusalCode.ownership_not_verified,
            "ownership was "
            + (
                "not re-verified against live observation"
                if preconditions.ownership_verified is False
                else "never checked (unknown)"
            )
            + " immediately before this destroy; an object can change hands between deploy and "
            "destroy, and a matching name has never been proof of ownership",
        )
    if preconditions.discovery_fresh is not True:
        _refuse(
            DestroyRefusalCode.discovery_stale,
            "discovery is "
            + ("stale" if preconditions.discovery_fresh is False else "of unknown age")
            + "; a destroy planned against stale discovery deletes what used to be there",
        )
    passed.append("freshness")

    # -- 4. exclusive access and credentials -------------------------------------------
    if preconditions.remote_state_lock_held is not True:
        _refuse(
            DestroyRefusalCode.remote_state_lock_unavailable,
            "the remote-state lock is not held; a concurrent operation could corrupt state",
        )
    if preconditions.credential_resolved is not True:
        _refuse(
            DestroyRefusalCode.credential_unresolvable,
            "the operation-specific provider credential could not be resolved",
        )
    passed.append("exclusive_access")

    # -- 5. the plan itself ------------------------------------------------------------
    if regenerated is None:
        _refuse(
            DestroyRefusalCode.prepared_plan_is_not_a_destroy_plan,
            "no prepared destroy plan was produced; there is nothing whose hash could be approved",
        )
    assert regenerated is not None

    # The PLAN must itself be a destroy. The approval being one is checked above and is a different
    # claim: this catches an operator approving "destroy this range" against a plan that creates.
    if regenerated.kind != DESTROY_OPERATION_KIND:
        _refuse(
            DestroyRefusalCode.prepared_plan_is_not_a_destroy_plan,
            f"the regenerated change set's kind is {regenerated.kind!r}, not "
            f"{DESTROY_OPERATION_KIND!r}; a destroy approval does not authorize a plan that "
            "creates resources",
        )
    if not regenerated.binary_plan_present:
        _refuse(
            DestroyRefusalCode.stale_binary_destroy_plan,
            "the prepared binary destroy plan is no longer present; re-plan and re-approve rather "
            "than destroying from a plan that cannot be shown to be the approved one",
        )
    if regenerated.change_set_hash != approval.change_set_hash:
        _refuse(
            DestroyRefusalCode.destroy_change_set_hash_mismatch,
            "the regenerated destroy plan's canonical change set differs from the approved one",
        )
    passed.append("change_set_binding")

    # The deletion-set binding. Checked SEPARATELY from the change-set hash because the two can
    # disagree: canonicalization keeps addresses and actions, so a plan deleting a different number
    # of resources changes this hash — but a plan whose change set matches can still be pointed at
    # a set the operator never saw enumerated.
    if regenerated.deletion_set_hash != approval.deletion_set_hash:
        _refuse(
            DestroyRefusalCode.deletion_set_mismatch,
            f"the plan would delete {len(regenerated.deletion_addresses)} resource(s) whose set "
            "does not match the reviewed one; approving a destroy approves an exact list of "
            "resources, not a count",
        )
    passed.append("deletion_set_binding")

    if regenerated.ownership_scope != approval.ownership_scope:
        _refuse(
            DestroyRefusalCode.ownership_scope_mismatch,
            "the ownership scope of what would be deleted differs from the approved scope; "
            "deleting under a different scope means deleting objects this approval never covered",
        )
    if regenerated.target_id != approval.target_id:
        _refuse(
            DestroyRefusalCode.target_mismatch,
            "the resolved target is not the approved target",
        )
    if regenerated.cluster_fingerprint != approval.cluster_fingerprint:
        _refuse(
            DestroyRefusalCode.target_mismatch,
            "the target's cluster fingerprint differs from the approved destroy; this is a "
            "different cluster",
        )
    passed.append("ownership_and_target")

    return DestroyAuthorization(
        change_set_hash=regenerated.change_set_hash,
        deletion_set_hash=regenerated.deletion_set_hash,
        ownership_scope=regenerated.ownership_scope,
        approval_id=approval.approval_id,
        checks_passed=tuple(passed),
    )
