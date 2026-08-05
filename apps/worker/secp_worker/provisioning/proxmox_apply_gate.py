"""The Proxmox apply gate — closed, coded refusals evaluated before anything is applied.

The generic provisioning chain in :mod:`secp_worker.provisioning.execution` already enforces the
structural safety properties: exactly one plan is prepared, its canonical hash must match a
human-approved change set, and THAT prepared plan file is applied without a re-plan. This module
does not replace any of that and does not apply anything itself.

It adds the two things that chain cannot express, both specific to a Proxmox range:

**Allocation identity.** A second plan that renders the same resources with different VM ids, MACs,
subnets or VLAN tags produces a DIFFERENT desired state but can produce an identical canonical
change set — canonicalization keeps addresses and actions, not attributes (proved by
``test_the_change_set_hash_alone_does_not_bind_resource_attributes``). Approving a change-set hash
therefore does not bind the allocations. This gate compares the allocation ledger the operator
approved against the one about to be applied, entry by entry.

**Ownership scope.** Every generated object carries an immutable ownership stamp. An apply whose
ownership scope differs from the approved plan's would create objects a later destroy would not
recognise as its own — and, because a matching name is never proof of ownership, would strand them
permanently.

WHY EVERY REFUSAL HAS A CODE
-----------------------------
The existing chain refuses with prose. Prose is fine for a human reading one failure and useless
for the recovery guidance, metrics and tests that need to distinguish "nobody approved this" from
"the approval no longer matches". Every refusal here carries a stable :class:`ApplyRefusalCode`,
and the detail string is additional context rather than the identity of the failure.

This module performs NO privileged execution: no subprocess, no socket, no provider client, no
database session. It is a pure decision function over already-loaded authoritative records, which
is what makes every refusal below directly testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ApplyRefusalCode(str, Enum):
    """Every way this gate can refuse. Closed set — there is no generic "other"."""

    #: No prepared plan was handed to the gate at all.
    no_prepared_plan = "proxmox.apply.no_prepared_plan"
    #: The prepared plan's canonical hash is not the approved one.
    change_set_hash_mismatch = "proxmox.apply.change_set_hash_mismatch"
    #: The binary plan on disk is not the one whose hash was approved, or is gone.
    stale_binary_plan = "proxmox.apply.stale_binary_plan"
    #: Regeneration produced the same change set but DIFFERENT allocations.
    allocation_drift = "proxmox.apply.allocation_drift"
    #: The authoritative desired state differs from the reviewed one.
    desired_state_drift = "proxmox.apply.desired_state_drift"
    #: The ownership scope of what would be created differs from the approved scope.
    ownership_scope_mismatch = "proxmox.apply.ownership_scope_mismatch"
    #: This worker is not the enrolled worker the operation is bound to.
    worker_identity_mismatch = "proxmox.apply.worker_identity_mismatch"
    #: This worker's release differs from the one the plan was approved against.
    worker_release_mismatch = "proxmox.apply.worker_release_mismatch"
    #: The target this worker would act on is not the approved target.
    target_mismatch = "proxmox.apply.target_mismatch"
    #: The remote-state lock could not be acquired.
    remote_state_lock_unavailable = "proxmox.apply.remote_state_lock_unavailable"
    #: The operation-specific credential could not be resolved.
    credential_unresolvable = "proxmox.apply.credential_unresolvable"
    #: An ordinary worker reached the controlled-live path at all.
    ordinary_worker_on_controlled_live_path = (
        "proxmox.apply.ordinary_worker_on_controlled_live_path"
    )
    #: Discovery is older than the freshness window the plan requires.
    discovery_stale = "proxmox.apply.discovery_stale"
    #: Target onboarding is not currently valid.
    onboarding_not_current = "proxmox.apply.onboarding_not_current"
    #: Eligibility preflight is missing or no longer passing.
    eligibility_not_current = "proxmox.apply.eligibility_not_current"
    #: The persisted reservations are absent or do not match the plan.
    reservations_not_persisted = "proxmox.apply.reservations_not_persisted"


#: The role permitted on the controlled-live queue. There is exactly one.
INFRASTRUCTURE_OPERATOR_ROLE = "infrastructure_operator"


class ApplyRefused(Exception):
    """A coded refusal. Carries the code separately from the human-readable detail."""

    def __init__(self, code: ApplyRefusalCode, detail: str) -> None:
        super().__init__(f"[{code.value}] {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class WorkerIdentity:
    """Who is asking to apply."""

    worker_id: str
    role: str
    release: str
    #: The queue this worker consumed the task from.
    queue: str


@dataclass(frozen=True)
class ApprovedPlanBinding:
    """What a human actually approved, reduced to the values that must still hold."""

    change_set_hash: str
    desired_state_hash: str
    plan_document_hash: str
    #: ``(kind, scope, purpose) -> value`` for every allocation in the approved ledger.
    allocations: dict[str, str]
    ownership_scope: tuple[str, str, str, int]
    target_id: str
    cluster_fingerprint: str
    worker_id: str
    worker_release: str


@dataclass(frozen=True)
class RegeneratedPlan:
    """What regenerating from authoritative state right now produced."""

    change_set_hash: str
    desired_state_hash: str
    allocations: dict[str, str]
    ownership_scope: tuple[str, str, str, int]
    target_id: str
    cluster_fingerprint: str
    #: True only when the binary plan file the hash refers to is still the prepared one.
    binary_plan_present: bool = True
    binary_plan_fingerprint: str = ""


@dataclass(frozen=True)
class AuthoritativeState:
    """Freshness and prerequisite facts reloaded immediately before apply.

    Every field is ``| None`` where "not checked" is distinguishable from "checked and false".
    ``None`` refuses — this gate never treats an unmade check as a passed one.
    """

    onboarding_current: bool | None = None
    eligibility_passing: bool | None = None
    discovery_fresh: bool | None = None
    reservations_persisted: bool | None = None
    remote_state_lock_held: bool | None = None
    credential_resolved: bool | None = None


@dataclass(frozen=True)
class ApplyAuthorization:
    """The gate's positive result. Holds no handle to anything executable."""

    change_set_hash: str
    desired_state_hash: str
    ownership_scope: tuple[str, str, str, int]
    checks_passed: tuple[str, ...] = field(default_factory=tuple)


def _refuse(code: ApplyRefusalCode, detail: str) -> None:
    raise ApplyRefused(code, detail)


def evaluate_apply_gate(
    *,
    worker: WorkerIdentity,
    approved: ApprovedPlanBinding,
    regenerated: RegeneratedPlan | None,
    state: AuthoritativeState,
    controlled_live_queue: str,
) -> ApplyAuthorization:
    """Decide whether this apply may proceed. Returns an authorization or raises.

    Checks run in a deliberate order: identity and authority first, then the prerequisites that
    make the plan meaningful, then the plan-to-approval bindings. An ordinary worker is rejected
    before anything else is even looked at, so an unauthorized caller learns nothing about the
    plan's contents from the refusal it receives.
    """
    passed: list[str] = []

    # -- 1. authority ------------------------------------------------------------------
    # An ordinary worker must never reach this path. The installer already refuses to place a
    # second worker on the controlled-live queue; this is the in-process restatement of that, not
    # an alternative route around it.
    if worker.queue == controlled_live_queue and worker.role != INFRASTRUCTURE_OPERATOR_ROLE:
        _refuse(
            ApplyRefusalCode.ordinary_worker_on_controlled_live_path,
            f"worker role {worker.role!r} consumed the controlled-live queue; only "
            f"{INFRASTRUCTURE_OPERATOR_ROLE!r} may",
        )
    passed.append("authority")

    if worker.worker_id != approved.worker_id:
        _refuse(
            ApplyRefusalCode.worker_identity_mismatch,
            "this worker is not the worker the approved plan is bound to",
        )
    if worker.release != approved.worker_release:
        _refuse(
            ApplyRefusalCode.worker_release_mismatch,
            f"worker release {worker.release!r} differs from the approved "
            f"{approved.worker_release!r}",
        )
    passed.append("worker_identity")

    # -- 2. prerequisites --------------------------------------------------------------
    # Each is tri-state: None means the check never ran, which refuses exactly as False does.
    for value, code, label in (
        (state.onboarding_current, ApplyRefusalCode.onboarding_not_current, "onboarding"),
        (state.eligibility_passing, ApplyRefusalCode.eligibility_not_current, "eligibility"),
        (state.discovery_fresh, ApplyRefusalCode.discovery_stale, "discovery freshness"),
        (
            state.reservations_persisted,
            ApplyRefusalCode.reservations_not_persisted,
            "persisted reservations",
        ),
    ):
        if value is not True:
            _refuse(
                code,
                f"{label} is {'not satisfied' if value is False else 'unknown (never checked)'}",
            )
    passed.append("prerequisites")

    # -- 3. exclusive access and credentials -------------------------------------------
    if state.remote_state_lock_held is not True:
        _refuse(
            ApplyRefusalCode.remote_state_lock_unavailable,
            "the remote-state lock is not held; a concurrent apply could corrupt state",
        )
    if state.credential_resolved is not True:
        _refuse(
            ApplyRefusalCode.credential_unresolvable,
            "the operation-specific provider credential could not be resolved",
        )
    passed.append("exclusive_access")

    # -- 4. the plan itself ------------------------------------------------------------
    if regenerated is None:
        _refuse(
            ApplyRefusalCode.no_prepared_plan,
            "no prepared plan was produced; there is nothing whose hash could be approved",
        )
    assert regenerated is not None  # narrowed for type checkers; _refuse never returns

    if not regenerated.binary_plan_present:
        _refuse(
            ApplyRefusalCode.stale_binary_plan,
            "the prepared binary plan is no longer present; re-plan and re-approve rather than "
            "applying a plan that cannot be shown to be the approved one",
        )
    if regenerated.change_set_hash != approved.change_set_hash:
        _refuse(
            ApplyRefusalCode.change_set_hash_mismatch,
            "the regenerated plan's canonical change set differs from the approved one",
        )
    passed.append("change_set_binding")

    # The desired-state hash is checked SEPARATELY and after the change-set hash, because the two
    # can disagree: identical actions on identical addresses with different attributes. This is the
    # check that makes approval bind the actual machines.
    if regenerated.desired_state_hash != approved.desired_state_hash:
        _refuse(
            ApplyRefusalCode.desired_state_drift,
            "the authoritative desired state differs from the reviewed plan even though the "
            "change set matches; the approved actions would create different resources",
        )

    if regenerated.allocations != approved.allocations:
        differing = sorted(
            key
            for key in set(regenerated.allocations) | set(approved.allocations)
            if regenerated.allocations.get(key) != approved.allocations.get(key)
        )
        _refuse(
            ApplyRefusalCode.allocation_drift,
            f"{len(differing)} allocation(s) differ from the approved ledger "
            f"(first: {differing[0] if differing else 'unknown'}); a changed allocation requires a "
            "new plan and a new approval",
        )
    passed.append("allocation_identity")

    if regenerated.ownership_scope != approved.ownership_scope:
        _refuse(
            ApplyRefusalCode.ownership_scope_mismatch,
            "the ownership scope differs from the approved plan; objects created under a "
            "different scope would not be recognised as ours by a later teardown",
        )
    if regenerated.target_id != approved.target_id:
        _refuse(
            ApplyRefusalCode.target_mismatch,
            "the resolved target is not the approved target",
        )
    if regenerated.cluster_fingerprint != approved.cluster_fingerprint:
        _refuse(
            ApplyRefusalCode.target_mismatch,
            "the target's cluster fingerprint differs from the approved plan; this is a "
            "different cluster",
        )
    passed.append("ownership_and_target")

    return ApplyAuthorization(
        change_set_hash=regenerated.change_set_hash,
        desired_state_hash=regenerated.desired_state_hash,
        ownership_scope=regenerated.ownership_scope,
        checks_passed=tuple(passed),
    )


def allocations_fingerprint(ledger_payload: dict) -> dict[str, str]:
    """Reduce an allocation-ledger payload to the ``key -> value`` map the gate compares.

    Keyed on ``kind|org|target|range|team|generation|purpose`` so two ledgers are compared by what
    each allocation IS FOR, not by list position. Comparing serialized order would report drift for
    a re-serialized but identical ledger, and would miss a swap of two values between purposes.
    """
    fingerprint: dict[str, str] = {}
    for record in ledger_payload.get("allocations", []):
        key = "|".join(
            str(record.get(part, ""))
            for part in (
                "kind",
                "organization_id",
                "target_id",
                "range_id",
                "team_ref",
                "generation",
                "purpose",
            )
        )
        fingerprint[key] = str(record.get("value", ""))
    return fingerprint
