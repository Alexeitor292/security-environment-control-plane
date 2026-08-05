"""Range reset — recreate the disposable, preserve everything that gives the range its identity.

A reset is not a redeploy. A redeploy is allowed to produce a different range; a reset must produce
*this* range again. Everything in this module follows from that one sentence:

PRESERVED                                   RECREATED
-------------------------------------------  ------------------------------------------------
range identity (``range_id``, generation)    the guests, from the reviewed base image
the approved topology: zone, VNets, VLANs,   challenge state, replanted over the post-provisioning
subnets, firewall groups and IPSets          channel
the sealed allocation ledger — every vmid,   nothing else. A reset that recreated a VNet would
MAC, subnet and address is re-resolved,      renumber nothing but would still drop every guest's
never reallocated                            layer-2 attachment mid-operation
team membership and the challenge catalog
scores, unless the operator explicitly
asked for them to be cleared

WHY A RESET STILL NEEDS AN APPROVAL
------------------------------------
``Ownership.as_tags()`` includes ``secp.operation_generation``, and a reset advances it — that is
how a reset's objects are distinguishable from the deploy's. Advancing it changes the ownership
stamp on every object, so it changes ``desired_state_hash``, so
:func:`~secp_worker.provisioning.proxmox_apply_gate.evaluate_apply_gate` will refuse the reset apply
until the new plan is approved. That is not friction to be worked around: it is the mechanism that
stops "reset" from becoming an unreviewed apply path. What this module guarantees is narrower and
more useful — that the plan being approved is the SAME TOPOLOGY, differing only in the operation
generation. :func:`topology_fingerprint` is that comparison, and
:func:`plan_reset` refuses when it does not hold.

WHY THE LEDGER MUST BE SEALED
------------------------------
An open ledger will happily allocate. A reset run against an open ledger whose recorded allocations
have been partially lost would allocate NEW vmids and NEW addresses for the missing guests and
report success — a renumbered range wearing the old range's name. So an unsealed ledger is a
refusal here, not a warning.

RE-VERIFICATION IS THE SAME VERIFICATION
-----------------------------------------
After a reset the range must be re-proved, and it is re-proved by the #107 contract rather than by
a reset-specific check: :data:`REQUIRED_RESET_CHECKS` names the checks that must be both OBSERVED
and passing, and :func:`evaluate_reset_verification` reads
:class:`~secp_worker.provisioning.proxmox_verification.VerificationReport` findings directly. A
check that could not be run leaves the reset unproved, exactly as it leaves a deploy unproved.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum

from secp_scenario_schema import content_hash

from secp_worker.provisioning.proxmox_verification import (
    VerificationCheck,
    VerificationOutcome,
    VerificationReport,
)

#: The checks a reset must land before the range is usable again. Every one of them is an
#: OBSERVATION in the #107 contract, and each maps to a promise the product makes about a reset
#: range: the guests came up, teams can score, teams cannot reach each other, and nothing can reach
#: the management plane.
REQUIRED_RESET_CHECKS: frozenset[VerificationCheck] = frozenset(
    {
        VerificationCheck.guest_readiness,
        VerificationCheck.required_reachability,
        VerificationCheck.cross_team_denial,
        VerificationCheck.management_denial,
    }
)


class ResetRefusalCode(str, Enum):
    """Every way a reset can be refused before anything is touched. Closed set."""

    #: There is no approved desired state to reset back to.
    no_approved_desired_state = "proxmox.reset.no_approved_desired_state"
    #: The proposed reset would change the topology, and no new plan was approved.
    topology_change_without_approval = "proxmox.reset.topology_change_without_approval"
    #: The allocation ledger differs from the approved one; identifiers would move.
    allocation_ledger_drift = "proxmox.reset.allocation_ledger_drift"
    #: The ledger is open, so a reset could allocate new identities for lost guests.
    ledger_not_sealed = "proxmox.reset.ledger_not_sealed"
    #: The operation generation did not advance, so reset objects would be indistinguishable.
    operation_generation_not_advanced = "proxmox.reset.operation_generation_not_advanced"


class ResetDisposition(str, Enum):
    """What happens to one class of resource during a reset."""

    #: Left exactly as it is. Not touched, not re-applied.
    preserved = "preserved"
    #: Destroyed and rebuilt from the reviewed base image.
    recreated = "recreated"
    #: Re-planted over the post-provisioning channel after the guest is up.
    restored = "restored"
    #: Deleted, and only because the operator asked for it in this request.
    cleared = "cleared"


class ResetSubject(str, Enum):
    """The things a reset has an opinion about. Anything absent here is a bug, not a default."""

    range_identity = "range_identity"
    sdn_zone = "sdn_zone"
    vnets = "vnets"
    subnets_and_vlans = "subnets_and_vlans"
    firewall_objects = "firewall_objects"
    allocation_ledger = "allocation_ledger"
    guests = "guests"
    challenge_state = "challenge_state"
    team_membership = "team_membership"
    scores = "scores"


class ResetRefused(Exception):
    """A coded reset refusal, with the code kept separate from the human-readable detail."""

    def __init__(self, code: ResetRefusalCode, detail: str) -> None:
        super().__init__(f"[{code.value}] {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ResetRequest:
    """What the operator asked for. Everything destructive beyond recreating guests is opt-in."""

    range_id: str
    #: The operation generation this reset will stamp. Must be greater than the approved one.
    operation_generation: int
    #: Scores survive a reset unless this is explicitly true. A reset returns the ENVIRONMENT to
    #: its initial state; whether the event's history should also be discarded is a separate
    #: decision that only the operator running the event can make, so it is never implied.
    clear_scores: bool = False
    #: Set when a human approved a plan whose topology genuinely differs. Without it, a topology
    #: change is a refusal rather than a silent re-shape of a running range.
    new_topology_approved: bool = False


@dataclass(frozen=True)
class ResetAction:
    """One subject's disposition, with the reason it was chosen."""

    subject: ResetSubject
    disposition: ResetDisposition
    detail: str


@dataclass(frozen=True)
class ResetPlan:
    """A reset that may proceed, and exactly what it will do."""

    range_id: str
    operation_generation: int
    #: The desired state to apply: the approved topology, re-stamped for this operation.
    desired_state: dict
    actions: tuple[ResetAction, ...]
    #: Guest refs that will be destroyed and rebuilt.
    recreated_guest_refs: tuple[str, ...]
    #: Material references replanted after the guests come up. References, never values.
    restored_material_refs: tuple[str, ...]
    #: The topology fingerprint proved identical to the approved plan's.
    topology_fingerprint: str
    required_checks: frozenset[VerificationCheck] = field(default=REQUIRED_RESET_CHECKS)

    def disposition(self, subject: ResetSubject) -> ResetDisposition | None:
        return next((a.disposition for a in self.actions if a.subject is subject), None)


def _strip_operation_generation(node: object) -> object:
    """Deep-copy a payload with every ``operation_generation`` removed.

    Removing it is what makes two desired states comparable ACROSS operations. It is removed
    everywhere it appears rather than only at the top level, because it is stamped into the
    ownership block of every guest, VNet, IPSet and security group — comparing only the root would
    call a plan unchanged while every object's stamp had moved.
    """
    if isinstance(node, dict):
        return {
            key: _strip_operation_generation(value)
            for key, value in node.items()
            if key != "operation_generation"
        }
    if isinstance(node, list):
        return [_strip_operation_generation(item) for item in node]
    return node


def topology_fingerprint(desired_state: dict) -> str:
    """A hash of the desired state that ignores the operation generation and nothing else.

    Two desired states with the same fingerprint describe the same machines, on the same nodes,
    with the same identifiers, on the same segments, behind the same rules — differing only in
    which lifecycle operation stamped them. That is precisely the equivalence "a reset preserves
    the approved topology" needs, and it is deliberately not a subset comparison: a changed disk
    size, a moved guest or an added rule all change the fingerprint.
    """
    stripped = _strip_operation_generation(copy.deepcopy(desired_state))
    assert isinstance(stripped, dict)  # a dict in always yields a dict out
    return content_hash(stripped)


def _restamp(node: object, generation: int) -> object:
    if isinstance(node, dict):
        return {
            key: (generation if key == "operation_generation" else _restamp(value, generation))
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [_restamp(item, generation) for item in node]
    return node


def restamp_operation_generation(desired_state: dict, generation: int) -> dict:
    """The reset's desired state: the approved one, with every ownership stamp advanced.

    The worker-side twin of
    :func:`secp_api.range_providers.proxmox_manifest.with_operation_generation`, operating on the
    serialized payload the worker actually holds. The desired-state ``generation`` is untouched, so
    ``Ownership.scope_key()`` is unchanged and every allocation resolves to the value the deploy
    recorded.
    """
    result = _restamp(copy.deepcopy(desired_state), generation)
    assert isinstance(result, dict)
    return result


def _approved_operation_generation(desired_state: dict) -> int | None:
    ownership = desired_state.get("ownership")
    if not isinstance(ownership, dict):
        return None
    value = ownership.get("operation_generation")
    return int(value) if isinstance(value, int) else None


def plan_reset(
    *,
    approved_desired_state: dict | None,
    approved_ledger: dict | None,
    current_ledger: dict | None,
    proposed_desired_state: dict | None,
    material_refs: tuple[str, ...],
    request: ResetRequest,
) -> ResetPlan:
    """Decide what this reset will do, or refuse with a code. Touches nothing.

    ``proposed_desired_state`` is optional and exists for the case where something upstream
    recompiled: when supplied it is compared against the approved topology and a difference is a
    refusal. When it is ``None`` the approved state is simply re-stamped, which is the ordinary
    path and the one that cannot drift.
    """
    if not approved_desired_state:
        raise ResetRefused(
            ResetRefusalCode.no_approved_desired_state,
            "there is no approved desired state to reset this range back to; a reset that "
            "recompiles from scratch is a redeploy wearing a reset's name",
        )

    approved_generation = _approved_operation_generation(approved_desired_state)
    if approved_generation is not None and request.operation_generation <= approved_generation:
        raise ResetRefused(
            ResetRefusalCode.operation_generation_not_advanced,
            f"operation generation {request.operation_generation} does not advance past the "
            f"approved {approved_generation}; the reset's objects would carry the same stamp as "
            "the deploy's and could not be told apart",
        )

    if not isinstance(approved_ledger, dict) or not approved_ledger.get("allocations"):
        raise ResetRefused(
            ResetRefusalCode.allocation_ledger_drift,
            "the approved allocation ledger is missing or empty; without it a reset cannot prove "
            "it is re-resolving the deploy's identifiers rather than inventing new ones",
        )
    if not approved_ledger.get("sealed"):
        raise ResetRefused(
            ResetRefusalCode.ledger_not_sealed,
            "the approved allocation ledger is not sealed; an open ledger would allocate fresh "
            "vmids and addresses for any guest whose record was lost, producing a renumbered range "
            "under the old range's name",
        )
    if current_ledger is not None and current_ledger.get("ledger_hash") != approved_ledger.get(
        "ledger_hash"
    ):
        raise ResetRefused(
            ResetRefusalCode.allocation_ledger_drift,
            "the current allocation ledger does not hash to the approved one; identifiers would "
            "move and the reset would not restore this range",
        )

    approved_fingerprint = topology_fingerprint(approved_desired_state)
    if proposed_desired_state is not None:
        proposed_fingerprint = topology_fingerprint(proposed_desired_state)
        if proposed_fingerprint != approved_fingerprint and not request.new_topology_approved:
            raise ResetRefused(
                ResetRefusalCode.topology_change_without_approval,
                "the proposed reset would apply a different topology than the approved one; a "
                "reset preserves the approved topology, and changing it requires a new plan and a "
                "new approval rather than a reset",
            )
        source = proposed_desired_state
    else:
        source = approved_desired_state

    desired_state = restamp_operation_generation(source, request.operation_generation)
    guests = desired_state.get("guests") or []
    guest_refs = tuple(sorted(str(guest.get("guest_ref")) for guest in guests))

    actions = (
        ResetAction(
            subject=ResetSubject.range_identity,
            disposition=ResetDisposition.preserved,
            detail=f"range {request.range_id} keeps its id, its generation and its ownership scope",
        ),
        ResetAction(
            subject=ResetSubject.sdn_zone,
            disposition=ResetDisposition.preserved,
            detail="the approved SDN zone is not recreated; recreating it would detach every guest",
        ),
        ResetAction(
            subject=ResetSubject.vnets,
            disposition=ResetDisposition.preserved,
            detail=f"{len(desired_state.get('network', {}).get('vnets', []))} segment(s) preserved",
        ),
        ResetAction(
            subject=ResetSubject.subnets_and_vlans,
            disposition=ResetDisposition.preserved,
            detail="addressing and VLAN tags are re-resolved from the sealed ledger, not reissued",
        ),
        ResetAction(
            subject=ResetSubject.firewall_objects,
            disposition=ResetDisposition.preserved,
            detail="the approved security groups and IPSets stay; isolation is re-PROVED, not "
            "re-authored",
        ),
        ResetAction(
            subject=ResetSubject.allocation_ledger,
            disposition=ResetDisposition.preserved,
            detail=(
                f"{len(approved_ledger.get('allocations', []))} sealed allocation(s) re-resolved"
            ),
        ),
        ResetAction(
            subject=ResetSubject.guests,
            disposition=ResetDisposition.recreated,
            detail=(
                f"{len(guest_refs)} disposable guest(s) rebuilt from the reviewed base image at "
                "their existing vmids, MACs and addresses"
            ),
        ),
        ResetAction(
            subject=ResetSubject.challenge_state,
            disposition=ResetDisposition.restored,
            detail=(
                f"{len(material_refs)} material reference(s) replanted over the post-provisioning "
                "channel once the guests report ready"
            ),
        ),
        ResetAction(
            subject=ResetSubject.team_membership,
            disposition=ResetDisposition.preserved,
            detail=(
                "teams and their members are competition state, not range state; a reset returns "
                "the environment and never the roster"
            ),
        ),
        ResetAction(
            subject=ResetSubject.scores,
            disposition=(
                ResetDisposition.cleared if request.clear_scores else ResetDisposition.preserved
            ),
            detail=(
                "the operator explicitly asked for scores to be cleared"
                if request.clear_scores
                else "scores are kept; clearing them was not requested and is never implied"
            ),
        ),
    )

    return ResetPlan(
        range_id=request.range_id,
        operation_generation=request.operation_generation,
        desired_state=desired_state,
        actions=actions,
        recreated_guest_refs=guest_refs,
        restored_material_refs=tuple(sorted(material_refs)),
        topology_fingerprint=approved_fingerprint,
    )


@dataclass(frozen=True)
class ResetVerdict:
    """Whether a reset actually restored the range, judged against observation only."""

    outcome: VerificationOutcome
    #: Required checks that ran and passed.
    proved: tuple[VerificationCheck, ...]
    #: Required checks that failed or could not be run at all.
    outstanding: tuple[VerificationCheck, ...]
    detail: str

    @property
    def restored(self) -> bool:
        return self.outcome is VerificationOutcome.verified and not self.outstanding


def evaluate_reset_verification(report: VerificationReport) -> ResetVerdict:
    """Judge a completed reset against the #107 verification report.

    Two conditions must hold, and they are checked separately because they fail separately: the
    report's own outcome must be ``verified``, AND every check in :data:`REQUIRED_RESET_CHECKS`
    must be present, observed and passing. The second is not implied by the first — a report is
    only as complete as the findings it was given, and a reset judged against a report that never
    contained ``cross_team_denial`` would be declared restored without anyone having looked at
    whether the teams can still reach each other.
    """
    proved: list[VerificationCheck] = []
    outstanding: list[VerificationCheck] = []
    for check in sorted(REQUIRED_RESET_CHECKS, key=lambda c: c.value):
        finding = report.finding(check)
        if finding is not None and finding.observed and finding.ok:
            proved.append(check)
        else:
            outstanding.append(check)

    if outstanding and report.outcome is VerificationOutcome.verified:
        # The report says verified over a finding set that does not contain everything a reset
        # must prove. Downgrade rather than inherit: "verified" over an incomplete check set is the
        # exact shape of a green gate that covered less than it claimed.
        outcome = VerificationOutcome.verification_failed
        detail = (
            "the verification report reported 'verified' but did not contain every check a reset "
            f"must land; missing or unobserved: {[c.value for c in outstanding]}"
        )
    else:
        outcome = report.outcome
        detail = (
            f"{len(proved)} required check(s) observed and passing"
            if not outstanding
            else f"required checks outstanding: {[c.value for c in outstanding]}"
        )

    return ResetVerdict(
        outcome=outcome,
        proved=tuple(proved),
        outstanding=tuple(outstanding),
        detail=detail,
    )


def reset_evidence(plan: ResetPlan, verdict: ResetVerdict, bootstrap: dict) -> dict:
    """The durable record of one reset. Secret-free by construction — refs only, never values."""
    return {
        "evidence_version": "secp-proxmox/reset-evidence/v1",
        "range_id": plan.range_id,
        "operation_generation": plan.operation_generation,
        "topology_fingerprint": plan.topology_fingerprint,
        "desired_state_hash": content_hash(plan.desired_state),
        "dispositions": {action.subject.value: action.disposition.value for action in plan.actions},
        "recreated_guests": list(plan.recreated_guest_refs),
        "restored_material_refs": list(plan.restored_material_refs),
        "bootstrap": bootstrap,
        "verification": {
            "outcome": verdict.outcome.value,
            "required_checks_proved": [check.value for check in verdict.proved],
            "required_checks_outstanding": [check.value for check in verdict.outstanding],
            "detail": verdict.detail,
        },
        "restored": verdict.restored,
    }
