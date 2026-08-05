"""Reconciliation — decide whether an interrupted apply may be resumed, or must stop. Worker-only.

An apply that did not clearly finish leaves one question: what exists now? The cheap answer is to
run the apply again and let the provider sort it out. On a Proxmox range that answer builds a
second copy of the lab, or strands the first one — because a create that timed out on the client
side may well have succeeded on the server side, and a retry that cannot see the first result has
no way to tell "not created" from "created, unseen".

So this module never resolves that question by acting. It resolves it by looking, and when it
cannot look it says so:

**Unknown provider outcome stops everything.** If the apply's own result was not established, the
decision is :attr:`~secp_worker.provisioning.proxmox_verification.VerificationOutcome.
recovery_required` and the action is :attr:`ReconcileAction.halt`. No amount of subsequent
observation upgrades that, because a provider that accepted a call whose result we never saw may
still be acting on it.

**Partial observation stops everything too.** This is the subtler half and the one that makes the
difference in practice. An observation that came back "reachable" but that did not read ownership
tags, or did not read OpenTofu state, is not a small gap — it is exactly the gap in which a
duplicate gets created. :func:`decide_reconciliation` demands the fields it needs and halts with
``recovery_required`` when any of them is ``None``, rather than reasoning over what it did get.

**A retry never allocates.** The only resources a resume may create are ones the SEALED allocation
ledger already names and that a WORKING observation proved absent. An unsealed ledger is itself a
halt: an open ledger would hand a "missing" guest a brand-new vmid and address, and the range would
come back renumbered under its own name.

**An object we do not own is never adopted and never removed.** Ownership is decided by
:func:`~secp_api.range_providers.proxmox_model.is_owned_by_secp` — tags, never names — and anything
at one of our allocated ids that is not ours produces ``state_disagreement`` and a halt. Adopting
it would put someone else's VM under this range's teardown; removing it would delete it.

The outcome vocabulary is the #107 one, unchanged. This module adds an ACTION alongside it, because
"what is true" and "what may now be done" are different questions and collapsing them is how a
``verification_failed`` quietly becomes a retry.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from secp_api.range_enums import RangeResourceKind
from secp_api.range_providers.proxmox_model import (
    ObjectProvenance,
    Ownership,
    is_owned_by_secp,
)

from secp_worker.provisioning.proxmox_verification import (
    ObservedInfrastructure,
    VerificationOutcome,
    VerificationReport,
)


class ProviderOutcome(str, Enum):
    """What the apply itself reported. ``unknown`` is a third answer, not a slow success."""

    #: The runner observed the apply complete with a result.
    succeeded = "succeeded"
    #: The runner observed the apply fail.
    failed = "failed"
    #: The runner did not establish an outcome: it was killed, timed out, or lost the connection.
    unknown = "unknown"


class ReconcileAction(str, Enum):
    """The closed set of things reconciliation may authorise. There is no "retry anyway"."""

    #: Everything the plan describes is present and ours. Nothing to do.
    no_action = "no_action"
    #: A bounded, ledger-bound set of resources was PROVED absent and may be created.
    resume_apply = "resume_apply"
    #: Stop. A human must look at the provider before anything else happens.
    halt = "halt"


class ReconcileReason(str, Enum):
    """Why the decision came out the way it did. Stable keys for guidance and metrics."""

    #: The apply's own outcome was never established.
    provider_outcome_unknown = "proxmox.reconcile.provider_outcome_unknown"
    #: The provider could not be observed at all.
    provider_unobservable = "proxmox.reconcile.provider_unobservable"
    #: The observation is missing a field the decision needs.
    observation_incomplete = "proxmox.reconcile.observation_incomplete"
    #: The ledger is open, so a resume could allocate new identities.
    ledger_not_sealed = "proxmox.reconcile.ledger_not_sealed"
    #: A resource this plan expects is claimed by OpenTofu state but absent from the provider.
    state_claims_absent_resource = "proxmox.reconcile.state_claims_absent_resource"
    #: The desired state expects an identifier the sealed ledger does not record.
    resource_not_in_sealed_ledger = "proxmox.reconcile.resource_not_in_sealed_ledger"
    #: Something exists at one of our allocated ids that is not ours.
    foreign_object_at_allocated_id = "proxmox.reconcile.foreign_object_at_allocated_id"
    #: A forbidden path was OBSERVED to work. Teardown, never retry.
    isolation_violation_observed = "proxmox.reconcile.isolation_violation_observed"
    #: A bounded set of ledger-bound resources was proved absent.
    resources_proved_absent = "proxmox.reconcile.resources_proved_absent"
    #: Everything expected is present and ours.
    converged = "proxmox.reconcile.converged"


@dataclass(frozen=True)
class ReconcileDecision:
    """What is true, and — separately — what may now be done about it."""

    action: ReconcileAction
    outcome: VerificationOutcome
    reason: ReconcileReason
    detail: str
    #: vmids a resume may create. Always a subset of the sealed ledger's recorded vmids, always
    #: proved absent by a working observation. Empty for every action except ``resume_apply``.
    create_vmids: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if self.create_vmids and self.action is not ReconcileAction.resume_apply:
            raise ValueError("only a resume_apply decision may carry resources to create")


def _halt(outcome: VerificationOutcome, reason: ReconcileReason, detail: str) -> ReconcileDecision:
    return ReconcileDecision(
        action=ReconcileAction.halt, outcome=outcome, reason=reason, detail=detail
    )


def _ledger_vmids(ledger: dict) -> set[int]:
    """Every guest id the sealed ledger recorded. VM and CT ids share one Proxmox namespace."""
    vmids: set[int] = set()
    for record in ledger.get("allocations", []):
        if record.get("kind") in ("vmid", "lxc_id"):
            try:
                vmids.add(int(record["value"]))
            except (KeyError, TypeError, ValueError):
                continue
    return vmids


def _expected_ownership(guest: dict) -> Ownership | None:
    """Rebuild the ownership stamp the plan says this guest must carry.

    Returns ``None`` when the payload cannot express one — which the caller treats as an incomplete
    observation rather than as a guest with no owner, because "we could not work out who should own
    it" must never license touching it.
    """
    payload = guest.get("ownership")
    if not isinstance(payload, dict):
        return None
    try:
        return Ownership(
            organization_id=str(payload["organization_id"]),
            target_id=str(payload["target_id"]),
            range_id=str(payload["range_id"]),
            generation=int(payload["generation"]),
            operation_generation=int(payload.get("operation_generation", 0)),
            resource_kind=RangeResourceKind(
                payload.get("resource_kind", RangeResourceKind.virtual_machine.value)
            ),
            team_ref=payload.get("team_ref") or None,
        )
    except (KeyError, TypeError, ValueError):
        return None


def decide_reconciliation(
    *,
    desired_state: dict,
    ledger: dict,
    observed: ObservedInfrastructure,
    provider_outcome: ProviderOutcome,
    verification: VerificationReport | None = None,
) -> ReconcileDecision:
    """Decide whether the interrupted apply may be resumed. Performs no privileged execution.

    The order of the checks is the order of their severity, and it matters: an unknown provider
    outcome is evaluated before the observation is even looked at, so a reassuring observation
    collected after a lost apply cannot talk the decision into a retry.
    """
    if provider_outcome is ProviderOutcome.unknown:
        return _halt(
            VerificationOutcome.recovery_required,
            ReconcileReason.provider_outcome_unknown,
            "the apply's outcome was never established; the provider may have acted on a call "
            "whose result was never seen, so nothing may be re-applied until a human establishes "
            "what exists",
        )

    if not observed.reachable:
        return _halt(
            VerificationOutcome.recovery_required,
            ReconcileReason.provider_unobservable,
            "the provider could not be observed; resources may or may not exist and re-applying "
            "over an unknown state is how a second copy of the range gets built",
        )

    # -- completeness. Every field below is one the decision genuinely needs; an absent one is not
    # -- a smaller answer, it is the absence of an answer.
    gaps: list[str] = []
    if observed.tofu_state_addresses is None:
        gaps.append("OpenTofu state was not read")
    if observed.observed_addresses is None:
        gaps.append("no provider-derived address list was collected")
    untagged_guests = [guest.vmid for guest in observed.guests if guest.tags is None]
    if untagged_guests:
        gaps.append(f"ownership tags were not read for vmid(s) {sorted(untagged_guests)}")
    desired_guests = desired_state.get("guests") or []
    if any(_expected_ownership(guest) is None for guest in desired_guests):
        gaps.append("the desired state does not carry a usable ownership stamp for every guest")
    if gaps:
        return _halt(
            VerificationOutcome.recovery_required,
            ReconcileReason.observation_incomplete,
            "the observation is partial and a partial observation is exactly the gap a duplicate "
            f"is created in: {'; '.join(gaps)}",
        )

    if not ledger.get("sealed"):
        return _halt(
            VerificationOutcome.recovery_required,
            ReconcileReason.ledger_not_sealed,
            "the allocation ledger is not sealed; a resume would hand any missing guest a new vmid "
            "and a new address, silently allocating fresh identities during what is supposed to be "
            "a retry of an approved plan",
        )

    # -- an observed isolation violation is never a retry. It is a teardown.
    if verification is not None and verification.outcome is VerificationOutcome.isolation_failed:
        return _halt(
            VerificationOutcome.isolation_failed,
            ReconcileReason.isolation_violation_observed,
            "a forbidden path was OBSERVED to work; this range must be torn down rather than "
            "reconciled forward",
        )

    observed_by_vmid = {guest.vmid: guest for guest in observed.guests}
    ledger_vmids = _ledger_vmids(ledger)

    # -- ownership. A matching vmid is not proof, so the tag decides, and anything that is not
    # -- ours halts: adopting it would put someone else's machine under this range's teardown.
    foreign: list[str] = []
    for guest in desired_guests:
        vmid = int(guest["vmid"])
        live = observed_by_vmid.get(vmid)
        expected = _expected_ownership(guest)
        if live is None or expected is None:
            continue
        provenance = is_owned_by_secp(live.tags, expected)
        if provenance is not ObjectProvenance.secp_owned:
            foreign.append(f"vmid {vmid}: {provenance.value}")
    if foreign:
        return _halt(
            VerificationOutcome.state_disagreement,
            ReconcileReason.foreign_object_at_allocated_id,
            "an object exists at an id this plan allocated but does not carry this range's "
            f"ownership stamp ({'; '.join(sorted(foreign))}); it is neither adopted nor removed",
        )

    expected_vmids = {int(guest["vmid"]) for guest in desired_guests}
    absent = sorted(expected_vmids - set(observed_by_vmid))

    # -- state disagreement. If OpenTofu state claims a resource the provider does not have, the
    # -- two disagree about reality and a resume would try to create something state thinks exists.
    state_addresses = set(observed.tofu_state_addresses or ())
    provider_addresses = set(observed.observed_addresses or ())
    claimed_but_absent = sorted(state_addresses - provider_addresses)
    if claimed_but_absent:
        return _halt(
            VerificationOutcome.state_disagreement,
            ReconcileReason.state_claims_absent_resource,
            "OpenTofu state claims resources the provider does not report "
            f"({claimed_but_absent[:5]}); resuming would either duplicate them or fail on an "
            "address state already holds",
        )

    if not absent:
        return ReconcileDecision(
            action=ReconcileAction.no_action,
            outcome=(
                verification.outcome if verification is not None else VerificationOutcome.verified
            ),
            reason=ReconcileReason.converged,
            detail=(
                f"all {len(expected_vmids)} expected guest(s) are present and carry this range's "
                "ownership stamp"
            ),
        )

    # -- the only creating path. Every id is one the sealed ledger already recorded, and every one
    # -- was proved absent by an observation that was itself complete. No new identity is minted,
    # -- and nothing already present is in the list, so a retry cannot duplicate.
    unledgered = sorted(set(absent) - ledger_vmids)
    if unledgered:
        return _halt(
            VerificationOutcome.state_disagreement,
            ReconcileReason.resource_not_in_sealed_ledger,
            f"the desired state expects vmid(s) {unledgered} that the sealed ledger does not "
            "record; resuming would create infrastructure no approved allocation covers",
        )

    return ReconcileDecision(
        action=ReconcileAction.resume_apply,
        outcome=VerificationOutcome.verification_failed,
        reason=ReconcileReason.resources_proved_absent,
        detail=(
            f"{len(absent)} guest(s) were proved absent by a complete observation and are recorded "
            "in the sealed ledger; they may be created at their existing identifiers"
        ),
        create_vmids=tuple(absent),
    )
