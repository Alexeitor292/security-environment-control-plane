"""Guest bootstrap accounting — observable, bounded, and never ambiguous. Worker-only.

A guest that has been *created* is not a guest that is *running the workload*. The create call
returning zero says a VM object exists; it says nothing about whether cloud-init finished, whether
the reviewed post-provisioning steps ran, or whether the software that came up is the software the
plan named. This module is where that gap is closed, and it closes it the same way
:mod:`secp_worker.provisioning.proxmox_verification` closes its own: by refusing to let "we could
not tell" resolve into either answer.

FOUR STATES, AND WHY "IN PROGRESS" IS NOT ONE OF THEM
------------------------------------------------------
:class:`BootstrapState` has exactly four members and every one of them is closed:

``ready``       the guest reported completion, and the report was ATTRIBUTED to that guest and
                carried the workload version and base-image digest the plan pinned.
``failed``      the guest reported, and what it reported is not success — a failed operation, or
                the wrong workload.
``timed_out``   the deadline passed with no attributable report. This is a closed FAILURE, not a
                pending state: at the moment the deadline expires the question stops being open.
``unobserved``  the report channel itself could not be consulted. Nothing is known.

There is deliberately no ``in_progress``. A caller that could distinguish "still working" from
"finished" would be tempted to poll forever and report neither outcome, which is precisely the
ambiguous state the requirement excludes. Progress belongs in step records; the bootstrap VERDICT
is one of four closed values, decided against a bound.

HOW A REPORT IS ATTRIBUTED
---------------------------
An inbound report is accepted only when it carries the ``attestation_ref`` the plan minted for that
guest AND the vmid matches. A report that cannot be attributed does NOT become ``failed`` — nothing
about the guest was learned from a message that may not have come from it — it leaves the guest
``timed_out`` or ``unobserved`` on its own merits. Treating an unattributable message as evidence
in either direction is the mistake that makes an attacker's forged report a passing readiness
check on a range full of deliberately vulnerable machines.

WHAT THIS MODULE DOES NOT DO
-----------------------------
No privileged execution, no socket, no subprocess. Reports are supplied to it; collecting them over
the reviewed channel is the caller's job. It emits :class:`CheckFinding` values from the #107
verification contract and hands the verdict to :func:`decide_outcome` rather than deciding one of
its own, so a range's bootstrap can never be "verified" by a different set of rules than everything
else about it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from secp_worker.provisioning.proxmox_verification import (
    CheckFinding,
    VerificationCheck,
    finding_from,
)


class BootstrapState(str, Enum):
    """The closed verdict for ONE guest's bootstrap. Nothing here means "probably came up"."""

    #: Reported complete, attributed to this guest, running the pinned workload.
    ready = "ready"
    #: Reported, and what it reported is not success.
    failed = "failed"
    #: The deadline passed with no attributable report. A closed failure.
    timed_out = "timed_out"
    #: The report channel could not be consulted. Nothing is known about this guest.
    unobserved = "unobserved"


#: The one state that counts as success. Written as a set so a future member cannot be silently
#: swept into "success" by a truthiness check somewhere.
BOOTSTRAP_SUCCESS: frozenset[BootstrapState] = frozenset({BootstrapState.ready})

#: States that mean the guest was heard from and the answer was no. Distinguished from
#: ``unobserved`` because recovery guidance differs: one is a broken guest, the other a broken
#: channel, and telling an operator to reinstall a guest whose report channel was down is wrong.
BOOTSTRAP_OBSERVED_FAILURES: frozenset[BootstrapState] = frozenset(
    {BootstrapState.failed, BootstrapState.timed_out}
)


class BootstrapPhase(str, Enum):
    """How far a guest got. Reported for guidance; never used to decide the verdict.

    Kept strictly separate from :class:`BootstrapState` on purpose: a phase is a progress hint and
    an unfinished phase must not be readable as a third kind of outcome.
    """

    not_started = "not_started"
    cloud_init_running = "cloud_init_running"
    cloud_init_complete = "cloud_init_complete"
    operations_running = "operations_running"
    operations_complete = "operations_complete"
    workload_serving = "workload_serving"


class ReportRejection(str, Enum):
    """Why an inbound report was not accepted as evidence about a guest."""

    #: No contract exists for the guest_ref it names.
    unknown_guest = "unknown_guest"
    #: The attestation reference does not match the one minted for that guest.
    attestation_mismatch = "attestation_mismatch"
    #: The vmid does not match the guest the attestation belongs to.
    vmid_mismatch = "vmid_mismatch"
    #: More than one report claimed the same guest. Neither is trusted.
    duplicate_report = "duplicate_report"


@dataclass(frozen=True)
class GuestBootstrapReport:
    """What a guest said about itself, as received over the reviewed channel.

    Every field is what the GUEST claimed. Nothing here is trusted until
    :func:`evaluate_bootstrap` has attributed it and compared the claimed workload identity against
    the plan.
    """

    guest_ref: str
    vmid: int
    attestation_ref: str
    phase: BootstrapPhase
    #: The guest's own verdict on its bounded operations.
    operations_succeeded: bool
    #: Which declared operations the guest says it completed.
    completed_operations: tuple[str, ...] = ()
    #: The workload version the guest found installed. Compared against the pinned one.
    workload_version: str | None = None
    #: The base-image digest the guest read back. Compared against the pinned one.
    image_digest: str | None = None
    detail: str = ""
    #: Seconds from guest start to this report. Compared against the deadline.
    elapsed_seconds: int | None = None


@dataclass(frozen=True)
class ExpectedGuest:
    """The plan's side of one guest's bootstrap contract.

    A worker-local restatement of
    :class:`secp_api.range_providers.proxmox_workload.GuestBootstrapContract`, carried as plain
    values so this module keeps the same zero-dependency shape as the rest of the worker
    verification chain: dicts and scalars in, closed enums out.
    """

    guest_ref: str
    vmid: int
    attestation_ref: str
    workload_version: str
    image_digest: str
    required_operations: tuple[str, ...]
    deadline_seconds: int


@dataclass(frozen=True)
class GuestBootstrapVerdict:
    """One guest's closed outcome, with the reason kept separate from the outcome."""

    guest_ref: str
    vmid: int
    state: BootstrapState
    phase: BootstrapPhase
    detail: str
    #: Set when a report existed but was not accepted as evidence.
    rejection: ReportRejection | None = None

    @property
    def is_success(self) -> bool:
        return self.state in BOOTSTRAP_SUCCESS


def evaluate_bootstrap(
    expected: tuple[ExpectedGuest, ...],
    reports: tuple[GuestBootstrapReport, ...],
    *,
    channel_reachable: bool,
    elapsed_seconds: int,
) -> tuple[GuestBootstrapVerdict, ...]:
    """Decide each guest's closed bootstrap state.

    ``channel_reachable`` is the health of the REPORT CHANNEL, and it dominates: when the channel
    could not be consulted, every guest is ``unobserved`` regardless of how much time has passed.
    Calling a guest ``timed_out`` because no report arrived through a channel that was down would
    blame the guest for the channel's failure, and the two need different recovery.

    ``elapsed_seconds`` is measured by the caller against the operation's own clock, not taken from
    the reports — a guest that lies about its elapsed time must not be able to extend its own
    deadline.
    """
    if not channel_reachable:
        return tuple(
            GuestBootstrapVerdict(
                guest_ref=guest.guest_ref,
                vmid=guest.vmid,
                state=BootstrapState.unobserved,
                phase=BootstrapPhase.not_started,
                detail=(
                    "the bootstrap report channel could not be consulted; this guest's state is "
                    "unknown and is not being read as either success or failure"
                ),
            )
            for guest in sorted(expected, key=lambda g: g.guest_ref)
        )

    by_ref: dict[str, list[GuestBootstrapReport]] = {}
    for report in reports:
        by_ref.setdefault(report.guest_ref, []).append(report)

    verdicts: list[GuestBootstrapVerdict] = []
    for guest in sorted(expected, key=lambda g: g.guest_ref):
        candidates = by_ref.get(guest.guest_ref, [])
        rejection: ReportRejection | None = None
        accepted: GuestBootstrapReport | None = None

        if len(candidates) > 1:
            # Two reports for one guest means at least one did not come from it. Neither is
            # evidence, and picking "the successful one" is how a forged report wins.
            rejection = ReportRejection.duplicate_report
        elif candidates:
            report = candidates[0]
            if report.attestation_ref != guest.attestation_ref:
                rejection = ReportRejection.attestation_mismatch
            elif report.vmid != guest.vmid:
                rejection = ReportRejection.vmid_mismatch
            else:
                accepted = report

        if accepted is None:
            # No attributable report. Whether that is a timeout is decided against the bound, and
            # before the bound it is still a timeout as far as this function's contract goes — the
            # caller is expected to run it at or after the deadline. Reporting the remaining time
            # keeps that legible without inventing an "in progress" verdict.
            expired = elapsed_seconds >= guest.deadline_seconds
            detail = (
                f"no attributable report {elapsed_seconds}s after start "
                f"(deadline {guest.deadline_seconds}s)"
            )
            if rejection is not None:
                detail = f"{detail}; a report arrived but was rejected: {rejection.value}"
            verdicts.append(
                GuestBootstrapVerdict(
                    guest_ref=guest.guest_ref,
                    vmid=guest.vmid,
                    state=BootstrapState.timed_out if expired else BootstrapState.unobserved,
                    phase=BootstrapPhase.not_started,
                    detail=detail,
                    rejection=rejection,
                )
            )
            continue

        problems: list[str] = []
        if not accepted.operations_succeeded:
            problems.append("the guest reported its bounded operations did not all succeed")
        outstanding = sorted(set(guest.required_operations) - set(accepted.completed_operations))
        if outstanding:
            problems.append(f"operations not completed: {outstanding}")
        # The wrong software booting is a bootstrap failure, not a cosmetic mismatch: the whole
        # range is described by a plan that names this version, and the challenges were written
        # against it.
        if accepted.workload_version != guest.workload_version:
            problems.append(
                f"workload version {accepted.workload_version!r} is not the pinned "
                f"{guest.workload_version!r}"
            )
        if accepted.image_digest != guest.image_digest:
            problems.append("the base-image digest read back does not match the reviewed image")
        if accepted.phase is not BootstrapPhase.workload_serving:
            problems.append(f"reached only {accepted.phase.value}")
        if (
            accepted.elapsed_seconds is not None
            and accepted.elapsed_seconds > guest.deadline_seconds
        ):
            problems.append(
                f"the guest itself reports {accepted.elapsed_seconds}s, beyond its "
                f"{guest.deadline_seconds}s bound"
            )

        verdicts.append(
            GuestBootstrapVerdict(
                guest_ref=guest.guest_ref,
                vmid=guest.vmid,
                state=BootstrapState.failed if problems else BootstrapState.ready,
                phase=accepted.phase,
                detail=(
                    "; ".join(problems)
                    if problems
                    else (
                        f"reported serving {guest.workload_version} at the pinned digest after "
                        f"{len(accepted.completed_operations)} bounded operation(s)"
                    )
                ),
            )
        )
    return tuple(verdicts)


def bootstrap_finding(verdicts: tuple[GuestBootstrapVerdict, ...]) -> CheckFinding:
    """Reduce per-guest verdicts to the one ``guest_readiness`` finding the #107 contract expects.

    The mapping is where "unobserved is not passed" is actually enforced for bootstrap:

    * any ``unobserved`` guest sets ``observed=False``, which
      :func:`~secp_worker.provisioning.proxmox_verification.decide_outcome` treats exactly as a
      failure and which makes ``verified`` unreachable;
    * ``failed`` and ``timed_out`` set ``ok=False`` with ``observed=True``, because those guests
      WERE heard from (or their bound WAS reached) and the answer was no;
    * an empty verdict set is ``observed=False``. A range with no guests to bootstrap is not a
      range whose bootstrap passed — it is one nothing was checked about.
    """
    if not verdicts:
        return finding_from(
            check=VerificationCheck.guest_readiness,
            observed=False,
            ok=False,
            detail="no guest bootstrap verdicts were produced; nothing about readiness was checked",
        )
    unobserved = [v.guest_ref for v in verdicts if v.state is BootstrapState.unobserved]
    failures = [
        f"{v.guest_ref}: {v.state.value}"
        for v in verdicts
        if v.state in BOOTSTRAP_OBSERVED_FAILURES
    ]
    return finding_from(
        check=VerificationCheck.guest_readiness,
        observed=not unobserved,
        ok=not failures and not unobserved,
        detail=(
            f"{len(unobserved)} guest(s) could not be observed at all: {sorted(unobserved)}"
            if unobserved
            else (
                "; ".join(sorted(failures))
                if failures
                else f"{len(verdicts)} guest(s) reported serving the pinned workload"
            )
        ),
    )


def bootstrap_summary(verdicts: tuple[GuestBootstrapVerdict, ...]) -> dict:
    """A durable, secret-free evidence record of one bootstrap round.

    Carries counts and guest refs, never a report's raw payload: reports arrive from deliberately
    vulnerable machines and a raw payload persisted into evidence is attacker-controlled content in
    an operator's console.
    """
    by_state: dict[str, list[str]] = {}
    for verdict in sorted(verdicts, key=lambda v: v.guest_ref):
        by_state.setdefault(verdict.state.value, []).append(verdict.guest_ref)
    return {
        "guest_count": len(verdicts),
        "by_state": {state: sorted(refs) for state, refs in sorted(by_state.items())},
        "rejections": sorted({v.rejection.value for v in verdicts if v.rejection is not None}),
        "all_ready": bool(verdicts) and all(v.is_success for v in verdicts),
    }
