"""Observed verification of an applied Proxmox range. Worker-only.

A zero exit code from OpenTofu means the API calls it made returned successfully. It does not mean
the range exists, is placed where the plan said, is powered on, or is isolated. This module answers
that question by comparing the APPROVED desired state against an INDEPENDENT observation of what is
actually on the target, and — for isolation — against probes run from the segments themselves.

TWO RULES DECIDE EVERY OUTCOME HERE
------------------------------------
**Isolation is never inferred from configuration.** A firewall rule set that reads correctly and
behaves otherwise is the exact failure this design exists to prevent, so a rule comparison can only
ever produce ``firewall_objects``. The isolation verdicts (``cross_team_denial`` and its siblings)
come solely from :class:`SegmentProber` results. With no prober, they are not
"assumed fine" — they are unobserved, and an unobserved isolation check cannot yield
:attr:`VerificationOutcome.verified`.

**Unobserved is not passed.** Every :class:`CheckFinding` carries ``observed`` separately from
``ok``. A check that could not be run at all sets ``observed=False``, and
:func:`decide_outcome` treats that exactly as it treats a failure — never as a success. This is why
the outcome enum has no "partially verified": a partial verification is a failed one.

A NOTE ON ``verification_failed`` CARRYING "COULD NOT CHECK"
------------------------------------------------------------
The closed outcome set does not distinguish "a check failed" from "a check could not run". Both
land in ``verification_failed``, which is correct in that neither is success, but it means the
outcome alone under-describes the situation. The findings carry the distinction: callers rendering
guidance should read ``observed`` rather than branching on the outcome alone.

This module performs NO privileged execution and opens no connection. Observations and probe
results are supplied to it; collecting them is the caller's job.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol


class VerificationOutcome(str, Enum):
    """The closed set of verdicts. Nothing here means "probably fine"."""

    #: Every check ran and every check passed.
    verified = "verified"
    #: At least one check failed, or could not be run at all.
    verification_failed = "verification_failed"
    #: A path that must not exist was OBSERVED to work.
    isolation_failed = "isolation_failed"
    #: OpenTofu state and the provider disagree about what exists.
    state_disagreement = "state_disagreement"
    #: The target could not be observed. Resources may or may not exist.
    recovery_required = "recovery_required"


class VerificationCheck(str, Enum):
    guest_inventory = "guest_inventory"
    guest_names = "guest_names"
    node_placement = "node_placement"
    disks_and_storage = "disks_and_storage"
    nics_and_macs = "nics_and_macs"
    network_objects = "network_objects"
    firewall_objects = "firewall_objects"
    ownership_tags = "ownership_tags"
    power_state = "power_state"
    guest_readiness = "guest_readiness"
    required_reachability = "required_reachability"
    cross_team_denial = "cross_team_denial"
    management_denial = "management_denial"
    protected_denial = "protected_denial"
    external_denial = "external_denial"
    state_agreement = "state_agreement"


#: The checks whose failure means a forbidden path was proved to WORK.
ISOLATION_CHECKS = frozenset(
    {
        VerificationCheck.cross_team_denial,
        VerificationCheck.management_denial,
        VerificationCheck.protected_denial,
        VerificationCheck.external_denial,
    }
)


class ProbeVerdict(str, Enum):
    """What a reachability probe established. ``unknown`` is a third answer, not a shade of pass."""

    reachable = "reachable"
    blocked = "blocked"
    unknown = "unknown"


class SegmentProber(Protocol):
    """Runs a reachability test FROM a segment. Implemented outside this module."""

    def probe(self, *, from_segment: str, to_address: str, port: int) -> ProbeVerdict:
        """Attempt a connection from inside ``from_segment``. Never raises; returns ``unknown``."""
        ...


@dataclass(frozen=True)
class ObservedDisk:
    slot: str
    size_gb: int | None
    storage_id: str | None


@dataclass(frozen=True)
class ObservedGuest:
    """One guest as the provider actually reports it. Unobserved fields stay ``None``."""

    vmid: int
    name: str | None = None
    node_name: str | None = None
    kind: str | None = None
    powered_on: bool | None = None
    #: Readiness as OBSERVED from the guest responding, never from "the create call returned 0".
    ready: bool | None = None
    disks: tuple[ObservedDisk, ...] = ()
    macs: tuple[str, ...] = ()
    bridges: tuple[str, ...] = ()
    #: Ownership tags read back off the object. ``None`` = not read.
    tags: dict[str, str] | None = None


@dataclass(frozen=True)
class ObservedVNet:
    name: str
    zone: str | None = None
    vlan_tag: int | None = None
    cidr: str | None = None


@dataclass(frozen=True)
class ObservedInfrastructure:
    """The independent observation the verification is judged against."""

    #: False when the provider could not be observed at all. Everything else is then meaningless.
    reachable: bool
    guests: tuple[ObservedGuest, ...] = ()
    zones: tuple[str, ...] = ()
    vnets: tuple[ObservedVNet, ...] = ()
    security_groups: tuple[str, ...] = ()
    ip_sets: tuple[str, ...] = ()
    #: Resource addresses OpenTofu state claims exist. ``None`` = state was not read.
    tofu_state_addresses: tuple[str, ...] | None = None
    #: Resource addresses derived from the observation, for the state-agreement comparison.
    observed_addresses: tuple[str, ...] | None = None


class CheckFindingInvalid(ValueError):
    """A finding was constructed in a state that cannot describe a real observation."""


@dataclass(frozen=True)
class CheckFinding:
    """One check's result, as a PAIR with exactly three legal states.

        observed=False, ok=None    the check could not be run; nothing is known
        observed=True,  ok=False   the check ran and failed
        observed=True,  ok=True    the check ran and passed

    ``ok`` is ``bool | None`` because "unknown" needs a representation of its own. It used to be
    ``bool``, which meant the only way to express "could not run" was ``ok=False`` — and that is
    the exact substitution this pair exists to prevent: a check nobody could make became
    indistinguishable from a check that failed, everywhere downstream. Two producers were doing
    precisely that.

    The other two combinations are REFUSED at construction rather than merely discouraged:

    * ``observed=False, ok=True`` would be a pass nobody observed. It was reachable before, because
      several call sites computed ``observed`` and ``ok`` from independent expressions and nothing
      cross-checked them — "no problems were found" is trivially true when nothing was looked at.
    * ``observed=True, ok=None`` is a contradiction: the check ran and has no verdict. Left legal,
      it would eventually be resolved to a pass or a fail by whoever read it next.

    Use :meth:`unobserved` and :meth:`observed_result` rather than the constructor, so each site
    says which of the three it means instead of computing two fields and hoping they agree.
    """

    check: VerificationCheck
    #: False when the check could not be run. Never treated as a pass.
    observed: bool
    #: ``None`` exactly when ``observed`` is False. A verdict requires an observation.
    ok: bool | None
    detail: str

    def __post_init__(self) -> None:
        if self.observed and self.ok is None:
            raise CheckFindingInvalid(
                f"{self.check.value}: observed=True with ok=None is a contradiction — the check "
                "ran and produced no verdict. Report it as unobserved, or give it a verdict."
            )
        if not self.observed and self.ok is not None:
            raise CheckFindingInvalid(
                f"{self.check.value}: observed=False with ok={self.ok!r} claims a verdict for a "
                "check that was never run. An unobserved check has ok=None."
            )

    @classmethod
    def unobserved(cls, check: VerificationCheck, detail: str) -> CheckFinding:
        """The check could not be run. NOT a failure and not a pass — nobody looked."""
        return cls(check=check, observed=False, ok=None, detail=detail)

    @classmethod
    def observed_result(cls, check: VerificationCheck, *, ok: bool, detail: str) -> CheckFinding:
        """The check ran and reached ``ok``."""
        return cls(check=check, observed=True, ok=bool(ok), detail=detail)

    @property
    def counts_as_failure(self) -> bool:
        """Unobserved counts as a failure. ``ok is None`` is never a pass.

        Written against ``self.ok is True`` rather than truthiness so that the tri-state is read
        explicitly: with ``ok`` now nullable, ``not (observed and ok)`` would still be correct but
        would rely on ``None`` being falsey, which is how the distinction gets lost again.
        """
        return not (self.observed and self.ok is True)


def finding_payload(finding: CheckFinding) -> dict:
    """One finding as the durable record the control plane reads back.

    ``ok`` is emitted as ``None`` for an unobserved check rather than omitted, because an absent
    key and an explicit null are different facts downstream and only one of them says "no verdict".
    """
    return {
        "check": finding.check.value,
        "observed": finding.observed,
        "ok": finding.ok,
        "detail": finding.detail,
    }


def verification_evidence(report: VerificationReport) -> dict:
    """Serialize a report into the ``proxmox_verification_recorded`` event payload.

    THIS DID NOT EXIST. The API published ``infrastructure_checks`` and ``isolation_checks``, the
    projection carried them, the frontend read them and two separate tests asserted their shape —
    and nothing in the worker ever produced one. The two tests did not even agree with each other
    (``{check, outcome}`` in one, ``{check, observed, ok, detail}`` in the other), which is the
    proof that both were describing a payload they had invented rather than one the system emits.

    So the shape is now derived from :class:`CheckFinding`, the type the verification actually
    produces, and this is the single place it is written. The split between the two arrays is
    :data:`ISOLATION_CHECKS`, the same set :func:`decide_outcome` uses — so a check cannot be
    classified one way for the verdict and the other way for the record.

    The two outcomes are reported SEPARATELY and neither is derived from the other: a deployment
    can be structurally perfect and still let one team reach another, and a combined verdict would
    let the first mask the second.
    """
    isolation = tuple(f for f in report.findings if f.check in ISOLATION_CHECKS)
    infrastructure = tuple(f for f in report.findings if f.check not in ISOLATION_CHECKS)
    return {
        "outcome": report.outcome.value,
        # Each half reports its own worst state. `unproven` is a third value, never folded into
        # either of the other two: it is what an unobserved check leaves behind.
        "infrastructure_outcome": _half_outcome(infrastructure),
        "isolation_outcome": _half_outcome(isolation),
        "infrastructure_checks": [finding_payload(f) for f in infrastructure],
        "isolation_checks": [finding_payload(f) for f in isolation],
    }


def _half_outcome(findings: tuple[CheckFinding, ...]) -> str:
    """The verdict for one half of the report, keeping "nobody looked" as its own answer.

    ``unproven`` outranks ``passed`` and is distinct from ``failed``: a half in which every check
    that RAN passed, but some check could not be run, has not been proved and has not failed.
    Collapsing it into either is the substitution the whole finding type exists to prevent.
    """
    if not findings:
        return "unproven"
    if any(f.observed and f.ok is False for f in findings):
        return "failed"
    if any(not f.observed for f in findings):
        return "unproven"
    return "passed"


def finding_from(
    check: VerificationCheck, *, observed: bool, ok: bool, detail: str
) -> CheckFinding:
    """Build a finding from a separately-computed ``observed`` flag and verdict.

    When ``observed`` is False the verdict is DISCARDED and the finding is unobserved. That is the
    correction, not a convenience: several call sites here computed the two from independent
    expressions — ``observed=unobserved == 0`` beside ``ok=not problems`` — and "no problems were
    found" is trivially true when nothing was examined. So an unobservable check could report
    ``ok=True``, a pass nobody made, and ``counts_as_failure`` was the only thing standing between
    that and a green verification.

    Call sites that already know which of the three states they mean should use
    :meth:`CheckFinding.unobserved` or :meth:`CheckFinding.observed_result` directly.
    """
    if not observed:
        return CheckFinding.unobserved(check, detail)
    return CheckFinding.observed_result(check, ok=ok, detail=detail)


@dataclass(frozen=True)
class VerificationReport:
    outcome: VerificationOutcome
    findings: tuple[CheckFinding, ...] = field(default_factory=tuple)

    def finding(self, check: VerificationCheck) -> CheckFinding | None:
        for item in self.findings:
            if item.check == check:
                return item
        return None

    @property
    def failures(self) -> tuple[CheckFinding, ...]:
        return tuple(f for f in self.findings if f.counts_as_failure)

    @property
    def unobserved(self) -> tuple[CheckFinding, ...]:
        return tuple(f for f in self.findings if not f.observed)


def decide_outcome(
    findings: tuple[CheckFinding, ...],
    *,
    provider_reachable: bool,
) -> VerificationOutcome:
    """Reduce findings to one closed verdict.

    Precedence, most severe first:

    1. ``recovery_required`` — the provider could not be observed. Nothing else is knowable, and
       resources may or may not exist.
    2. ``isolation_failed`` — a forbidden path was PROVED to work. Ranked above state disagreement
       because it is the outcome that requires immediate teardown rather than investigation.
    3. ``state_disagreement`` — OpenTofu state and the provider disagree about what exists.
    4. ``verification_failed`` — any other check failed OR could not be run.
    5. ``verified`` — every check ran and passed.
    """
    if not provider_reachable:
        return VerificationOutcome.recovery_required

    for finding in findings:
        # Only an OBSERVED violation is an isolation failure. An isolation check that could not run
        # is a verification failure, because nothing was proved either way.
        if finding.check in ISOLATION_CHECKS and finding.observed and not finding.ok:
            return VerificationOutcome.isolation_failed

    state = next((f for f in findings if f.check == VerificationCheck.state_agreement), None)
    if state is not None and state.observed and not state.ok:
        return VerificationOutcome.state_disagreement

    if any(f.counts_as_failure for f in findings):
        return VerificationOutcome.verification_failed
    return VerificationOutcome.verified


def _first_host(cidr: str) -> str:
    return str(next(iter(ipaddress.ip_network(cidr, strict=False).hosts())))


def verify_deployment(
    desired_state: dict,
    observed: ObservedInfrastructure,
    *,
    prober: SegmentProber | None = None,
    management_cidrs: tuple[str, ...] = (),
    protected_cidrs: tuple[str, ...] = (),
    external_probe_addresses: tuple[str, ...] = (),
    scoring_port: int = 443,
) -> VerificationReport:
    """Verify an applied range against its approved desired state and live observation."""
    if not observed.reachable:
        # Nothing below is meaningful. Report the one honest thing: we could not look.
        return VerificationReport(
            outcome=VerificationOutcome.recovery_required,
            findings=(
                finding_from(
                    check=VerificationCheck.guest_inventory,
                    observed=False,
                    ok=False,
                    detail="the provider could not be observed; resources may or may not exist",
                ),
            ),
        )

    findings: list[CheckFinding] = []
    network = desired_state.get("network") or {}
    desired_vnets = network.get("vnets") or []
    desired_guests = desired_state.get("guests") or []

    findings.extend(_check_guests(desired_guests, observed))
    findings.extend(_check_network(network, desired_vnets, observed))
    findings.append(_check_firewall(network, observed))
    findings.append(_check_state_agreement(observed))
    findings.extend(
        _check_reachability(
            desired_vnets,
            desired_guests,
            prober,
            management_cidrs=management_cidrs,
            protected_cidrs=protected_cidrs,
            external_probe_addresses=external_probe_addresses,
            scoring_port=scoring_port,
        )
    )

    return VerificationReport(
        outcome=decide_outcome(tuple(findings), provider_reachable=True),
        findings=tuple(findings),
    )


def _check_guests(
    desired_guests: list[dict], observed: ObservedInfrastructure
) -> list[CheckFinding]:
    by_vmid = {guest.vmid: guest for guest in observed.guests}
    expected_vmids = {int(g["vmid"]) for g in desired_guests}

    missing = sorted(expected_vmids - set(by_vmid))
    unexpected = sorted(set(by_vmid) - expected_vmids)
    findings = [
        finding_from(
            check=VerificationCheck.guest_inventory,
            observed=True,
            ok=not missing and not unexpected,
            detail=(
                f"{len(expected_vmids)} guest(s) expected and observed"
                if not missing and not unexpected
                else f"missing vmids {missing}, unexpected vmids {unexpected}"
            ),
        )
    ]

    def compare(check: VerificationCheck, attribute: str, expected_key: str) -> CheckFinding:
        problems: list[str] = []
        unobserved = 0
        for guest in desired_guests:
            live = by_vmid.get(int(guest["vmid"]))
            if live is None:
                continue
            actual = getattr(live, attribute)
            if actual is None:
                unobserved += 1
                continue
            if actual != guest[expected_key]:
                problems.append(f"vmid {guest['vmid']}: {actual!r} != {guest[expected_key]!r}")
        return finding_from(
            check=check,
            observed=unobserved == 0,
            ok=not problems,
            detail=(
                f"{unobserved} guest(s) did not report {attribute}"
                if unobserved
                else ("; ".join(problems) if problems else f"all guests match on {attribute}")
            ),
        )

    findings.append(compare(VerificationCheck.guest_names, "name", "name"))
    findings.append(compare(VerificationCheck.node_placement, "node_name", "node_name"))

    # Disks: compare slot and storage. Size is compared only where the provider reported one.
    disk_problems: list[str] = []
    disk_unobserved = 0
    for guest in desired_guests:
        live = by_vmid.get(int(guest["vmid"]))
        if live is None:
            continue
        if not live.disks:
            disk_unobserved += 1
            continue
        live_by_slot = {disk.slot: disk for disk in live.disks}
        for disk in guest.get("disks", []):
            actual = live_by_slot.get(disk["slot"])
            if actual is None:
                disk_problems.append(f"vmid {guest['vmid']}: no disk at {disk['slot']}")
                continue
            if actual.storage_id is not None and actual.storage_id != disk["storage_id"]:
                disk_problems.append(
                    f"vmid {guest['vmid']} {disk['slot']}: storage {actual.storage_id!r} != "
                    f"{disk['storage_id']!r}"
                )
            if actual.size_gb is not None and actual.size_gb != disk["size_gb"]:
                disk_problems.append(
                    f"vmid {guest['vmid']} {disk['slot']}: size {actual.size_gb} != "
                    f"{disk['size_gb']}"
                )
    findings.append(
        finding_from(
            check=VerificationCheck.disks_and_storage,
            observed=disk_unobserved == 0,
            ok=not disk_problems,
            detail=(
                f"{disk_unobserved} guest(s) reported no disks"
                if disk_unobserved
                else ("; ".join(disk_problems) if disk_problems else "all disks match")
            ),
        )
    )

    # NICs: every desired MAC must be present on the guest that should carry it.
    mac_problems: list[str] = []
    mac_unobserved = 0
    for guest in desired_guests:
        live = by_vmid.get(int(guest["vmid"]))
        if live is None:
            continue
        if not live.macs:
            mac_unobserved += 1
            continue
        expected_macs = {str(nic["mac_address"]).upper() for nic in guest.get("nics", [])}
        actual_macs = {mac.upper() for mac in live.macs}
        if expected_macs != actual_macs:
            mac_problems.append(
                f"vmid {guest['vmid']}: {sorted(actual_macs)} != {sorted(expected_macs)}"
            )
    findings.append(
        finding_from(
            check=VerificationCheck.nics_and_macs,
            observed=mac_unobserved == 0,
            ok=not mac_problems,
            detail=(
                f"{mac_unobserved} guest(s) reported no NICs"
                if mac_unobserved
                else ("; ".join(mac_problems) if mac_problems else "all MACs match")
            ),
        )
    )

    # Ownership: read the tag back off the object. A matching name proves nothing.
    tag_problems: list[str] = []
    tag_unobserved = 0
    for guest in desired_guests:
        live = by_vmid.get(int(guest["vmid"]))
        if live is None:
            continue
        if live.tags is None:
            tag_unobserved += 1
            continue
        expected_tags = (guest.get("ownership") or {}).get("tags") or {}
        for key, value in expected_tags.items():
            if live.tags.get(key) != value:
                tag_problems.append(f"vmid {guest['vmid']}: {key}={live.tags.get(key)!r}")
    findings.append(
        finding_from(
            check=VerificationCheck.ownership_tags,
            observed=tag_unobserved == 0,
            ok=not tag_problems,
            detail=(
                f"{tag_unobserved} guest(s) reported no ownership tags"
                if tag_unobserved
                else (
                    "; ".join(tag_problems)
                    if tag_problems
                    else "every guest carries its ownership stamp"
                )
            ),
        )
    )

    for check, attribute, label in (
        (VerificationCheck.power_state, "powered_on", "power state"),
        (VerificationCheck.guest_readiness, "ready", "readiness"),
    ):
        problems = []
        unobserved = 0
        for guest in desired_guests:
            live = by_vmid.get(int(guest["vmid"]))
            if live is None:
                continue
            actual = getattr(live, attribute)
            if actual is None:
                unobserved += 1
            elif attribute == "powered_on" and actual is not bool(
                guest.get("start_on_deploy", True)
            ):
                problems.append(f"vmid {guest['vmid']}: powered_on={actual}")
            elif attribute == "ready" and actual is not True:
                problems.append(f"vmid {guest['vmid']}: not ready")
        findings.append(
            finding_from(
                check=check,
                observed=unobserved == 0,
                ok=not problems,
                detail=(
                    f"{unobserved} guest(s) did not report {label}"
                    if unobserved
                    else ("; ".join(problems) if problems else f"all guests match on {label}")
                ),
            )
        )

    return findings


def _check_network(
    network: dict, desired_vnets: list[dict], observed: ObservedInfrastructure
) -> list[CheckFinding]:
    zone_name = (network.get("zone") or {}).get("name")
    live_vnets = {vnet.name: vnet for vnet in observed.vnets}

    problems: list[str] = []
    unobserved = 0
    if zone_name and zone_name not in observed.zones:
        problems.append(f"SDN zone {zone_name!r} not observed")
    for vnet in desired_vnets:
        live = live_vnets.get(str(vnet["name"]))
        if live is None:
            problems.append(f"VNet {vnet['name']!r} not observed")
            continue
        if live.vlan_tag is None or live.cidr is None:
            unobserved += 1
            continue
        if live.vlan_tag != vnet["vlan_tag"]:
            problems.append(f"VNet {vnet['name']}: vlan {live.vlan_tag} != {vnet['vlan_tag']}")
        if live.cidr != vnet["subnet"]["cidr"]:
            problems.append(f"VNet {vnet['name']}: cidr {live.cidr} != {vnet['subnet']['cidr']}")
    return [
        finding_from(
            check=VerificationCheck.network_objects,
            observed=unobserved == 0,
            ok=not problems,
            detail=(
                f"{unobserved} VNet(s) did not report a tag or subnet"
                if unobserved
                else (
                    "; ".join(problems)
                    if problems
                    else f"zone and {len(desired_vnets)} VNet(s) match"
                )
            ),
        )
    ]


def _check_firewall(network: dict, observed: ObservedInfrastructure) -> CheckFinding:
    """Compares firewall OBJECTS only.

    Deliberately does not conclude anything about isolation: the objects existing says nothing
    about whether traffic is actually blocked. That verdict comes from probes.
    """
    expected_groups = {str(g["name"]) for g in network.get("security_groups", [])}
    expected_sets = {str(i["name"]) for i in network.get("ip_sets", [])}
    missing_groups = sorted(expected_groups - set(observed.security_groups))
    missing_sets = sorted(expected_sets - set(observed.ip_sets))
    return finding_from(
        check=VerificationCheck.firewall_objects,
        observed=True,
        ok=not missing_groups and not missing_sets,
        detail=(
            f"{len(expected_groups)} security group(s) and {len(expected_sets)} IPSet(s) present"
            if not missing_groups and not missing_sets
            else f"missing groups {missing_groups}, missing ipsets {missing_sets}"
        ),
    )


def _check_state_agreement(observed: ObservedInfrastructure) -> CheckFinding:
    if observed.tofu_state_addresses is None or observed.observed_addresses is None:
        return finding_from(
            check=VerificationCheck.state_agreement,
            observed=False,
            ok=False,
            detail="OpenTofu state or the provider observation was not collected for comparison",
        )
    in_state = set(observed.tofu_state_addresses)
    in_provider = set(observed.observed_addresses)
    only_state = sorted(in_state - in_provider)
    only_provider = sorted(in_provider - in_state)
    return finding_from(
        check=VerificationCheck.state_agreement,
        observed=True,
        ok=not only_state and not only_provider,
        detail=(
            f"state and provider agree on {len(in_state)} resource(s)"
            if not only_state and not only_provider
            else f"in state only: {only_state}; on provider only: {only_provider}"
        ),
    )


def _check_reachability(
    desired_vnets: list[dict],
    desired_guests: list[dict],
    prober: SegmentProber | None,
    *,
    management_cidrs: tuple[str, ...],
    protected_cidrs: tuple[str, ...],
    external_probe_addresses: tuple[str, ...],
    scoring_port: int,
) -> list[CheckFinding]:
    """Reachability verdicts from actual probes. With no prober, every verdict is unobserved."""
    checks = (
        VerificationCheck.required_reachability,
        VerificationCheck.cross_team_denial,
        VerificationCheck.management_denial,
        VerificationCheck.protected_denial,
        VerificationCheck.external_denial,
    )
    if prober is None:
        return [
            finding_from(
                check=check,
                observed=False,
                ok=False,
                detail=(
                    "no segment prober was supplied; reachability was not tested. Isolation is "
                    "never inferred from configuration, so this is unproved rather than assumed."
                ),
            )
            for check in checks
        ]

    by_name = {str(v["name"]): v for v in desired_vnets}
    teams: dict[str, list[dict]] = {}
    scoring: list[dict] = []
    for vnet in desired_vnets:
        team = (vnet.get("ownership") or {}).get("team_ref")
        if vnet.get("role") == "scoring":
            scoring.append(vnet)
        elif team:
            teams.setdefault(team, []).append(vnet)

    guest_addresses: dict[str, list[str]] = {}
    for guest in desired_guests:
        for nic in guest.get("nics", []):
            guest_addresses.setdefault(str(nic["vnet_name"]), []).append(
                str(guest["address"]["published_address"])
            )

    findings: list[CheckFinding] = []

    # -- required: attacker -> its own team's target, and every team -> scoring --------
    required_failures: list[str] = []
    required_unknown: list[str] = []
    for _team, vnets in sorted(teams.items()):
        attacker = next((v for v in vnets if v.get("role") == "attacker"), None)
        target = next((v for v in vnets if v.get("role") == "vulnerable"), None)
        if attacker and target:
            for address in guest_addresses.get(str(target["name"]), []):
                verdict = prober.probe(
                    from_segment=str(attacker["name"]), to_address=address, port=80
                )
                if verdict is ProbeVerdict.unknown:
                    required_unknown.append(f"{attacker['name']} -> {address}:80")
                elif verdict is not ProbeVerdict.reachable:
                    required_failures.append(f"{attacker['name']} cannot reach target {address}:80")
        for scoring_vnet in scoring:
            source = attacker or (vnets[0] if vnets else None)
            if source is None:
                continue
            address = _first_host(str(scoring_vnet["subnet"]["cidr"]))
            verdict = prober.probe(
                from_segment=str(source["name"]), to_address=address, port=scoring_port
            )
            if verdict is ProbeVerdict.unknown:
                required_unknown.append(f"{source['name']} -> {address}:{scoring_port}")
            elif verdict is not ProbeVerdict.reachable:
                required_failures.append(
                    f"{source['name']} cannot reach scoring {address}:{scoring_port}"
                )
    findings.append(
        finding_from(
            check=VerificationCheck.required_reachability,
            observed=not required_unknown,
            ok=not required_failures,
            detail=(
                f"{len(required_unknown)} required probe(s) returned unknown"
                if required_unknown
                else (
                    "; ".join(required_failures)
                    if required_failures
                    else "attacker->target and team->scoring both reachable"
                )
            ),
        )
    )

    # -- denials: every one of these must come back blocked ---------------------------
    def denial_check(
        check: VerificationCheck, probes: list[tuple[str, str, int]], label: str
    ) -> CheckFinding:
        violations: list[str] = []
        unknown: list[str] = []
        for segment, address, port in probes:
            verdict = prober.probe(from_segment=segment, to_address=address, port=port)
            if verdict is ProbeVerdict.unknown:
                unknown.append(f"{segment} -> {address}:{port}")
            elif verdict is ProbeVerdict.reachable:
                violations.append(f"{segment} REACHED {address}:{port}")
        return finding_from(
            check=check,
            observed=not unknown,
            ok=not violations,
            detail=(
                f"{len(unknown)} probe(s) returned unknown; {label} unproved"
                if unknown
                else ("; ".join(violations) if violations else f"{label} holds")
            ),
        )

    cross: list[tuple[str, str, int]] = []
    for team, vnets in sorted(teams.items()):
        for other_team, other_vnets in sorted(teams.items()):
            if other_team == team:
                continue
            for source in vnets:
                for dest in other_vnets:
                    for address in guest_addresses.get(
                        str(dest["name"]), [_first_host(str(dest["subnet"]["cidr"]))]
                    ):
                        cross.append((str(source["name"]), address, 80))
    findings.append(denial_check(VerificationCheck.cross_team_denial, cross, "cross-team denial"))

    findings.append(
        denial_check(
            VerificationCheck.management_denial,
            [
                (name, _first_host(cidr), port)
                for name in sorted(by_name)
                for cidr in management_cidrs
                for port in (22, 8006)
            ],
            "management-network denial",
        )
    )
    findings.append(
        denial_check(
            VerificationCheck.protected_denial,
            [
                (name, _first_host(cidr), port)
                for name in sorted(by_name)
                for cidr in protected_cidrs
                for port in (22, 443)
            ],
            "protected-network denial",
        )
    )
    findings.append(
        denial_check(
            VerificationCheck.external_denial,
            [
                (name, address, 443)
                for name in sorted(by_name)
                for address in external_probe_addresses
            ],
            "external denial",
        )
    )
    return findings
