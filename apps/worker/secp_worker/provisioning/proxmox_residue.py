"""Ownership-bounded deletion and the zero-residue proof. Worker-only.

This module answers two questions that are easy to conflate and must not be:

**What are we allowed to delete?** Only what we can prove we own, and ownership is proved by tags
read back off the live object — never by a name, never by a vmid matching our records. An object
sitting at one of our allocated ids that does not carry our stamp is *protected*: it is excluded
from the deletion set, its reservation is NOT released, and the range cannot be declared clean.
Deleting it because it resembles what we expected is how a destroy removes somebody else's machine.

**Did we actually leave nothing behind?** Only when a probe that was itself demonstrably working
said so, for every resource class the range can own. This repository has already shipped a false
``clean`` once: a teardown reported success while a container ran, because the removal step and the
"is it actually gone?" step shared a failure mode — the daemon being unreachable made the removal
fail and made the existence check return nothing, and "nothing found" was read as "nothing there".

THE THIRD STATE, AND WHERE IT COMES FROM
-----------------------------------------
:class:`~secp_api.range_providers.base.TeardownResourceOutcome` already has three members, and this
module's job is to make sure the third one is actually reachable. Every residue class is mapped to
the PROBE DOMAIN that can answer for it (:data:`CLASS_PROBE_DOMAIN`), and each domain carries its
own health flag measured *after* the deletion attempts. When a domain's probe could not run, every
class in that domain reports ``unproven`` — never ``removed``. That is the structural version of
"a probe that can fail for the same reason as the thing it probes must report a third state": the
health flag and the observation come from the same call, so an unreachable provider cannot produce
an empty inventory that reads as success.

NOTHING IS CLEAN BY OMISSION
-----------------------------
:func:`residue_verdict` is driven by the EXPECTED resource list, not by the findings it was handed.
A resource with no finding at all is ``unproven``, exactly as a resource with a failed probe is.
A proof that grades itself against the answers it happens to have is not a proof, and an empty
finding set must never read as a clean teardown.

RESERVATIONS ARE RELEASED LAST, AND ONLY ON PROOF
--------------------------------------------------
VM ids, MACs, addresses, subnets, VLAN tags and remote-state keys stay held until the object that
occupied them is CONFIRMED absent. :meth:`~secp_api.range_providers.proxmox_ipam.AllocationLedger.
release` already refuses to release without ``absence_proved``; this module never passes that flag
a literal, only a value derived from a finding, so the ledger's guard is a real backstop rather
than a formality.

No privileged execution: no subprocess, no socket, no provider client, no database session.
Observations and probe results are supplied; collecting them is the caller's job.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from secp_api.range_enums import ResidueVerdict
from secp_api.range_providers.base import TeardownResourceOutcome
from secp_api.range_providers.proxmox_ipam import AllocationKind, AllocationLedger
from secp_api.range_providers.proxmox_model import ObjectProvenance, Ownership, is_owned_by_secp

from secp_worker.provisioning.proxmox_verification import ObservedInfrastructure


class ResidueClass(str, Enum):
    """Every class of thing a Proxmox range can leave behind.

    The list is the coverage contract. A class that is not here is a class nobody looks for after a
    destroy, so adding a new kind of owned object means adding a member and being forced by
    :func:`residue_verdict` to produce a finding for it.
    """

    # -- provider objects ---------------------------------------------------------------
    qemu_vm = "qemu_vm"
    lxc_container = "lxc_container"
    disk_volume = "disk_volume"
    nic = "nic"
    sdn_zone = "sdn_zone"
    vnet = "vnet"
    bridge = "bridge"
    subnet = "subnet"
    vlan_assignment = "vlan_assignment"
    firewall_group = "firewall_group"
    firewall_rule = "firewall_rule"
    ip_set = "ip_set"
    firewall_alias = "firewall_alias"
    cloud_init_snippet = "cloud_init_snippet"
    bootstrap_object = "bootstrap_object"
    # -- things we hold rather than things that exist on the provider -------------------
    vmid_reservation = "vmid_reservation"
    mac_reservation = "mac_reservation"
    ip_reservation = "ip_reservation"
    subnet_reservation = "subnet_reservation"
    vlan_reservation = "vlan_reservation"
    remote_state_key_reservation = "remote_state_key_reservation"
    # -- local and remote artifacts of the operation itself -----------------------------
    transient_workspace = "transient_workspace"
    binary_plan_file = "binary_plan_file"
    temporary_credential_file = "temporary_credential_file"
    remote_state_object = "remote_state_object"


class ProbeDomain(str, Enum):
    """Which probe can answer for a residue class, and therefore whose health decides it."""

    #: The Proxmox API observation.
    provider = "provider"
    #: The worker's own filesystem: workspace, binary plan, temporary credential material.
    local_artifact = "local_artifact"
    #: The remote-state backend.
    remote_state = "remote_state"
    #: The allocation ledger — our own record, answered by whether the release happened.
    ledger = "ledger"


#: Every residue class mapped to the domain that can answer for it. Exhaustiveness is enforced by
#: a test rather than trusted: a class with no domain would silently never be probed.
CLASS_PROBE_DOMAIN: dict[ResidueClass, ProbeDomain] = {
    ResidueClass.qemu_vm: ProbeDomain.provider,
    ResidueClass.lxc_container: ProbeDomain.provider,
    ResidueClass.disk_volume: ProbeDomain.provider,
    ResidueClass.nic: ProbeDomain.provider,
    ResidueClass.sdn_zone: ProbeDomain.provider,
    ResidueClass.vnet: ProbeDomain.provider,
    ResidueClass.bridge: ProbeDomain.provider,
    ResidueClass.subnet: ProbeDomain.provider,
    ResidueClass.vlan_assignment: ProbeDomain.provider,
    ResidueClass.firewall_group: ProbeDomain.provider,
    ResidueClass.firewall_rule: ProbeDomain.provider,
    ResidueClass.ip_set: ProbeDomain.provider,
    ResidueClass.firewall_alias: ProbeDomain.provider,
    ResidueClass.cloud_init_snippet: ProbeDomain.provider,
    ResidueClass.bootstrap_object: ProbeDomain.provider,
    ResidueClass.vmid_reservation: ProbeDomain.ledger,
    ResidueClass.mac_reservation: ProbeDomain.ledger,
    ResidueClass.ip_reservation: ProbeDomain.ledger,
    ResidueClass.subnet_reservation: ProbeDomain.ledger,
    ResidueClass.vlan_reservation: ProbeDomain.ledger,
    ResidueClass.remote_state_key_reservation: ProbeDomain.ledger,
    ResidueClass.transient_workspace: ProbeDomain.local_artifact,
    ResidueClass.binary_plan_file: ProbeDomain.local_artifact,
    ResidueClass.temporary_credential_file: ProbeDomain.local_artifact,
    ResidueClass.remote_state_object: ProbeDomain.remote_state,
}

#: The reservation classes, and the ledger allocation kind each one releases.
RESERVATION_ALLOCATION_KIND: dict[ResidueClass, tuple[AllocationKind, ...]] = {
    ResidueClass.vmid_reservation: (AllocationKind.vmid, AllocationKind.lxc_id),
    ResidueClass.mac_reservation: (AllocationKind.mac,),
    ResidueClass.ip_reservation: (
        AllocationKind.guest_address,
        AllocationKind.gateway_address,
    ),
    ResidueClass.subnet_reservation: (AllocationKind.subnet,),
    ResidueClass.vlan_reservation: (AllocationKind.vlan_tag,),
    ResidueClass.remote_state_key_reservation: (AllocationKind.remote_state_key,),
}


@dataclass(frozen=True)
class OwnedResource:
    """One thing this range's records say it owns.

    ``expected_ownership`` is present for objects whose ownership is tag-readable. Where it is
    ``None`` the object carries no readable stamp (a disk volume, a workspace directory), and
    ownership is established by the object being named in this range's own approved records — which
    is why those records are the only place such a resource may come from.
    """

    residue_class: ResidueClass
    #: The provider-side or filesystem identifier: a vmid, a VNet name, a volume id, a path.
    identifier: str
    #: The OpenTofu resource address, where the resource has one. Used for the deletion-set hash.
    address: str | None = None
    expected_ownership: Ownership | None = None
    #: ``(scope, kind, purpose)`` when releasing this resource releases a ledger allocation.
    allocation_key: tuple[tuple[str, str, str, str, int], AllocationKind, str] | None = None

    @property
    def domain(self) -> ProbeDomain:
        return CLASS_PROBE_DOMAIN[self.residue_class]


@dataclass(frozen=True)
class ProtectedResource:
    """Something at one of our identifiers that we proved we must NOT touch."""

    resource: OwnedResource
    provenance: ObjectProvenance
    detail: str


@dataclass(frozen=True)
class SupplementalObservation:
    """Provider-side inventory the #107 observation does not carry.

    Additive on purpose: :class:`~secp_worker.provisioning.proxmox_verification.
    ObservedInfrastructure` is the verification contract and is not widened here. Every field is
    ``| None`` with the same meaning it has there — ``None`` is "not observed", which blocks a
    ``removed`` verdict rather than implying one.
    """

    disk_volume_ids: tuple[str, ...] | None = None
    nic_macs: tuple[str, ...] | None = None
    bridges: tuple[str, ...] | None = None
    subnet_cidrs: tuple[str, ...] | None = None
    vlan_tags_in_use: tuple[int, ...] | None = None
    firewall_rule_ids: tuple[str, ...] | None = None
    firewall_aliases: tuple[str, ...] | None = None
    cloud_init_snippet_ids: tuple[str, ...] | None = None
    bootstrap_object_ids: tuple[str, ...] | None = None


@dataclass(frozen=True)
class ArtifactProbe:
    """What the worker's own filesystem still holds.

    ``readable`` is the health of THIS probe, measured after the cleanup attempts. A probe that
    could not stat its own directories reports ``readable=False``, and everything in its domain
    becomes ``unproven`` — an unreadable filesystem returning "no files found" is not evidence.
    """

    readable: bool
    present_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class RemoteStateProbe:
    """What the remote-state backend still holds."""

    readable: bool
    present_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeletionSet:
    """The ownership-bounded outcome of planning a destroy.

    The four buckets are exhaustive over the resources handed in, and a resource lands in exactly
    one. ``undetermined`` exists because "we could not tell whether this is ours" is a third answer
    to the ownership question, and it must not collapse into either of the other two.
    """

    deletable: tuple[OwnedResource, ...] = ()
    protected: tuple[ProtectedResource, ...] = ()
    already_absent: tuple[OwnedResource, ...] = ()
    undetermined: tuple[OwnedResource, ...] = ()

    @property
    def deletion_addresses(self) -> tuple[str, ...]:
        """Addresses of exactly what would be deleted, for the destroy gate's deletion-set hash."""
        return tuple(sorted({r.address for r in self.deletable if r.address}))

    @property
    def may_proceed(self) -> bool:
        """A destroy may run even with protected objects — it just cannot then be ``clean``.

        Refusing outright would leave the range's own resources standing because someone else's
        object happens to sit at one of our ids. Deleting what we own and reporting the rest is
        both safer and more useful; :func:`residue_verdict` makes sure it is never called clean.
        """
        return not self.undetermined


@dataclass(frozen=True)
class AbsenceFinding:
    """One resource's absence outcome, plus the health of the probe that decided it."""

    resource: OwnedResource
    outcome: TeardownResourceOutcome
    #: The health of the probe domain at the moment this was decided. False forces ``unproven``.
    probe_healthy: bool
    detail: str

    @property
    def absence_proved(self) -> bool:
        """The ONLY thing a reservation release may be gated on."""
        return self.probe_healthy and self.outcome is TeardownResourceOutcome.removed


def bound_deletion_set(
    owned: tuple[OwnedResource, ...],
    observed: ObservedInfrastructure,
    supplemental: SupplementalObservation | None = None,
) -> DeletionSet:
    """Decide what this destroy is allowed to delete. Ownership is read from tags, never names.

    A resource is ``deletable`` only when a working observation found it AND — where the object
    carries a readable stamp — that stamp is this range's. Anything else at one of our identifiers
    is ``protected`` and is never touched, whatever its name says.
    """
    if not observed.reachable:
        # Nothing can be classified. Every resource is undetermined, and `may_proceed` is False, so
        # a destroy cannot run at all against an unobservable provider.
        return DeletionSet(undetermined=tuple(sorted(owned, key=_sort_key)))

    supplemental = supplemental or SupplementalObservation()
    guests_by_vmid = {guest.vmid: guest for guest in observed.guests}

    deletable: list[OwnedResource] = []
    protected: list[ProtectedResource] = []
    already_absent: list[OwnedResource] = []
    undetermined: list[OwnedResource] = []

    for resource in sorted(owned, key=_sort_key):
        if resource.domain is not ProbeDomain.provider:
            # Ledger and artifact resources are ours by construction: they exist only because this
            # operation created them, and nothing else can be sitting at their identifier.
            deletable.append(resource)
            continue

        if resource.residue_class in (ResidueClass.qemu_vm, ResidueClass.lxc_container):
            live = guests_by_vmid.get(_as_int(resource.identifier))
            if live is None:
                already_absent.append(resource)
                continue
            if resource.expected_ownership is None:
                undetermined.append(resource)
                continue
            if live.tags is None:
                # The object is there and its tags were NOT read. We do not know whose it is, and
                # "it is at the vmid we recorded" is not an answer — that is precisely the
                # reasoning that deletes a stranger's VM.
                undetermined.append(resource)
                continue
            provenance = is_owned_by_secp(live.tags, resource.expected_ownership)
            if provenance is ObjectProvenance.secp_owned:
                deletable.append(resource)
            else:
                protected.append(
                    ProtectedResource(
                        resource=resource,
                        provenance=provenance,
                        detail=(
                            f"an object exists at vmid {resource.identifier} but its ownership "
                            f"reads as {provenance.value}; it is not ours and will not be removed, "
                            "however closely its name matches what we expected"
                        ),
                    )
                )
            continue

        present, observable = _observe_simple(resource, observed, supplemental)
        if not observable:
            undetermined.append(resource)
        elif present:
            deletable.append(resource)
        else:
            already_absent.append(resource)

    return DeletionSet(
        deletable=tuple(deletable),
        protected=tuple(protected),
        already_absent=tuple(already_absent),
        undetermined=tuple(undetermined),
    )


def _sort_key(resource: OwnedResource) -> tuple[str, str]:
    return (resource.residue_class.value, resource.identifier)


def _as_int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def _observe_simple(
    resource: OwnedResource,
    observed: ObservedInfrastructure,
    supplemental: SupplementalObservation,
) -> tuple[bool, bool]:
    """``(present, observable)`` for the provider classes with no per-object ownership tag.

    ``observable`` is False when the relevant inventory was never collected. It is returned
    separately from ``present`` for the same reason ``observed`` is separate from ``ok`` in the
    verification contract: an uncollected inventory is not an empty one.
    """
    identifier = resource.identifier
    match resource.residue_class:
        case ResidueClass.sdn_zone:
            return identifier in observed.zones, True
        case ResidueClass.vnet:
            return any(vnet.name == identifier for vnet in observed.vnets), True
        case ResidueClass.firewall_group:
            return identifier in observed.security_groups, True
        case ResidueClass.ip_set:
            return identifier in observed.ip_sets, True
        case ResidueClass.disk_volume:
            source: tuple[object, ...] | None = supplemental.disk_volume_ids
        case ResidueClass.nic:
            source = supplemental.nic_macs
            identifier = identifier.upper()
            source = None if source is None else tuple(str(m).upper() for m in source)
        case ResidueClass.bridge:
            source = supplemental.bridges
        case ResidueClass.subnet:
            source = supplemental.subnet_cidrs
        case ResidueClass.vlan_assignment:
            source = (
                None
                if supplemental.vlan_tags_in_use is None
                else tuple(str(tag) for tag in supplemental.vlan_tags_in_use)
            )
        case ResidueClass.firewall_rule:
            source = supplemental.firewall_rule_ids
        case ResidueClass.firewall_alias:
            source = supplemental.firewall_aliases
        case ResidueClass.cloud_init_snippet:
            source = supplemental.cloud_init_snippet_ids
        case ResidueClass.bootstrap_object:
            source = supplemental.bootstrap_object_ids
        case _:  # pragma: no cover - every provider class is handled above
            return False, False
    if source is None:
        return False, False
    return identifier in source, True


def verify_absence(
    expected: tuple[OwnedResource, ...],
    *,
    observed: ObservedInfrastructure,
    supplemental: SupplementalObservation | None = None,
    artifacts: ArtifactProbe,
    remote_state: RemoteStateProbe,
) -> tuple[AbsenceFinding, ...]:
    """Prove, per resource, whether it is actually gone. Reservations are handled separately.

    ``observed`` MUST be a fresh observation taken after the deletion attempts — not the one the
    deletion set was planned from. The whole hazard this guards is that the delete and the check
    fail together, and reusing a pre-delete observation reintroduces it in a new shape.
    """
    supplemental = supplemental or SupplementalObservation()
    findings: list[AbsenceFinding] = []

    for resource in sorted(expected, key=_sort_key):
        domain = resource.domain
        if domain is ProbeDomain.ledger:
            # Not answered here: a reservation's fate follows the release, in
            # `reservation_findings`. Including a placeholder verdict would be a finding nobody
            # produced from a probe.
            continue

        if domain is ProbeDomain.provider:
            if not observed.reachable:
                findings.append(_unproven(resource, "the provider could not be observed"))
                continue
            if resource.residue_class in (ResidueClass.qemu_vm, ResidueClass.lxc_container):
                live = next(
                    (g for g in observed.guests if g.vmid == _as_int(resource.identifier)), None
                )
                present, observable = live is not None, True
            else:
                present, observable = _observe_simple(resource, observed, supplemental)
            if not observable:
                findings.append(
                    _unproven(
                        resource,
                        f"the {resource.residue_class.value} inventory was never collected, so "
                        "absence was not proved",
                    )
                )
            else:
                findings.append(_present_or_removed(resource, present, probe_healthy=True))
            continue

        if domain is ProbeDomain.local_artifact:
            if not artifacts.readable:
                findings.append(
                    _unproven(resource, "the worker's own filesystem could not be inspected")
                )
            else:
                findings.append(
                    _present_or_removed(
                        resource, resource.identifier in artifacts.present_paths, probe_healthy=True
                    )
                )
            continue

        if not remote_state.readable:
            findings.append(_unproven(resource, "the remote-state backend could not be read"))
        else:
            findings.append(
                _present_or_removed(
                    resource, resource.identifier in remote_state.present_keys, probe_healthy=True
                )
            )

    return tuple(findings)


def _unproven(resource: OwnedResource, reason: str) -> AbsenceFinding:
    return AbsenceFinding(
        resource=resource,
        outcome=TeardownResourceOutcome.unproven,
        probe_healthy=False,
        detail=(
            f"{reason}; this resource may or may not exist. An unreachable probe returning nothing "
            "is not evidence of absence."
        ),
    )


def _present_or_removed(
    resource: OwnedResource, present: bool, *, probe_healthy: bool
) -> AbsenceFinding:
    return AbsenceFinding(
        resource=resource,
        outcome=(TeardownResourceOutcome.present if present else TeardownResourceOutcome.removed),
        probe_healthy=probe_healthy,
        detail=(
            f"{resource.residue_class.value} {resource.identifier!r} is still present"
            if present
            else f"{resource.residue_class.value} {resource.identifier!r} confirmed absent"
        ),
    )


@dataclass(frozen=True)
class ReleaseDecision:
    """Whether one ledger allocation may be released, and why."""

    allocation_key: tuple[tuple[str, str, str, str, int], AllocationKind, str]
    residue_class: ResidueClass
    release: bool
    reason: str


def releasable_allocations(
    findings: tuple[AbsenceFinding, ...],
    *,
    protected: tuple[ProtectedResource, ...] = (),
) -> tuple[ReleaseDecision, ...]:
    """Decide which reservations may be released. Only proved absence releases anything.

    A protected resource's reservation is retained without exception: something is sitting at that
    identifier, and handing the identifier to the next range would put a new guest on top of an
    object we already established is not ours.
    """
    protected_identifiers = {
        (item.resource.residue_class, item.resource.identifier) for item in protected
    }
    decisions: list[ReleaseDecision] = []
    for finding in sorted(findings, key=lambda f: _sort_key(f.resource)):
        key = finding.resource.allocation_key
        if key is None:
            continue
        residue_class = _reservation_class_for(key[1])
        if residue_class is None:
            continue
        if (finding.resource.residue_class, finding.resource.identifier) in protected_identifiers:
            decisions.append(
                ReleaseDecision(
                    allocation_key=key,
                    residue_class=residue_class,
                    release=False,
                    reason=(
                        "an object that is not ours occupies this identifier; releasing it would "
                        "hand the next range an identifier something else already holds"
                    ),
                )
            )
            continue
        decisions.append(
            ReleaseDecision(
                allocation_key=key,
                residue_class=residue_class,
                # Derived from the finding, never asserted. `absence_proved` is False whenever the
                # probe was unhealthy, so an unreachable provider releases nothing.
                release=finding.absence_proved,
                reason=(
                    "absence was proved by a working probe"
                    if finding.absence_proved
                    else f"absence was not proved ({finding.outcome.value}); the reservation stays "
                    "held"
                ),
            )
        )
    return tuple(decisions)


def _reservation_class_for(kind: AllocationKind) -> ResidueClass | None:
    for residue_class, kinds in RESERVATION_ALLOCATION_KIND.items():
        if kind in kinds:
            return residue_class
    return None


def release_proved_allocations(
    ledger: AllocationLedger,
    decisions: tuple[ReleaseDecision, ...],
) -> tuple[tuple[ReleaseDecision, ...], tuple[ReleaseDecision, ...], tuple[ReleaseDecision, ...]]:
    """Release exactly the reservations whose absence was proved.

    Returns ``(released, retained, already_released)``.

    ``absence_proved`` is passed through from the decision rather than hard-coded, so the ledger's
    own refusal remains a real second line of defence: if this function's logic were ever wrong,
    :meth:`AllocationLedger.release` raises instead of quietly freeing an id whose guest may still
    be running.

    An allocation the ledger does not hold is reported as ``already_released`` rather than raising.
    A destroy interrupted partway through its release phase must be safe to re-run, and an
    allocation nobody holds is not a reservation anybody can collide with. It is reported
    separately rather than folded into ``released`` because the two are different facts: one is
    something this run freed, the other is something this run found already free.
    """
    released: list[ReleaseDecision] = []
    retained: list[ReleaseDecision] = []
    already_released: list[ReleaseDecision] = []
    for decision in decisions:
        if not decision.release:
            retained.append(decision)
            continue
        scope, kind, purpose = decision.allocation_key
        if ledger.get(scope, kind, purpose) is None:
            already_released.append(decision)
            continue
        ledger.release(
            scope=scope,
            kind=kind,
            purpose=purpose,
            absence_proved=decision.release,
            proof_detail=decision.reason,
        )
        released.append(decision)
    return tuple(released), tuple(retained), tuple(already_released)


def reservation_findings(
    decisions: tuple[ReleaseDecision, ...],
    released: tuple[ReleaseDecision, ...],
) -> tuple[AbsenceFinding, ...]:
    """Turn release outcomes into findings, so reservations are graded like everything else.

    A released reservation is ``removed``; a retained one whose backing absence was unproved is
    ``unproven``, not ``present`` — the distinction is what tells an operator whether to look at
    the provider or simply to wait.
    """
    released_keys = {decision.allocation_key for decision in released}
    findings: list[AbsenceFinding] = []
    for decision in sorted(decisions, key=lambda d: (d.residue_class.value, str(d.allocation_key))):
        scope, kind, purpose = decision.allocation_key
        resource = OwnedResource(
            residue_class=decision.residue_class,
            identifier=f"{kind.value}:{purpose}",
            allocation_key=decision.allocation_key,
        )
        if decision.allocation_key in released_keys:
            findings.append(
                AbsenceFinding(
                    resource=resource,
                    outcome=TeardownResourceOutcome.removed,
                    probe_healthy=True,
                    detail="reservation released after absence was proved",
                )
            )
        else:
            findings.append(
                AbsenceFinding(
                    resource=resource,
                    outcome=TeardownResourceOutcome.unproven,
                    probe_healthy=False,
                    detail=f"reservation retained: {decision.reason}",
                )
            )
    return tuple(findings)


def residue_verdict(
    findings: tuple[AbsenceFinding, ...],
    *,
    expected: tuple[OwnedResource, ...],
    protected: tuple[ProtectedResource, ...] = (),
) -> ResidueVerdict:
    """The single headline verdict, graded against what was EXPECTED rather than what was answered.

    Precedence:

    1. ``residue`` — something owned was confirmed still present. The most actionable answer, so it
       outranks an unproven sibling: an operator who must go and delete something does not need to
       be told about a probe that also failed.
    2. ``unproven`` — any expected resource has no finding, or has a finding whose probe was not
       healthy, or a protected object occupies one of our identifiers. Not a shade of success.
    3. ``clean`` — every expected resource was confirmed absent by a working probe.

    An empty ``expected`` list yields ``unproven``: a teardown that expected nothing proved nothing.
    """
    if not expected:
        return ResidueVerdict.unproven

    by_identity = {(_sort_key(f.resource)): f for f in findings}
    saw_present = False
    saw_unproven = bool(protected)

    for resource in expected:
        finding = by_identity.get(_sort_key(resource))
        if finding is None:
            # Nothing looked at this at all. Silence is not absence.
            saw_unproven = True
            continue
        if not finding.probe_healthy:
            saw_unproven = True
        elif finding.outcome is TeardownResourceOutcome.present:
            saw_present = True
        elif finding.outcome is TeardownResourceOutcome.unproven:
            saw_unproven = True

    if saw_present:
        return ResidueVerdict.residue
    if saw_unproven:
        return ResidueVerdict.unproven
    return ResidueVerdict.clean


def uncovered_classes(
    findings: tuple[AbsenceFinding, ...],
    expected: tuple[OwnedResource, ...],
) -> tuple[ResidueClass, ...]:
    """Residue classes the range owned that nothing produced a finding for.

    Reported separately from the verdict so an operator can see *which* class went unexamined,
    rather than only that the teardown came back ``unproven``.
    """
    answered = {_sort_key(f.resource) for f in findings}
    return tuple(
        sorted({r.residue_class for r in expected if _sort_key(r) not in answered}, key=str)
    )


@dataclass(frozen=True)
class ZeroResidueProof:
    """The durable record of one destroy. Secret-free: identifiers and verdicts, never values."""

    verdict: ResidueVerdict
    expected_count: int
    confirmed_absent: int
    still_present: int
    unproven: int
    protected: tuple[str, ...] = ()
    uncovered: tuple[ResidueClass, ...] = ()
    released_reservations: int = 0
    retained_reservations: int = 0
    by_class: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def is_clean(self) -> bool:
        return self.verdict is ResidueVerdict.clean


def zero_residue_proof(
    findings: tuple[AbsenceFinding, ...],
    *,
    expected: tuple[OwnedResource, ...],
    protected: tuple[ProtectedResource, ...] = (),
    decisions: tuple[ReleaseDecision, ...] = (),
    released: tuple[ReleaseDecision, ...] = (),
    retained: tuple[ReleaseDecision, ...] = (),
) -> ZeroResidueProof:
    """Build the evidence record. The verdict is computed here, never passed in.

    Reservation findings are composed HERE rather than by the caller. :func:`verify_absence` cannot
    answer for a reservation — its fate follows the release, which happens later — so a caller
    grading the two separately has to remember to add them to both the findings and the expected
    list, and forgetting either half produces a wrong verdict in a different direction each time.
    Composing once, in the one function that produces the durable record, removes that choice.
    """
    reservations = reservation_findings(decisions, released)
    findings = tuple(findings) + reservations
    expected = tuple(expected) + tuple(f.resource for f in reservations)

    by_class: dict[str, dict[str, int]] = {}
    confirmed = present = unproven = 0
    for finding in findings:
        bucket = by_class.setdefault(finding.resource.residue_class.value, {})
        effective = (
            TeardownResourceOutcome.unproven if not finding.probe_healthy else finding.outcome
        )
        bucket[effective.value] = bucket.get(effective.value, 0) + 1
        if effective is TeardownResourceOutcome.removed:
            confirmed += 1
        elif effective is TeardownResourceOutcome.present:
            present += 1
        else:
            unproven += 1

    return ZeroResidueProof(
        verdict=residue_verdict(findings, expected=expected, protected=protected),
        expected_count=len(expected),
        confirmed_absent=confirmed,
        still_present=present,
        unproven=unproven,
        protected=tuple(
            sorted(f"{p.resource.residue_class.value}:{p.resource.identifier}" for p in protected)
        ),
        uncovered=uncovered_classes(findings, expected),
        released_reservations=len(released),
        retained_reservations=len(retained),
        by_class={key: dict(sorted(value.items())) for key, value in sorted(by_class.items())},
    )
