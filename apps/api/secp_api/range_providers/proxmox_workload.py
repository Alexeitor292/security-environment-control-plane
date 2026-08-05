"""The Web Breach Lab workload compiler — guests placed onto an already-segregated network.

:mod:`secp_api.range_providers.proxmox_network` compiles the *empty* range: an SDN zone, one VNet
per team segment, the addressing, and the firewall objects that isolate them. It stops there on
purpose, because a segment is provable in isolation while a workload is not. This module is the
other half: it turns the shipped product definition in :mod:`secp_api.range_catalog` — OWASP Juice
Shop, DVWA where the template includes it, the challenges and the flags — into the concrete guests
that run on those segments, per team, for a two-team competition.

WHAT THIS MODULE REFUSES TO INVENT
-----------------------------------
Every value that decides *what software actually boots* is an input, reviewed by a human, or the
compile blocks:

``ReviewedGuestImage``  binds one catalog component to one template that discovery actually
                        observed, at a pinned version, with a content digest. No digest, no
                        approval reference, or a floating tag — no plan. "Immutable base image" is
                        not a claim this module makes on the operator's behalf; it is a property of
                        an input that carries a digest, and an input without one is refused.
``GuestProfile``        cpu, memory and disk. Never defaulted from the catalog, which describes
                        containers on a laptop and says nothing about a VM's sizing.
``placement``           which node each guest lands on. A proposal is generated deterministically
                        when the operator supplies none, but it is written into the desired state,
                        so the plan an operator approves NAMES the node — and a later compile that
                        would move a guest changes the desired-state hash and is refused by the
                        apply gate rather than silently re-placing it.

WHY THE SCOREBOARD IS NOT A GUEST
----------------------------------
The authoritative scoreboard is the native SECP competition core (:mod:`secp_api.services.
competitions`), exactly as on the proven local Docker path. Compiling a scoring VM here would fork
the product into two scoreboards that can disagree. What the range needs instead is *reachability
to it*, which the network compiler already provides: the shared ``score`` segment, reachable one
way from every team. This module therefore pins the scoring endpoint to the scoring segment's first
host — the same address :func:`secp_worker.provisioning.proxmox_verification.verify_deployment`
probes for ``required_reachability`` — rather than inventing a second convention.

WHY THERE ARE NO SECRETS IN HERE
---------------------------------
Challenge flags, per-team credentials and guest attestation values are dynamic per range and per
team. Every one of them would end up in OpenTofu state if it travelled through the desired state,
and OpenTofu state is not a secret store. So this module compiles :class:`MaterialRef` — a
*reference* with no value field at all, which is why "the value leaked into the plan" is not
expressible here rather than merely discouraged. :func:`assert_no_durable_secrets` then proves the
rendered payload is clean by searching for the actual literals the caller holds, keying on content
rather than on whether a field happens to be named ``secret``.

PLAN READINESS IS NOT VERIFICATION
-----------------------------------
:func:`assess_competition_readiness` answers "would this plan, if applied exactly, constitute a
runnable two-team competition?". It reads the compiled artifact, so it catches a missing attacker
or an uncovered challenge before anything is created. It CANNOT and does not conclude anything
about a deployed range: isolation and reachability verdicts come only from observation, in
:mod:`secp_worker.provisioning.proxmox_verification`. The two vocabularies are deliberately
disjoint — nothing here returns a ``VerificationOutcome``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum

from secp_api.range_catalog import CatalogTemplate
from secp_api.range_enums import ComponentRole, RangeResourceKind
from secp_api.range_providers.proxmox_ipam import (
    AllocationKind,
    AllocationLedger,
    AllocationRequestLog,
    IpamPools,
)
from secp_api.range_providers.proxmox_model import (
    BlockedPlan,
    CloneStrategy,
    CloudInitSpec,
    CompiledTopology,
    DiskSpec,
    FirewallVerdict,
    GuestAddress,
    GuestKind,
    GuestSpec,
    MissingPrerequisite,
    NicSpec,
    Ownership,
    ProxmoxModelError,
    SegmentRole,
    SegregatedNetworkPlan,
    TargetObservation,
    VNetSpec,
)
from secp_api.range_providers.proxmox_network import evaluate_flow

#: The content type a Proxmox storage must accept before a QEMU disk may be pinned to it. A storage
#: whose observed content types are EMPTY is not "probably fine" — it was not observed, and pinning
#: a disk to it produces a plan that fails at apply.
STORAGE_CONTENT_IMAGES = "images"

#: Bootstrap is bounded. An unbounded post-provisioning script is an arbitrary remote-execution
#: surface on a machine that is deliberately vulnerable, and "it only does a few things" is not a
#: property anybody can check later. Ten is generous for install-and-configure and small enough
#: that the whole list fits in a plan document a human reads.
MAX_BOOTSTRAP_OPERATIONS = 10

#: The attacker workload is not a catalog component: the shipped Docker templates describe targets
#: and the scoring core, and the attacker is a Proxmox-only addition (a container image is not an
#: attack workstation). It gets its own key so the two never collide.
ATTACKER_WORKLOAD_KEY = "attacker"

#: A pinned version must be an actual version. ``latest``, ``main`` and an empty string are the
#: three ways a "pinned" workload silently becomes whatever was published this morning.
_FLOATING_TAGS = frozenset({"latest", "main", "master", "stable", "edge", "", "dev", "nightly"})

#: A digest we will accept as proof of an immutable base image.
_DIGEST_RE = re.compile(r"^[a-z0-9]+:[0-9a-f]{32,128}$")

#: Guest names are DNS labels (enforced again by :class:`GuestSpec`); this keeps the generated part
#: short enough that ``{prefix}-{team}-{workload}`` cannot overflow the label limit.
_MAX_NAME_PART = 16


class WorkloadRole(str, Enum):
    """What a guest is FOR inside the competition.

    Deliberately a separate vocabulary from :class:`~secp_api.range_enums.ComponentRole`, which
    describes the shipped Docker catalog and has no attacker member. Widening the shared enum to
    add one would change a persisted, provider-neutral vocabulary for a Proxmox-only concept.
    """

    #: The team's offensive workstation. Lands on the team's ``attacker`` segment.
    attacker = "attacker"
    #: An intentionally vulnerable application. Lands on the team's ``vulnerable`` segment.
    target = "target"
    #: A passive collector. Compiled only when the team's network plan includes a sensor segment.
    sensor = "sensor"


#: Which segment each workload role belongs on. A target on the attacker segment would be reachable
#: without crossing the segment boundary the whole lab exists to exercise, so the mapping is fixed
#: here rather than left to the caller.
_ROLE_SEGMENT: dict[WorkloadRole, SegmentRole] = {
    WorkloadRole.attacker: SegmentRole.attacker,
    WorkloadRole.target: SegmentRole.vulnerable,
    WorkloadRole.sensor: SegmentRole.sensor,
}


class WorkloadError(ProxmoxModelError):
    """A workload input was structurally invalid. Never contains a secret value."""


class MaterialScope(str, Enum):
    """How widely one piece of post-provisioning material is shared."""

    #: One value for the whole range (a shared challenge flag).
    range = "range"
    #: One value per team (a team credential, a per-team flag).
    team = "team"
    #: One value per guest (its bootstrap attestation).
    guest = "guest"


@dataclass(frozen=True)
class MaterialRef:
    """A reference to a value delivered AFTER provisioning, over a reviewed channel.

    There is no ``value`` field and there will not be one. The compiler, the manifest, the plan
    document and OpenTofu state therefore carry the fact that a value exists and what it is for,
    and never the value — which is the difference between a plan that is safe to persist and show
    and one that is not.
    """

    ref: str
    scope: MaterialScope
    purpose: str
    #: The reviewed channel that will deliver it. Named so a reviewer can check the channel exists.
    channel: str

    def __post_init__(self) -> None:
        if not self.ref or not self.purpose or not self.channel:
            raise WorkloadError("a material reference needs a ref, a purpose and a channel")


@dataclass(frozen=True)
class BootstrapOperation:
    """One bounded post-provisioning step, declared before anything runs.

    ``timeout_seconds`` is required because an operation with no bound is how a bootstrap ends up
    hanging forever and being reported as "still going" rather than as a closed failure.
    """

    key: str
    description: str
    timeout_seconds: int

    def __post_init__(self) -> None:
        if not self.key or not self.description:
            raise WorkloadError("a bootstrap operation needs a key and a description")
        if self.timeout_seconds <= 0:
            raise WorkloadError(f"bootstrap operation {self.key!r} needs a positive timeout")


@dataclass(frozen=True)
class ReviewedGuestImage:
    """A reviewed, immutable base image bound to a template discovery actually observed.

    ``template_ref`` must appear in :attr:`TargetObservation.templates`; the compiler never clones
    a template it has only been told about.
    """

    workload_key: str
    role: WorkloadRole
    template_ref: str
    #: The exact workload version this template contains, e.g. ``v17.1.0``. Never a floating tag.
    workload_version: str
    #: Content digest of the base image. Its presence is what makes "immutable" checkable.
    image_digest: str
    #: Who reviewed the template, recorded so the plan document can show it.
    approval_reference: str
    guest_kind: GuestKind = GuestKind.qemu
    #: ``full`` unless the operator has a reason; a linked clone dies with its template.
    clone_strategy: CloneStrategy = CloneStrategy.full
    #: The port the workload serves on. Used for the required-connectivity contract, not opened.
    service_port: int = 80

    def __post_init__(self) -> None:
        if not self.workload_key:
            raise WorkloadError("a reviewed image needs a workload key")
        if self.workload_version.lower() in _FLOATING_TAGS:
            raise WorkloadError(
                f"workload {self.workload_key!r} is pinned to {self.workload_version!r}, which is "
                "a floating tag; a reproducible range needs an exact version"
            )
        if not _DIGEST_RE.match(self.image_digest):
            raise WorkloadError(
                f"workload {self.workload_key!r} has no usable image digest; without one the base "
                "image cannot be shown to be immutable and the range is not reproducible"
            )
        if not self.approval_reference:
            raise WorkloadError(
                f"workload {self.workload_key!r} has no approval reference; an unreviewed template "
                "is exactly what a reviewed-template requirement excludes"
            )


@dataclass(frozen=True)
class GuestProfile:
    """Sizing for one guest. Never derived from the container catalog."""

    cpu_cores: int
    memory_mb: int
    disk_gb: int
    disk_slot: str = "scsi0"

    def __post_init__(self) -> None:
        if self.cpu_cores <= 0 or self.memory_mb <= 0 or self.disk_gb <= 0:
            raise WorkloadError("a guest profile needs positive cpu, memory and disk")


@dataclass(frozen=True)
class WorkloadRequest:
    """The workload an operator asked for, on top of an already-compiled segregated network."""

    organization_id: str
    target_id: str
    range_id: str
    generation: int
    operation_generation: int
    #: The shipped product definition. Its components and challenges are the contract.
    template: CatalogTemplate
    #: Must be exactly the teams the network was compiled for.
    team_refs: tuple[str, ...]
    images: tuple[ReviewedGuestImage, ...]
    profiles: dict[WorkloadRole, GuestProfile]
    #: cloud-init login user. Public keys only — :class:`CloudInitSpec` refuses private material.
    cloud_init_user: str = "secp"
    ssh_authorized_keys: tuple[str, ...] = ()
    #: Bounded post-provisioning operations, identical for every guest of a role.
    bootstrap_operations: tuple[BootstrapOperation, ...] = ()
    #: The reviewed channel that delivers every dynamic value. Named, never carrying values.
    material_channel: str = "secp.post-provisioning.v1"
    #: Explicit node placement, ``guest_ref -> node_name``. Empty means "propose deterministically".
    placement: dict[str, str] = field(default_factory=dict)
    #: Seconds a guest has to report a closed bootstrap state before it is ``timed_out``.
    bootstrap_deadline_seconds: int = 900
    #: The port teams reach the SECP scoreboard on. Must match the network request's scoring port.
    scoring_port: int = 443
    pools: IpamPools = IpamPools()

    def __post_init__(self) -> None:
        if len(self.team_refs) < 2:
            raise WorkloadError(
                "a two-team competition needs at least two teams; with one there is no opponent "
                "and cross-team isolation is not a property that can be exercised"
            )
        if len(set(self.team_refs)) != len(self.team_refs):
            raise WorkloadError("duplicate team_ref in workload request")
        if len(self.bootstrap_operations) > MAX_BOOTSTRAP_OPERATIONS:
            raise WorkloadError(
                f"{len(self.bootstrap_operations)} bootstrap operations exceeds the bound of "
                f"{MAX_BOOTSTRAP_OPERATIONS}; bootstrap is deliberately bounded"
            )
        keys = [op.key for op in self.bootstrap_operations]
        if len(set(keys)) != len(keys):
            raise WorkloadError("duplicate bootstrap operation key")
        image_keys = [image.workload_key for image in self.images]
        if len(set(image_keys)) != len(image_keys):
            raise WorkloadError("duplicate workload_key in reviewed images")

    def image(self, workload_key: str) -> ReviewedGuestImage | None:
        return next((i for i in self.images if i.workload_key == workload_key), None)


@dataclass(frozen=True)
class GuestBootstrapContract:
    """What ONE guest must do before it counts as bootstrapped, and how that is observed.

    ``attestation_ref`` names the per-guest value the control plane uses to bind an inbound report
    to this guest. The value travels over the post-provisioning channel, never through cloud-init,
    because anything in cloud-init is in OpenTofu state.

    ``probe_address`` is populated ONLY when the compiled firewall was evaluated to permit the
    declared readiness vantage to reach this guest. On an isolated segment it stays ``None`` and
    readiness comes from the guest's own outbound report — which is why the field is not simply
    copied from the published address. A pull check pointed at an address nothing can reach passes
    for the wrong reason or fails for the wrong reason; neither is an observation.
    """

    guest_ref: str
    vmid: int
    team_ref: str
    workload_key: str
    workload_version: str
    image_digest: str
    operations: tuple[BootstrapOperation, ...]
    attestation_ref: MaterialRef
    #: Where the guest reports its outcome. The scoring segment's first host — the same address
    #: ``required_reachability`` probes, so a range that can score can also report.
    report_address: str
    report_port: int
    deadline_seconds: int
    probe_address: str | None = None
    #: The port a pull probe would use when ``probe_address`` is set.
    probe_port: int | None = None

    @property
    def deadline_covers_operations(self) -> bool:
        """True when the deadline is at least the sum of the declared operation timeouts.

        A deadline shorter than the work it bounds turns every slow-but-correct bootstrap into a
        ``timed_out``, which is a closed failure state and therefore an expensive lie.
        """
        return self.deadline_seconds >= sum(op.timeout_seconds for op in self.operations)


@dataclass(frozen=True)
class WorkloadPlan:
    """A compiled workload: the topology to apply, plus everything needed to bootstrap and score."""

    topology: CompiledTopology
    bootstrap: tuple[GuestBootstrapContract, ...]
    #: Every dynamic value the range needs, as references. No values.
    materials: tuple[MaterialRef, ...]
    #: ``(team_ref, address, port)`` each team must be able to reach for scoring to work.
    scoring_endpoints: tuple[tuple[str, str, int], ...]
    #: The catalog challenges this workload actually stands up, per team.
    challenge_keys: tuple[str, ...]

    def contract(self, guest_ref: str) -> GuestBootstrapContract | None:
        return next((c for c in self.bootstrap if c.guest_ref == guest_ref), None)

    def guests_for_team(self, team_ref: str) -> tuple[GuestSpec, ...]:
        return self.topology.guests_for_team(team_ref)


# --------------------------------------------------------------------------------------
# Compilation
# --------------------------------------------------------------------------------------


def _ownership(
    request: WorkloadRequest, team_ref: str | None, kind: RangeResourceKind
) -> Ownership:
    return Ownership(
        organization_id=request.organization_id,
        target_id=request.target_id,
        range_id=request.range_id,
        generation=request.generation,
        operation_generation=request.operation_generation,
        resource_kind=kind,
        team_ref=team_ref,
    )


def _workload_keys(template: CatalogTemplate) -> tuple[str, ...]:
    """The catalog components this compiler stands up as guests, in catalog order.

    Only ``target`` components. ``scoring`` is the native competition core and never a guest;
    ``support`` components have no Proxmox equivalent in the shipped product and are refused rather
    than silently dropped, by :func:`compile_workload`.
    """
    return tuple(c.key for c in template.components if c.role is ComponentRole.target)


def _guest_ref(team_ref: str, workload_key: str) -> str:
    return f"{team_ref}/{workload_key}"


def _guest_name(range_id: str, team_ref: str, workload_key: str) -> str:
    """A DNS-label guest name. The NAME is cosmetic — ownership is decided by tags, never by it."""
    parts = [
        re.sub(r"[^a-z0-9-]", "-", part.lower())[:_MAX_NAME_PART].strip("-")
        for part in (range_id, team_ref, workload_key)
    ]
    name = "-".join(part for part in parts if part)
    if not name or not name[0].isalpha():
        name = f"g{name}"
    return name[:63].rstrip("-")


def _eligible_nodes(observation: TargetObservation) -> tuple[str, ...]:
    """Online nodes that have at least one storage OBSERVED to accept disk images.

    A node whose storages reported no content types is not eligible: empty means "not observed",
    and placing a disk on a storage whose capabilities are unknown is the guess this module does
    not make.
    """
    eligible = [
        node.node_name
        for node in observation.online_nodes()
        if any(STORAGE_CONTENT_IMAGES in storage.content_types for storage in node.storages)
    ]
    return tuple(sorted(eligible))


def _storage_for(observation: TargetObservation, node_name: str) -> str | None:
    node = observation.node(node_name)
    if node is None:
        return None
    candidates = sorted(
        storage.storage_id
        for storage in node.storages
        if STORAGE_CONTENT_IMAGES in storage.content_types
    )
    return candidates[0] if candidates else None


def _segment_for(
    network: SegregatedNetworkPlan, team_ref: str, role: WorkloadRole
) -> VNetSpec | None:
    wanted = _ROLE_SEGMENT[role]
    return next(
        (v for v in network.vnets_for_team(team_ref) if v.role is wanted),
        None,
    )


def _scoring_segment(network: SegregatedNetworkPlan) -> VNetSpec | None:
    return next((v for v in network.vnets if v.role is SegmentRole.scoring), None)


def _first_host(cidr: str) -> str:
    """The first usable host of a subnet.

    This is the scoring endpoint convention, and it is the SAME derivation
    ``proxmox_verification._check_reachability`` uses to decide what to probe. Two derivations of
    one address is how a range verifies connectivity to somewhere nothing actually listens.
    """
    return str(next(iter(ipaddress.ip_network(cidr, strict=False).hosts())))


def compile_workload(
    request: WorkloadRequest,
    network: SegregatedNetworkPlan,
    observation: TargetObservation,
    ledger: AllocationLedger,
) -> WorkloadPlan | BlockedPlan:
    """Compile the Web Breach Lab guests onto ``network``, or refuse with every blocker named.

    The ledger is used exactly as the network compiler uses it: allocations are keyed by
    ``(scope, kind, purpose)`` and asking twice returns the same value, so recompiling this request
    against the same ledger is a no-op. When the ledger is SEALED — which the service does at
    approval — any allocation not already recorded raises rather than widening an approved plan.
    That is what makes a reset re-resolve the deploy's identifiers instead of renumbering the range.
    """
    log = AllocationRequestLog()
    missing: list[MissingPrerequisite] = []

    unsupported = [
        component.key
        for component in request.template.components
        if component.role is ComponentRole.support
    ]
    if unsupported:
        missing.append(
            MissingPrerequisite(
                reason_id="proxmox.workload.support_component_unmapped",
                observation="WorkloadRequest.images",
                detail=(
                    f"template {request.template.slug!r} declares support component(s) "
                    f"{sorted(unsupported)} with no Proxmox equivalent; dropping them silently "
                    "would stand up a range the catalog does not describe"
                ),
            )
        )

    plan_team_refs = set(network.team_refs)
    if plan_team_refs != set(request.team_refs):
        missing.append(
            MissingPrerequisite(
                reason_id="proxmox.workload.team_set_mismatch",
                observation="SegregatedNetworkPlan.team_refs",
                detail=(
                    f"the network was compiled for teams {sorted(plan_team_refs)} but the workload "
                    f"requests {sorted(request.team_refs)}; a guest with no segment cannot be "
                    "isolated into one"
                ),
            )
        )

    scoring = _scoring_segment(network)
    if scoring is None:
        missing.append(
            MissingPrerequisite(
                reason_id="proxmox.workload.no_scoring_segment",
                observation="SegregatedNetworkPlan.vnets",
                detail=(
                    "the compiled network has no scoring segment; teams would have nowhere to "
                    "submit flags and no guest could report its bootstrap outcome"
                ),
            )
        )

    eligible_nodes = _eligible_nodes(observation)
    if not eligible_nodes:
        missing.append(
            MissingPrerequisite(
                reason_id="proxmox.workload.no_eligible_node",
                observation="NodeObservation.storages",
                detail=(
                    "no online node was observed with a storage that accepts disk images; a guest "
                    "cannot be placed and a storage whose content types were not observed is not "
                    "a candidate"
                ),
            )
        )

    workload_keys = _workload_keys(request.template)
    if not workload_keys:
        missing.append(
            MissingPrerequisite(
                reason_id="proxmox.workload.no_target_component",
                observation="CatalogTemplate.components",
                detail=(
                    f"template {request.template.slug!r} declares no target component; there would "
                    "be nothing for a team to attack"
                ),
            )
        )

    # Telemetry is compiled where the operator supplied a reviewed sensor image AND the network was
    # compiled with a sensor segment for that team. It is opt-in on both sides, and a sensor image
    # supplied without a segment to put it on blocks below rather than being quietly discarded — a
    # dropped collector reads as "telemetry is on" to everyone who asked for it.
    sensor_keys = tuple(
        sorted(image.workload_key for image in request.images if image.role is WorkloadRole.sensor)
    )
    per_team_keys = (ATTACKER_WORKLOAD_KEY, *workload_keys, *sensor_keys)

    observed_templates = {t.template_ref for t in observation.templates}
    for key in per_team_keys:
        image = request.image(key)
        if image is None:
            missing.append(
                MissingPrerequisite(
                    reason_id="proxmox.workload.image_not_reviewed",
                    observation="WorkloadRequest.images",
                    detail=(
                        f"no reviewed template was supplied for workload {key!r}; the compiler "
                        "will not pick one, because which image boots decides what the range is"
                    ),
                )
            )
            continue
        if image.template_ref not in observed_templates:
            missing.append(
                MissingPrerequisite(
                    reason_id="proxmox.workload.template_not_observed",
                    observation="TargetObservation.templates",
                    detail=(
                        f"workload {key!r} names template {image.template_ref!r}, which discovery "
                        "never observed on this target; cloning a template that may not exist "
                        "fails at apply with an unhelpful error"
                    ),
                )
            )
        role = image.role
        if role not in request.profiles:
            missing.append(
                MissingPrerequisite(
                    reason_id="proxmox.workload.profile_missing",
                    observation="WorkloadRequest.profiles",
                    detail=(
                        f"no sizing profile for role {role.value!r}; the container catalog "
                        "describes images on a laptop and says nothing about a VM's cpu, memory "
                        "or disk"
                    ),
                )
            )

    if missing:
        return BlockedPlan(tuple(missing))
    assert scoring is not None  # narrowed: a missing scoring segment already returned above

    report_address = _first_host(scoring.subnet.cidr)
    guests: list[GuestSpec] = []
    contracts: list[GuestBootstrapContract] = []
    materials: list[MaterialRef] = []
    scoring_endpoints: list[tuple[str, str, int]] = []

    # Range-scoped material: one reference per catalog challenge. The VALUE is planted by the
    # post-provisioning channel at reset and at deploy, which is what makes "restore challenge
    # state" a real operation rather than a hope that nobody solved anything destructively.
    for challenge in request.template.challenges:
        materials.append(
            MaterialRef(
                ref=f"{request.range_id}/challenge/{challenge.key}",
                scope=MaterialScope.range,
                purpose=f"flag material for challenge {challenge.key}",
                channel=request.material_channel,
            )
        )

    for team_index, team_ref in enumerate(sorted(request.team_refs)):
        team_ownership = _ownership(request, team_ref, RangeResourceKind.virtual_machine)
        materials.append(
            MaterialRef(
                ref=f"{request.range_id}/team/{team_ref}/credentials",
                scope=MaterialScope.team,
                purpose="per-team guest login material",
                channel=request.material_channel,
            )
        )
        scoring_endpoints.append((team_ref, report_address, request.scoring_port))

        for workload_index, key in enumerate(per_team_keys):
            image = request.image(key)
            assert image is not None  # every key was proved present above
            segment = _segment_for(network, team_ref, image.role)
            if segment is None:
                missing.append(
                    MissingPrerequisite(
                        reason_id="proxmox.workload.segment_missing",
                        observation="SegregatedNetworkPlan.vnets",
                        detail=(
                            f"team {team_ref!r} has no "
                            f"{_ROLE_SEGMENT[image.role].value!r} segment for workload {key!r}"
                        ),
                    )
                )
                continue

            guest_ref = _guest_ref(team_ref, key)
            # Placement is deterministic but WRITTEN DOWN: it lands in the desired state, so a
            # later compile that would move this guest changes the desired-state hash and is
            # refused by the apply gate rather than quietly re-placing a running machine.
            ordinal = team_index * len(per_team_keys) + workload_index
            node_name = request.placement.get(
                guest_ref, eligible_nodes[ordinal % len(eligible_nodes)]
            )
            if node_name not in eligible_nodes:
                missing.append(
                    MissingPrerequisite(
                        reason_id="proxmox.workload.placement_not_eligible",
                        observation="NodeObservation.storages",
                        detail=(
                            f"guest {guest_ref!r} is placed on node {node_name!r}, which is not "
                            "online with an observed image-capable storage"
                        ),
                    )
                )
                continue
            storage_id = _storage_for(observation, node_name)
            if storage_id is None:
                missing.append(
                    MissingPrerequisite(
                        reason_id="proxmox.workload.storage_not_observed",
                        observation="StorageObservation.content_types",
                        detail=(
                            f"node {node_name!r} reported no storage accepting "
                            f"{STORAGE_CONTENT_IMAGES!r}; guest {guest_ref!r} has nowhere to put "
                            "its disk"
                        ),
                    )
                )
                continue

            vmid = log.run(
                lambda o=team_ownership, p=guest_ref, k=image.guest_kind: ledger.allocate_vmid(
                    ownership=o,
                    purpose=p,
                    pools=request.pools,
                    observed_vmids=observation.vmids_in_use,
                    lxc=k is GuestKind.lxc,
                )
            )
            mac = log.run(
                lambda o=team_ownership, p=guest_ref: ledger.allocate_mac(
                    ownership=o,
                    purpose=f"{p}/nic0",
                    observed_macs=observation.macs_in_use,
                )
            )
            if vmid is None or mac is None:
                continue
            address = ledger.allocate_address(
                ownership=team_ownership,
                purpose=f"{guest_ref}/address",
                subnet=segment.subnet.network,
                kind=AllocationKind.guest_address,
            )

            profile = request.profiles[image.role]
            # A pull probe is only offered where the compiled rules were EVALUATED to permit it.
            # Everywhere else the field stays None and readiness comes from the guest's outbound
            # report; a probe address nobody can reach is worse than no probe address.
            probe_address = _probe_address_if_reachable(
                network,
                from_vnet=scoring.name,
                to_address=str(address),
                port=image.service_port,
            )
            guests.append(
                GuestSpec(
                    guest_ref=guest_ref,
                    name=_guest_name(request.range_id, team_ref, key),
                    kind=image.guest_kind,
                    vmid=vmid,
                    node_name=node_name,
                    template_ref=image.template_ref,
                    clone_strategy=image.clone_strategy,
                    cpu_cores=profile.cpu_cores,
                    memory_mb=profile.memory_mb,
                    disks=(
                        DiskSpec(
                            slot=profile.disk_slot,
                            size_gb=profile.disk_gb,
                            storage_id=storage_id,
                        ),
                    ),
                    nics=(NicSpec(index=0, vnet_name=segment.name, mac_address=mac),),
                    address=GuestAddress(
                        published_address=str(address),
                        probe_address=probe_address,
                    ),
                    ownership=team_ownership,
                    cloud_init=CloudInitSpec(
                        user=request.cloud_init_user,
                        ssh_authorized_keys=request.ssh_authorized_keys,
                        # No nameservers and no gateway: the segment is unrouted, and a gateway on
                        # an unrouted segment is a lie the guest then spends its boot retrying.
                        nameservers=(),
                        search_domain=None,
                        gateway=None,
                    ),
                    start_on_deploy=True,
                    readiness_timeout_seconds=request.bootstrap_deadline_seconds,
                )
            )
            attestation = MaterialRef(
                ref=f"{request.range_id}/guest/{guest_ref}/attestation",
                scope=MaterialScope.guest,
                purpose="binds an inbound bootstrap report to this guest",
                channel=request.material_channel,
            )
            materials.append(attestation)
            contracts.append(
                GuestBootstrapContract(
                    guest_ref=guest_ref,
                    vmid=vmid,
                    team_ref=team_ref,
                    workload_key=key,
                    workload_version=image.workload_version,
                    image_digest=image.image_digest,
                    operations=request.bootstrap_operations,
                    attestation_ref=attestation,
                    report_address=report_address,
                    report_port=request.scoring_port,
                    deadline_seconds=request.bootstrap_deadline_seconds,
                    probe_address=probe_address,
                    probe_port=image.service_port if probe_address else None,
                )
            )

    missing.extend(log.blocked)
    if missing:
        return BlockedPlan(tuple(missing))

    topology = CompiledTopology(
        target=observation.identity,
        ownership=_ownership(request, None, RangeResourceKind.virtual_machine),
        network=network,
        guests=tuple(sorted(guests, key=lambda g: g.guest_ref)),
        allocations=tuple(allocation.as_dict() for allocation in ledger.all()),
    )
    return WorkloadPlan(
        topology=topology,
        bootstrap=tuple(sorted(contracts, key=lambda c: c.guest_ref)),
        materials=tuple(sorted(materials, key=lambda m: (m.scope.value, m.ref))),
        scoring_endpoints=tuple(sorted(scoring_endpoints)),
        challenge_keys=tuple(sorted(c.key for c in request.template.challenges)),
    )


def _probe_address_if_reachable(
    network: SegregatedNetworkPlan,
    *,
    from_vnet: str,
    to_address: str,
    port: int,
) -> str | None:
    """Offer a pull-probe address only where the COMPILED rules permit that flow.

    This is a statement about the artifact, not about the world: it decides whether a pull probe is
    worth attempting at all. Whether the probe then succeeds is an observation, made elsewhere. A
    ``None`` here is not a failure — it is the ordinary case for an isolated segment, and it routes
    readiness through the guest's own outbound report instead.
    """
    try:
        verdict = evaluate_flow(network, from_vnet=from_vnet, to_address=to_address, port=port)
    except ProxmoxModelError:
        return None
    return to_address if verdict is FirewallVerdict.accept else None


# --------------------------------------------------------------------------------------
# Competition readiness — a property of the PLAN, never of a deployed range
# --------------------------------------------------------------------------------------


class ReadinessRequirement(str, Enum):
    """Each requirement a runnable two-team competition has, checked against the artifact."""

    two_teams_present = "two_teams_present"
    attacker_per_team = "attacker_per_team"
    targets_per_team = "targets_per_team"
    challenges_covered = "challenges_covered"
    scoring_reachable_by_plan = "scoring_reachable_by_plan"
    flags_delivered_out_of_band = "flags_delivered_out_of_band"
    bootstrap_bounded_and_observable = "bootstrap_bounded_and_observable"
    workload_versions_pinned = "workload_versions_pinned"


@dataclass(frozen=True)
class ReadinessFinding:
    """One plan-level requirement, met or not.

    There is no ``unobserved`` member here and there should not be: everything this checks is a
    property of a document already in hand. The moment a question needs the world to answer it, it
    belongs in :mod:`secp_worker.provisioning.proxmox_verification` instead.
    """

    requirement: ReadinessRequirement
    met: bool
    detail: str


def assess_competition_readiness(
    plan: WorkloadPlan,
    request: WorkloadRequest,
) -> tuple[ReadinessFinding, ...]:
    """Check the compiled workload against what a two-team competition actually needs.

    Returns findings; it never raises and never returns a verification outcome. Passing every
    requirement here means the plan is worth applying — it says nothing whatsoever about a range
    that has been applied, and callers must not treat it as though it did.
    """
    findings: list[ReadinessFinding] = []
    network = plan.topology.network
    teams = sorted(request.team_refs)

    findings.append(
        ReadinessFinding(
            requirement=ReadinessRequirement.two_teams_present,
            met=len(teams) >= 2 and set(teams) == set(network.team_refs),
            detail=(f"{len(teams)} team(s) requested; network carries {sorted(network.team_refs)}"),
        )
    )

    workload_keys = _workload_keys(request.template)
    missing_attacker = [
        team
        for team in teams
        if not any(
            c.workload_key == ATTACKER_WORKLOAD_KEY and c.team_ref == team for c in plan.bootstrap
        )
    ]
    findings.append(
        ReadinessFinding(
            requirement=ReadinessRequirement.attacker_per_team,
            met=not missing_attacker,
            detail=(
                f"teams without an attacker system: {missing_attacker}"
                if missing_attacker
                else "every team has a bounded attacker system on its own segment"
            ),
        )
    )

    # Every catalog target must be present per team. Stated as a subset rather than an equality so
    # an opt-in sensor does not read as a missing target — but it is still every target, so a team
    # that is short one is caught.
    short_teams = [
        team
        for team in teams
        if not set(workload_keys) <= {c.workload_key for c in plan.bootstrap if c.team_ref == team}
    ]
    findings.append(
        ReadinessFinding(
            requirement=ReadinessRequirement.targets_per_team,
            met=not short_teams,
            detail=(
                f"teams missing a target: {short_teams}"
                if short_teams
                else f"every team runs {sorted(workload_keys)}"
            ),
        )
    )

    # A challenge whose component is not standing up is a challenge nobody can solve, and a
    # scoreboard that lists it is wrong from the first minute of the event.
    stood_up = set(workload_keys)
    uncovered = sorted(
        {
            challenge.key
            for challenge in request.template.challenges
            if challenge.component_key not in stood_up
        }
    )
    findings.append(
        ReadinessFinding(
            requirement=ReadinessRequirement.challenges_covered,
            met=not uncovered,
            detail=(
                f"challenges with no deployed component: {uncovered}"
                if uncovered
                else f"{len(request.template.challenges)} challenge(s) all have a target"
            ),
        )
    )

    # Plan-level only, and named that way. The real verdict is `required_reachability`, observed.
    unreachable: list[str] = []
    for team_ref, address, port in plan.scoring_endpoints:
        for vnet in network.vnets_for_team(team_ref):
            try:
                verdict = evaluate_flow(network, from_vnet=vnet.name, to_address=address, port=port)
            except ProxmoxModelError as exc:  # pragma: no cover - defensive
                unreachable.append(f"{vnet.name}: {exc}")
                continue
            if verdict is not FirewallVerdict.accept:
                unreachable.append(f"{vnet.name} -> {address}:{port} = {verdict.value}")
    findings.append(
        ReadinessFinding(
            requirement=ReadinessRequirement.scoring_reachable_by_plan,
            met=not unreachable,
            detail=(
                "; ".join(unreachable)
                if unreachable
                else (
                    "the compiled rules permit every team segment to reach the scoreboard; this is "
                    "the artifact's intent and is NOT evidence the applied range does so"
                )
            ),
        )
    )

    findings.append(
        ReadinessFinding(
            requirement=ReadinessRequirement.flags_delivered_out_of_band,
            met=all(m.channel == request.material_channel for m in plan.materials)
            and any(m.scope is MaterialScope.range for m in plan.materials),
            detail=(f"{len(plan.materials)} dynamic value(s) referenced, none carried in the plan"),
        )
    )

    unbounded = [c.guest_ref for c in plan.bootstrap if not c.deadline_covers_operations]
    no_report = [c.guest_ref for c in plan.bootstrap if not c.report_address]
    findings.append(
        ReadinessFinding(
            requirement=ReadinessRequirement.bootstrap_bounded_and_observable,
            met=not unbounded and not no_report and bool(plan.bootstrap),
            detail=(
                f"deadline shorter than declared work: {unbounded}; no report channel: {no_report}"
                if unbounded or no_report
                else f"{len(plan.bootstrap)} guest(s) bounded and reporting to the scoring segment"
            ),
        )
    )

    unpinned = sorted(
        {c.workload_key for c in plan.bootstrap if c.workload_version.lower() in _FLOATING_TAGS}
        | {c.workload_key for c in plan.bootstrap if not c.image_digest}
    )
    findings.append(
        ReadinessFinding(
            requirement=ReadinessRequirement.workload_versions_pinned,
            met=not unpinned,
            detail=(
                f"unpinned workloads: {unpinned}"
                if unpinned
                else "every workload carries an exact version and a base-image digest"
            ),
        )
    )
    return tuple(findings)


def readiness_is_satisfied(findings: tuple[ReadinessFinding, ...]) -> bool:
    """True only when every requirement is met. An empty finding set is NOT satisfied."""
    return bool(findings) and all(finding.met for finding in findings)


# --------------------------------------------------------------------------------------
# The secret guard
# --------------------------------------------------------------------------------------


class DurableSecretLeak(WorkloadError):
    """A secret-shaped value reached a payload that becomes OpenTofu state.

    The message deliberately names the PATH and never the value: an exception that quotes the leaked
    secret writes it into every log that catches it.
    """


#: Markers that identify private key material by CONTENT. Keying on a field name would miss the
#: whole failure mode — nobody calls the field ``private_key`` when they leak one by accident.
_PRIVATE_KEY_MARKERS = ("PRIVATE KEY-----", "PuTTY-User-Key-File")

#: A value made only of lowercase letters must be at least this long before it can be searched for.
#: Below it, ordinary English is indistinguishable from the value — see :func:`unsearchable_values`.
_MIN_ALPHA_NEEDLE = 16


def unsearchable_values(values: tuple[str, ...]) -> tuple[str, ...]:
    """The declared values a substring guard CANNOT reliably prove absent, and why that matters.

    A needle that is nothing but lowercase letters and shorter than 16 characters is not
    distinguishable from ordinary English appearing incidentally. The shipped catalog contains a
    live example: DVWA's flag value is the word ``password``, which occurs inside the *public*
    challenge key ``dvwa-sqli-password-hash``. A guard that searched for it would fire on a payload
    containing nothing secret at all — and a guard that cries wolf is a guard somebody switches
    off, which is strictly worse than not having one.

    So such values are reported here rather than silently skipped or noisily matched. Being on this
    list is itself the finding: it means the value is guessable enough that no automated check can
    protect it, which is the same thing :mod:`secp_api.range_catalog` says in prose about its static
    demo flags. Event-grade material — generated per range, per team — is never on this list.
    """
    return tuple(
        sorted(
            {
                value
                for value in values
                if len(value) < 4
                or (value.isalpha() and value.islower() and len(value) < _MIN_ALPHA_NEEDLE)
            }
        )
    )


def assert_no_durable_secrets(
    payload: object,
    *,
    forbidden_values: tuple[str, ...] = (),
    _path: str = "",
) -> None:
    """Prove a payload destined for OpenTofu state carries no durable secret.

    ``forbidden_values`` is how a caller proves the thing it actually holds — this range's challenge
    flags, this team's credentials — did not travel. Checking those literals is stronger than any
    name-based rule, because it fails on the leak regardless of what the field ended up being
    called, and it is exactly the check a name-based guard cannot make.

    Values :func:`unsearchable_values` reports are not searched for. That is a deliberate, narrow
    exclusion with a stated reason, not a convenience: callers holding such a value should read the
    exclusion as "this value cannot be guarded", not as "this value was checked and was clean".
    """
    skip = set(unsearchable_values(forbidden_values))
    needles = tuple(value for value in forbidden_values if value not in skip)
    _scan(payload, needles, _path)


def _scan(node: object, needles: tuple[str, ...], path: str) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            _scan(value, needles, f"{path}/{key}")
        return
    if isinstance(node, (list, tuple)):
        for index, item in enumerate(node):
            _scan(item, needles, f"{path}[{index}]")
        return
    if not isinstance(node, str):
        return
    for marker in _PRIVATE_KEY_MARKERS:
        if marker in node:
            raise DurableSecretLeak(
                f"private key material would be written to OpenTofu state at {path or '/'}"
            )
    for needle in needles:
        if needle in node:
            raise DurableSecretLeak(
                f"a value the caller declared secret would be written to OpenTofu state at "
                f"{path or '/'}; dynamic per-range and per-team values travel over the "
                f"post-provisioning channel as a MaterialRef, never through the desired state"
            )
