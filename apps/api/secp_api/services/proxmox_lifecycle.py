"""The Proxmox range lifecycle, projected for HTTP — the READ and AUTHORIZE half.

Everything merged across the Proxmox stream compiles a plan, gates an apply, verifies a deployment
and proves a teardown left nothing behind. None of it was reachable by a client. This module is the
projection that makes it reachable, and it is deliberately the *control* half only: it computes,
folds and authorizes. It never applies anything.

WHAT THIS MODULE MAY AND MAY NOT IMPORT
----------------------------------------
The pure compilers — :mod:`~secp_api.range_providers.proxmox_network`,
:mod:`~secp_api.range_providers.proxmox_workload`, :mod:`~secp_api.range_providers.proxmox_ipam`,
:mod:`~secp_api.range_providers.proxmox_manifest` — live in ``secp_api`` and are pure data
transforms. Compiling a topology contacts nothing, so the API may and does run them.

The GATES do not live here and cannot be imported here.
:mod:`secp_worker.provisioning.proxmox_apply_gate`, ``proxmox_destroy_gate``,
``proxmox_verification`` and ``proxmox_residue`` are worker modules, and
``tests/test_architecture_boundary.py`` refuses ``secp_worker`` in every API file but
``dispatch.py``. That is not an inconvenience to work around — those modules decide whether real
VMs get created and destroyed, and the whole point of the split is that the process serving HTTP
cannot make that decision. So this module NEVER reproduces a gate verdict. Where a gate's answer is
wanted, it reports the gate's RECORDED answer, and where none was recorded it says ``undetermined``.

WHERE THE DURABLE STATE LIVES, AND WHY IT IS AN EVENT LOG
----------------------------------------------------------
No migration. ``RUNTIME_REQUIRED_MIGRATION_HEAD`` is pinned, so there is no new table and no new
column, and :class:`~secp_api.range_models.RangeInstance` has no JSON column to hide state in.

That constraint turns out to fit what is being stored. An approval is not a mutable field — it is
something a named principal did to an exact document at an exact moment, and it must stay true
afterwards even when the plan is recompiled and the hash moves. That is an append-only audit record,
which is precisely :class:`~secp_api.range_models.RangeLifecycleEvent`: org-scoped, densely
sequenced, already read by the timeline UI. So every approval, authorization and worker-recorded
observation is an event, and the "current state" of each stage is a FOLD over the log rather than a
column somebody can overwrite. Superseding an approval appends; it never erases.

WHY A PLAN CAN BE BLOCKED AND THAT IS THE CORRECT ANSWER
---------------------------------------------------------
Compiling needs a :class:`~secp_api.range_providers.proxmox_model.TargetObservation` — what live
discovery actually PROVED about the cluster. Nothing in the system produces one yet: the existing
discovery snapshot carries the B5 nested-lab evidence schema (node, storage, two candidate VMIDs),
which has no SDN support flag, no VLANs in use, no MACs in use, no cluster fingerprint and no
management CIDRs. Deriving a ``TargetObservation`` from it would mean inventing the six facts the
compiler blocks on, and the compiler blocks on them precisely because guessing them produces a plan
that fails at apply — or worse, bridges a team segment onto the management plane.

So the observation is read from what the worker RECORDED for this range, and when there is none the
plan is ``blocked`` with named reason ids. A blocked plan is a real, honest, renderable state, not
an error and not an empty success.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.enums import Permission
from secp_api.errors import DomainError
from secp_api.range_catalog import CatalogTemplate, get_template
from secp_api.range_enums import RangeResourceKind
from secp_api.range_models import RangeInstance, RangeLifecycleEvent, RangeTemplate
from secp_api.range_providers.proxmox_ipam import (
    AllocationKind,
    AllocationLedger,
    IpamPools,
)
from secp_api.range_providers.proxmox_manifest import to_manifest_payload
from secp_api.range_providers.proxmox_model import (
    BlockedPlan,
    GuestKind,
    MissingPrerequisite,
    NodeObservation,
    ProxmoxModelError,
    ProxmoxTargetIdentity,
    StorageObservation,
    TargetObservation,
    TemplateObservation,
)
from secp_api.range_providers.proxmox_network import (
    ControlPlaneReviewedPath,
    IsolationFinding,
    TeamRequest,
    WebBreachLabRequest,
    compile_web_breach_lab,
    verify_isolation,
)
from secp_api.range_providers.proxmox_workload import (
    CloneStrategy,
    GuestProfile,
    ReadinessFinding,
    ReviewedGuestImage,
    WorkloadPlan,
    WorkloadRequest,
    WorkloadRole,
    assert_no_durable_secrets,
    assess_competition_readiness,
    compile_workload,
    unsearchable_values,
)
from secp_api.services import ranges as range_service

#: The value persisted on ``RangeInstance.provider`` for a Proxmox range.
PROXMOX_PROVIDER = "proxmox"

# --- event kinds ---------------------------------------------------------------------------
#
# These are the durable record. They are read by the folds below and written either by the worker
# (the observation, the verification report, the reset dispositions, the residue proof) or by the
# authorization endpoints (the four approval kinds). Nothing else writes them.

#: Written by the WORKER when discovery has proved the cluster facts the compiler needs.
EVENT_OBSERVATION = "proxmox_observation_recorded"
#: Written by an operator approving the exact compiled plan, by hash.
EVENT_PLAN_APPROVED = "proxmox_plan_approved"
#: Written by an operator authorizing apply of an already-approved plan.
EVENT_APPLY_AUTHORIZED = "proxmox_apply_authorized"
#: Written by an operator approving the exact destroy plan, by its own distinct hash.
EVENT_DESTROY_PLAN_APPROVED = "proxmox_destroy_plan_approved"
#: Written by an operator authorizing destroy of an already-approved destroy plan.
EVENT_DESTROY_AUTHORIZED = "proxmox_destroy_authorized"
#: Written by the WORKER from an observed deployment.
EVENT_VERIFICATION = "proxmox_verification_recorded"
#: Written by the WORKER from an observed reset.
EVENT_RESET_DISPOSITIONS = "proxmox_reset_dispositions_recorded"
#: Written by the WORKER from an observed teardown.
EVENT_RESIDUE = "proxmox_residue_recorded"

#: How long a recorded observation may be relied on before the surface calls it stale.
#:
#: A cluster changes underneath a plan — someone creates a VM and takes a VMID, someone adds a VLAN.
#: Compiling against an hours-old snapshot is how a plan allocates an identifier that is no longer
#: free. Stale does NOT block compilation: the allocations are still deterministic and still worth
#: reading. It blocks nothing here and is surfaced so the operator approving the plan can see it.
OBSERVATION_FRESHNESS_SECONDS = 3600

#: Domain separation for the two hashes. An apply approval and a destroy approval are different
#: acts over different documents, and #110 made it impossible to construct one as the other. A
#: SHARED hash function would quietly undo that: approve a plan, and the same digest would satisfy
#: the destroy gate. The domain prefix is mixed into the digest, so a plan hash is not a valid
#: destroy hash for the same range even when the underlying document is byte-identical.
_PLAN_HASH_DOMAIN = b"secp-proxmox/plan/v1"
_DESTROY_HASH_DOMAIN = b"secp-proxmox/destroy/v1"

#: The document version this API publishes. Deliberately NOT
#: ``secp-proxmox/plan-document/v1``, which is the worker's OpenTofu plan document
#: (:mod:`secp_worker.provisioning.plan_document`) and describes what ``tofu plan`` computed. This
#: one is the DESIRED STATE the API compiled, before any tofu ran. Two different documents at two
#: different stages; giving them the same version string would invite a client to treat one as the
#: other.
DESIRED_STATE_DOCUMENT_VERSION = "secp-proxmox/desired-state-document/v1"


class ProxmoxNotApplicableError(DomainError):
    """The range is not a Proxmox range, so it has no Proxmox lifecycle to report."""

    http_status = 409
    code = "range_not_proxmox"


class ProxmoxPlanBlockedError(DomainError):
    """An authorization was attempted against a plan that does not compile."""

    http_status = 409
    code = "proxmox_plan_blocked"


class ProxmoxHashMismatchError(DomainError):
    """The hash the caller approved is not the hash the plan currently has.

    This is the entire point of approving BY HASH. Between reading a plan and approving it the
    observation can be re-recorded, the catalog can change, a team can be added — and the document
    the operator actually read is then not the document that would be applied. Refusing here is what
    makes the approval mean something.
    """

    http_status = 409
    code = "proxmox_plan_hash_mismatch"


class ProxmoxApprovalMissingError(DomainError):
    """Apply (or destroy) was authorized before its plan was approved."""

    http_status = 409
    code = "proxmox_approval_missing"


# --------------------------------------------------------------------------------------
# Wire vocabularies
#
# These are the values a client switches on. Each keeps its unknowns as their own members: an
# absent verification is `undetermined`, never `failed`; an unproved resource is `unproven`, never
# `removed`. Collapsing either into a boolean is the failure this whole stream exists to prevent.
# --------------------------------------------------------------------------------------


class ApprovalKind(str, Enum):
    """Which of the four authorization acts a recorded approval is."""

    plan_approval = "plan_approval"
    apply_authorization = "apply_authorization"
    destroy_plan_approval = "destroy_plan_approval"
    destroy_authorization = "destroy_authorization"


class ObservationFreshness(str, Enum):
    """How much the recorded cluster observation can still be relied on."""

    #: Recorded within :data:`OBSERVATION_FRESHNESS_SECONDS`.
    fresh = "fresh"
    #: Recorded, but old enough that the cluster may have moved underneath it.
    stale = "stale"
    #: Recorded without a usable timestamp — age cannot be computed, so it is not claimed.
    undetermined = "undetermined"
    #: No observation has ever been recorded for this range.
    absent = "absent"


class PlanState(str, Enum):
    """Where the compiled plan stands."""

    #: Compiled cleanly and not yet approved.
    compiled = "compiled"
    #: Compiled, and the current hash carries a live approval.
    approved = "approved"
    #: An approval exists but it names a DIFFERENT hash — the plan moved after it was approved.
    superseded = "superseded"
    #: The compiler refused. ``blocked_reasons`` names every missing prerequisite.
    blocked = "blocked"


class AuthorizationState(str, Enum):
    """Whether an apply/destroy authorization exists, folded from the log."""

    #: No authorization has been recorded.
    absent = "absent"
    #: Authorized against the hash the plan currently has.
    authorized = "authorized"
    #: Authorized, but against a hash the plan no longer has. Not usable.
    superseded = "superseded"
    #: An authorization cannot be assessed because the plan does not compile.
    undetermined = "undetermined"


class RecordedStageState(str, Enum):
    """Whether a worker-recorded stage (verification, reset, residue) has an answer yet."""

    #: The worker recorded a result. The payload is the worker's, reported verbatim.
    recorded = "recorded"
    #: Nothing has been recorded. NOT a pass and NOT a failure — nobody has looked.
    undetermined = "undetermined"


# --------------------------------------------------------------------------------------
# The binding: what a Proxmox range was compiled against
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ProxmoxBinding:
    """The recorded inputs a Proxmox plan compiles from.

    Written by the worker as an :data:`EVENT_OBSERVATION` event. The API reads it and never
    synthesises one — an observation the control plane invented is indistinguishable, downstream,
    from one discovery proved, and the compiler's entire safety argument rests on the difference.
    """

    observation: TargetObservation
    teams: tuple[TeamRequest, ...]
    images: tuple[ReviewedGuestImage, ...]
    profiles: dict[WorkloadRole, GuestProfile]
    #: Identity of the discovery snapshot this observation came from, for traceability.
    snapshot_id: str | None
    snapshot_evidence_hash: str | None
    observed_at: datetime | None
    #: Control-plane interfaces the scenario must not reach, and any reviewed exception.
    control_plane_cidrs: tuple[str, ...]
    reviewed_control_plane_paths: tuple[ControlPlaneReviewedPath, ...]
    scoring_port: int
    generation: int
    ssh_authorized_keys: tuple[str, ...]

    def freshness(self, *, now: datetime | None = None) -> ObservationFreshness:
        if self.observed_at is None:
            return ObservationFreshness.undetermined
        moment = now or datetime.now(UTC)
        age = moment - self.observed_at
        if age <= timedelta(seconds=OBSERVATION_FRESHNESS_SECONDS):
            return ObservationFreshness.fresh
        return ObservationFreshness.stale


class BindingDecodeError(ProxmoxModelError):
    """A recorded observation event could not be read back into the compiler's types."""


def _as_tuple(value: object) -> tuple | None:
    """A list becomes a tuple; ``None`` stays ``None``.

    The distinction is the whole contract of :class:`TargetObservation`: ``None`` means "not
    observed" and blocks allocation, while ``()`` means "observed, and there are none". Mapping a
    missing key to an empty tuple would turn "we never looked" into "the cluster is empty", which is
    exactly the guess the compiler refuses to make.
    """
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return tuple(value)
    raise BindingDecodeError(f"expected a list or null, got {type(value).__name__}")


def read_observation(payload: dict) -> TargetObservation:
    """Rebuild a :class:`TargetObservation` from a recorded event payload.

    Absent keys stay ``None`` rather than defaulting, for the reason in :func:`_as_tuple`.
    """
    identity_payload = payload.get("identity")
    if not isinstance(identity_payload, dict):
        raise BindingDecodeError("recorded observation has no target identity")
    identity = ProxmoxTargetIdentity(
        target_id=str(identity_payload["target_id"]),
        cluster_name=str(identity_payload["cluster_name"]),
        cluster_fingerprint=str(identity_payload["cluster_fingerprint"]),
        management_cidrs=tuple(identity_payload.get("management_cidrs") or ()),
        management_bridges=tuple(identity_payload.get("management_bridges") or ()),
    )
    nodes = tuple(
        NodeObservation(
            node_name=str(node["node_name"]),
            online=bool(node["online"]),
            cpu_cores_total=node.get("cpu_cores_total"),
            memory_bytes_total=node.get("memory_bytes_total"),
            storages=tuple(
                StorageObservation(
                    storage_id=str(storage["storage_id"]),
                    content_types=tuple(storage.get("content_types") or ()),
                    available_bytes=storage.get("available_bytes"),
                    shared=storage.get("shared"),
                )
                for storage in (node.get("storages") or ())
            ),
            bridges=tuple(node.get("bridges") or ()),
        )
        for node in (payload.get("nodes") or ())
    )
    templates = tuple(
        TemplateObservation(
            template_ref=str(item["template_ref"]),
            vmid=int(item["vmid"]),
            node_name=str(item["node_name"]),
            guest_kind=GuestKind(item.get("guest_kind", GuestKind.qemu.value)),
        )
        for item in (payload.get("templates") or ())
    )
    vlan_tags = _as_tuple(payload.get("vlan_tags_in_use"))
    vmids = _as_tuple(payload.get("vmids_in_use"))
    return TargetObservation(
        identity=identity,
        nodes=nodes,
        templates=templates,
        sdn_supported=payload.get("sdn_supported"),
        firewall_supported=payload.get("firewall_supported"),
        vlan_tags_in_use=None if vlan_tags is None else tuple(int(tag) for tag in vlan_tags),
        vmids_in_use=None if vmids is None else tuple(int(vmid) for vmid in vmids),
        macs_in_use=_as_tuple(payload.get("macs_in_use")),
        subnets_in_use=_as_tuple(payload.get("subnets_in_use")),
        sdn_names_in_use=_as_tuple(payload.get("sdn_names_in_use")),
        firewall_names_in_use=_as_tuple(payload.get("firewall_names_in_use")),
    )


def read_binding(payload: dict) -> ProxmoxBinding:
    """Rebuild the full binding from a recorded :data:`EVENT_OBSERVATION` payload."""
    observation = read_observation(payload.get("observation") or {})
    teams = tuple(
        TeamRequest(
            team_ref=str(team["team_ref"]),
            label=str(team.get("label") or team["team_ref"]),
            include_sensor=bool(team.get("include_sensor", False)),
        )
        for team in (payload.get("teams") or ())
    )
    images = tuple(
        ReviewedGuestImage(
            workload_key=str(image["workload_key"]),
            role=WorkloadRole(image["role"]),
            template_ref=str(image["template_ref"]),
            workload_version=str(image["workload_version"]),
            image_digest=str(image["image_digest"]),
            approval_reference=str(image["approval_reference"]),
            guest_kind=GuestKind(image.get("guest_kind", GuestKind.qemu.value)),
            clone_strategy=CloneStrategy(image.get("clone_strategy", CloneStrategy.full.value)),
            service_port=int(image.get("service_port", 80)),
        )
        for image in (payload.get("images") or ())
    )
    profiles = {
        WorkloadRole(role): GuestProfile(
            cpu_cores=int(profile["cpu_cores"]),
            memory_mb=int(profile["memory_mb"]),
            disk_gb=int(profile["disk_gb"]),
            disk_slot=str(profile.get("disk_slot", "scsi0")),
        )
        for role, profile in (payload.get("profiles") or {}).items()
    }
    reviewed_paths = tuple(
        ControlPlaneReviewedPath(
            dest_cidr=str(path["dest_cidr"]),
            proto=str(path["proto"]),
            dport=str(path["dport"]),
            justification=str(path["justification"]),
            approval_reference=str(path["approval_reference"]),
        )
        for path in (payload.get("reviewed_control_plane_paths") or ())
    )
    observed_at = _parse_moment(payload.get("observed_at"))
    return ProxmoxBinding(
        observation=observation,
        teams=teams,
        images=images,
        profiles=profiles,
        snapshot_id=(str(payload["snapshot_id"]) if payload.get("snapshot_id") else None),
        snapshot_evidence_hash=(
            str(payload["evidence_hash"]) if payload.get("evidence_hash") else None
        ),
        observed_at=observed_at,
        control_plane_cidrs=tuple(payload.get("control_plane_cidrs") or ()),
        reviewed_control_plane_paths=reviewed_paths,
        scoring_port=int(payload.get("scoring_port", 443)),
        generation=int(payload.get("generation", 1)),
        ssh_authorized_keys=tuple(payload.get("ssh_authorized_keys") or ()),
    )


def _parse_moment(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


# --------------------------------------------------------------------------------------
# Reading the log
# --------------------------------------------------------------------------------------


def _latest_event(
    session: Session, instance: RangeInstance, kind: str
) -> RangeLifecycleEvent | None:
    """The most recent event of ``kind`` for this range.

    ``sequence`` is per-range, dense and monotonic, so it orders the log exactly. Ordering by
    ``occurred_at`` would tie whenever two events land in the same transaction — which approvals and
    their operations routinely do.
    """
    return session.execute(
        select(RangeLifecycleEvent)
        .where(
            RangeLifecycleEvent.range_instance_id == instance.id,
            RangeLifecycleEvent.kind == kind,
        )
        .order_by(RangeLifecycleEvent.sequence.desc())
        .limit(1)
    ).scalar_one_or_none()


def load_binding(session: Session, instance: RangeInstance) -> ProxmoxBinding | None:
    """The newest recorded observation for this range, or ``None`` if the worker recorded none."""
    event = _latest_event(session, instance, EVENT_OBSERVATION)
    if event is None:
        return None
    return read_binding(event.data or {})


def require_proxmox(instance: RangeInstance) -> None:
    if instance.provider != PROXMOX_PROVIDER:
        raise ProxmoxNotApplicableError(
            f"range '{instance.name}' runs on provider '{instance.provider}', which has no Proxmox "
            "lifecycle. The Proxmox plan, apply authorization, destroy authorization and residue "
            "proof exist only for ranges created from a Proxmox template."
        )


def _catalog_template(session: Session, instance: RangeInstance) -> CatalogTemplate:
    row = session.get(RangeTemplate, instance.template_id)
    if row is None:  # pragma: no cover - FK makes this unreachable
        raise ProxmoxPlanBlockedError("the range's template no longer exists")
    template = get_template(row.slug)
    if template is None:
        raise ProxmoxPlanBlockedError(
            f"template '{row.slug}' is no longer in the shipped catalog; the plan cannot be "
            "recompiled from a definition this build does not have"
        )
    return template


# --------------------------------------------------------------------------------------
# Compilation
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class CompiledRangePlan:
    """A fully compiled Proxmox plan for one range, with everything derived from it."""

    template: CatalogTemplate
    binding: ProxmoxBinding
    workload: WorkloadPlan
    ledger: AllocationLedger
    isolation: tuple[IsolationFinding, ...]
    readiness: tuple[ReadinessFinding, ...]
    #: The canonical desired-state payload. The plan hash is taken over exactly this.
    manifest: dict
    plan_hash: str
    #: The bounded set of owned objects a destroy would remove. The destroy hash is taken over
    #: exactly this — a deletion scope, never the creation plan reversed.
    deletion_set: list[dict]
    destroy_hash: str


def _no_observation_block(instance: RangeInstance) -> BlockedPlan:
    return BlockedPlan(
        missing=(
            MissingPrerequisite(
                reason_id="proxmox.no_observation_of_record",
                observation="RangeLifecycleEvent[proxmox_observation_recorded]",
                detail=(
                    "no discovery observation has been recorded for this range, so there is "
                    "nothing to compile against. The compiler needs facts a live cluster scan "
                    "proves — SDN support, cluster firewall support, the VMIDs, VLAN tags, MACs "
                    "and subnets already in use, and the management CIDRs the scenario must not "
                    "reach. None of those may be assumed: a guessed VMID collides with a real "
                    "guest, and a guessed management CIDR is how a team segment ends up bridged "
                    "onto the management plane. Run discovery against the target and record its "
                    "observation before planning this range."
                ),
            ),
        ),
    )


def compile_plan(session: Session, instance: RangeInstance) -> CompiledRangePlan | BlockedPlan:
    """Compile this range's Proxmox plan, or return the blocked plan naming every prerequisite.

    Deterministic: the same binding and the same catalog template always produce the same
    allocations and therefore the same hash. That is what lets an operator approve a hash and have
    the approval still mean something on the next request.
    """
    require_proxmox(instance)
    template = _catalog_template(session, instance)
    binding = load_binding(session, instance)
    if binding is None:
        return _no_observation_block(instance)

    range_id = str(instance.id)
    network_request = WebBreachLabRequest(
        organization_id=str(instance.organization_id),
        target_id=binding.observation.identity.target_id,
        range_id=range_id,
        generation=binding.generation,
        operation_generation=binding.generation,
        teams=binding.teams,
        control_plane_cidrs=binding.control_plane_cidrs,
        reviewed_control_plane_paths=binding.reviewed_control_plane_paths,
        scoring_port=binding.scoring_port,
        pools=IpamPools(),
    )
    try:
        compiled = compile_web_breach_lab(network_request, binding.observation)
    except ProxmoxModelError as exc:
        return BlockedPlan(
            missing=(
                MissingPrerequisite(
                    reason_id="proxmox.network_request_invalid",
                    observation="WebBreachLabRequest",
                    detail=str(exc),
                ),
            ),
        )
    if isinstance(compiled, BlockedPlan):
        return compiled
    network, ledger = compiled

    workload_request = WorkloadRequest(
        organization_id=str(instance.organization_id),
        target_id=binding.observation.identity.target_id,
        range_id=range_id,
        generation=binding.generation,
        operation_generation=binding.generation,
        template=template,
        team_refs=tuple(team.team_ref for team in binding.teams),
        images=binding.images,
        profiles=binding.profiles,
        ssh_authorized_keys=binding.ssh_authorized_keys,
        scoring_port=binding.scoring_port,
        pools=IpamPools(),
    )
    try:
        workload = compile_workload(workload_request, network, binding.observation, ledger)
    except ProxmoxModelError as exc:
        return BlockedPlan(
            missing=(
                MissingPrerequisite(
                    reason_id="proxmox.workload_request_invalid",
                    observation="WorkloadRequest",
                    detail=str(exc),
                ),
            ),
        )
    if isinstance(workload, BlockedPlan):
        return workload

    isolation = verify_isolation(network, binding.observation, network_request)
    readiness = assess_competition_readiness(workload, workload_request)
    manifest = to_manifest_payload(workload.topology, ledger)

    # The desired state is what becomes OpenTofu state. Prove no challenge flag travelled in it
    # before it is ever put on the wire — this is the same guard the workload compiler applies, run
    # again here because THIS payload is the one a client receives.
    assert_no_durable_secrets(manifest, forbidden_values=_flag_values(template))

    deletion_set = _deletion_set(manifest)
    return CompiledRangePlan(
        template=template,
        binding=binding,
        workload=workload,
        ledger=ledger,
        isolation=isolation,
        readiness=readiness,
        manifest=manifest,
        plan_hash=_hash(_PLAN_HASH_DOMAIN, manifest),
        deletion_set=deletion_set,
        destroy_hash=_hash(_DESTROY_HASH_DOMAIN, deletion_set),
    )


def _flag_values(template: CatalogTemplate) -> tuple[str, ...]:
    return tuple(flag.value for challenge in template.challenges for flag in challenge.flags)


def unguardable_flag_values(template: CatalogTemplate) -> tuple[str, ...]:
    """Flag values no substring guard can prove absent — reported, never silently skipped.

    See :func:`~secp_api.range_providers.proxmox_workload.unsearchable_values`. DVWA's flag is the
    word ``password``, which appears inside a public challenge key, so searching for it would fire
    on a clean payload. Being on this list is the finding.
    """
    return unsearchable_values(_flag_values(template))


def _canonical(payload: object) -> bytes:
    """Canonical JSON: sorted keys and fixed separators, so the digest is stable everywhere."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _hash(domain: bytes, payload: object) -> str:
    """A domain-separated content hash.

    The domain is mixed in ahead of the payload, which is why a plan hash can never be a valid
    destroy hash even for a byte-identical document. See :data:`_PLAN_HASH_DOMAIN`.
    """
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(b"\x00")
    digest.update(_canonical(payload))
    return f"sha256:{digest.hexdigest()}"


def _deletion_set(manifest: dict) -> list[dict]:
    """The objects a destroy would remove, as its own document.

    A destroy is NOT "the plan, reversed". It is a bounded set of owned objects, and it is hashed
    over that set alone so that approving a destroy approves a deletion scope rather than a
    creation scope. Sorted, so the digest does not depend on compile order.
    """
    network = manifest.get("network") or {}
    entries: list[dict] = []
    for guest in manifest.get("guests") or ():
        entries.append(
            {
                "kind": (
                    RangeResourceKind.lxc_container.value
                    if guest.get("kind") == GuestKind.lxc.value
                    else RangeResourceKind.virtual_machine.value
                ),
                "ref": guest.get("guest_ref"),
                "name": guest.get("name"),
                "vmid": guest.get("vmid"),
                "node": guest.get("node_name"),
            }
        )
    zone = network.get("zone") or {}
    if zone:
        entries.append(
            {
                "kind": RangeResourceKind.sdn_zone.value,
                "ref": zone.get("name"),
                "name": zone.get("name"),
            }
        )
    for vnet in network.get("vnets") or ():
        entries.append(
            {
                "kind": RangeResourceKind.vnet.value,
                "ref": vnet.get("name"),
                "name": vnet.get("name"),
            }
        )
    for group in network.get("security_groups") or ():
        entries.append(
            {
                "kind": RangeResourceKind.firewall_group.value,
                "ref": group.get("name"),
                "name": group.get("name"),
            }
        )
    for ip_set in network.get("ip_sets") or ():
        entries.append(
            {
                "kind": RangeResourceKind.ip_set.value,
                "ref": ip_set.get("name"),
                "name": ip_set.get("name"),
            }
        )
    return sorted(entries, key=lambda item: (str(item["kind"]), str(item.get("ref") or "")))


# --------------------------------------------------------------------------------------
# Allocation projection
# --------------------------------------------------------------------------------------

#: Which allocation kinds are addresses/identifiers a client renders. Every kind is projected —
#: this map only supplies the label, so a kind added upstream still appears rather than vanishing.
_ALLOCATION_LABELS: dict[AllocationKind, str] = {
    AllocationKind.vmid: "VM id",
    AllocationKind.lxc_id: "LXC id",
    AllocationKind.mac: "MAC address",
    AllocationKind.subnet: "subnet",
    AllocationKind.guest_address: "guest address",
    AllocationKind.gateway_address: "gateway address",
    AllocationKind.vlan_tag: "VLAN tag",
    AllocationKind.vnet_name: "VNet name",
    AllocationKind.zone_name: "SDN zone name",
    AllocationKind.resource_name: "resource name",
    AllocationKind.firewall_object_name: "firewall object name",
    AllocationKind.remote_state_key: "remote state key",
}


@dataclass(frozen=True)
class ApprovalRecord:
    """One recorded approval or authorization, as it was made.

    Immutable by construction: it is an event row. Recompiling the plan can make this record
    ``superseded``, but it can never make it untrue that this principal approved this hash.
    """

    #: WHICH of the four acts this was. Carried on the record rather than inferred from the
    #: endpoint that returned it, so an apply approval stays distinguishable from a destroy
    #: approval wherever it travels.
    operation_kind: ApprovalKind
    #: The exact digest the principal approved. Compared, never recomputed.
    approved_hash: str
    approved_by: uuid.UUID | None
    at: datetime
    sequence: int


def _read_approval(
    session: Session,
    instance: RangeInstance,
    kind: str,
    field: str,
    act: ApprovalKind,
) -> ApprovalRecord | None:
    event = _latest_event(session, instance, kind)
    if event is None:
        return None
    data = event.data or {}
    approved_hash = data.get(field)
    if not isinstance(approved_hash, str) or not approved_hash:
        return None
    approved_by = data.get("approved_by")
    return ApprovalRecord(
        operation_kind=act,
        approved_hash=approved_hash,
        approved_by=uuid.UUID(approved_by) if isinstance(approved_by, str) else None,
        at=event.occurred_at,
        sequence=event.sequence,
    )


def plan_approval(session: Session, instance: RangeInstance) -> ApprovalRecord | None:
    return _read_approval(
        session, instance, EVENT_PLAN_APPROVED, "plan_hash", ApprovalKind.plan_approval
    )


def apply_authorization(session: Session, instance: RangeInstance) -> ApprovalRecord | None:
    return _read_approval(
        session, instance, EVENT_APPLY_AUTHORIZED, "plan_hash", ApprovalKind.apply_authorization
    )


def destroy_plan_approval(session: Session, instance: RangeInstance) -> ApprovalRecord | None:
    return _read_approval(
        session,
        instance,
        EVENT_DESTROY_PLAN_APPROVED,
        "destroy_hash",
        ApprovalKind.destroy_plan_approval,
    )


def destroy_authorization(session: Session, instance: RangeInstance) -> ApprovalRecord | None:
    return _read_approval(
        session,
        instance,
        EVENT_DESTROY_AUTHORIZED,
        "destroy_hash",
        ApprovalKind.destroy_authorization,
    )


def plan_state(
    compiled: CompiledRangePlan | BlockedPlan, approval: ApprovalRecord | None
) -> PlanState:
    if isinstance(compiled, BlockedPlan):
        return PlanState.blocked
    if approval is None:
        return PlanState.compiled
    if approval.approved_hash == compiled.plan_hash:
        return PlanState.approved
    return PlanState.superseded


def destroy_plan_state(
    compiled: CompiledRangePlan | BlockedPlan, approval: ApprovalRecord | None
) -> PlanState:
    if isinstance(compiled, BlockedPlan):
        return PlanState.blocked
    if approval is None:
        return PlanState.compiled
    if approval.approved_hash == compiled.destroy_hash:
        return PlanState.approved
    return PlanState.superseded


def authorization_state(
    compiled: CompiledRangePlan | BlockedPlan,
    record: ApprovalRecord | None,
    *,
    expected_hash: str | None = None,
) -> AuthorizationState:
    """Fold an authorization against the hash the plan currently has.

    ``undetermined`` when the plan does not compile: an authorization for a plan we cannot
    reproduce is neither valid nor invalid, and calling it either would be a claim nobody checked.
    """
    if isinstance(compiled, BlockedPlan):
        return AuthorizationState.undetermined
    if record is None:
        return AuthorizationState.absent
    if record.approved_hash == expected_hash:
        return AuthorizationState.authorized
    return AuthorizationState.superseded


def _require_compiled(session: Session, instance: RangeInstance) -> CompiledRangePlan:
    compiled = compile_plan(session, instance)
    if isinstance(compiled, BlockedPlan):
        raise ProxmoxPlanBlockedError(
            f"this range's plan does not compile, so there is nothing to authorize: "
            f"{compiled.describe()}"
        )
    return compiled


# --------------------------------------------------------------------------------------
# The four authorization acts
#
# STRUCTURALLY DISTINCT, and this is the property #110 established and that a shared endpoint or a
# shared schema would quietly undo. Four separate paths, four separate event kinds, two separate
# permissions, and two hash DOMAINS — so an approved plan hash is not a syntactically valid destroy
# hash for the same range. There is no code path on which one of these can be constructed as, or
# mistaken for, another.
#
# None of them executes anything. Approving records an approval and stops; authorizing records an
# authorization and stops. What may then be ENQUEUED is the ordinary deploy/destroy operation, which
# the router refuses for a Proxmox range unless the matching authorization is present and current.
# --------------------------------------------------------------------------------------


def approve_plan(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    *,
    plan_hash: str,
) -> tuple[RangeInstance, CompiledRangePlan, ApprovalRecord]:
    """Approve the exact compiled plan, by hash. Starts nothing."""
    instance = range_service.get_range(session, principal, range_id)
    require_proxmox(instance)
    principal.require(Permission.exercise_apply)
    compiled = _require_compiled(session, instance)
    if plan_hash != compiled.plan_hash:
        raise ProxmoxHashMismatchError(
            f"the plan has changed since it was read: you approved {plan_hash}, the current plan "
            f"is {compiled.plan_hash}. Re-read the plan and approve the document you actually saw."
        )
    range_service.record_event(
        session,
        instance,
        kind=EVENT_PLAN_APPROVED,
        message=f"Proxmox plan {compiled.plan_hash} approved",
        data={"plan_hash": compiled.plan_hash, "approved_by": str(principal.user_id)},
    )
    return (
        instance,
        compiled,
        ApprovalRecord(
            operation_kind=ApprovalKind.plan_approval,
            approved_hash=compiled.plan_hash,
            approved_by=principal.user_id,
            at=datetime.now(UTC),
            sequence=instance.event_sequence,
        ),
    )


def authorize_apply(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    *,
    plan_hash: str,
) -> tuple[RangeInstance, CompiledRangePlan, ApprovalRecord]:
    """Authorize apply of an already-approved plan. Starts nothing; enqueues nothing.

    Requires an approval of the SAME hash first. Authorizing an unapproved plan would collapse two
    decisions — "this is the right plan" and "apply it now" — into one, and the second is worth
    making separately precisely because it is the one that creates real VMs.
    """
    instance = range_service.get_range(session, principal, range_id)
    require_proxmox(instance)
    principal.require(Permission.exercise_apply)
    compiled = _require_compiled(session, instance)
    if plan_hash != compiled.plan_hash:
        raise ProxmoxHashMismatchError(
            f"the plan has changed since it was approved: you authorized {plan_hash}, the current "
            f"plan is {compiled.plan_hash}"
        )
    approval = plan_approval(session, instance)
    if approval is None or approval.approved_hash != compiled.plan_hash:
        raise ProxmoxApprovalMissingError(
            "this plan has not been approved, so apply cannot be authorized. Approve the plan "
            f"({compiled.plan_hash}) first; approval and apply authorization are separate acts."
        )
    range_service.record_event(
        session,
        instance,
        kind=EVENT_APPLY_AUTHORIZED,
        message=f"Apply authorized for Proxmox plan {compiled.plan_hash}",
        data={"plan_hash": compiled.plan_hash, "approved_by": str(principal.user_id)},
    )
    return (
        instance,
        compiled,
        ApprovalRecord(
            operation_kind=ApprovalKind.apply_authorization,
            approved_hash=compiled.plan_hash,
            approved_by=principal.user_id,
            at=datetime.now(UTC),
            sequence=instance.event_sequence,
        ),
    )


def approve_destroy_plan(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    *,
    destroy_hash: str,
) -> tuple[RangeInstance, CompiledRangePlan, ApprovalRecord]:
    """Approve the exact destroy plan, by its own hash. Starts nothing.

    Takes ``destroy_hash`` and never ``plan_hash``. The field name differs, the hash domain differs,
    and the permission differs — an apply approval body cannot be posted here and be accepted.
    """
    instance = range_service.get_range(session, principal, range_id)
    require_proxmox(instance)
    principal.require(Permission.exercise_destroy)
    compiled = _require_compiled(session, instance)
    if destroy_hash != compiled.destroy_hash:
        raise ProxmoxHashMismatchError(
            f"the destroy plan has changed since it was read: you approved {destroy_hash}, the "
            f"current destroy plan is {compiled.destroy_hash}"
        )
    range_service.record_event(
        session,
        instance,
        kind=EVENT_DESTROY_PLAN_APPROVED,
        message=f"Proxmox destroy plan {compiled.destroy_hash} approved",
        data={"destroy_hash": compiled.destroy_hash, "approved_by": str(principal.user_id)},
    )
    return (
        instance,
        compiled,
        ApprovalRecord(
            operation_kind=ApprovalKind.destroy_plan_approval,
            approved_hash=compiled.destroy_hash,
            approved_by=principal.user_id,
            at=datetime.now(UTC),
            sequence=instance.event_sequence,
        ),
    )


def authorize_destroy(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    *,
    destroy_hash: str,
) -> tuple[RangeInstance, CompiledRangePlan, ApprovalRecord]:
    """Authorize destroy of an already-approved destroy plan. Starts nothing; enqueues nothing."""
    instance = range_service.get_range(session, principal, range_id)
    require_proxmox(instance)
    principal.require(Permission.exercise_destroy)
    compiled = _require_compiled(session, instance)
    if destroy_hash != compiled.destroy_hash:
        raise ProxmoxHashMismatchError(
            f"the destroy plan has changed since it was approved: you authorized {destroy_hash}, "
            f"the current destroy plan is {compiled.destroy_hash}"
        )
    approval = destroy_plan_approval(session, instance)
    if approval is None or approval.approved_hash != compiled.destroy_hash:
        raise ProxmoxApprovalMissingError(
            "this destroy plan has not been approved, so destroy cannot be authorized. Approve "
            f"the destroy plan ({compiled.destroy_hash}) first."
        )
    range_service.record_event(
        session,
        instance,
        kind=EVENT_DESTROY_AUTHORIZED,
        message=f"Destroy authorized for Proxmox destroy plan {compiled.destroy_hash}",
        level="warning",
        data={"destroy_hash": compiled.destroy_hash, "approved_by": str(principal.user_id)},
    )
    return (
        instance,
        compiled,
        ApprovalRecord(
            operation_kind=ApprovalKind.destroy_authorization,
            approved_hash=compiled.destroy_hash,
            approved_by=principal.user_id,
            at=datetime.now(UTC),
            sequence=instance.event_sequence,
        ),
    )


# --------------------------------------------------------------------------------------
# The enqueue gate
# --------------------------------------------------------------------------------------


def require_operation_authorized(session: Session, instance: RangeInstance, kind: str) -> None:
    """Refuse to enqueue a Proxmox deploy/destroy without its current, matching authorization.

    This is what makes the authorization surfaces load-bearing rather than decorative: without it,
    ``POST /ranges/{id}/deploy`` would still enqueue an apply that nobody authorized, and the whole
    approval chain would be an unenforced convention.

    Non-Proxmox ranges are untouched — the local Docker lifecycle keeps its existing behaviour.
    """
    if instance.provider != PROXMOX_PROVIDER:
        return
    compiled = compile_plan(session, instance)
    if isinstance(compiled, BlockedPlan):
        raise ProxmoxPlanBlockedError(
            f"this Proxmox range has no compilable plan, so no {kind} can be enqueued: "
            f"{compiled.describe()}"
        )
    if kind == "destroy":
        record = destroy_authorization(session, instance)
        if record is None or record.approved_hash != compiled.destroy_hash:
            raise ProxmoxApprovalMissingError(
                "destroy is not authorized for this range's current destroy plan "
                f"({compiled.destroy_hash}). Approve the destroy plan and then authorize destroy; "
                "an apply authorization does not authorize a destroy."
            )
        return
    record = apply_authorization(session, instance)
    if record is None or record.approved_hash != compiled.plan_hash:
        raise ProxmoxApprovalMissingError(
            f"apply is not authorized for this range's current plan ({compiled.plan_hash}). "
            "Approve the plan and then authorize apply; a destroy authorization does not "
            "authorize an apply."
        )


# --------------------------------------------------------------------------------------
# Worker-recorded stages
# --------------------------------------------------------------------------------------


def recorded_stage(session: Session, instance: RangeInstance, kind: str) -> dict | None:
    """The worker's most recent recorded payload for a stage, verbatim, or ``None``.

    Reported without reinterpretation. The verification report's ``outcome``, the residue proof's
    verdict and each reset disposition are the WORKER's words — this process did not observe the
    cluster and must not upgrade, downgrade or summarise a verdict it did not reach.
    """
    event = _latest_event(session, instance, kind)
    if event is None:
        return None
    return dict(event.data or {})


def allocation_rows(ledger: AllocationLedger) -> list[dict]:
    """Every deterministic allocation, flattened for the wire.

    The remote-state KEY is included and the remote-state CREDENTIALS are not — a key names where
    state lives, which an operator needs in order to reason about a stuck apply; the credential that
    opens it is never in this process and never in a response.
    """
    rows: list[dict] = []
    for allocation in ledger.all():
        rows.append(
            {
                "kind": allocation.kind.value,
                "label": _ALLOCATION_LABELS.get(allocation.kind, allocation.kind.value),
                "purpose": allocation.purpose,
                "value": allocation.value,
                # scope is (organization_id, target_id, range_id, team_ref, generation); the
                # range-wide allocations carry "" rather than a team, which reads as null.
                "team_ref": allocation.scope[3] or None,
            }
        )
    return rows
