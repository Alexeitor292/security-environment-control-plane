"""Response and request schemas for the Proxmox range lifecycle.

THE GENERATED OPENAPI IS THE CONTRACT. These models are what ``/openapi.json`` publishes, and a
client transcription that disagrees with them is wrong — not the other way round.

Three properties hold across every model here and each is load-bearing:

* **No secret has a field to travel in.** No provider credential, no OpenTofu or remote-state
  credential, no enrollment material, no signing key, no flag value. The remote-state KEY is
  published (an operator reasoning about a stuck apply needs to know where state lives); the
  credential that opens it is not in this process at all. cloud-init is published with its
  ``ssh_authorized_keys`` — public keys, which
  :class:`~secp_api.range_providers.proxmox_model.CloudInitSpec` already refuses to let carry
  private material — and the compiled desired state is additionally scanned by
  :func:`~secp_api.range_providers.proxmox_workload.assert_no_durable_secrets` before it is
  serialised.

* **Unknown is its own value everywhere.** ``undetermined``, ``unproven``, ``blocked`` and
  ``recovery_required`` are members of the enums a client switches on, never absences to be
  defaulted. A verification that has not run is ``undetermined`` and never ``passed``; a resource
  nobody could observe is ``unproven`` and never ``removed``.

* **Apply and destroy never share a shape.** :class:`ProxmoxApplyAuthorizationRequest` requires
  ``plan_hash``; :class:`ProxmoxDestroyAuthorizationRequest` requires ``destroy_hash``. The field
  names differ and both are required with ``extra="forbid"``, so neither body validates as the
  other — posting an apply authorization to the destroy endpoint is a 422, not a destroyed range.

Every response is an ordinary JSON body of plain data, materialised before the session closes.
Nothing here is streamed: a ``StreamingResponse`` over ORM instances would send a 200 and then
truncate (see :mod:`secp_api.deps`).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from secp_api.services.proxmox_lifecycle import (
    ApprovalKind,
    AuthorizationState,
    ObservationFreshness,
    PlanState,
    RecordedStageState,
)


class _Strict(BaseModel):
    """Request bodies reject unknown fields.

    Silently ignoring an unexpected key is how a client posts ``{"destroy_hash": ...}`` to the
    apply endpoint, gets a 200, and believes it authorized something it did not.
    """

    model_config = ConfigDict(extra="forbid")


# --- requests -----------------------------------------------------------------


class ProxmoxPlanApprovalRequest(_Strict):
    """Approve the exact compiled plan. ``plan_hash`` is required and is compared, never trusted."""

    plan_hash: str = Field(min_length=8, max_length=200)


class ProxmoxApplyAuthorizationRequest(_Strict):
    """Authorize apply of an already-approved plan. Deliberately carries ``plan_hash`` ONLY."""

    plan_hash: str = Field(min_length=8, max_length=200)


class ProxmoxDestroyPlanApprovalRequest(_Strict):
    """Approve the exact destroy plan. Deliberately carries ``destroy_hash`` ONLY."""

    destroy_hash: str = Field(min_length=8, max_length=200)


class ProxmoxDestroyAuthorizationRequest(_Strict):
    """Authorize destroy of an already-approved destroy plan. ``destroy_hash`` ONLY."""

    destroy_hash: str = Field(min_length=8, max_length=200)


# --- shared response fragments -------------------------------------------------


class BlockedReasonOut(BaseModel):
    """One named missing prerequisite. ``reason_id`` is a stable key a client may branch on."""

    reason_id: str
    #: The exact observation field that was not available, so an operator knows what to collect.
    observation: str
    detail: str


class ApprovalOut(BaseModel):
    """A recorded approval or authorization, as it was made.

    ``operation_kind`` names WHICH act this was, in the payload rather than only in the URL
    that returned it. Without it an approval record is a bare hash plus a principal, and an
    apply approval is indistinguishable from a destroy approval once it has been read out of
    its response. The hash domains already make one unusable as the other; this makes the
    difference legible as well.
    """

    operation_kind: ApprovalKind
    approved_hash: str
    approved_by: uuid.UUID | None
    at: datetime


class ProxmoxObservationOut(BaseModel):
    """The discovery snapshot this range's plan compiles against, and how much it can be trusted.

    ``freshness`` is ``absent`` when the worker has recorded no observation — which is not an error
    and not an empty cluster, but the reason the plan below it is ``blocked``.
    """

    freshness: ObservationFreshness
    snapshot_id: str | None = None
    snapshot_evidence_hash: str | None = None
    observed_at: datetime | None = None
    age_seconds: int | None = None
    freshness_bound_seconds: int
    target_id: str | None = None
    cluster_name: str | None = None
    cluster_fingerprint: str | None = None
    #: ``None`` when no observation was recorded — NOT "this cluster declares no management
    #: network", which is a claim no compiled plan may ever be built on.
    management_cidrs: list[str] | None = None
    management_bridges: list[str] | None = None
    online_node_count: int | None = None
    #: ``None`` means the fact was never observed — it does NOT mean "no" and never means zero.
    sdn_supported: bool | None = None
    firewall_supported: bool | None = None
    #: Which observation fields are absent, and therefore which allocations cannot be made.
    unobserved_fields: list[str] = Field(default_factory=list)


class ProxmoxAllocationOut(BaseModel):
    """One deterministic allocation. The same binding always produces the same value."""

    kind: str
    label: str
    purpose: str
    value: str
    team_ref: str | None = None


class IsolationFindingOut(BaseModel):
    """One isolation property, proved or violated against the COMPILED firewall.

    This is a property of the document, established before anything is applied. It is deliberately
    not the same claim as the observed isolation in the verification report, which is why the two
    appear in different places and are never merged.
    """

    property: str
    holds: bool
    detail: str


class ReadinessFindingOut(BaseModel):
    """One competition-readiness requirement, met or not, checked against the plan."""

    requirement: str
    met: bool
    detail: str


class OwnershipClassOut(BaseModel):
    """How this range stamps the objects it creates, and what that excludes.

    Ownership is decided by TAGS and never by name: a name collision or a recycled id must not put
    an unrelated guest in this range's destroy scope.
    """

    organization_id: str
    target_id: str
    range_id: str
    generation: int
    operation_generation: int
    #: The exact tag set written onto every object this range creates.
    tags: dict[str, str]
    #: The provenance values a sweep acts on, and the ones it must never touch.
    acts_on: list[str]
    never_touches: list[str]


# --- read surfaces -------------------------------------------------------------


class ProxmoxGuestAddressOut(BaseModel):
    """A guest's addresses, kept strictly separate — THREE concepts, never one.

    This repository has already paid for conflating them. A worker probed the address the range
    had *published* — a loopback address, from inside a container where the port was not — so
    readiness could never be observed and the range hung. #103 fixed it by separating the two, and
    :class:`~secp_api.range_providers.proxmox_model.GuestAddress` refuses to fall back from one to
    the other for the same reason: a readiness check that quietly probes the published address
    proves the address was published, not that the guest is reachable.

    The wire has to keep them apart too, or a client re-derives the same wrong conclusion:

    ``published_address``  what a scoreboard or a participant is told to use. NOT NECESSARILY
                           REACHABLE from the worker.
    ``probe_address``      what readiness verification actually connects to. ``None`` means no
                           distinct probe address was assigned — never "use the published one".
    ``observed_address``   what the provider actually reported for this guest after apply.
                           ``None`` means not observed, which is not an address and not a failure.
    """

    published_address: str
    probe_address: str | None = None
    #: The domain's own :attr:`GuestAddress.probe_is_distinct`, published so a client does not
    #: re-derive it (and cannot re-derive it wrongly).
    probe_is_distinct: bool
    #: ``None`` until a verification is recorded that reports one. Distinct from ``observed``.
    observed_address: str | None = None
    #: Whether ANY observation of this guest has been recorded. ``False`` with
    #: ``observed_address: null`` means nobody has looked; ``True`` with ``null`` means the
    #: provider was observed and reported no address.
    observed: bool = False


class ProxmoxGuestOut(BaseModel):
    """One planned guest, typed — so the contract carries it rather than an opaque blob."""

    guest_ref: str
    name: str
    kind: str
    vmid: int | None = None
    node_name: str | None = None
    template_ref: str | None = None
    team_ref: str | None = None
    address: ProxmoxGuestAddressOut
    #: MAC addresses this guest's NICs are allocated, in NIC order.
    mac_addresses: list[str] = Field(default_factory=list)
    #: Carried per guest because it distinguishes THIS operation's objects from a previous
    #: generation's. Dropping it is how a reset's objects become indistinguishable from a deploy's.
    generation: int | None = None
    operation_generation: int | None = None


class ProxmoxTopologyOut(BaseModel):
    """The compiled desired state: what would exist if this plan were applied exactly."""

    state: PlanState
    plan_hash: str | None = None
    blocked_reason: str | None = None
    blocked_reasons: list[BlockedReasonOut] = Field(default_factory=list)
    observation: ProxmoxObservationOut
    #: The canonical desired-state document. Same content the plan hash is taken over.
    topology: dict[str, Any] | None = None
    #: The same guests as ``topology["guests"]``, typed. The raw document stays because the plan
    #: hash is taken over it and a reviewer must be able to see exactly what was hashed; this is
    #: what a client should actually read.
    guests: list[ProxmoxGuestOut] | None = None
    #: ``None`` when the plan did not compile. An empty list would read as "a lab with no
    #: teams", which is a shape the compiler refuses to produce.
    team_refs: list[str] | None = None
    guest_count: int | None = None
    vnet_count: int | None = None


class ProxmoxAllocationsOut(BaseModel):
    """Every identifier the plan reserves, before any of them exists on the cluster."""

    state: PlanState
    plan_hash: str | None = None
    blocked_reasons: list[BlockedReasonOut] = Field(default_factory=list)
    #: ``None`` when the plan did not compile — no identifiers were reserved because none
    #: could be computed, which is not the same as a plan that reserves nothing.
    allocations: list[ProxmoxAllocationOut] | None = None
    #: Content hash of the allocation ledger alone, stable across recompiles of the same binding.
    ledger_hash: str | None = None


class ProxmoxPlanOut(BaseModel):
    """The plan document, its hash, and whether it has been approved.

    ``document_version`` is ``secp-proxmox/desired-state-document/v1`` — the DESIRED STATE this API
    compiled. It is NOT the worker's OpenTofu plan document
    (``secp-proxmox/plan-document/v1``), which describes what ``tofu plan`` computed against real
    remote state and is produced only inside the privileged worker.
    """

    state: PlanState
    document_version: str
    plan_hash: str | None = None
    blocked_reason: str | None = None
    blocked_reasons: list[BlockedReasonOut] = Field(default_factory=list)
    document: dict[str, Any] | None = None
    approval: ApprovalOut | None = None
    #: True only when a live approval names exactly the current ``plan_hash``.
    #: ``None`` when there is no current hash to compare against, so the question is
    #: unanswerable rather than answered "no".
    approved_hash_is_current: bool | None = None
    #: ``None`` when nothing was compiled. An empty list would read as "no isolation
    #: properties were claimed", the opposite of what a blocked plan means.
    isolation: list[IsolationFindingOut] | None = None
    isolation_holds: bool | None = None
    #: Flag values no substring guard can prove absent. Being listed is itself the finding.
    #: ``None`` when no plan was compiled. An empty list is a real and different finding:
    #: every flag this template ships CAN be guarded by the substring scan.
    unguardable_flag_values: list[str] | None = None


class ProxmoxApplyAuthorizationOut(BaseModel):
    """Whether apply is authorized for the plan the range currently has."""

    state: AuthorizationState
    plan_hash: str | None = None
    plan_state: PlanState
    approval: ApprovalOut | None = None
    authorization: ApprovalOut | None = None
    #: Why apply cannot be enqueued right now, or ``None`` when it can.
    blocked_reason: str | None = None


class ProxmoxDestroyPlanOut(BaseModel):
    """The destroy plan and its own hash — a deletion scope, not the creation plan reversed."""

    state: PlanState
    destroy_hash: str | None = None
    blocked_reasons: list[BlockedReasonOut] = Field(default_factory=list)
    #: The bounded set of owned objects a destroy would remove.
    #: ``None`` when the destroy plan did not compile. An UNCOMPUTED deletion set and an
    #: EMPTY one are different facts and must not share a representation: an empty set says
    #: "a destroy would remove nothing because this range owns nothing", which makes a
    #: destroy look safe when in truth nothing has been enumerated.
    deletion_set: list[dict[str, Any]] | None = None
    #: ``None``, never ``0``, when the deletion set was not computed.
    deletion_set_size: int | None = None
    approval: ApprovalOut | None = None
    approved_hash_is_current: bool | None = None


class ProxmoxDestroyAuthorizationOut(BaseModel):
    """Whether destroy is authorized. Never satisfied by an apply authorization."""

    state: AuthorizationState
    destroy_hash: str | None = None
    destroy_plan_state: PlanState
    approval: ApprovalOut | None = None
    authorization: ApprovalOut | None = None
    blocked_reason: str | None = None


class ProxmoxVerificationOut(BaseModel):
    """What was OBSERVED after an apply — infrastructure and isolation reported separately.

    They are separate because they fail for different reasons and mean different things: every VM
    can exist, be running and have the right disks while the firewall lets one team reach another.
    Reporting a single verdict would let a passing infrastructure check mask an isolation
    violation, so ``infrastructure`` and ``isolation`` each carry their own outcome and neither is
    derived from the other.

    ``state`` is ``undetermined`` when no verification has been recorded. That is not a pass.
    """

    state: RecordedStageState
    #: The worker's outcome, verbatim. Absent when nothing was recorded.
    infrastructure_outcome: str | None = None
    isolation_outcome: str | None = None
    #: ``None`` when nothing was recorded, and ``None`` also when a recorded report carried
    #: no such key. Each finding keeps whatever the worker wrote — in particular a check's
    #: observed/ok PAIR, never flattened to one boolean: a check that could not be observed
    #: and a check that ran and failed are different outcomes, and one boolean makes them
    #: indistinguishable to every client downstream.
    infrastructure_checks: list[dict[str, Any]] | None = None
    isolation_checks: list[dict[str, Any]] | None = None
    observed_at: datetime | None = None
    detail: str | None = None


class ProxmoxReadinessOut(BaseModel):
    """Whether the PLAN would constitute a runnable two-team competition.

    A property of a document already in hand, and never a statement about a deployed range. Passing
    every requirement here means the plan is worth applying and says nothing about what is running.
    """

    state: PlanState
    plan_hash: str | None = None
    #: ``None`` when the plan did not compile: readiness was not assessed, which is not the
    #: same as assessed and found wanting.
    satisfied: bool | None = None
    blocked_reasons: list[BlockedReasonOut] = Field(default_factory=list)
    findings: list[ReadinessFindingOut] | None = None
    challenge_keys: list[str] | None = None
    scoring_endpoints: list[dict[str, Any]] | None = None


class ProxmoxResetDispositionsOut(BaseModel):
    """What a reset did to each guest, as the worker observed it.

    ``state`` is ``undetermined`` when no reset has been recorded — distinct from a reset that ran
    and reported every guest as ``recovery_required``.
    """

    state: RecordedStageState
    #: ``None`` when no reset was recorded. An empty list would say "a reset ran and touched
    #: no guest", which is a real and very different observation.
    dispositions: list[dict[str, Any]] | None = None
    observed_at: datetime | None = None
    detail: str | None = None


class ProxmoxResidueOut(BaseModel):
    """The zero-residue proof: what a teardown actually PROVED absent.

    ``unproven`` is a first-class verdict here and is never folded into ``clean``. A probe that
    could not run leaves the resource unproven, and a destroy with any unproven resource has not
    proved zero residue however many others it removed.
    """

    state: RecordedStageState
    verdict: str | None = None
    probe_reachable: bool | None = None
    expected_count: int | None = None
    removed_confirmed: int | None = None
    still_present: int | None = None
    unproven_count: int | None = None
    #: Residue classes no probe covered. A non-empty list means the proof is incomplete.
    #: ``None`` when not computed. An EMPTY list is the STRONG claim — every residue class
    #: was probed — and must never be produced by a missing key.
    uncovered_classes: list[str] | None = None
    resources: list[dict[str, Any]] | None = None
    reason: str | None = None
    observed_at: datetime | None = None


class ProxmoxOwnershipOut(BaseModel):
    """How this range's objects are stamped and classified."""

    state: PlanState
    blocked_reasons: list[BlockedReasonOut] = Field(default_factory=list)
    ownership: OwnershipClassOut | None = None


class ProxmoxLifecycleOut(BaseModel):
    """One request that answers "where is this range in the Proxmox lifecycle".

    A convenience over the individual surfaces, for a client that would otherwise open eight
    connections to render one page. Every field is the same value the dedicated endpoint returns.
    """

    range_id: uuid.UUID
    provider: str
    range_state: str
    observation: ProxmoxObservationOut
    plan_state: PlanState
    plan_hash: str | None = None
    destroy_hash: str | None = None
    apply_authorization: AuthorizationState
    destroy_authorization: AuthorizationState
    verification: RecordedStageState
    reset_dispositions: RecordedStageState
    residue: RecordedStageState
    readiness_satisfied: bool | None = None
    isolation_holds: bool | None = None
    blocked_reasons: list[BlockedReasonOut] = Field(default_factory=list)
