"""The Proxmox reads that had no route: worker, workload/bootstrap, reset plan, reconciliation,
evidence references.

Each one folds data that already exists — the compiled plan, the worker enrollment head row, the
worker-recorded stages — rather than building a second Proxmox product universe beside the first.
Where an existing surface already answers a question it is NOT duplicated here: discovery freshness
and provenance stay on ``/proxmox/observation``, apply-authorization state on
``/proxmox/apply-authorization``, competition readiness on ``/proxmox/readiness``, deployment
operation state on the provider-neutral ``/range-operations/{id}``, activity events on
``/ranges/{id}/events``, and target eligibility on ``/ranges/{id}/scenario``.

FOUR ADDRESSES, AND THE ONE THAT WAS MISSING
----------------------------------------------
:class:`~secp_api.schemas_proxmox.ProxmoxGuestAddressOut` already publishes the topology's
``published_address`` and ``probe_address`` plus the ``observed_address`` from a recorded
verification. What had no route at all was the WORKER's side: every
:class:`~secp_api.range_providers.proxmox_workload.GuestBootstrapContract` carries its own
``probe_address``/``probe_port`` (what the worker connects to when it checks the guest came up) and
``report_address``/``report_port`` (where the guest reports back). Those are not the topology's
addresses and must never be substituted for them — the whole reason #103 happened is that a worker
probed an address that was published rather than reachable.

So :class:`ProxmoxGuestBootstrapOut` publishes them separately and beside the topology's, and each
stays ``None`` when it is genuinely absent rather than falling back to a neighbour.

NOTHING SECRET HAS A FIELD
----------------------------
The worker read publishes the enrollment's PUBLIC identity — its state, installation ids, key id,
release digest, site label, contract version, expiry. It deliberately omits ``transaction_id``,
``state_digest``, ``offer_digest`` and ``result_digest``: those are the controller's
compare-and-swap chain, not facts about the worker, and an operator needs none of them to decide
whether this worker may be given live work. Bootstrap material is published as a REFERENCE
(:class:`MaterialRefOut`) and never as material.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from secp_api.services.proxmox_lifecycle import PlanState, RecordedStageState

# --- the worker that would execute ---------------------------------------------


class ProxmoxWorkerOut(BaseModel):
    """The enrolled worker bound to this range's organization and site, and whether it may execute.

    ``eligible_for_execution`` is DERIVED from the fields below it, in one place, so the flag and
    the reasons can never disagree. It is ``false`` with named blockers rather than the endpoint
    404ing or omitting the worker: "no worker is enrolled" is an answer an operator needs, and it is
    not the same answer as "a worker is enrolled but is not healthy".
    """

    #: ``False`` when no enrollment matches this organization at all. Every other field is then
    #: ``None`` — which says nobody is enrolled, not that an enrolled worker has no identity.
    enrolled: bool
    #: The enrollment lifecycle state, verbatim: one of the eight closed values. Only ``healthy``
    #: has completed the full attestation exchange.
    state: str | None = None
    worker_installation_id: str | None = None
    #: The worker's public key identifier — a digest, never key material.
    worker_key_id: str | None = None
    controller_installation_id: str | None = None
    #: Which build is enrolled. The release decides which gates the executing process runs, so a
    #: command that names a different one is refused rather than tolerated.
    release_digest: str | None = None
    deployment_site_label: str | None = None
    contract_version: str | None = None
    revision: int | None = None
    expires_at: str | None = None
    #: Set only on a terminal/refused enrollment; a bounded closed code, never free-form prose.
    refusal_reason: str | None = None
    #: Whether this worker may be handed controlled-live execution right now.
    eligible_for_execution: bool
    #: Why not, as stable ``RefusalCode`` values a client may branch on. Empty exactly when
    #: ``eligible_for_execution`` is true.
    blockers: list[str] = Field(default_factory=list)


# --- workload and bootstrap -----------------------------------------------------


class MaterialRefOut(BaseModel):
    """A REFERENCE to post-provisioning material. Never the material.

    The reference names where something lives and on which channel it travels. Publishing the
    reference lets an operator reason about a stuck bootstrap; publishing the material would put
    it in a response, a log and a browser cache.
    """

    ref: str
    scope: str
    purpose: str
    channel: str


class BootstrapOperationOut(BaseModel):
    key: str
    description: str
    timeout_seconds: int


class ProxmoxGuestBootstrapOut(BaseModel):
    """One guest's bootstrap contract — the WORKER's view, kept apart from the topology's.

    ``probe_address`` here is what the worker connects to in order to check this guest came up. It
    is NOT the topology's ``published_address`` (what a participant is told to use) and NOT the
    topology's own ``probe_address``, and there is no fallback between any of them. A readiness
    check that quietly probes the published address proves the address was published.

    ``report_address`` is a fourth thing again: where the guest reports its own bootstrap result.
    """

    guest_ref: str
    vmid: int
    team_ref: str
    workload_key: str
    workload_version: str
    #: The digest of the reviewed image this guest is cloned from. Pinned, never ``latest``.
    image_digest: str
    operations: list[BootstrapOperationOut] = Field(default_factory=list)
    #: A reference to the attestation material, never the material itself.
    attestation_ref: MaterialRefOut
    report_address: str
    report_port: int
    #: ``None`` means no distinct worker probe address was assigned — never "use another one".
    probe_address: str | None = None
    probe_port: int | None = None
    deadline_seconds: int
    #: What a recorded verification observed for this guest, or ``None`` with ``observed: false``
    #: when nothing has looked. An unobserved guest is not a failed one.
    observed_address: str | None = None
    observed: bool = False


class ProxmoxWorkloadOut(BaseModel):
    """The workload and bootstrap plan, and what has been observed of it."""

    state: PlanState
    plan_hash: str | None = None
    #: ``None`` when the plan did not compile. An empty list would say "a lab with no guests".
    guests: list[ProxmoxGuestBootstrapOut] | None = None
    materials: list[MaterialRefOut] | None = None
    challenge_keys: list[str] | None = None
    #: Whether a verification has been recorded at all. ``undetermined`` is not a pass.
    verification: RecordedStageState
    blocked_reasons: list[dict[str, Any]] = Field(default_factory=list)


# --- the reset plan, as distinct from what a reset did --------------------------


class ProxmoxResetGuestOut(BaseModel):
    """What a reset WOULD do to one guest."""

    guest_ref: str
    name: str
    vmid: int
    team_ref: str | None = None
    #: The identifiers a reset resolves rather than renumbering. Determinism is the whole reason a
    #: reset can restore a range instead of building a second one beside it.
    node_name: str | None = None
    #: ``recreate`` for a guest the plan rebuilds from its reviewed template. Named rather than
    #: implied so a client is never left to infer the action from the absence of another field.
    intended_action: str


class ProxmoxResetPlanOut(BaseModel):
    """What a reset would do — NOT what one did.

    Deliberately a different endpoint and a different shape from
    ``/proxmox/reset-dispositions``, which reports what the worker OBSERVED a reset doing. A plan
    and an observation are different claims and the moment they share a surface a client starts
    reading one as the other.
    """

    state: PlanState
    plan_hash: str | None = None
    #: ``None`` when the plan did not compile: no reset was planned because none could be.
    guests: list[ProxmoxResetGuestOut] | None = None
    #: Whether a reset has ever been observed on this range. ``undetermined`` means none has.
    last_observed: RecordedStageState
    blocked_reasons: list[dict[str, Any]] = Field(default_factory=list)


# --- reconciliation -------------------------------------------------------------


class ProxmoxReconciliationOut(BaseModel):
    """Whether reconciliation was asked for, and whether anything has answered.

    TWO independent facts, and conflating them is the failure this shape exists to prevent. A
    request being recorded says an operator asked; it says nothing about a worker having looked.
    ``state`` is the OBSERVATION and stays ``undetermined`` until a worker records one.
    """

    #: The worker-recorded reconciliation, or ``undetermined`` when there is none. Not a pass.
    state: RecordedStageState
    #: Whether an operator has requested reconciliation on this range.
    requested: bool
    requested_at: datetime | None = None
    requested_by: uuid.UUID | None = None
    #: True only when a request was recorded AND handed to a queue. ``False`` with
    #: ``requested: true`` is the current, honest state — see ``not_enqueued_reason``.
    enqueued: bool = False
    #: Why nothing was enqueued, as a stable code. ``None`` when nothing was requested.
    not_enqueued_reason: str | None = None
    #: The worker's recorded findings, verbatim. ``None`` when nothing was recorded — distinct from
    #: an empty list, which would say a reconciliation ran and found no drift.
    findings: list[dict[str, Any]] | None = None
    observed_at: datetime | None = None
    detail: str | None = None


# --- evidence references --------------------------------------------------------


class EvidenceReferenceOut(BaseModel):
    """One pointer to evidence. A reference and a timestamp, never a payload.

    ``present`` is false with ``reference: null`` when this class of evidence does not exist yet —
    which is a different fact from evidence that exists and could not be read, and both are
    different from evidence that exists and is clean.
    """

    kind: str
    present: bool
    reference: str | None = None
    observed_at: datetime | None = None
    detail: str | None = None


class ProxmoxEvidenceOut(BaseModel):
    """Every evidence reference this range has, in one place.

    References only. The verification report, the residue proof and the discovery snapshot are each
    reachable through their own endpoints; this says WHICH of them exist and what identifies them,
    so an operator assembling a record for an event knows what they have before they fetch it.
    """

    range_id: uuid.UUID
    references: list[EvidenceReferenceOut]
    #: Teardown evidence rows recorded for this range, by id. Empty means none was recorded — which
    #: for a range that has never been destroyed is correct and expected.
    teardown_evidence_ids: list[uuid.UUID] = Field(default_factory=list)
