"""Request and response schemas for the Proxmox operator command surface.

THE GENERATED OPENAPI IS THE CONTRACT. A generated client transcribes these; a transcription that
disagrees with them is wrong, not the other way round.

APPLY AND DESTROY NEVER SHARE A SHAPE
---------------------------------------
This is the property #110 established, that a shared request model would quietly undo, and that a
generated client must inherit rather than be trusted to reconstruct.

* :class:`ProxmoxExecutionRequest` and :class:`ProxmoxResetRequest` require ``plan_hash``.
* :class:`ProxmoxDestroyPlanGenerateRequest` and :class:`ProxmoxDestroyExecutionRequest` require
  ``destroy_hash``.
* Every model sets ``extra="forbid"`` and every hash field is required.

So posting an execution body to the destroy endpoint is a 422 — the required ``destroy_hash`` is
absent AND the supplied ``plan_hash`` is rejected as unknown — and there is no body that validates
as both. Combined with the two hash DOMAINS (a plan digest is not a syntactically valid destroy
digest for the same range), a valid apply authorization is structurally incapable of authorizing a
destroy.

``operation_kind`` IS ON THE RESPONSE
---------------------------------------
:class:`ProxmoxCommandOut` carries ``operation_kind`` as a required enum field. It travels
DB -> API schema -> OpenAPI -> generated client, so a client never infers which act a record
represents from the path it happened to call. An inferred kind is one refactor away from being the
wrong kind, and the record it labels is the audit record for creating or deleting real machines.

NO SECRET HAS A FIELD TO TRAVEL IN
------------------------------------
No provider credential, no OpenTofu or remote-state credential, no enrollment key material, no
signing key, no flag value. The worker assertion carries an installation ID and a release DIGEST —
both public identifiers the operator already holds — and never a key, a token or an endpoint.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from secp_api.services.proxmox_commands import CommandKind, RefusalCode


class _CommandBody(BaseModel):
    """The envelope every command request carries, plus a closed field set.

    ``extra="forbid"`` is load-bearing rather than tidy: silently ignoring an unexpected key is how
    a client posts ``{"destroy_hash": ...}`` to the execution endpoint, receives a 2xx, and believes
    it requested something it did not.
    """

    model_config = ConfigDict(extra="forbid")

    #: Deduplicates a retry. Compared together with a digest of the WHOLE request — a different
    #: request under a used key is refused (``idempotency_key_reused``), never served from the
    #: earlier record.
    idempotency_key: str = Field(min_length=8, max_length=200)
    #: The range's version as the caller last read it (``event_sequence``). A compare-and-swap
    #: token: anything recorded since — an approval, a fresh observation, another operator's
    #: command — invalidates it and the command is refused rather than applied to a world the
    #: caller has not seen.
    expected_version: int = Field(ge=0)
    #: The generation of resources this command intends to act on.
    operation_generation: int = Field(ge=0)
    #: The target the caller believes this range plans against. Checked, never trusted.
    target_id: str = Field(min_length=1, max_length=200)
    #: The cluster fingerprint the caller believes that target has. A cluster rebuilt under the
    #: same name is a different cluster, and this is what notices.
    cluster_fingerprint: str = Field(min_length=1, max_length=200)


class _WorkerFields(BaseModel):
    """Named by the three commands that hand work to a privileged worker.

    Public identifiers only. The installation id says WHICH worker; the release digest says which
    build of it — which decides which gates the executing process actually runs, so a mismatch is
    never a detail. Neither is a credential and neither authenticates anything: the control plane
    checks them against the enrollment record it already holds.
    """

    worker_installation_id: str = Field(min_length=8, max_length=64)
    release_digest: str = Field(min_length=8, max_length=80)


# --- requests: the apply family carries plan_hash ONLY --------------------------


class ProxmoxCompileTopologyRequest(_CommandBody):
    """Recompile the topology from the observation of record.

    Deliberately carries NO hash: this is the act that produces one. Requiring the caller to name
    the hash they expect would make it impossible to refresh after the observation changed, which
    is the only case in which refreshing is interesting.
    """


class ProxmoxGeneratePlanRequest(_CommandBody):
    """Materialise the compiled plan as a durable record. Carries ``plan_hash`` ONLY."""

    plan_hash: str = Field(min_length=8, max_length=200)


class ProxmoxSubmitPlanRequest(_CommandBody):
    """Submit an exact generated plan for review. APPROVES NOTHING. ``plan_hash`` ONLY."""

    plan_hash: str = Field(min_length=8, max_length=200)


class ProxmoxExecutionRequest(_CommandBody, _WorkerFields):
    """Request execution of the authorized apply. ``plan_hash`` ONLY — never ``destroy_hash``."""

    plan_hash: str = Field(min_length=8, max_length=200)


class ProxmoxResetRequest(_CommandBody, _WorkerFields):
    """Request a reset of the authorized reset scope. ``reset_hash`` ONLY.

    Not ``plan_hash``. A reset DESTROYS every guest in the range and rebuilds it, so it is
    authorized by naming the guests that will be destroyed — a third hash domain, distinct from
    both the creation plan and the destroy deletion set (a reset preserves the whole network).
    """

    reset_hash: str = Field(min_length=8, max_length=200)


class ProxmoxReconciliationRequest(_CommandBody):
    """Request reconciliation of the deployed range against its desired state.

    Carries no hash: reconciliation compares what EXISTS against what the current plan describes,
    so pinning it to a document the operator read would be pinning the wrong side of the comparison.
    """


# --- requests: the destroy family carries destroy_hash ONLY ---------------------


class ProxmoxDestroyPlanGenerateRequest(_CommandBody):
    """Materialise the deletion scope. ``destroy_hash`` ONLY.

    An apply body cannot validate here: ``plan_hash`` is rejected as an unknown field and the
    required ``destroy_hash`` is absent.
    """

    destroy_hash: str = Field(min_length=8, max_length=200)


class ProxmoxDestroyExecutionRequest(_CommandBody, _WorkerFields):
    """Request execution of the authorized destroy. ``destroy_hash`` ONLY."""

    destroy_hash: str = Field(min_length=8, max_length=200)


# --- response -------------------------------------------------------------------


class ProxmoxCommandOut(BaseModel):
    """One durable command record, as it was accepted."""

    #: WHICH act this record is. Required, on the payload, never inferred from the URL that
    #: returned it — so an execution request stays distinguishable from a destroy execution request
    #: everywhere it travels, including inside a generated client.
    operation_kind: CommandKind
    range_id: uuid.UUID
    organization_id: uuid.UUID
    #: The exact digest this command was issued against: a PLAN hash for the apply family, a
    #: DESTROY hash for the destroy family. ``None`` only for the two commands that name no
    #: document. The two are never interchangeable — they are computed under different domain
    #: prefixes, so one is not a valid value for the other even for a byte-identical document.
    subject_hash: str | None = None
    idempotency_key: str
    #: The range version this command was accepted at — the version the caller's compare-and-swap
    #: matched, not the one this command's own record created.
    accepted_version: int
    operation_generation: int
    target_id: str
    cluster_fingerprint: str
    requested_by: uuid.UUID | None = None
    at: datetime
    sequence: int
    #: The durable infrastructure operation this command enqueued. ``None`` when it enqueued none.
    #: A retry returns the SAME id and dispatches nothing — one accepted command is one job.
    operation_id: uuid.UUID | None = None
    #: True when this response replays an earlier identical request rather than accepting a new
    #: one. Distinguishable so a caller whose first response was lost can tell what happened.
    deduplicated: bool = False
    #: Whether anything is actually in flight. ``False`` on an ACCEPTED command is a real state,
    #: not a failure — see ``not_enqueued_reason``.
    enqueued: bool = False
    #: Why nothing was enqueued, as a stable code. ``None`` exactly when ``enqueued`` is true or
    #: when this command never enqueues by design. It is published rather than implied because
    #: "recorded, and nothing has picked it up" and "recorded, and a worker is running it" are
    #: different facts and a client that cannot tell them apart will show a spinner forever.
    not_enqueued_reason: RefusalCode | None = None
