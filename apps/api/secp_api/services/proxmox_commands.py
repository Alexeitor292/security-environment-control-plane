"""The operator COMMAND half of the Proxmox range lifecycle.

:mod:`secp_api.services.proxmox_lifecycle` is the read-and-authorize half: it compiles, folds and
records the four approvals. This module is the rest of the operator's verbs — compile/refresh the
topology, generate the plan, submit it for review, request execution, request a reset, request
reconciliation, generate the destroy plan, request destroy execution — and the single preflight
every one of them passes through.

WHAT A COMMAND DOES, AND WHAT IT CANNOT DO
--------------------------------------------
A command PERSISTS INTENT and, where a worker is needed, ENQUEUES. That is all. Nothing here runs
OpenTofu, spawns a process, opens a socket to a cluster, holds a provider credential, projects a
provider secret, touches host networking, or imports a privileged execution adapter — and it cannot,
because ``tests/test_architecture_boundary.py`` refuses ``secp_worker`` in every API module but
``dispatch.py``. Approving is not executing; authorizing is not executing; requesting execution
writes a durable operation row and hands it to the outbox, and the API's involvement ends there.

APPLY AND DESTROY ARE STRUCTURALLY SEPARATE, ALL THE WAY DOWN
---------------------------------------------------------------
There is no generic approval object and no generic command object. :class:`CommandKind` gives each
act its own member; the apply family carries ``plan_hash`` and the destroy family carries
``destroy_hash``; the two hashes are computed in different domains, so a plan hash is not even a
syntactically valid destroy hash for the same range. A valid apply authorization is therefore
*structurally incapable* of authorizing a destroy: there is no body that satisfies both schemas, no
record that can be read as either, and no code path that converts one into the other.

``operation_kind`` is carried ON THE RECORD, not inferred from the URL that returned it — so it
survives DB -> API schema -> OpenAPI -> generated client, and a client never has to guess which act
a record represents.

WHY THE DURABLE STATE IS THE EVENT LOG
----------------------------------------
No migration. ``RUNTIME_REQUIRED_MIGRATION_HEAD`` is pinned and CI verifies the live Alembic head,
so there is no new table and no new column. That constraint fits what is being stored: a command is
something a named principal asked for, against an exact document, at an exact moment, and it must
stay true afterwards even when the plan is recompiled and the hash moves. That is an append-only
audit record — :class:`~secp_api.range_models.RangeLifecycleEvent`, org-scoped and densely
sequenced, which the approvals already use.

IDEMPOTENCY IS OVER THE WHOLE REQUEST, NOT THE KEY ALONE
----------------------------------------------------------
A retry must reuse the durable operation and must never enqueue a second infrastructure job. So a
repeat of an accepted command with the same key returns the SAME record — including the same
``operation_id`` — and dispatches nothing. A DIFFERENT request under a key that has already been
used is refused (:data:`RefusalCode.idempotency_key_reused`) rather than served from the first
record: silently returning the first answer to a second, different question is how an operator
believes they authorized what they just sent when they authorized something else.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.enums import Permission
from secp_api.errors import DomainError
from secp_api.range_enums import RangeOperationKind, RangeState
from secp_api.range_models import RangeInstance, RangeLifecycleEvent
from secp_api.range_providers.proxmox_model import BlockedPlan
from secp_api.services import proxmox_lifecycle
from secp_api.services import ranges as range_service
from secp_api.worker_enrollment_models import WorkerEnrollmentState

# --------------------------------------------------------------------------------------
# The command vocabulary
# --------------------------------------------------------------------------------------


class CommandKind(str, Enum):
    """Which operator act a durable command record is.

    Each member is its own act with its own permission, its own preconditions and its own request
    schema. There is deliberately no ``approve`` or ``execute`` member that could stand for either
    an apply or a destroy — see the module docstring. ``operation_kind`` on the wire is exactly one
    of these, never derived by a client from the path it called.
    """

    #: Recompile the topology from the observation of record and record what it produced.
    compile_topology = "compile_topology"
    #: Materialise the compiled plan as a durable, hash-identified generation record.
    generate_plan = "generate_plan"
    #: Put an exact generated plan in front of a reviewer. Approves nothing.
    submit_plan_for_review = "submit_plan_for_review"
    #: Ask for the authorized apply to be executed. Enqueues; applies nothing here.
    request_execution = "request_execution"
    #: Ask for a reset of the deployed range. Enqueues; resets nothing here.
    request_reset = "request_reset"
    #: Ask for the deployed range to be reconciled against its desired state.
    request_reconciliation = "request_reconciliation"
    #: Materialise the deletion scope as a durable, hash-identified generation record.
    generate_destroy_plan = "generate_destroy_plan"
    #: Ask for the authorized destroy to be executed. Enqueues; destroys nothing here.
    request_destroy_execution = "request_destroy_execution"


#: The event kind each command appends. One kind per command, so a fold never has to disambiguate
#: two acts recorded under one name, and so an operator reading the raw timeline sees what happened.
COMMAND_EVENT_KINDS: dict[CommandKind, str] = {
    CommandKind.compile_topology: "proxmox_topology_compiled",
    CommandKind.generate_plan: "proxmox_plan_generated",
    CommandKind.submit_plan_for_review: "proxmox_plan_submitted_for_review",
    CommandKind.request_execution: "proxmox_execution_requested",
    CommandKind.request_reset: "proxmox_reset_requested",
    CommandKind.request_reconciliation: "proxmox_reconciliation_requested",
    CommandKind.generate_destroy_plan: "proxmox_destroy_plan_generated",
    CommandKind.request_destroy_execution: "proxmox_destroy_execution_requested",
}

#: The permission each command requires, exactly. Read permission (``exercise_operate``) is checked
#: first by ``range_service.get_range`` and is never sufficient on its own for any of these.
#:
#: ``request_destroy_execution`` and ``generate_destroy_plan`` require ``exercise_destroy`` and
#: NOTHING ELSE grants it: holding ``exercise_apply`` never permits a destroy, which is the same
#: separation the two hash domains enforce, expressed in the permission model.
COMMAND_PERMISSIONS: dict[CommandKind, Permission] = {
    CommandKind.compile_topology: Permission.plan_generate,
    CommandKind.generate_plan: Permission.plan_generate,
    CommandKind.submit_plan_for_review: Permission.plan_approve,
    CommandKind.request_execution: Permission.exercise_apply,
    CommandKind.request_reset: Permission.exercise_reset,
    CommandKind.request_reconciliation: Permission.exercise_operate,
    CommandKind.generate_destroy_plan: Permission.exercise_destroy,
    CommandKind.request_destroy_execution: Permission.exercise_destroy,
}

#: Which commands enqueue durable infrastructure work, and as which operation kind.
#:
#: ``request_reconciliation`` IS NOT HERE, and that is a deliberate refusal rather than an omission.
#: ``secp_worker.range.execution.execute_range_operation`` dispatches ``destroy`` and ``reset``
#: explicitly and treats EVERY OTHER operation kind as a deploy. Enqueueing a reconciliation as a
#: range operation would therefore run a deploy against real hardware. Reconciliation records its
#: intent durably and stops; :data:`RefusalCode.reconciliation_consumer_unavailable` is what the
#: read surface says instead of pretending a job is in flight.
COMMAND_OPERATION_KINDS: dict[CommandKind, RangeOperationKind] = {
    CommandKind.request_execution: RangeOperationKind.deploy,
    CommandKind.request_reset: RangeOperationKind.reset,
    CommandKind.request_destroy_execution: RangeOperationKind.destroy,
}

#: Which hash family a command is identified by. The apply family is compared against the plan hash
#: and the destroy family against the destroy hash; a command in one family can never be satisfied
#: by a digest from the other, because the two are computed under different domain prefixes.
DESTROY_FAMILY: frozenset[CommandKind] = frozenset(
    {CommandKind.generate_destroy_plan, CommandKind.request_destroy_execution}
)

#: The RESET family, identified by the reset scope's own digest — a third domain, not a variant of
#: either other one. A reset destroys every guest and preserves every network object, so its scope
#: is neither the creation manifest nor the destroy deletion set.
RESET_FAMILY: frozenset[CommandKind] = frozenset({CommandKind.request_reset})


def subject_hash_for(kind: CommandKind, compiled: proxmox_lifecycle.CompiledRangePlan) -> str:
    """Which digest identifies this command, by family.

    A function rather than a conditional expression inline in the preflight, because it is the one
    place the three families are distinguished and it must stay exhaustive: a command added to
    neither set silently falls into the apply family, which is the same fail-open shape that let a
    string-compared gate authorize a destroy with an apply approval.
    """
    if kind in DESTROY_FAMILY:
        return compiled.destroy_hash
    if kind in RESET_FAMILY:
        return compiled.reset_hash
    return compiled.plan_hash


#: Commands that require the range to be in a state where it still owns (or may own) resources.
_ALLOWED_RANGE_STATES: dict[CommandKind, frozenset[RangeState]] = {
    CommandKind.compile_topology: frozenset(
        {RangeState.draft, RangeState.ready, RangeState.active, RangeState.failed}
    ),
    CommandKind.generate_plan: frozenset(
        {RangeState.draft, RangeState.ready, RangeState.active, RangeState.failed}
    ),
    CommandKind.submit_plan_for_review: frozenset(
        {RangeState.draft, RangeState.ready, RangeState.active, RangeState.failed}
    ),
    CommandKind.request_execution: frozenset({RangeState.draft, RangeState.failed}),
    CommandKind.request_reset: frozenset({RangeState.ready, RangeState.active, RangeState.failed}),
    CommandKind.request_reconciliation: frozenset(
        {RangeState.ready, RangeState.active, RangeState.failed, RangeState.recovery_required}
    ),
    CommandKind.generate_destroy_plan: frozenset(
        {
            RangeState.draft,
            RangeState.ready,
            RangeState.active,
            RangeState.failed,
            RangeState.recovery_required,
        }
    ),
    CommandKind.request_destroy_execution: frozenset(
        {
            RangeState.draft,
            RangeState.ready,
            RangeState.active,
            RangeState.failed,
            RangeState.recovery_required,
        }
    ),
}


# --------------------------------------------------------------------------------------
# Refusals
# --------------------------------------------------------------------------------------


class RefusalCode(str, Enum):
    """Stable, machine-readable reasons a command is refused.

    A client branches on these; the message beside them is for a human and may change. Every member
    must have a test that provokes exactly it —
    ``test_proxmox_operator_commands.py::test_every_refusal_code_has_a_test_that_provokes_it``
    enumerates this enum FROM THE LIVE MODULE and fails on any member no test covers. It is
    enumerated rather than listed because a hand-maintained list written by the same author cannot
    notice a code that author forgot.
    """

    # --- scope and identity -------------------------------------------------------------
    #: The range is not a Proxmox range, so it has no Proxmox command surface.
    range_not_proxmox = "range_not_proxmox"
    #: The caller named a target that is not the one this range's observation was taken from.
    target_mismatch = "target_mismatch"
    #: The caller named a cluster fingerprint the observation of record does not carry. A cluster
    #: rebuilt under the same name is a DIFFERENT cluster, and its identifiers are not this plan's.
    cluster_fingerprint_mismatch = "cluster_fingerprint_mismatch"
    #: The caller's declared ownership scope is not the one the plan stamps its objects with.
    ownership_scope_mismatch = "ownership_scope_mismatch"

    # --- prerequisites ------------------------------------------------------------------
    #: The plan does not compile. Nothing can be generated, submitted, approved or executed.
    plan_blocked = "plan_blocked"
    #: No discovery observation has been recorded. An UNCHECKED prerequisite, not a failed one.
    observation_absent = "observation_absent"
    #: The observation of record is older than the freshness bound. A STALE prerequisite.
    observation_stale = "observation_stale"
    #: A plan generation record must exist before the plan can be submitted or executed.
    plan_not_generated = "plan_not_generated"
    #: The plan has not been put in front of a reviewer.
    plan_not_submitted = "plan_not_submitted"
    #: The plan carries no current approval.
    plan_not_approved = "plan_not_approved"
    #: Apply is not authorized for the plan the range currently has.
    apply_not_authorized = "apply_not_authorized"
    #: The reset scope carries no current approval. A reset destroys every guest, so it is approved
    #: by naming the guests that will be destroyed — an apply approval is not that approval.
    reset_plan_not_approved = "reset_plan_not_approved"
    #: A reset is not authorized. An apply authorization never satisfies this.
    reset_not_authorized = "reset_not_authorized"
    #: A destroy plan generation record must exist before destroy can be approved or executed.
    destroy_plan_not_generated = "destroy_plan_not_generated"
    #: The destroy plan carries no current approval.
    destroy_plan_not_approved = "destroy_plan_not_approved"
    #: Destroy is not authorized. An apply authorization never satisfies this.
    destroy_not_authorized = "destroy_not_authorized"

    # --- drift --------------------------------------------------------------------------
    #: The caller named a plan hash that is not the plan's current hash.
    plan_identity_mismatch = "plan_identity_mismatch"
    #: The caller named a destroy hash that is not the destroy plan's current hash.
    destroy_plan_identity_mismatch = "destroy_plan_identity_mismatch"
    #: The caller named a reset hash that is not the reset scope's current hash.
    reset_plan_identity_mismatch = "reset_plan_identity_mismatch"
    #: The desired state moved between the record being referenced and now.
    desired_state_changed = "desired_state_changed"
    #: The allocation ledger moved: the same plan would now reserve different identifiers.
    allocation_changed = "allocation_changed"

    # --- concurrency and replay ----------------------------------------------------------
    #: The caller's expected version is not the range's current version (CAS).
    version_conflict = "version_conflict"
    #: The caller named a different operation generation than the one in force.
    operation_generation_mismatch = "operation_generation_mismatch"
    #: This idempotency key was used for a DIFFERENT request. Never served from the first record.
    idempotency_key_reused = "idempotency_key_reused"
    #: An operation is already in flight on this range.
    operation_in_flight = "operation_in_flight"
    #: The range is not in a state this command may act from.
    lifecycle_state_invalid = "lifecycle_state_invalid"

    # --- the executing worker -------------------------------------------------------------
    #: No enrollment in this organization matches the declared worker installation.
    worker_mismatch = "worker_mismatch"
    #: The declared release digest is not the one that worker is enrolled with.
    release_mismatch = "release_mismatch"
    #: The matching worker is enrolled but not healthy, so it may not be given live work.
    worker_not_healthy = "worker_not_healthy"
    #: No consumer exists for this command. Nothing was enqueued and nothing is in flight.
    reconciliation_consumer_unavailable = "reconciliation_consumer_unavailable"


#: Every refusal is a 409 except the two that are genuinely about the request rather than the state.
#: Mapped explicitly, member by member: a default would let a code added later fall into whatever
#: status happened to be the fallback, which is how a precondition failure starts looking like a
#: malformed request.
_REFUSAL_STATUS: dict[RefusalCode, int] = {
    RefusalCode.range_not_proxmox: 409,
    RefusalCode.target_mismatch: 409,
    RefusalCode.cluster_fingerprint_mismatch: 409,
    RefusalCode.ownership_scope_mismatch: 409,
    RefusalCode.plan_blocked: 409,
    RefusalCode.observation_absent: 409,
    RefusalCode.observation_stale: 409,
    RefusalCode.plan_not_generated: 409,
    RefusalCode.plan_not_submitted: 409,
    RefusalCode.plan_not_approved: 409,
    RefusalCode.apply_not_authorized: 409,
    RefusalCode.reset_plan_not_approved: 409,
    RefusalCode.reset_not_authorized: 409,
    RefusalCode.reset_plan_identity_mismatch: 409,
    RefusalCode.destroy_plan_not_generated: 409,
    RefusalCode.destroy_plan_not_approved: 409,
    RefusalCode.destroy_not_authorized: 409,
    RefusalCode.plan_identity_mismatch: 409,
    RefusalCode.destroy_plan_identity_mismatch: 409,
    RefusalCode.desired_state_changed: 409,
    RefusalCode.allocation_changed: 409,
    RefusalCode.version_conflict: 409,
    RefusalCode.operation_generation_mismatch: 409,
    RefusalCode.idempotency_key_reused: 409,
    RefusalCode.operation_in_flight: 409,
    RefusalCode.lifecycle_state_invalid: 409,
    RefusalCode.worker_mismatch: 409,
    RefusalCode.release_mismatch: 409,
    RefusalCode.worker_not_healthy: 409,
    RefusalCode.reconciliation_consumer_unavailable: 501,
}


class ProxmoxCommandRefused(DomainError):
    """A command was refused. Carries a stable :class:`RefusalCode` a client may branch on.

    The message is NOT redacted, deliberately and unlike the closed-code errors elsewhere in this
    codebase. Those protect facts about a target an unauthorized caller must not learn; every fact
    named here — a hash, a range state, a version — the caller already holds or has just been told
    by a read endpoint they are authorized for. An operator who cannot be told WHICH prerequisite is
    unmet retries blind against real hardware.
    """

    def __init__(self, code: RefusalCode, message: str) -> None:
        super().__init__(message)
        self.code = code.value
        self.refusal_code = code
        self.http_status = _REFUSAL_STATUS[code]


def _refuse(code: RefusalCode, message: str) -> ProxmoxCommandRefused:
    return ProxmoxCommandRefused(code, message)


# --------------------------------------------------------------------------------------
# The request envelope
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class CommandEnvelope:
    """What every command carries besides its own identity fields.

    Each field is a claim the caller is making about the world they read before deciding. The
    preflight checks every one of them against the authoritative record rather than trusting it,
    which is the entire point: an operator acting on a page rendered ninety seconds ago must be
    refused if anything they based the decision on has moved.
    """

    #: Deduplicates a retry. See the module docstring — the key is compared together with a digest
    #: of the whole request, so a different request under a used key is refused, not served.
    idempotency_key: str
    #: The range's ``event_sequence`` as the caller last read it. A compare-and-swap token: the
    #: sequence advances on every recorded event, so anything that happened since — an approval, a
    #: new observation, another operator's command — invalidates it.
    expected_version: int
    #: The generation of resources this command intends to act on.
    operation_generation: int
    #: The target the caller believes this range plans against.
    target_id: str
    #: The cluster fingerprint the caller believes that target has.
    cluster_fingerprint: str


@dataclass(frozen=True)
class WorkerAssertion:
    """The worker an execution request names, asserted by the operator and checked here.

    Carried only by the three commands that enqueue infrastructure work. Generating a plan needs no
    worker; asking for real virtual machines to be created does, and naming it is what lets the
    control plane refuse when the worker that would pick the job up is not the one the operator
    thinks they are handing it to.
    """

    worker_installation_id: str
    release_digest: str


@dataclass(frozen=True)
class CommandRecord:
    """One durable command, as it was accepted.

    Immutable: it is an event row. Later drift can make what it references stale, but it can never
    make it untrue that this principal asked for this act against this document at this moment.
    """

    #: WHICH act. On the record, not inferred from the endpoint that returned it.
    operation_kind: CommandKind
    range_id: uuid.UUID
    organization_id: uuid.UUID
    #: The exact digest this command was issued against — a plan hash for the apply family, a
    #: destroy hash for the destroy family. Never interchangeable.
    subject_hash: str | None
    idempotency_key: str
    #: The range version this command was accepted at. The caller's ``expected_version`` matched it.
    accepted_version: int
    operation_generation: int
    target_id: str
    cluster_fingerprint: str
    requested_by: uuid.UUID | None
    at: datetime
    sequence: int
    #: The durable infrastructure operation this command enqueued, or ``None`` when it enqueued
    #: none. A retry returns the SAME id and dispatches nothing.
    operation_id: uuid.UUID | None
    #: True when this response is a replay of an earlier identical request. The caller can tell a
    #: fresh acceptance from a deduplicated retry, which matters when the first response was lost.
    deduplicated: bool
    #: Whether anything is actually in flight for this command. ``False`` with an accepted command
    #: is a real state — see :data:`COMMAND_OPERATION_KINDS`.
    enqueued: bool
    #: Why nothing was enqueued, when nothing was. ``None`` exactly when ``enqueued`` is true or
    #: when the command never enqueues by design and that is not a limitation.
    not_enqueued_reason: RefusalCode | None


# --------------------------------------------------------------------------------------
# Reading the command log
# --------------------------------------------------------------------------------------


def _request_digest(
    kind: CommandKind,
    envelope: CommandEnvelope,
    subject_hash: str | None,
    worker: WorkerAssertion | None,
) -> str:
    """A content digest of the WHOLE request, not just its key.

    This is what makes idempotency safe. Keyed on the key alone, a second, different request under a
    reused key would be answered with the first request's record — so an operator who changed the
    plan hash, the generation or the worker between attempts would be told their new request
    succeeded when what actually stands is the old one.
    """
    payload = {
        "kind": kind.value,
        "subject_hash": subject_hash,
        "operation_generation": envelope.operation_generation,
        "target_id": envelope.target_id,
        "cluster_fingerprint": envelope.cluster_fingerprint,
        "worker_installation_id": worker.worker_installation_id if worker else None,
        "release_digest": worker.release_digest if worker else None,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _command_events(
    session: Session, instance: RangeInstance, kind: CommandKind
) -> list[RangeLifecycleEvent]:
    return list(
        session.execute(
            select(RangeLifecycleEvent)
            .where(
                RangeLifecycleEvent.range_instance_id == instance.id,
                RangeLifecycleEvent.kind == COMMAND_EVENT_KINDS[kind],
            )
            .order_by(RangeLifecycleEvent.sequence.desc())
        )
        .scalars()
        .all()
    )


def latest_command(
    session: Session, instance: RangeInstance, kind: CommandKind
) -> CommandRecord | None:
    """The most recent accepted command of ``kind`` for this range, or ``None``."""
    events = _command_events(session, instance, kind)
    return _record_from_event(instance, kind, events[0]) if events else None


def _record_from_event(
    instance: RangeInstance,
    kind: CommandKind,
    event: RangeLifecycleEvent,
    *,
    deduplicated: bool = False,
) -> CommandRecord:
    data = event.data or {}
    operation_id = data.get("operation_id")
    reason = data.get("not_enqueued_reason")
    return CommandRecord(
        operation_kind=kind,
        range_id=instance.id,
        organization_id=instance.organization_id,
        subject_hash=data.get("subject_hash"),
        idempotency_key=str(data.get("idempotency_key") or ""),
        accepted_version=int(data.get("accepted_version") or 0),
        operation_generation=int(data.get("operation_generation") or 0),
        target_id=str(data.get("target_id") or ""),
        cluster_fingerprint=str(data.get("cluster_fingerprint") or ""),
        requested_by=(
            uuid.UUID(data["requested_by"]) if isinstance(data.get("requested_by"), str) else None
        ),
        at=event.occurred_at,
        sequence=event.sequence,
        operation_id=uuid.UUID(operation_id) if isinstance(operation_id, str) else None,
        deduplicated=deduplicated,
        enqueued=bool(data.get("enqueued")),
        not_enqueued_reason=RefusalCode(reason) if isinstance(reason, str) else None,
    )


def _find_replay(
    session: Session,
    instance: RangeInstance,
    kind: CommandKind,
    envelope: CommandEnvelope,
    digest: str,
) -> CommandRecord | None:
    """Resolve an idempotency key against this range's log for this command kind.

    Returns the earlier record on an EXACT repeat. Raises on a key reused for a different request —
    including a key reused across two command kinds, which is why the scan is per-kind but the
    conflict check is not: a key that authorized an apply must not be reusable to request a destroy.
    """
    for other_kind in CommandKind:
        for event in _command_events(session, instance, other_kind):
            data = event.data or {}
            if data.get("idempotency_key") != envelope.idempotency_key:
                continue
            if other_kind is kind and data.get("request_digest") == digest:
                return _record_from_event(instance, kind, event, deduplicated=True)
            raise _refuse(
                RefusalCode.idempotency_key_reused,
                f"idempotency key '{envelope.idempotency_key}' was already used on this range for "
                f"a {other_kind.value} command with different contents. A key identifies ONE "
                f"request; reusing it for another would return you the earlier command's result "
                f"and let you believe you issued this one. Use a fresh key.",
            )
    return None


# --------------------------------------------------------------------------------------
# The preflight
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Preflight:
    """Everything a command handler needs, after every check has passed."""

    instance: RangeInstance
    compiled: proxmox_lifecycle.CompiledRangePlan
    binding: proxmox_lifecycle.ProxmoxBinding
    subject_hash: str
    request_digest: str


def _require_compiled(
    session: Session, instance: RangeInstance
) -> proxmox_lifecycle.CompiledRangePlan:
    binding = proxmox_lifecycle.load_binding(session, instance)
    if binding is None:
        raise _refuse(
            RefusalCode.observation_absent,
            "no discovery observation has been recorded for this range, so there is nothing to "
            "compile against. This is an UNCHECKED prerequisite, not a failed one: the compiler "
            "needs facts a live cluster scan proves — SDN support, firewall support, the VMIDs, "
            "VLAN tags, MACs and subnets in use, and the management CIDRs the scenario must not "
            "reach — and none of them may be assumed. Run discovery against the target first.",
        )
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    if isinstance(compiled, BlockedPlan):
        raise _refuse(
            RefusalCode.plan_blocked,
            f"this range's plan does not compile, so no command can act on it: "
            f"{compiled.describe()}",
        )
    return compiled


def _check_scope(
    envelope: CommandEnvelope,
    compiled: proxmox_lifecycle.CompiledRangePlan,
    instance: RangeInstance,
) -> None:
    """Target, cluster and ownership scope — each checked against the plan, never inferred."""
    identity = compiled.binding.observation.identity
    if envelope.target_id != identity.target_id:
        raise _refuse(
            RefusalCode.target_mismatch,
            f"this range plans against target '{identity.target_id}', not '{envelope.target_id}'. "
            "A command names the target it believes it is acting on so that acting on the wrong "
            "one is a refusal rather than a surprise.",
        )
    if envelope.cluster_fingerprint != identity.cluster_fingerprint:
        raise _refuse(
            RefusalCode.cluster_fingerprint_mismatch,
            f"this range's observation was taken from cluster fingerprint "
            f"'{identity.cluster_fingerprint}', not '{envelope.cluster_fingerprint}'. A cluster "
            "rebuilt under the same name is a different cluster and none of this plan's reserved "
            "identifiers are known to be free on it.",
        )
    ownership = compiled.workload.topology.ownership
    if ownership.organization_id != str(instance.organization_id):
        raise _refuse(
            RefusalCode.ownership_scope_mismatch,
            "the compiled plan stamps its objects with an organization that is not this range's. "
            "Ownership is what a destroy sweep acts on, and it is never inferred from names.",
        )
    if envelope.operation_generation != ownership.operation_generation:
        raise _refuse(
            RefusalCode.operation_generation_mismatch,
            f"this range's objects are stamped operation generation "
            f"{ownership.operation_generation}, not {envelope.operation_generation}. Acting on the "
            "wrong generation is how a reset's objects become indistinguishable from a deploy's.",
        )


def _check_worker(
    session: Session, instance: RangeInstance, worker: WorkerAssertion
) -> WorkerEnrollmentState:
    """The worker that will execute must be the enrolled, healthy, matching-release one.

    An ORDINARY worker cannot be handed this work. ``healthy`` is the only enrollment state that has
    completed the full attestation exchange; every other state — including ``recovery_required`` and
    ``refused`` — is a worker whose identity or release the controller has not (or no longer has)
    established, and controlled-live execution creates real virtual machines on real hardware.
    """
    row = session.execute(
        select(WorkerEnrollmentState).where(
            WorkerEnrollmentState.organization_id == instance.organization_id,
            WorkerEnrollmentState.worker_installation_id == worker.worker_installation_id,
        )
    ).scalar_one_or_none()
    if row is None:
        raise _refuse(
            RefusalCode.worker_mismatch,
            f"no worker enrolled in this organization has installation id "
            f"'{worker.worker_installation_id}'. Execution is handed to a named, enrolled worker; "
            "an unenrolled installation is not one this control plane has ever authenticated.",
        )
    if row.state != "healthy":
        raise _refuse(
            RefusalCode.worker_not_healthy,
            f"worker '{worker.worker_installation_id}' is enrolled but its enrollment state is "
            f"'{row.state}', not 'healthy'. Only a worker that completed the full enrollment "
            "exchange may be given controlled-live execution; an ordinary or partially-enrolled "
            "worker may not.",
        )
    if row.release_digest != worker.release_digest:
        raise _refuse(
            RefusalCode.release_mismatch,
            f"worker '{worker.worker_installation_id}' is enrolled with release "
            f"{row.release_digest}, not {worker.release_digest}. The release is what decides which "
            "gates the executing process actually runs, so a mismatch is never a detail.",
        )
    return row


def _check_freshness(binding: proxmox_lifecycle.ProxmoxBinding, kind: CommandKind) -> None:
    """A STALE observation blocks execution but not planning.

    Compiling and reading a plan built on an hours-old snapshot is still useful — the allocations
    are deterministic and the document is worth reviewing. Creating real virtual machines from one
    is not: a VMID that was free when the snapshot was taken may belong to somebody else's guest
    now. So the freshness bound gates the three commands that enqueue and nothing else.
    """
    if kind not in COMMAND_OPERATION_KINDS:
        return
    freshness = binding.freshness()
    if freshness is proxmox_lifecycle.ObservationFreshness.fresh:
        return
    raise _refuse(
        RefusalCode.observation_stale,
        f"the observation this plan compiles against is '{freshness.value}' "
        f"(bound: {proxmox_lifecycle.OBSERVATION_FRESHNESS_SECONDS}s). A stale snapshot is fine to "
        "plan and review against and is not fine to create real guests from — the cluster may have "
        "taken an identifier this plan reserves. Re-run discovery and record a fresh observation.",
    )


def _check_no_operation_in_flight(session: Session, instance: RangeInstance) -> None:
    operation = range_service.current_operation(session, instance)
    if operation is None:
        return
    if operation.status.value not in ("pending", "running"):
        return
    staleness = range_service.operation_staleness(operation)
    if staleness.stale:
        raise _refuse(
            RefusalCode.operation_in_flight,
            f"a {operation.kind.value} operation is stuck on this range: {staleness.reason}. "
            f"Abandon it (POST /api/v1/range-operations/{operation.id}/abandon) before requesting "
            "anything else.",
        )
    raise _refuse(
        RefusalCode.operation_in_flight,
        f"a {operation.kind.value} operation is already in flight on this range. Requesting a "
        "second would put two writers on one range.",
    )


def preflight(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    kind: CommandKind,
    envelope: CommandEnvelope,
    *,
    declared_hash: str | None = None,
    worker: WorkerAssertion | None = None,
) -> Preflight | CommandRecord:
    """Every check every command passes, in one place, in a fixed order.

    Returns a :class:`CommandRecord` instead of a :class:`Preflight` when this is an exact retry of
    an already-accepted command — the caller then returns that record and dispatches nothing.

    ORDER MATTERS and is not arbitrary. Authentication and read authorization come first (through
    ``range_service.get_range``, which also enforces the organization boundary), then the exact
    permission, then provider applicability, then the compile, then scope, then version, then
    idempotency, then lifecycle, then the worker. A caller who is not authorized learns nothing
    about the range's state; a caller whose key is stale is told so before anything is enqueued.
    """
    # 1. authenticated operator + organization scope + read permission.
    instance = range_service.get_range(session, principal, range_id)
    # 2. the exact permission for THIS act. `exercise_operate` got us here and is not enough.
    principal.require(COMMAND_PERMISSIONS[kind])
    # 3. provider applicability.
    if instance.provider != proxmox_lifecycle.PROXMOX_PROVIDER:
        raise _refuse(
            RefusalCode.range_not_proxmox,
            f"range '{instance.name}' runs on provider '{instance.provider}'. The Proxmox command "
            "surface exists only for ranges created from a Proxmox template.",
        )
    # 4. the plan must compile; an absent observation and a blocked plan are different refusals.
    compiled = _require_compiled(session, instance)
    binding = compiled.binding

    # 5. exact plan identity, in the RIGHT hash family. A destroy hash can never satisfy an apply
    #    command: the two are computed under different domain prefixes, so this is not merely a
    #    comparison that happens to fail — there is no digest that passes both.
    subject_hash = subject_hash_for(kind, compiled)
    if declared_hash is not None and declared_hash != subject_hash:
        if kind in DESTROY_FAMILY:
            raise _refuse(
                RefusalCode.destroy_plan_identity_mismatch,
                f"the destroy plan has changed since you read it: you named {declared_hash}, the "
                f"current destroy plan is {subject_hash}. Re-read the destroy plan and act on the "
                "deletion scope you actually saw.",
            )
        if kind in RESET_FAMILY:
            raise _refuse(
                RefusalCode.reset_plan_identity_mismatch,
                f"the reset scope has changed since you read it: you named {declared_hash}, the "
                f"current reset scope is {subject_hash}. Re-read it and act on the set of guests "
                "you actually saw — it names what will be destroyed.",
            )
        raise _refuse(
            RefusalCode.plan_identity_mismatch,
            f"the plan has changed since you read it: you named {declared_hash}, the current plan "
            f"is {subject_hash}. Re-read the plan and act on the document you actually saw.",
        )

    # 6. target / cluster / ownership / generation scope.
    _check_scope(envelope, compiled, instance)

    # 7. compare-and-swap on the range version.
    if envelope.expected_version != instance.event_sequence:
        raise _refuse(
            RefusalCode.version_conflict,
            f"this range is at version {instance.event_sequence}; you acted on version "
            f"{envelope.expected_version}. Something has happened to it since you read it — an "
            "approval, a new observation, another operator's command. Re-read and decide again.",
        )

    # 8. idempotency, over the whole request. May return an earlier record; may refuse a reuse.
    digest = _request_digest(kind, envelope, subject_hash, worker)
    replay = _find_replay(session, instance, kind, envelope, digest)
    if replay is not None:
        return replay

    # 9. authoritative lifecycle state.
    if instance.state not in _ALLOWED_RANGE_STATES[kind]:
        allowed = ", ".join(sorted(state.value for state in _ALLOWED_RANGE_STATES[kind]))
        raise _refuse(
            RefusalCode.lifecycle_state_invalid,
            f"a range in state '{instance.state.value}' cannot {kind.value}. Allowed from: "
            f"{allowed}.",
        )

    # 10. freshness, for the commands that create real objects.
    _check_freshness(binding, kind)

    # 11. no second writer.
    if kind in COMMAND_OPERATION_KINDS:
        _check_no_operation_in_flight(session, instance)

    # 12. the worker that will execute.
    if worker is not None:
        _check_worker(session, instance, worker)

    return Preflight(
        instance=instance,
        compiled=compiled,
        binding=binding,
        subject_hash=subject_hash,
        request_digest=digest,
    )


# --------------------------------------------------------------------------------------
# Accepting a command
# --------------------------------------------------------------------------------------


def _accept(
    session: Session,
    principal: Principal,
    checked: Preflight,
    kind: CommandKind,
    envelope: CommandEnvelope,
    *,
    message: str,
    level: str = "info",
    operation_id: uuid.UUID | None = None,
    enqueued: bool = False,
    not_enqueued_reason: RefusalCode | None = None,
    extra: dict | None = None,
) -> CommandRecord:
    """Append the durable command record and return it.

    ``accepted_version`` is read BEFORE ``record_event`` bumps the sequence, so it is the version
    the caller's compare-and-swap actually matched rather than the one this command created.
    """
    accepted_version = checked.instance.event_sequence
    data = {
        "command_kind": kind.value,
        "subject_hash": checked.subject_hash,
        "idempotency_key": envelope.idempotency_key,
        "request_digest": checked.request_digest,
        "accepted_version": accepted_version,
        "operation_generation": envelope.operation_generation,
        "target_id": envelope.target_id,
        "cluster_fingerprint": envelope.cluster_fingerprint,
        "requested_by": str(principal.user_id),
        "enqueued": enqueued,
        "operation_id": str(operation_id) if operation_id is not None else None,
        "not_enqueued_reason": (
            not_enqueued_reason.value if not_enqueued_reason is not None else None
        ),
        **(extra or {}),
    }
    event = range_service.record_event(
        session,
        checked.instance,
        kind=COMMAND_EVENT_KINDS[kind],
        message=message,
        level=level,
        data=data,
        operation_id=operation_id,
    )
    return CommandRecord(
        operation_kind=kind,
        range_id=checked.instance.id,
        organization_id=checked.instance.organization_id,
        subject_hash=checked.subject_hash,
        idempotency_key=envelope.idempotency_key,
        accepted_version=accepted_version,
        operation_generation=envelope.operation_generation,
        target_id=envelope.target_id,
        cluster_fingerprint=envelope.cluster_fingerprint,
        requested_by=principal.user_id,
        at=event.occurred_at,
        sequence=event.sequence,
        operation_id=operation_id,
        deduplicated=False,
        enqueued=enqueued,
        not_enqueued_reason=not_enqueued_reason,
    )


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _ledger_hash(compiled: proxmox_lifecycle.CompiledRangePlan) -> str | None:
    try:
        return compiled.ledger.content_hash()
    except Exception:  # pragma: no cover - a ledger that cannot hash is reported as unknown
        return None


def _require_generation(
    session: Session,
    checked: Preflight,
    kind: CommandKind,
    *,
    missing: RefusalCode,
    what: str,
) -> CommandRecord:
    """The generation record a later command depends on, proved still current.

    THREE separate things can be wrong and each gets its own code, because they call for different
    actions. ``missing`` means nobody generated it — generate it. ``desired_state_changed`` means
    the document moved — re-read and regenerate. ``allocation_changed`` means the document is the
    same but the identifiers it reserves are not, which is subtler and more dangerous: a plan that
    looks byte-identical while pointing at different VMIDs is exactly the shape that gets approved
    without anyone noticing.
    """
    record = latest_command(session, checked.instance, kind)
    if record is None:
        raise _refuse(
            missing,
            f"no {what} has been generated for this range. Generate it first — a later command "
            "may only reference a document that actually exists.",
        )
    if record.subject_hash != checked.subject_hash:
        raise _refuse(
            RefusalCode.desired_state_changed,
            f"the {what} has changed since it was generated: the generated record names "
            f"{record.subject_hash}, the current one is {checked.subject_hash}. Regenerate and "
            "review the document that would actually be used.",
        )
    return record


def _check_allocations_unchanged(
    session: Session, checked: Preflight, record_kind: CommandKind
) -> None:
    """The ledger the plan was generated with must still be the ledger it compiles to.

    Separate from the plan hash on purpose. The manifest hash covers the desired-state document;
    this covers the identifier reservations underneath it. They usually move together and the case
    that matters is when they do not.
    """
    events = _command_events(session, checked.instance, record_kind)
    if not events:
        return
    recorded = (events[0].data or {}).get("ledger_hash")
    current = _ledger_hash(checked.compiled)
    if recorded is None or current is None:
        return
    if recorded != current:
        raise _refuse(
            RefusalCode.allocation_changed,
            f"the allocation ledger has changed since this plan was generated: it reserved "
            f"{recorded} and now reserves {current}. The same plan would take different VMIDs, "
            "MACs, subnets or VLAN tags than the one that was reviewed.",
        )


# --------------------------------------------------------------------------------------
# The eight commands
#
# Each one: preflight, then append a durable record, then — for the three that need a worker —
# create the operation and hand it to the outbox. Nothing between those steps touches a provider.
# --------------------------------------------------------------------------------------


def compile_topology(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    *,
    envelope: CommandEnvelope,
) -> CommandRecord:
    """Recompile the topology from the observation of record and record what came out.

    Takes no hash, because it is the act that PRODUCES one: requiring the caller to name the hash
    they expect would make it impossible to refresh a topology after the observation changed, which
    is the only situation in which refreshing is interesting.

    It contacts nothing. "Refresh" here means recompile against the newest observation the worker
    has recorded — the API cannot go and look at a cluster, and a control plane that invented an
    observation would be indistinguishable downstream from one discovery proved.
    """
    checked = preflight(session, principal, range_id, CommandKind.compile_topology, envelope)
    if isinstance(checked, CommandRecord):
        return checked
    return _accept(
        session,
        principal,
        checked,
        CommandKind.compile_topology,
        envelope,
        message=f"Proxmox topology compiled to {checked.subject_hash}",
        extra={
            "ledger_hash": _ledger_hash(checked.compiled),
            "guest_count": len(checked.compiled.workload.topology.guests),
            "vnet_count": len(checked.compiled.workload.topology.network.vnets),
            "observation_freshness": checked.binding.freshness().value,
            "snapshot_id": checked.binding.snapshot_id,
        },
    )


def generate_plan(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    *,
    envelope: CommandEnvelope,
    plan_hash: str,
) -> CommandRecord:
    """Materialise the compiled plan as a durable, hash-identified generation record.

    Requires the topology to have been compiled first: a plan generated without a compilation of
    record has nothing to say it was ever derived from an observation anybody looked at.
    """
    checked = preflight(
        session,
        principal,
        range_id,
        CommandKind.generate_plan,
        envelope,
        declared_hash=plan_hash,
    )
    if isinstance(checked, CommandRecord):
        return checked
    _require_generation(
        session,
        checked,
        CommandKind.compile_topology,
        missing=RefusalCode.plan_not_generated,
        what="topology compilation",
    )
    _check_allocations_unchanged(session, checked, CommandKind.compile_topology)
    return _accept(
        session,
        principal,
        checked,
        CommandKind.generate_plan,
        envelope,
        message=f"Proxmox plan {checked.subject_hash} generated",
        extra={
            "ledger_hash": _ledger_hash(checked.compiled),
            "document_version": proxmox_lifecycle.DESIRED_STATE_DOCUMENT_VERSION,
            "deletion_set_size": len(checked.compiled.deletion_set),
        },
    )


def submit_plan_for_review(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    *,
    envelope: CommandEnvelope,
    plan_hash: str,
) -> CommandRecord:
    """Put an exact generated plan in front of a reviewer. APPROVES NOTHING.

    Deliberately a separate act from approval, and it requires a DIFFERENT permission
    (``plan:approve`` to submit, and the existing ``exercise:apply`` to approve). Submitting is
    "this is ready to be looked at"; approving is "I looked at it and it is right". Collapsing them
    would mean whoever prepared a plan also signed it off.
    """
    checked = preflight(
        session,
        principal,
        range_id,
        CommandKind.submit_plan_for_review,
        envelope,
        declared_hash=plan_hash,
    )
    if isinstance(checked, CommandRecord):
        return checked
    _require_generation(
        session,
        checked,
        CommandKind.generate_plan,
        missing=RefusalCode.plan_not_generated,
        what="plan",
    )
    _check_allocations_unchanged(session, checked, CommandKind.generate_plan)
    return _accept(
        session,
        principal,
        checked,
        CommandKind.submit_plan_for_review,
        envelope,
        message=f"Proxmox plan {checked.subject_hash} submitted for review",
        extra={"ledger_hash": _ledger_hash(checked.compiled)},
    )


def generate_destroy_plan(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    *,
    envelope: CommandEnvelope,
    destroy_hash: str,
) -> CommandRecord:
    """Materialise the deletion scope as its own durable, hash-identified record.

    Takes ``destroy_hash`` and never ``plan_hash``. A destroy plan is a bounded set of owned objects
    and its digest is computed in a different domain from the plan digest — so an approved plan hash
    is not a valid destroy hash for this range even when the underlying document is byte-identical.
    Requires ``exercise:destroy``: holding ``exercise:apply`` does not let you enumerate a deletion.
    """
    checked = preflight(
        session,
        principal,
        range_id,
        CommandKind.generate_destroy_plan,
        envelope,
        declared_hash=destroy_hash,
    )
    if isinstance(checked, CommandRecord):
        return checked
    return _accept(
        session,
        principal,
        checked,
        CommandKind.generate_destroy_plan,
        envelope,
        message=f"Proxmox destroy plan {checked.subject_hash} generated",
        level="warning",
        extra={
            "ledger_hash": _ledger_hash(checked.compiled),
            "deletion_set_size": len(checked.compiled.deletion_set),
        },
    )


def request_reconciliation(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    *,
    envelope: CommandEnvelope,
) -> CommandRecord:
    """Ask for the deployed range to be reconciled against its desired state.

    THIS COMMAND DOES NOT ENQUEUE, and the record says so rather than implying work is in flight.

    ``secp_worker.range.execution.execute_range_operation`` dispatches ``destroy`` and ``reset``
    explicitly and treats every other operation kind as a DEPLOY. Adding a ``reconcile`` value to
    ``RangeOperationKind`` and handing it to the outbox would therefore run a deploy against real
    hardware — the reconciliation decision logic exists (``secp_worker.provisioning
    .proxmox_reconcile.decide_reconciliation``) but nothing consumes a reconcile OPERATION.

    So the intent is recorded durably, ``enqueued`` is ``false`` and ``not_enqueued_reason`` is
    :data:`RefusalCode.reconciliation_consumer_unavailable`. That is the honest shape: an operator
    can see that they asked, and can see that nothing has picked it up. When the worker's dispatch
    becomes an explicit match with a refusing default, this becomes an ordinary enqueue and the
    reason disappears.
    """
    checked = preflight(session, principal, range_id, CommandKind.request_reconciliation, envelope)
    if isinstance(checked, CommandRecord):
        return checked
    return _accept(
        session,
        principal,
        checked,
        CommandKind.request_reconciliation,
        envelope,
        message=(
            "Proxmox reconciliation requested; no consumer has taken it and nothing is in flight"
        ),
        level="warning",
        enqueued=False,
        not_enqueued_reason=RefusalCode.reconciliation_consumer_unavailable,
        extra={"ledger_hash": _ledger_hash(checked.compiled)},
    )


def _enqueue(
    session: Session,
    principal: Principal,
    checked: Preflight,
    kind: CommandKind,
    envelope: CommandEnvelope,
    *,
    message: str,
    level: str = "info",
) -> CommandRecord:
    """Create the durable operation, record the command against it, and hand it to the outbox.

    RETRIES REUSE THE DURABLE OPERATION. An exact repeat never reaches here — ``preflight`` returned
    the earlier record — so there is exactly one ``start_operation`` and exactly one dispatch per
    accepted command. That is the property that keeps a lost response from turning into two applies.

    The dispatch is enqueue-only: it writes a durable outbox row and nothing is submitted to
    Temporal until this request's transaction commits, so a rolled-back request cannot leave a range
    half-applied.
    """
    from secp_api.dispatch import get_dispatcher

    operation_kind = COMMAND_OPERATION_KINDS[kind]
    _, operation = range_service.start_operation(
        session, principal, checked.instance.id, operation_kind
    )
    record = _accept(
        session,
        principal,
        checked,
        kind,
        envelope,
        message=message,
        level=level,
        operation_id=operation.id,
        enqueued=True,
        extra={"ledger_hash": _ledger_hash(checked.compiled)},
    )
    get_dispatcher().dispatch_range_operation(session, operation.id)
    return record


def request_execution(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    *,
    envelope: CommandEnvelope,
    plan_hash: str,
    worker: WorkerAssertion,
) -> CommandRecord:
    """Ask for the authorized apply to be executed. APPLIES NOTHING HERE.

    The full chain is required and each link refuses with its own code: the plan must have been
    generated, submitted for review, approved by hash, and apply must have been authorized against
    that same hash. Four separate acts, four separate refusals, and none of them is inferred from
    another — an approval is not an authorization and a submission is not an approval.
    """
    checked = preflight(
        session,
        principal,
        range_id,
        CommandKind.request_execution,
        envelope,
        declared_hash=plan_hash,
        worker=worker,
    )
    if isinstance(checked, CommandRecord):
        return checked

    _require_generation(
        session,
        checked,
        CommandKind.generate_plan,
        missing=RefusalCode.plan_not_generated,
        what="plan",
    )
    _check_allocations_unchanged(session, checked, CommandKind.generate_plan)
    submitted = latest_command(session, checked.instance, CommandKind.submit_plan_for_review)
    if submitted is None or submitted.subject_hash != checked.subject_hash:
        raise _refuse(
            RefusalCode.plan_not_submitted,
            f"plan {checked.subject_hash} has not been submitted for review. Submission is the act "
            "that puts a document in front of a reviewer, and it is not implied by generating one.",
        )
    approval = proxmox_lifecycle.plan_approval(session, checked.instance)
    if approval is None or approval.approved_hash != checked.subject_hash:
        raise _refuse(
            RefusalCode.plan_not_approved,
            f"plan {checked.subject_hash} carries no current approval. Approve the exact plan "
            f"(POST /api/v1/ranges/{range_id}/proxmox/plan-approval) first.",
        )
    authorization = proxmox_lifecycle.apply_authorization(session, checked.instance)
    if authorization is None or authorization.approved_hash != checked.subject_hash:
        raise _refuse(
            RefusalCode.apply_not_authorized,
            f"apply is not authorized for plan {checked.subject_hash}. Approving a plan and "
            "authorizing its apply are two decisions; the second is the one that creates real "
            "virtual machines. A destroy authorization does not authorize an apply.",
        )
    return _enqueue(
        session,
        principal,
        checked,
        CommandKind.request_execution,
        envelope,
        message=f"Execution requested for authorized Proxmox plan {checked.subject_hash}",
    )


def request_reset(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    *,
    envelope: CommandEnvelope,
    reset_hash: str,
    worker: WorkerAssertion,
) -> CommandRecord:
    """Ask for a reset of the deployed range. RESETS NOTHING HERE.

    Gated on the RESET authorization, over the reset scope's own hash — not on the apply
    authorization, and this is a correction rather than a preference.

    A reset destroys things. ``secp_worker.provisioning.proxmox_reset.plan_reset`` gives
    ``ResetSubject.guests`` the disposition ``ResetDisposition.recreated``, which that module
    defines as "Destroyed and rebuilt from the reviewed base image", and
    ``ResetPlan.recreated_guest_refs`` is "Guest refs that will be destroyed and rebuilt". Every
    guest in the range, and every disk with it, is deleted and made again. Letting the apply
    authorization stand for that would mean an approval to CREATE guests also authorized deleting
    the guests currently running — which on a live range discards every team's work mid-event, and
    is exactly the collapse the separation between the hash domains exists to prevent.

    The reset scope is narrower than a destroy's deletion set, and deliberately so: every network
    subject — the SDN zone, the VNets, the subnets and VLANs, the firewall objects — and the sealed
    allocation ledger are ``preserved``. So the reset hash is neither the plan hash nor the destroy
    hash, and no digest from either family satisfies this command.
    """
    checked = preflight(
        session,
        principal,
        range_id,
        CommandKind.request_reset,
        envelope,
        declared_hash=reset_hash,
        worker=worker,
    )
    if isinstance(checked, CommandRecord):
        return checked
    approval = proxmox_lifecycle.reset_plan_approval(session, checked.instance)
    if approval is None or approval.approved_hash != checked.subject_hash:
        raise _refuse(
            RefusalCode.reset_plan_not_approved,
            f"reset scope {checked.subject_hash} carries no current approval. Approve the reset "
            f"scope (POST /api/v1/ranges/{range_id}/proxmox/reset-plan-approval) first — it names "
            "the guests that will be destroyed.",
        )
    authorization = proxmox_lifecycle.reset_authorization(session, checked.instance)
    if authorization is None or authorization.approved_hash != checked.subject_hash:
        raise _refuse(
            RefusalCode.reset_not_authorized,
            f"reset is not authorized for reset scope {checked.subject_hash}. An apply "
            "authorization does not authorize a reset: a reset DESTROYS every guest in this range "
            "and rebuilds it, and approving their creation is not approving their deletion.",
        )
    return _enqueue(
        session,
        principal,
        checked,
        CommandKind.request_reset,
        envelope,
        message=f"Reset requested against authorized Proxmox reset scope {checked.subject_hash}",
        level="warning",
    )


def request_destroy_execution(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    *,
    envelope: CommandEnvelope,
    destroy_hash: str,
    worker: WorkerAssertion,
) -> CommandRecord:
    """Ask for the authorized destroy to be executed. DESTROYS NOTHING HERE.

    Structurally incapable of being satisfied by anything from the apply family: it takes
    ``destroy_hash``, it is compared against the destroy digest domain, it requires a destroy plan
    generation record, a destroy plan approval and a destroy authorization, and it requires
    ``exercise:destroy``. There is no apply artifact — no hash, no approval, no authorization, no
    permission — that reaches any of those checks.
    """
    checked = preflight(
        session,
        principal,
        range_id,
        CommandKind.request_destroy_execution,
        envelope,
        declared_hash=destroy_hash,
        worker=worker,
    )
    if isinstance(checked, CommandRecord):
        return checked

    _require_generation(
        session,
        checked,
        CommandKind.generate_destroy_plan,
        missing=RefusalCode.destroy_plan_not_generated,
        what="destroy plan",
    )
    approval = proxmox_lifecycle.destroy_plan_approval(session, checked.instance)
    if approval is None or approval.approved_hash != checked.subject_hash:
        raise _refuse(
            RefusalCode.destroy_plan_not_approved,
            f"destroy plan {checked.subject_hash} carries no current approval. Approve the exact "
            f"deletion scope (POST /api/v1/ranges/{range_id}/proxmox/destroy-plan-approval) first.",
        )
    authorization = proxmox_lifecycle.destroy_authorization(session, checked.instance)
    if authorization is None or authorization.approved_hash != checked.subject_hash:
        raise _refuse(
            RefusalCode.destroy_not_authorized,
            f"destroy is not authorized for destroy plan {checked.subject_hash}. An apply "
            "authorization does not authorize a destroy, and never can: the two are recorded under "
            "different event kinds against digests from different hash domains.",
        )
    return _enqueue(
        session,
        principal,
        checked,
        CommandKind.request_destroy_execution,
        envelope,
        message=f"Destroy execution requested for authorized destroy plan {checked.subject_hash}",
        level="warning",
    )
