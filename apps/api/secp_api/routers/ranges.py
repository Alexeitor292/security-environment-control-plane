"""Range catalog and lifecycle routes.

deploy/reset/destroy return ``202`` immediately and run in the background — a deploy takes minutes
and an HTTP request must not hold it. The operation row created here is the handle the UI polls.

Every route resolves its session through ``DB_SESSION`` (the shared function-scoped commit
boundary) and returns an ordinary JSON body. Nothing streams: the session closes before the body
reaches the socket, so a ``StreamingResponse`` over ORM instances would truncate after the 200.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import DB_SESSION, current_principal
from secp_api.dispatch import get_dispatcher
from secp_api.errors import NotFoundError
from secp_api.proxmox_projection import (
    allocations_out,
    apply_authorization_out,
    command_out,
    destroy_authorization_out,
    destroy_plan_out,
    lifecycle_out,
    observation_out,
    ownership_out,
    plan_out,
    readiness_out,
    reset_authorization_out,
    reset_dispositions_out,
    residue_out,
    topology_out,
    verification_out,
)
from secp_api.proxmox_read_projection import (
    evidence_out,
    reconciliation_out,
    reset_plan_out,
    worker_out,
    workload_out,
)
from secp_api.range_enums import RangeOperationKind, RangeState
from secp_api.range_models import RangeTemplate
from secp_api.range_projection import (
    event_out,
    operation_out,
    range_out,
    resource_out,
    teardown_evidence_out,
    template_out,
)
from secp_api.range_scenario_projection import scenario_out
from secp_api.range_scenarios import (
    build_scenario,
    list_scenarios,
    scenario_key_for_template,
)
from secp_api.schemas_proxmox import (
    ProxmoxAllocationsOut,
    ProxmoxApplyAuthorizationOut,
    ProxmoxApplyAuthorizationRequest,
    ProxmoxDestroyAuthorizationOut,
    ProxmoxDestroyAuthorizationRequest,
    ProxmoxDestroyPlanApprovalRequest,
    ProxmoxDestroyPlanOut,
    ProxmoxLifecycleOut,
    ProxmoxObservationOut,
    ProxmoxOwnershipOut,
    ProxmoxPlanApprovalRequest,
    ProxmoxPlanOut,
    ProxmoxReadinessOut,
    ProxmoxResetAuthorizationOut,
    ProxmoxResetAuthorizationRequest,
    ProxmoxResetDispositionsOut,
    ProxmoxResetPlanApprovalRequest,
    ProxmoxResidueOut,
    ProxmoxTopologyOut,
    ProxmoxVerificationOut,
)
from secp_api.schemas_proxmox_commands import (
    ProxmoxCommandOut,
    ProxmoxCompileTopologyRequest,
    ProxmoxDestroyExecutionRequest,
    ProxmoxDestroyPlanGenerateRequest,
    ProxmoxExecutionRequest,
    ProxmoxGeneratePlanRequest,
    ProxmoxReconciliationRequest,
    ProxmoxResetRequest,
    ProxmoxSubmitPlanRequest,
)
from secp_api.schemas_proxmox_reads import (
    ProxmoxEvidenceOut,
    ProxmoxReconciliationOut,
    ProxmoxResetPlanOut,
    ProxmoxWorkerOut,
    ProxmoxWorkloadOut,
)
from secp_api.schemas_range import (
    RangeCreate,
    RangeEventOut,
    RangeOperationAbandonIn,
    RangeOperationOut,
    RangeOut,
    RangeResourceOut,
    RangeTemplateOut,
    TeardownEvidenceOut,
)
from secp_api.schemas_range_scenarios import ScenarioOut
from secp_api.services import proxmox_commands, proxmox_lifecycle, ranges
from secp_api.services.proxmox_lifecycle import EVENT_RECONCILIATION
from secp_api.worker_enrollment_models import WorkerEnrollmentState

router = APIRouter(prefix="/api/v1", tags=["ranges"])


@router.get("/range-templates", response_model=list[RangeTemplateOut])
def list_range_templates(
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[RangeTemplateOut]:
    del principal  # authentication only; the shipped catalog is not tenant data
    return [template_out(row) for row in ranges.list_templates(session)]


@router.get("/range-templates/{slug}", response_model=RangeTemplateOut)
def get_range_template(
    slug: str,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeTemplateOut:
    del principal
    return template_out(ranges.get_template_row(session, slug))


@router.get("/range-scenarios", response_model=list[ScenarioOut])
def list_range_scenarios(
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[ScenarioOut]:
    """Every shipped scenario ONCE, with every provider it can run on.

    This is the provider-compatibility view of the same catalog ``/range-templates`` lists. The
    templates endpoint is unchanged and still lists concrete deployable definitions — three of them,
    two of which are the Web Breach Lab on two substrates. Here that lab appears a single time with
    two provider variants, because an operator choosing a scenario is choosing a lab and then a
    substrate, not choosing between two labs.

    A scenario that cannot run on a provider is RETURNED, marked ``blocked``, with its blockers
    named. It is never omitted and never marked eligible. The substrate-dependent Proxmox
    requirements are ``undetermined`` here — this endpoint names no range, so no cluster observation
    is in scope and nothing has been checked. ``GET /ranges/{id}/scenario`` answers them against the
    observation actually recorded for that range.
    """
    del principal  # authentication only; the shipped catalog is not tenant data
    del session  # pure catalog projection: no row is read
    return [scenario_out(scenario) for scenario in list_scenarios()]


@router.get("/range-scenarios/{key}", response_model=ScenarioOut)
def get_range_scenario(
    key: str,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ScenarioOut:
    del principal
    del session
    scenario = build_scenario(key)
    if scenario is None:
        raise NotFoundError(f"range scenario '{key}' not found")
    return scenario_out(scenario)


@router.get("/ranges/{range_id}/scenario", response_model=ScenarioOut)
def get_range_scenario_for_range(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ScenarioOut:
    """This range's scenario, with compatibility answered against ITS recorded observation.

    The difference from the catalog read matters: there, every substrate-dependent Proxmox
    requirement is ``undetermined`` because no cluster is in scope. Here the requirements are
    answered from the observation the worker recorded for this range — so a missing management CIDR
    or an unobserved VLAN list becomes a NAMED blocker with the same ``reason_id`` the plan compiler
    would block on, rather than a generic "not ready".

    A non-Proxmox range still gets an answer: its own provider's requirements are decidable from the
    catalog, and the Proxmox column stays ``undetermined`` because this range records no cluster
    observation.
    """
    instance = ranges.get_range(session, principal, range_id)
    template_row = session.get(RangeTemplate, instance.template_id)
    slug = template_row.slug if template_row is not None else ""
    key = scenario_key_for_template(slug)
    if key is None:
        raise NotFoundError(
            f"template '{slug}' does not belong to a shipped scenario, so it has no provider "
            "compatibility to report"
        )
    binding = (
        proxmox_lifecycle.load_binding(session, instance)
        if instance.provider == proxmox_lifecycle.PROXMOX_PROVIDER
        else None
    )
    scenario = build_scenario(
        key,
        observation=binding.observation if binding is not None else None,
        team_count=len(binding.teams) if binding is not None else None,
    )
    if scenario is None:  # pragma: no cover - key came from the same table
        raise NotFoundError(f"range scenario '{key}' not found")
    return scenario_out(scenario)


@router.post("/ranges", response_model=RangeOut, status_code=201)
def create_range(
    body: RangeCreate,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeOut:
    instance = ranges.create_range(
        session, principal, template_slug=body.template_slug, name=body.name
    )
    return range_out(session, instance)


@router.get("/ranges", response_model=list[RangeOut])
def list_ranges(
    state: list[RangeState] | None = Query(default=None),
    include_destroyed: bool = Query(default=False),
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[RangeOut]:
    rows = ranges.list_ranges(session, principal, states=state, include_destroyed=include_destroyed)
    return [range_out(session, row) for row in rows]


@router.get("/ranges/{range_id}", response_model=RangeOut)
def get_range(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeOut:
    return range_out(session, ranges.get_range(session, principal, range_id))


def _start(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    kind: RangeOperationKind,
) -> RangeOperationOut:
    """Validate the transition, create the operation row, and DISPATCH it.

    The API stops here. Everything that touches a provider happens in the worker
    (:mod:`secp_worker.range.execution`), reached only through the dispatch seam — the API process
    never contacts a container runtime (Charter Invariants 6/7, ADR-005).

    Enqueue-only: the dispatcher writes a durable outbox row and nothing is submitted to Temporal
    until this request's transaction commits, so a rolled-back request cannot leave a range
    half-deployed.

    For a PROXMOX range there is an additional gate. A Proxmox apply creates real virtual machines
    on real hardware and consumes real addresses, so it may not be enqueued on the strength of a
    POST alone: the current plan must be approved and the matching authorization must exist. That
    check is what makes the approval surfaces load-bearing instead of advisory. Non-Proxmox ranges
    are unaffected.
    """
    instance = ranges.get_range(session, principal, range_id)
    # The ENUM, not ``kind.value``. Passing the string is what let the gate's destroy branch depend
    # on ``RangeOperationKind.destroy.value`` still spelling ``"destroy"`` — a rename away from a
    # destroy being authorized by an apply approval, with nothing to catch it.
    proxmox_lifecycle.require_operation_authorized(session, instance, kind)
    _, operation = ranges.start_operation(session, principal, range_id, kind)
    get_dispatcher().dispatch_range_operation(session, operation.id)
    return operation_out(operation)


@router.post("/ranges/{range_id}/deploy", response_model=RangeOperationOut, status_code=202)
def deploy_range(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeOperationOut:
    return _start(session, principal, range_id, RangeOperationKind.deploy)


@router.post("/ranges/{range_id}/reset", response_model=RangeOperationOut, status_code=202)
def reset_range(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeOperationOut:
    return _start(session, principal, range_id, RangeOperationKind.reset)


@router.post("/ranges/{range_id}/destroy", response_model=RangeOperationOut, status_code=202)
def destroy_range(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeOperationOut:
    return _start(session, principal, range_id, RangeOperationKind.destroy)


@router.post("/range-operations/{operation_id}/abandon", response_model=RangeOperationOut)
def abandon_range_operation(
    operation_id: uuid.UUID,
    body: RangeOperationAbandonIn | None = None,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeOperationOut:
    """Release a stranded operation and put its range into ``recovery_required``.

    This endpoint exists because there was previously NO way out. An operation dispatched to a
    worker that could not resolve it stayed ``pending`` forever, its range stayed ``resetting``
    forever, and ``destroy`` and ``reset`` both answered 409 because neither may start from an
    in-flight state. The only recovery was hand-written SQL against
    ``range_deployment_operation`` — on a running system, with the range's containers still up.

    Refuses (409) while the operation is still within its lease, unless the caller passes
    ``force``: abandoning an operation that IS executing puts a second writer on the range. The
    operation becomes ``unproven``, never ``failed``; nothing here observed it fail. Every resource
    the range has created stays enumerated and none is marked absent, so the destroy that follows
    still sweeps the complete set and still has to PROVE each one gone.
    """
    _, operation = ranges.abandon_operation(
        session, principal, operation_id, force=bool(body and body.force)
    )
    return operation_out(operation)


@router.get("/range-operations/{operation_id}", response_model=RangeOperationOut)
def get_range_operation(
    operation_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeOperationOut:
    return operation_out(ranges.get_operation(session, principal, operation_id))


@router.get("/ranges/{range_id}/operations", response_model=list[RangeOperationOut])
def list_range_operations(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[RangeOperationOut]:
    return [operation_out(row) for row in ranges.list_operations(session, principal, range_id)]


@router.get("/ranges/{range_id}/resources", response_model=list[RangeResourceOut])
def list_range_resources(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[RangeResourceOut]:
    return [resource_out(row) for row in ranges.list_resources(session, principal, range_id)]


@router.get("/ranges/{range_id}/events", response_model=list[RangeEventOut])
def list_range_events(
    range_id: uuid.UUID,
    after_sequence: int = Query(default=0, ge=0),
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[RangeEventOut]:
    return [
        event_out(row)
        for row in ranges.list_events(session, principal, range_id, after_sequence=after_sequence)
    ]


@router.get("/ranges/{range_id}/teardown-evidence", response_model=list[TeardownEvidenceOut])
def list_range_teardown_evidence(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[TeardownEvidenceOut]:
    return [
        teardown_evidence_out(row)
        for row in ranges.list_teardown_evidence(session, principal, range_id)
    ]


# --- the Proxmox range lifecycle ----------------------------------------------
#
# Everything below is READ or AUTHORIZE. Nothing here applies, destroys, resets or contacts a
# Proxmox cluster: the plan is compiled in-process from pure functions in
# ``secp_api.range_providers``, and the gate verdicts that decide whether real VMs get created live
# in the worker and are reported only as the worker RECORDED them.
#
# The four authorization routes record an approval and stop. Execution is enqueued by the ordinary
# deploy/destroy routes above, which now refuse for a Proxmox range without the matching
# authorization.


def _resolve(session: Session, principal: Principal, range_id: uuid.UUID):
    """Load the range, prove it is a Proxmox range, and compile its plan once.

    Compiled once per request and passed around, because compiling twice in one request could in
    principle produce two different hashes if the binding changed between them — and a response
    whose ``plan_hash`` did not match its own ``document`` would be worse than useless.
    """
    instance = ranges.get_range(session, principal, range_id)
    proxmox_lifecycle.require_proxmox(instance)
    binding = proxmox_lifecycle.load_binding(session, instance)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    return instance, binding, compiled


@router.get("/ranges/{range_id}/proxmox", response_model=ProxmoxLifecycleOut)
def get_proxmox_lifecycle(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxLifecycleOut:
    """Every stage of the Proxmox lifecycle in one answer, for a client rendering one page."""
    instance, binding, compiled = _resolve(session, principal, range_id)
    plan_approval = proxmox_lifecycle.plan_approval(session, instance)
    plan_state = proxmox_lifecycle.plan_state(compiled, plan_approval)
    return lifecycle_out(
        instance,
        compiled,
        binding,
        plan_state=plan_state,
        apply_state=proxmox_lifecycle.authorization_state(
            compiled,
            proxmox_lifecycle.apply_authorization(session, instance),
            expected_hash=getattr(compiled, "plan_hash", None),
        ),
        destroy_state=proxmox_lifecycle.authorization_state(
            compiled,
            proxmox_lifecycle.destroy_authorization(session, instance),
            expected_hash=getattr(compiled, "destroy_hash", None),
        ),
        verification=_stage_state(session, instance, proxmox_lifecycle.EVENT_VERIFICATION),
        reset_state=_stage_state(session, instance, proxmox_lifecycle.EVENT_RESET_DISPOSITIONS),
        residue=_stage_state(session, instance, proxmox_lifecycle.EVENT_RESIDUE),
    )


def _stage_state(session: Session, instance, kind: str):
    recorded = proxmox_lifecycle.recorded_stage(session, instance, kind)
    return (
        proxmox_lifecycle.RecordedStageState.undetermined
        if recorded is None
        else proxmox_lifecycle.RecordedStageState.recorded
    )


@router.get("/ranges/{range_id}/proxmox/observation", response_model=ProxmoxObservationOut)
def get_proxmox_observation(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxObservationOut:
    """Which discovery snapshot this range plans against, and how stale it is.

    ``freshness`` is ``absent`` when the worker has recorded no observation. That is the honest
    answer, not an error: the compiler needs facts a live cluster scan proves, and none may be
    assumed.
    """
    instance = ranges.get_range(session, principal, range_id)
    proxmox_lifecycle.require_proxmox(instance)
    return observation_out(proxmox_lifecycle.load_binding(session, instance))


@router.get("/ranges/{range_id}/proxmox/topology", response_model=ProxmoxTopologyOut)
def get_proxmox_topology(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxTopologyOut:
    """The compiled desired state — what would exist if this plan were applied exactly.

    Each guest carries three separate addresses: the ``published_address`` a participant is told to
    use, the ``probe_address`` readiness verification actually connects to, and the
    ``observed_address`` the provider reported after apply. The published address is not
    necessarily reachable from the worker — #103 was exactly that — so none of the three is ever
    substituted for another, and an unobserved address stays null.
    """
    instance, binding, compiled = _resolve(session, principal, range_id)
    state = proxmox_lifecycle.plan_state(
        compiled, proxmox_lifecycle.plan_approval(session, instance)
    )
    return topology_out(
        compiled,
        binding,
        state,
        verification=proxmox_lifecycle.recorded_stage(
            session, instance, proxmox_lifecycle.EVENT_VERIFICATION
        ),
    )


@router.get("/ranges/{range_id}/proxmox/allocations", response_model=ProxmoxAllocationsOut)
def get_proxmox_allocations(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxAllocationsOut:
    """Every identifier the plan reserves — VM/LXC ids, MACs, addresses, subnets, VLANs, state keys.

    Deterministic: the same observation and the same template always produce the same values, which
    is what lets a reset resolve the deploy's identifiers instead of renumbering the range.
    """
    instance, _, compiled = _resolve(session, principal, range_id)
    state = proxmox_lifecycle.plan_state(
        compiled, proxmox_lifecycle.plan_approval(session, instance)
    )
    return allocations_out(compiled, state)


@router.get("/ranges/{range_id}/proxmox/plan", response_model=ProxmoxPlanOut)
def get_proxmox_plan(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxPlanOut:
    """The plan document, its hash, its approval state, and the isolation it proves.

    The isolation findings here are properties of the COMPILED firewall, established before
    anything is applied. They are a different claim from the observed isolation in the verification
    report and are deliberately not merged with it.
    """
    instance, _, compiled = _resolve(session, principal, range_id)
    approval = proxmox_lifecycle.plan_approval(session, instance)
    return plan_out(compiled, approval, proxmox_lifecycle.plan_state(compiled, approval))


@router.get(
    "/ranges/{range_id}/proxmox/apply-authorization",
    response_model=ProxmoxApplyAuthorizationOut,
)
def get_proxmox_apply_authorization(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxApplyAuthorizationOut:
    """Whether apply is authorized for the plan the range currently has."""
    instance, _, compiled = _resolve(session, principal, range_id)
    approval = proxmox_lifecycle.plan_approval(session, instance)
    authorization = proxmox_lifecycle.apply_authorization(session, instance)
    return apply_authorization_out(
        compiled,
        approval,
        authorization,
        proxmox_lifecycle.plan_state(compiled, approval),
        proxmox_lifecycle.authorization_state(
            compiled, authorization, expected_hash=getattr(compiled, "plan_hash", None)
        ),
    )


@router.get("/ranges/{range_id}/proxmox/verification", response_model=ProxmoxVerificationOut)
def get_proxmox_verification(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxVerificationOut:
    """What was OBSERVED after an apply, with infrastructure and isolation reported separately.

    ``state`` is ``undetermined`` until the worker records a report. Undetermined is not a pass:
    nobody has looked yet.
    """
    instance = ranges.get_range(session, principal, range_id)
    proxmox_lifecycle.require_proxmox(instance)
    return verification_out(
        proxmox_lifecycle.recorded_stage(session, instance, proxmox_lifecycle.EVENT_VERIFICATION)
    )


@router.get("/ranges/{range_id}/proxmox/readiness", response_model=ProxmoxReadinessOut)
def get_proxmox_readiness(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxReadinessOut:
    """Whether the PLAN would constitute a runnable two-team competition.

    Says nothing about a deployed range — for that, read the verification report.
    """
    instance, _, compiled = _resolve(session, principal, range_id)
    state = proxmox_lifecycle.plan_state(
        compiled, proxmox_lifecycle.plan_approval(session, instance)
    )
    return readiness_out(compiled, state)


@router.get(
    "/ranges/{range_id}/proxmox/reset-dispositions", response_model=ProxmoxResetDispositionsOut
)
def get_proxmox_reset_dispositions(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxResetDispositionsOut:
    """What a reset did to each guest, as the worker observed it.

    ``undetermined`` (no reset recorded) is distinct from a reset that ran and reported guests as
    ``recovery_required``.
    """
    instance = ranges.get_range(session, principal, range_id)
    proxmox_lifecycle.require_proxmox(instance)
    return reset_dispositions_out(
        proxmox_lifecycle.recorded_stage(
            session, instance, proxmox_lifecycle.EVENT_RESET_DISPOSITIONS
        )
    )


@router.get("/ranges/{range_id}/proxmox/destroy-plan", response_model=ProxmoxDestroyPlanOut)
def get_proxmox_destroy_plan(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxDestroyPlanOut:
    """The destroy plan and its OWN hash.

    A destroy is a bounded deletion scope, not the creation plan reversed, and its hash is computed
    in a different domain from the plan hash — so an approved plan hash is not a valid destroy hash
    for the same range, even when the underlying document is byte-identical.
    """
    instance, _, compiled = _resolve(session, principal, range_id)
    approval = proxmox_lifecycle.destroy_plan_approval(session, instance)
    return destroy_plan_out(
        compiled, approval, proxmox_lifecycle.destroy_plan_state(compiled, approval)
    )


@router.get(
    "/ranges/{range_id}/proxmox/destroy-authorization",
    response_model=ProxmoxDestroyAuthorizationOut,
)
def get_proxmox_destroy_authorization(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxDestroyAuthorizationOut:
    """Whether destroy is authorized. An apply authorization never satisfies this."""
    instance, _, compiled = _resolve(session, principal, range_id)
    approval = proxmox_lifecycle.destroy_plan_approval(session, instance)
    authorization = proxmox_lifecycle.destroy_authorization(session, instance)
    return destroy_authorization_out(
        compiled,
        approval,
        authorization,
        proxmox_lifecycle.destroy_plan_state(compiled, approval),
        proxmox_lifecycle.authorization_state(
            compiled, authorization, expected_hash=getattr(compiled, "destroy_hash", None)
        ),
    )


@router.get("/ranges/{range_id}/proxmox/ownership", response_model=ProxmoxOwnershipOut)
def get_proxmox_ownership(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxOwnershipOut:
    """How this range stamps what it creates, and which provenance classes a sweep never touches."""
    instance, _, compiled = _resolve(session, principal, range_id)
    state = proxmox_lifecycle.plan_state(
        compiled, proxmox_lifecycle.plan_approval(session, instance)
    )
    return ownership_out(compiled, state)


@router.get("/ranges/{range_id}/proxmox/residue", response_model=ProxmoxResidueOut)
def get_proxmox_residue(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxResidueOut:
    """The zero-residue proof: what a teardown actually PROVED absent.

    ``unproven`` is a verdict in its own right and is never folded into ``clean``.
    """
    instance = ranges.get_range(session, principal, range_id)
    proxmox_lifecycle.require_proxmox(instance)
    return residue_out(
        proxmox_lifecycle.recorded_stage(session, instance, proxmox_lifecycle.EVENT_RESIDUE)
    )


# --- authorization: four separate acts, none of which executes anything --------


@router.get("/ranges/{range_id}/proxmox/worker", response_model=ProxmoxWorkerOut)
def get_proxmox_worker(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxWorkerOut:
    """The enrolled worker that would execute for this range, and whether it may.

    Installation, enrollment state, identity, release and eligibility in one answer. ``enrolled:
    false`` is a real response rather than a 404 — "nobody is enrolled" is something an operator
    needs to be told, and it is a different answer from "a worker is enrolled but is not healthy".

    Publishes public identity only: no transaction id, no compare-and-swap digests, no key material.
    """
    instance = ranges.get_range(session, principal, range_id)
    proxmox_lifecycle.require_proxmox(instance)
    row = (
        session.execute(
            select(WorkerEnrollmentState)
            .where(WorkerEnrollmentState.organization_id == instance.organization_id)
            .order_by(WorkerEnrollmentState.observed_at.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )
    return worker_out(row)


@router.get("/ranges/{range_id}/proxmox/workload", response_model=ProxmoxWorkloadOut)
def get_proxmox_workload(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxWorkloadOut:
    """The per-guest workload and bootstrap contracts — including the WORKER's own addresses.

    ``/proxmox/topology`` publishes the topology's ``published_address`` and ``probe_address`` plus
    the observed one. This publishes the bootstrap contract's ``probe_address``/``probe_port`` (what
    the worker connects to when it checks a guest came up) and ``report_address``/``report_port``
    (where the guest reports back), which had no route at all. They are separate concepts from the
    topology's addresses, none is ever substituted for another, and an absent one stays null.

    Bootstrap material appears as a REFERENCE and never as material.
    """
    instance, _, compiled = _resolve(session, principal, range_id)
    state = proxmox_lifecycle.plan_state(
        compiled, proxmox_lifecycle.plan_approval(session, instance)
    )
    return workload_out(
        compiled,
        state,
        verification=proxmox_lifecycle.recorded_stage(
            session, instance, proxmox_lifecycle.EVENT_VERIFICATION
        ),
    )


@router.get("/ranges/{range_id}/proxmox/reset-plan", response_model=ProxmoxResetPlanOut)
def get_proxmox_reset_plan(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxResetPlanOut:
    """What a reset WOULD do to each guest.

    A different endpoint and a different shape from ``/proxmox/reset-dispositions``, which reports
    what the worker OBSERVED a reset doing. A plan and an observation are different claims, and the
    moment they share a surface a client starts reading one as the other.
    """
    instance, _, compiled = _resolve(session, principal, range_id)
    state = proxmox_lifecycle.plan_state(
        compiled, proxmox_lifecycle.plan_approval(session, instance)
    )
    return reset_plan_out(
        compiled,
        state,
        last_reset=proxmox_lifecycle.recorded_stage(
            session, instance, proxmox_lifecycle.EVENT_RESET_DISPOSITIONS
        ),
    )


@router.get("/ranges/{range_id}/proxmox/reconciliation", response_model=ProxmoxReconciliationOut)
def get_proxmox_reconciliation(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxReconciliationOut:
    """Whether reconciliation was asked for, and whether anything has answered.

    Two independent facts. ``requested`` says an operator asked; ``state`` says whether a worker
    recorded an observation, and stays ``undetermined`` until one does. Neither implies the other.
    """
    instance = ranges.get_range(session, principal, range_id)
    proxmox_lifecycle.require_proxmox(instance)
    return reconciliation_out(
        proxmox_commands.latest_command(
            session, instance, proxmox_commands.CommandKind.request_reconciliation
        ),
        proxmox_lifecycle.recorded_stage(session, instance, EVENT_RECONCILIATION),
    )


@router.get("/ranges/{range_id}/proxmox/evidence", response_model=ProxmoxEvidenceOut)
def get_proxmox_evidence(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxEvidenceOut:
    """Which evidence exists for this range and what identifies it. REFERENCES, never payloads.

    Every class is listed whether or not it exists. Omitting the absent ones would make "we have no
    residue proof" indistinguishable from "nobody asked about residue".
    """
    instance = ranges.get_range(session, principal, range_id)
    proxmox_lifecycle.require_proxmox(instance)
    binding = proxmox_lifecycle.load_binding(session, instance)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    return evidence_out(
        instance,
        binding,
        compiled,
        verification=proxmox_lifecycle.recorded_stage(
            session, instance, proxmox_lifecycle.EVENT_VERIFICATION
        ),
        residue=proxmox_lifecycle.recorded_stage(
            session, instance, proxmox_lifecycle.EVENT_RESIDUE
        ),
        reset=proxmox_lifecycle.recorded_stage(
            session, instance, proxmox_lifecycle.EVENT_RESET_DISPOSITIONS
        ),
        teardown_ids=[
            row.id for row in ranges.list_teardown_evidence(session, principal, range_id)
        ],
    )


# --- the operator command surface ----------------------------------------------
#
# Eight acts, each with its own path, its own request schema, its own permission and its own event
# kind. Every one persists intent and stops; the three that need a worker create the durable
# operation and hand it to the OUTBOX, which submits nothing until this request's transaction
# commits. Nothing below runs OpenTofu, spawns a process, opens a socket to a cluster, holds a
# provider credential or imports a privileged adapter.
#
# The apply family takes ``plan_hash``; the destroy family takes ``destroy_hash``. Both are required
# and every body forbids unknown fields, so no request validates as the other — see
# :mod:`secp_api.schemas_proxmox_commands`.


def _envelope(body) -> proxmox_commands.CommandEnvelope:
    return proxmox_commands.CommandEnvelope(
        idempotency_key=body.idempotency_key,
        expected_version=body.expected_version,
        operation_generation=body.operation_generation,
        target_id=body.target_id,
        cluster_fingerprint=body.cluster_fingerprint,
    )


def _worker(body) -> proxmox_commands.WorkerAssertion:
    return proxmox_commands.WorkerAssertion(
        worker_installation_id=body.worker_installation_id,
        release_digest=body.release_digest,
    )


@router.post(
    "/ranges/{range_id}/proxmox/topology-compilation",
    response_model=ProxmoxCommandOut,
    status_code=201,
)
def compile_proxmox_topology(
    range_id: uuid.UUID,
    body: ProxmoxCompileTopologyRequest,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxCommandOut:
    """Recompile the topology from the observation of record. CONTACTS NOTHING.

    "Refresh" means recompile against the newest observation the WORKER recorded. This process
    cannot go and look at a cluster, and an observation the control plane invented would be
    indistinguishable downstream from one discovery proved — which is the assumption the entire
    compiler safety argument rests on not being made.
    """
    return command_out(
        proxmox_commands.compile_topology(session, principal, range_id, envelope=_envelope(body))
    )


@router.post(
    "/ranges/{range_id}/proxmox/plan-generation", response_model=ProxmoxCommandOut, status_code=201
)
def generate_proxmox_plan(
    range_id: uuid.UUID,
    body: ProxmoxGeneratePlanRequest,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxCommandOut:
    """Materialise the compiled plan as a durable, hash-identified record. STARTS NOTHING."""
    return command_out(
        proxmox_commands.generate_plan(
            session, principal, range_id, envelope=_envelope(body), plan_hash=body.plan_hash
        )
    )


@router.post(
    "/ranges/{range_id}/proxmox/plan-review-submission",
    response_model=ProxmoxCommandOut,
    status_code=201,
)
def submit_proxmox_plan_for_review(
    range_id: uuid.UUID,
    body: ProxmoxSubmitPlanRequest,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxCommandOut:
    """Put an exact generated plan in front of a reviewer. APPROVES NOTHING.

    A separate act from approval and a separate permission (``plan:approve`` here,
    ``exercise:apply`` to approve). Submitting says "this is ready to be looked at"; approving says
    "I looked at it and it is right". Collapsing them lets whoever prepared a plan sign it off.
    """
    return command_out(
        proxmox_commands.submit_plan_for_review(
            session, principal, range_id, envelope=_envelope(body), plan_hash=body.plan_hash
        )
    )


@router.post(
    "/ranges/{range_id}/proxmox/execution-request",
    response_model=ProxmoxCommandOut,
    status_code=202,
)
def request_proxmox_execution(
    range_id: uuid.UUID,
    body: ProxmoxExecutionRequest,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxCommandOut:
    """Request execution of the AUTHORIZED apply. APPLIES NOTHING HERE.

    Requires the whole chain, each link refusing with its own stable code: generated, submitted,
    approved by hash, and apply authorized against that same hash. ``202`` because what it produced
    is a queued operation, not a finished apply.
    """
    return command_out(
        proxmox_commands.request_execution(
            session,
            principal,
            range_id,
            envelope=_envelope(body),
            plan_hash=body.plan_hash,
            worker=_worker(body),
        )
    )


@router.post(
    "/ranges/{range_id}/proxmox/reset-request", response_model=ProxmoxCommandOut, status_code=202
)
def request_proxmox_reset(
    range_id: uuid.UUID,
    body: ProxmoxResetRequest,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxCommandOut:
    """Request a reset of the authorized reset scope. RESETS NOTHING HERE.

    Gated on the RESET authorization, not the apply one. A reset DESTROYS every guest in the range
    and rebuilds it — ``proxmox_reset.plan_reset`` gives ``ResetSubject.guests`` the disposition
    ``recreated``, defined there as "Destroyed and rebuilt from the reviewed base image" — so an
    approval to create those guests does not authorize deleting the ones currently running.
    """
    return command_out(
        proxmox_commands.request_reset(
            session,
            principal,
            range_id,
            envelope=_envelope(body),
            reset_hash=body.reset_hash,
            worker=_worker(body),
        )
    )


@router.post(
    "/ranges/{range_id}/proxmox/reconciliation-request",
    response_model=ProxmoxCommandOut,
    status_code=201,
)
def request_proxmox_reconciliation(
    range_id: uuid.UUID,
    body: ProxmoxReconciliationRequest,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxCommandOut:
    """Request reconciliation of the deployed range against its desired state.

    ``201`` and not ``202``, because ``202`` would claim the work was accepted for processing and
    nothing has taken it: the response carries ``enqueued: false`` with
    ``not_enqueued_reason: reconciliation_consumer_unavailable``. The intent is durable and
    auditable; a worker picking it up is a separate, later fact. See
    :func:`secp_api.services.proxmox_commands.request_reconciliation` for why enqueueing it as a
    range operation would run a deploy.
    """
    return command_out(
        proxmox_commands.request_reconciliation(
            session, principal, range_id, envelope=_envelope(body)
        )
    )


@router.post(
    "/ranges/{range_id}/proxmox/destroy-plan-generation",
    response_model=ProxmoxCommandOut,
    status_code=201,
)
def generate_proxmox_destroy_plan(
    range_id: uuid.UUID,
    body: ProxmoxDestroyPlanGenerateRequest,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxCommandOut:
    """Materialise the deletion scope as its own durable record. DESTROYS NOTHING.

    Takes ``destroy_hash`` and requires ``exercise:destroy``. Holding ``exercise:apply`` does not
    let you enumerate a deletion, and an apply body does not validate against this schema.
    """
    return command_out(
        proxmox_commands.generate_destroy_plan(
            session, principal, range_id, envelope=_envelope(body), destroy_hash=body.destroy_hash
        )
    )


@router.post(
    "/ranges/{range_id}/proxmox/destroy-execution-request",
    response_model=ProxmoxCommandOut,
    status_code=202,
)
def request_proxmox_destroy_execution(
    range_id: uuid.UUID,
    body: ProxmoxDestroyExecutionRequest,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxCommandOut:
    """Request execution of the AUTHORIZED destroy. DESTROYS NOTHING HERE.

    Structurally incapable of being satisfied by anything from the apply family: its own path, its
    own required field, its own hash domain, its own generation record, its own approval, its own
    authorization and its own permission. There is no apply artifact that reaches any of them.
    """
    return command_out(
        proxmox_commands.request_destroy_execution(
            session,
            principal,
            range_id,
            envelope=_envelope(body),
            destroy_hash=body.destroy_hash,
            worker=_worker(body),
        )
    )


@router.get("/ranges/{range_id}/proxmox/commands", response_model=list[ProxmoxCommandOut])
def list_proxmox_commands(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[ProxmoxCommandOut]:
    """The most recent record of each command kind for this range — the audit read.

    One row per kind rather than the full history, because this answers "where is this range in the
    operator workflow". The complete, ordered history is already published by
    ``GET /ranges/{id}/events``, which is the same log these are folded from.
    """
    instance = ranges.get_range(session, principal, range_id)
    proxmox_lifecycle.require_proxmox(instance)
    records = (
        proxmox_commands.latest_command(session, instance, kind)
        for kind in proxmox_commands.CommandKind
    )
    return [command_out(record) for record in records if record is not None]


@router.post(
    "/ranges/{range_id}/proxmox/plan-approval", response_model=ProxmoxPlanOut, status_code=201
)
def approve_proxmox_plan(
    range_id: uuid.UUID,
    body: ProxmoxPlanApprovalRequest,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxPlanOut:
    """Approve the exact compiled plan, by hash. STARTS NOTHING.

    409 if the hash is not the plan's current hash — which is the point of approving by hash. If the
    observation was re-recorded between reading the plan and approving it, the document the operator
    read is not the document that would be applied, and the approval must not silently transfer.
    """
    instance, compiled, approval = proxmox_lifecycle.approve_plan(
        session, principal, range_id, plan_hash=body.plan_hash
    )
    del instance
    return plan_out(compiled, approval, proxmox_lifecycle.PlanState.approved)


@router.post(
    "/ranges/{range_id}/proxmox/apply-authorization",
    response_model=ProxmoxApplyAuthorizationOut,
    status_code=201,
)
def authorize_proxmox_apply(
    range_id: uuid.UUID,
    body: ProxmoxApplyAuthorizationRequest,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxApplyAuthorizationOut:
    """Authorize apply of an already-approved plan. ENQUEUES NOTHING, APPLIES NOTHING.

    Requires an approval of the same hash first: "this is the right plan" and "apply it now" are
    two decisions, and the second is worth making separately because it is the one that creates
    real virtual machines. The apply itself is enqueued afterwards by ``POST /ranges/{id}/deploy``,
    which refuses without this authorization.
    """
    instance, compiled, authorization = proxmox_lifecycle.authorize_apply(
        session, principal, range_id, plan_hash=body.plan_hash
    )
    approval = proxmox_lifecycle.plan_approval(session, instance)
    return apply_authorization_out(
        compiled,
        approval,
        authorization,
        proxmox_lifecycle.PlanState.approved,
        proxmox_lifecycle.AuthorizationState.authorized,
    )


@router.get(
    "/ranges/{range_id}/proxmox/reset-authorization",
    response_model=ProxmoxResetAuthorizationOut,
)
def get_proxmox_reset_authorization(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxResetAuthorizationOut:
    """Whether a reset is authorized, and exactly which guests it would DESTROY.

    Neither an apply nor a destroy authorization satisfies this. The scope is published because
    that is what is being approved: approving a reset without seeing the guests that will be
    deleted would be approving a deletion sight unseen.
    """
    instance, _, compiled = _resolve(session, principal, range_id)
    approval = proxmox_lifecycle.reset_plan_approval(session, instance)
    authorization = proxmox_lifecycle.reset_authorization(session, instance)
    return reset_authorization_out(
        compiled,
        approval,
        authorization,
        proxmox_lifecycle.reset_plan_state(compiled, approval),
        proxmox_lifecycle.authorization_state(
            compiled, authorization, expected_hash=getattr(compiled, "reset_hash", None)
        ),
    )


@router.post(
    "/ranges/{range_id}/proxmox/reset-plan-approval",
    response_model=ProxmoxResetAuthorizationOut,
    status_code=201,
)
def approve_proxmox_reset_plan(
    range_id: uuid.UUID,
    body: ProxmoxResetPlanApprovalRequest,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxResetAuthorizationOut:
    """Approve the exact reset scope, by its own hash. STARTS NOTHING.

    Takes ``reset_hash`` and rejects unknown fields, so neither an apply nor a destroy body
    validates here. Requires ``exercise:reset``.
    """
    instance, compiled, approval = proxmox_lifecycle.approve_reset_plan(
        session, principal, range_id, reset_hash=body.reset_hash
    )
    return reset_authorization_out(
        compiled,
        approval,
        proxmox_lifecycle.reset_authorization(session, instance),
        proxmox_lifecycle.PlanState.approved,
        proxmox_lifecycle.AuthorizationState.absent,
    )


@router.post(
    "/ranges/{range_id}/proxmox/reset-authorization",
    response_model=ProxmoxResetAuthorizationOut,
    status_code=201,
)
def authorize_proxmox_reset(
    range_id: uuid.UUID,
    body: ProxmoxResetAuthorizationRequest,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxResetAuthorizationOut:
    """Authorize a reset of an already-approved reset scope. ENQUEUES NOTHING, RESETS NOTHING.

    Structurally distinct from the apply and destroy authorizations at every level: its own path,
    its own required field, its own hash domain, its own event kind and its own permission. There
    is no body that satisfies more than one of the three.
    """
    instance, compiled, authorization = proxmox_lifecycle.authorize_reset(
        session, principal, range_id, reset_hash=body.reset_hash
    )
    approval = proxmox_lifecycle.reset_plan_approval(session, instance)
    return reset_authorization_out(
        compiled,
        approval,
        authorization,
        proxmox_lifecycle.PlanState.approved,
        proxmox_lifecycle.AuthorizationState.authorized,
    )


@router.post(
    "/ranges/{range_id}/proxmox/destroy-plan-approval",
    response_model=ProxmoxDestroyPlanOut,
    status_code=201,
)
def approve_proxmox_destroy_plan(
    range_id: uuid.UUID,
    body: ProxmoxDestroyPlanApprovalRequest,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxDestroyPlanOut:
    """Approve the exact destroy plan, by its own hash. STARTS NOTHING.

    Takes ``destroy_hash`` and rejects unknown fields, so a body built for the apply approval does
    not validate here.
    """
    instance, compiled, approval = proxmox_lifecycle.approve_destroy_plan(
        session, principal, range_id, destroy_hash=body.destroy_hash
    )
    del instance
    return destroy_plan_out(compiled, approval, proxmox_lifecycle.PlanState.approved)


@router.post(
    "/ranges/{range_id}/proxmox/destroy-authorization",
    response_model=ProxmoxDestroyAuthorizationOut,
    status_code=201,
)
def authorize_proxmox_destroy(
    range_id: uuid.UUID,
    body: ProxmoxDestroyAuthorizationRequest,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ProxmoxDestroyAuthorizationOut:
    """Authorize destroy of an already-approved destroy plan. ENQUEUES NOTHING, DESTROYS NOTHING.

    Structurally distinct from the apply authorization at every level: its own path, its own
    required field, its own hash domain, its own event kind and its own permission. There is no
    body that satisfies both.
    """
    instance, compiled, authorization = proxmox_lifecycle.authorize_destroy(
        session, principal, range_id, destroy_hash=body.destroy_hash
    )
    approval = proxmox_lifecycle.destroy_plan_approval(session, instance)
    return destroy_authorization_out(
        compiled,
        approval,
        authorization,
        proxmox_lifecycle.PlanState.approved,
        proxmox_lifecycle.AuthorizationState.authorized,
    )
