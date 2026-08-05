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
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import DB_SESSION, current_principal
from secp_api.dispatch import get_dispatcher
from secp_api.errors import NotFoundError
from secp_api.proxmox_projection import (
    allocations_out,
    apply_authorization_out,
    destroy_authorization_out,
    destroy_plan_out,
    lifecycle_out,
    observation_out,
    ownership_out,
    plan_out,
    readiness_out,
    reset_dispositions_out,
    residue_out,
    topology_out,
    verification_out,
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
    ProxmoxResetDispositionsOut,
    ProxmoxResidueOut,
    ProxmoxTopologyOut,
    ProxmoxVerificationOut,
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
from secp_api.services import proxmox_lifecycle, ranges

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
    proxmox_lifecycle.require_operation_authorized(session, instance, kind.value)
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
