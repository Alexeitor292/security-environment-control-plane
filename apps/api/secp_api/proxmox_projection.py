"""Projection of the Proxmox lifecycle onto the published schemas.

Plain data only, materialised here rather than in the route body. The request session closes before
the response reaches the socket, so every ORM attribute a response depends on must already have been
read by the time these functions return — which is what they are for.

Nothing in this module decides anything. It renders what
:mod:`secp_api.services.proxmox_lifecycle` computed and what the worker recorded, and where an
answer is missing it renders the missing-ness rather than a default.
"""

from __future__ import annotations

from datetime import UTC, datetime

from secp_api.range_models import RangeInstance
from secp_api.range_providers.proxmox_ipam import AllocationLedger
from secp_api.range_providers.proxmox_model import BlockedPlan, ObjectProvenance, TargetObservation
from secp_api.range_providers.proxmox_workload import readiness_is_satisfied
from secp_api.schemas_proxmox import (
    ApprovalOut,
    BlockedReasonOut,
    IsolationFindingOut,
    OwnershipClassOut,
    ProxmoxAllocationOut,
    ProxmoxAllocationsOut,
    ProxmoxApplyAuthorizationOut,
    ProxmoxDestroyAuthorizationOut,
    ProxmoxDestroyPlanOut,
    ProxmoxLifecycleOut,
    ProxmoxObservationOut,
    ProxmoxOwnershipOut,
    ProxmoxPlanOut,
    ProxmoxReadinessOut,
    ProxmoxResetDispositionsOut,
    ProxmoxResidueOut,
    ProxmoxTopologyOut,
    ProxmoxVerificationOut,
    ReadinessFindingOut,
)
from secp_api.services.proxmox_lifecycle import (
    DESIRED_STATE_DOCUMENT_VERSION,
    OBSERVATION_FRESHNESS_SECONDS,
    ApprovalRecord,
    AuthorizationState,
    CompiledRangePlan,
    ObservationFreshness,
    PlanState,
    ProxmoxBinding,
    RecordedStageState,
    allocation_rows,
    unguardable_flag_values,
)

#: The observation fields the compiler blocks on when they were never collected. Reported by name
#: so an operator is told what to go and collect rather than just that something is missing.
_OBSERVATION_FIELDS = (
    "sdn_supported",
    "firewall_supported",
    "vlan_tags_in_use",
    "vmids_in_use",
    "macs_in_use",
    "subnets_in_use",
    "sdn_names_in_use",
    "firewall_names_in_use",
)


def _maybe_list(value: object) -> list | None:
    """Keep ``None`` (the worker recorded no such key) distinct from ``[]`` (it recorded none).

    ``list(x or [])`` would map both onto ``[]``, which is how "residue was never probed"
    becomes "no residue found" and how "isolation was not observed" becomes "no isolation
    checks failed". The two facts are not interchangeable and this is the only place the
    difference could be lost.
    """
    if value is None:
        return None
    return list(value) if isinstance(value, (list, tuple)) else [value]


def blocked_reasons_out(compiled: CompiledRangePlan | BlockedPlan) -> list[BlockedReasonOut]:
    if not isinstance(compiled, BlockedPlan):
        return []
    return [
        BlockedReasonOut(reason_id=item.reason_id, observation=item.observation, detail=item.detail)
        for item in compiled.missing
    ]


def blocked_summary(compiled: CompiledRangePlan | BlockedPlan) -> str | None:
    """A one-line summary of why the plan will not compile.

    ``BlockedPlan`` deliberately carries no single ``reason`` field — it names EVERY unmet
    prerequisite so an operator fixes them in one pass instead of six round-trips against a real
    cluster. This renders the headline; ``blocked_reasons`` carries the full set.
    """
    if not isinstance(compiled, BlockedPlan):
        return None
    ids = ", ".join(compiled.reason_ids)
    return f"{len(compiled.missing)} unmet prerequisite(s): {ids}"


def approval_out(record: ApprovalRecord | None) -> ApprovalOut | None:
    if record is None:
        return None
    return ApprovalOut(
        operation_kind=record.operation_kind,
        approved_hash=record.approved_hash,
        approved_by=record.approved_by,
        at=record.at,
    )


def _unobserved(observation: TargetObservation) -> list[str]:
    return [field for field in _OBSERVATION_FIELDS if getattr(observation, field) is None]


def observation_out(
    binding: ProxmoxBinding | None, *, now: datetime | None = None
) -> ProxmoxObservationOut:
    """Render the observation of record, or the fact that there is none.

    ``freshness=absent`` with every other field null is the honest answer when the worker has
    recorded nothing. It is not an error and it is not an empty cluster.
    """
    if binding is None:
        return ProxmoxObservationOut(
            freshness=ObservationFreshness.absent,
            freshness_bound_seconds=OBSERVATION_FRESHNESS_SECONDS,
            unobserved_fields=list(_OBSERVATION_FIELDS),
        )
    moment = now or datetime.now(UTC)
    observation = binding.observation
    age = (
        int((moment - binding.observed_at).total_seconds())
        if binding.observed_at is not None
        else None
    )
    return ProxmoxObservationOut(
        freshness=binding.freshness(now=moment),
        snapshot_id=binding.snapshot_id,
        snapshot_evidence_hash=binding.snapshot_evidence_hash,
        observed_at=binding.observed_at,
        age_seconds=age,
        freshness_bound_seconds=OBSERVATION_FRESHNESS_SECONDS,
        target_id=observation.identity.target_id,
        cluster_name=observation.identity.cluster_name,
        cluster_fingerprint=observation.identity.cluster_fingerprint,
        management_cidrs=list(observation.identity.management_cidrs),
        management_bridges=list(observation.identity.management_bridges),
        online_node_count=len(observation.online_nodes()),
        sdn_supported=observation.sdn_supported,
        firewall_supported=observation.firewall_supported,
        unobserved_fields=_unobserved(observation),
    )


def topology_out(
    compiled: CompiledRangePlan | BlockedPlan,
    binding: ProxmoxBinding | None,
    state: PlanState,
) -> ProxmoxTopologyOut:
    if isinstance(compiled, BlockedPlan):
        return ProxmoxTopologyOut(
            state=state,
            blocked_reason=blocked_summary(compiled),
            blocked_reasons=blocked_reasons_out(compiled),
            observation=observation_out(binding),
        )
    return ProxmoxTopologyOut(
        state=state,
        plan_hash=compiled.plan_hash,
        observation=observation_out(binding),
        topology=compiled.manifest,
        team_refs=[team.team_ref for team in compiled.binding.teams],
        guest_count=len(compiled.workload.topology.guests),
        vnet_count=len(compiled.workload.topology.network.vnets),
    )


def allocations_out(
    compiled: CompiledRangePlan | BlockedPlan, state: PlanState
) -> ProxmoxAllocationsOut:
    if isinstance(compiled, BlockedPlan):
        return ProxmoxAllocationsOut(state=state, blocked_reasons=blocked_reasons_out(compiled))
    return ProxmoxAllocationsOut(
        state=state,
        plan_hash=compiled.plan_hash,
        allocations=[ProxmoxAllocationOut(**row) for row in allocation_rows(compiled.ledger)],
        ledger_hash=_ledger_hash(compiled.ledger),
    )


def _ledger_hash(ledger: AllocationLedger) -> str | None:
    try:
        return ledger.content_hash()
    except Exception:  # pragma: no cover - a ledger that cannot hash is reported as unknown
        return None


def plan_out(
    compiled: CompiledRangePlan | BlockedPlan,
    approval: ApprovalRecord | None,
    state: PlanState,
) -> ProxmoxPlanOut:
    if isinstance(compiled, BlockedPlan):
        return ProxmoxPlanOut(
            state=state,
            document_version=DESIRED_STATE_DOCUMENT_VERSION,
            blocked_reason=blocked_summary(compiled),
            blocked_reasons=blocked_reasons_out(compiled),
            approval=approval_out(approval),
        )
    isolation = [
        IsolationFindingOut(property=finding.prop.value, holds=finding.holds, detail=finding.detail)
        for finding in compiled.isolation
    ]
    return ProxmoxPlanOut(
        state=state,
        document_version=DESIRED_STATE_DOCUMENT_VERSION,
        plan_hash=compiled.plan_hash,
        document=compiled.manifest,
        approval=approval_out(approval),
        approved_hash_is_current=(
            approval is not None and approval.approved_hash == compiled.plan_hash
        ),
        isolation=isolation,
        isolation_holds=all(finding.holds for finding in compiled.isolation) if isolation else None,
        unguardable_flag_values=list(unguardable_flag_values(compiled.template)),
    )


def apply_authorization_out(
    compiled: CompiledRangePlan | BlockedPlan,
    approval: ApprovalRecord | None,
    authorization: ApprovalRecord | None,
    plan_state: PlanState,
    auth_state: AuthorizationState,
) -> ProxmoxApplyAuthorizationOut:
    plan_hash = None if isinstance(compiled, BlockedPlan) else compiled.plan_hash
    blocked: str | None
    if isinstance(compiled, BlockedPlan):
        blocked = blocked_summary(compiled)
    elif auth_state is AuthorizationState.authorized:
        blocked = None
    elif approval is None or approval.approved_hash != plan_hash:
        blocked = "the current plan has not been approved"
    else:
        blocked = "the plan is approved but apply has not been authorized"
    return ProxmoxApplyAuthorizationOut(
        state=auth_state,
        plan_hash=plan_hash,
        plan_state=plan_state,
        approval=approval_out(approval),
        authorization=approval_out(authorization),
        blocked_reason=blocked,
    )


def destroy_plan_out(
    compiled: CompiledRangePlan | BlockedPlan,
    approval: ApprovalRecord | None,
    state: PlanState,
) -> ProxmoxDestroyPlanOut:
    if isinstance(compiled, BlockedPlan):
        return ProxmoxDestroyPlanOut(
            state=state,
            blocked_reasons=blocked_reasons_out(compiled),
            approval=approval_out(approval),
        )
    return ProxmoxDestroyPlanOut(
        state=state,
        destroy_hash=compiled.destroy_hash,
        deletion_set=list(compiled.deletion_set),
        deletion_set_size=len(compiled.deletion_set),
        approval=approval_out(approval),
        approved_hash_is_current=(
            approval is not None and approval.approved_hash == compiled.destroy_hash
        ),
    )


def destroy_authorization_out(
    compiled: CompiledRangePlan | BlockedPlan,
    approval: ApprovalRecord | None,
    authorization: ApprovalRecord | None,
    destroy_state: PlanState,
    auth_state: AuthorizationState,
) -> ProxmoxDestroyAuthorizationOut:
    destroy_hash = None if isinstance(compiled, BlockedPlan) else compiled.destroy_hash
    blocked: str | None
    if isinstance(compiled, BlockedPlan):
        blocked = blocked_summary(compiled)
    elif auth_state is AuthorizationState.authorized:
        blocked = None
    elif approval is None or approval.approved_hash != destroy_hash:
        blocked = "the current destroy plan has not been approved"
    else:
        blocked = "the destroy plan is approved but destroy has not been authorized"
    return ProxmoxDestroyAuthorizationOut(
        state=auth_state,
        destroy_hash=destroy_hash,
        destroy_plan_state=destroy_state,
        approval=approval_out(approval),
        authorization=approval_out(authorization),
        blocked_reason=blocked,
    )


def verification_out(recorded: dict | None) -> ProxmoxVerificationOut:
    """Split the worker's report into its infrastructure and isolation halves.

    Neither half is derived from the other and neither is summarised into a single verdict: a
    deployment can be structurally perfect and still let one team reach another, and a combined
    outcome would let the first mask the second.
    """
    if recorded is None:
        return ProxmoxVerificationOut(state=RecordedStageState.undetermined)
    return ProxmoxVerificationOut(
        state=RecordedStageState.recorded,
        infrastructure_outcome=recorded.get("infrastructure_outcome"),
        isolation_outcome=recorded.get("isolation_outcome"),
        infrastructure_checks=_maybe_list(recorded.get("infrastructure_checks")),
        isolation_checks=_maybe_list(recorded.get("isolation_checks")),
        observed_at=_moment(recorded.get("observed_at")),
        detail=recorded.get("detail"),
    )


def readiness_out(
    compiled: CompiledRangePlan | BlockedPlan, state: PlanState
) -> ProxmoxReadinessOut:
    if isinstance(compiled, BlockedPlan):
        return ProxmoxReadinessOut(state=state, blocked_reasons=blocked_reasons_out(compiled))
    return ProxmoxReadinessOut(
        state=state,
        plan_hash=compiled.plan_hash,
        satisfied=readiness_is_satisfied(compiled.readiness),
        findings=[
            ReadinessFindingOut(
                requirement=finding.requirement.value, met=finding.met, detail=finding.detail
            )
            for finding in compiled.readiness
        ],
        challenge_keys=list(compiled.workload.challenge_keys),
        scoring_endpoints=[
            {"team_ref": team, "address": address, "port": port}
            for team, address, port in compiled.workload.scoring_endpoints
        ],
    )


def reset_dispositions_out(recorded: dict | None) -> ProxmoxResetDispositionsOut:
    if recorded is None:
        return ProxmoxResetDispositionsOut(state=RecordedStageState.undetermined)
    return ProxmoxResetDispositionsOut(
        state=RecordedStageState.recorded,
        dispositions=_maybe_list(recorded.get("dispositions")),
        observed_at=_moment(recorded.get("observed_at")),
        detail=recorded.get("detail"),
    )


def residue_out(recorded: dict | None) -> ProxmoxResidueOut:
    if recorded is None:
        return ProxmoxResidueOut(state=RecordedStageState.undetermined)
    return ProxmoxResidueOut(
        state=RecordedStageState.recorded,
        verdict=recorded.get("verdict"),
        probe_reachable=recorded.get("probe_reachable"),
        expected_count=recorded.get("expected_count"),
        removed_confirmed=recorded.get("removed_confirmed"),
        still_present=recorded.get("still_present"),
        unproven_count=recorded.get("unproven_count"),
        uncovered_classes=_maybe_list(recorded.get("uncovered_classes")),
        resources=_maybe_list(recorded.get("resources")),
        reason=recorded.get("reason"),
        observed_at=_moment(recorded.get("observed_at")),
    )


def ownership_out(
    compiled: CompiledRangePlan | BlockedPlan, state: PlanState
) -> ProxmoxOwnershipOut:
    if isinstance(compiled, BlockedPlan):
        return ProxmoxOwnershipOut(state=state, blocked_reasons=blocked_reasons_out(compiled))
    ownership = compiled.workload.topology.ownership
    return ProxmoxOwnershipOut(
        state=state,
        ownership=OwnershipClassOut(
            organization_id=ownership.organization_id,
            target_id=ownership.target_id,
            range_id=ownership.range_id,
            generation=ownership.generation,
            operation_generation=ownership.operation_generation,
            tags=ownership.as_tags(),
            acts_on=[ObjectProvenance.secp_owned.value],
            never_touches=[
                ObjectProvenance.secp_foreign_scope.value,
                ObjectProvenance.untagged.value,
                ObjectProvenance.unreadable.value,
            ],
        ),
    )


def lifecycle_out(
    instance: RangeInstance,
    compiled: CompiledRangePlan | BlockedPlan,
    binding: ProxmoxBinding | None,
    *,
    plan_state: PlanState,
    apply_state: AuthorizationState,
    destroy_state: AuthorizationState,
    verification: RecordedStageState,
    reset_state: RecordedStageState,
    residue: RecordedStageState,
) -> ProxmoxLifecycleOut:
    blocked = isinstance(compiled, BlockedPlan)
    return ProxmoxLifecycleOut(
        range_id=instance.id,
        provider=instance.provider,
        range_state=instance.state.value,
        observation=observation_out(binding),
        plan_state=plan_state,
        plan_hash=None if blocked else compiled.plan_hash,
        destroy_hash=None if blocked else compiled.destroy_hash,
        apply_authorization=apply_state,
        destroy_authorization=destroy_state,
        verification=verification,
        reset_dispositions=reset_state,
        residue=residue,
        readiness_satisfied=(None if blocked else readiness_is_satisfied(compiled.readiness)),
        isolation_holds=(None if blocked else all(finding.holds for finding in compiled.isolation)),
        blocked_reasons=blocked_reasons_out(compiled),
    )


def _moment(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
