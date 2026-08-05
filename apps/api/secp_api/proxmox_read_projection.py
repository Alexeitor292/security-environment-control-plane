"""Projection for the five Proxmox reads that had no route.

Kept beside :mod:`secp_api.proxmox_projection` rather than inside it because these fold DIFFERENT
sources — the worker enrollment head row, the workload plan's bootstrap contracts, the reset and
reconciliation stages — and that module is already the projection of the plan/approval half.

Same discipline throughout: plain data materialised before the session closes, nothing decided here,
and where an answer is missing the missing-ness is rendered rather than a default.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from secp_api.range_models import RangeInstance
from secp_api.range_providers.proxmox_model import BlockedPlan
from secp_api.schemas_proxmox_reads import (
    BootstrapOperationOut,
    EvidenceReferenceOut,
    MaterialRefOut,
    ProxmoxEvidenceOut,
    ProxmoxGuestBootstrapOut,
    ProxmoxReconciliationOut,
    ProxmoxResetGuestOut,
    ProxmoxResetPlanOut,
    ProxmoxWorkerOut,
    ProxmoxWorkloadOut,
)
from secp_api.services.proxmox_commands import CommandRecord, RefusalCode
from secp_api.services.proxmox_lifecycle import (
    CompiledRangePlan,
    PlanState,
    ProxmoxBinding,
    RecordedStageState,
)
from secp_api.worker_enrollment_models import WorkerEnrollmentState

#: The single enrollment state that has completed the full attestation exchange. Anything else is a
#: worker whose identity or release the controller has not established, or no longer has.
HEALTHY = "healthy"


def _blocked_dicts(compiled: CompiledRangePlan | BlockedPlan) -> list[dict]:
    if not isinstance(compiled, BlockedPlan):
        return []
    return [
        {"reason_id": item.reason_id, "observation": item.observation, "detail": item.detail}
        for item in compiled.missing
    ]


# --- the worker -----------------------------------------------------------------


def worker_out(row: WorkerEnrollmentState | None) -> ProxmoxWorkerOut:
    """The enrolled worker, and whether it may be handed controlled-live execution.

    ``eligible_for_execution`` is computed from the blockers immediately above it, so the flag and
    the list cannot drift apart. The codes are the same :class:`RefusalCode` values a command
    refusal carries, so a client that has already learned to render one renders the other.
    """
    if row is None:
        return ProxmoxWorkerOut(
            enrolled=False,
            eligible_for_execution=False,
            blockers=[RefusalCode.worker_mismatch.value],
        )
    blockers: list[str] = []
    if row.state != HEALTHY:
        blockers.append(RefusalCode.worker_not_healthy.value)
    return ProxmoxWorkerOut(
        enrolled=True,
        state=row.state,
        worker_installation_id=row.worker_installation_id or None,
        worker_key_id=row.worker_key_id or None,
        controller_installation_id=row.controller_installation_id or None,
        release_digest=row.release_digest,
        deployment_site_label=row.deployment_site_label,
        contract_version=row.contract_version,
        revision=row.revision,
        expires_at=row.expires_at,
        refusal_reason=row.refusal_reason or None,
        eligible_for_execution=not blockers,
        blockers=blockers,
    )


# --- workload and bootstrap ------------------------------------------------------


def _material_out(ref) -> MaterialRefOut:
    return MaterialRefOut(
        ref=ref.ref,
        scope=getattr(ref.scope, "value", str(ref.scope)),
        purpose=ref.purpose,
        channel=ref.channel,
    )


def _observed_by_vmid(recorded: dict | None) -> dict[int, dict]:
    if not recorded:
        return {}
    return {
        entry["vmid"]: entry
        for entry in (recorded.get("guests") or ())
        if isinstance(entry, dict) and isinstance(entry.get("vmid"), int)
    }


def workload_out(
    compiled: CompiledRangePlan | BlockedPlan,
    state: PlanState,
    *,
    verification: dict | None = None,
) -> ProxmoxWorkloadOut:
    """The bootstrap contracts, with the worker's own addresses published for the first time.

    ``probe_address``/``probe_port`` and ``report_address``/``report_port`` come off the bootstrap
    contract and are NOT the topology's addresses. They are published side by side with the observed
    address and none is ever substituted for another: an absent probe address stays ``None``.
    """
    if isinstance(compiled, BlockedPlan):
        return ProxmoxWorkloadOut(
            state=state,
            verification=(
                RecordedStageState.recorded
                if verification is not None
                else RecordedStageState.undetermined
            ),
            blocked_reasons=_blocked_dicts(compiled),
        )
    observed = _observed_by_vmid(verification)
    guests = []
    for contract in compiled.workload.bootstrap:
        seen = observed.get(contract.vmid)
        guests.append(
            ProxmoxGuestBootstrapOut(
                guest_ref=contract.guest_ref,
                vmid=contract.vmid,
                team_ref=contract.team_ref,
                workload_key=contract.workload_key,
                workload_version=contract.workload_version,
                image_digest=contract.image_digest,
                operations=[
                    BootstrapOperationOut(
                        key=operation.key,
                        description=operation.description,
                        timeout_seconds=operation.timeout_seconds,
                    )
                    for operation in contract.operations
                ],
                attestation_ref=_material_out(contract.attestation_ref),
                report_address=contract.report_address,
                report_port=contract.report_port,
                probe_address=contract.probe_address,
                probe_port=contract.probe_port,
                deadline_seconds=contract.deadline_seconds,
                observed_address=(seen or {}).get("address"),
                observed=seen is not None,
            )
        )
    return ProxmoxWorkloadOut(
        state=state,
        plan_hash=compiled.plan_hash,
        guests=guests,
        materials=[_material_out(ref) for ref in compiled.workload.materials],
        challenge_keys=list(compiled.workload.challenge_keys),
        verification=(
            RecordedStageState.recorded
            if verification is not None
            else RecordedStageState.undetermined
        ),
    )


# --- the reset plan --------------------------------------------------------------


def reset_plan_out(
    compiled: CompiledRangePlan | BlockedPlan,
    state: PlanState,
    *,
    last_reset: dict | None = None,
) -> ProxmoxResetPlanOut:
    """What a reset WOULD do. Never what one did — that is ``/proxmox/reset-dispositions``.

    Every guest the plan describes is rebuilt from its reviewed template at the SAME resolved
    identifiers, which is what makes a reset restore this range rather than stand a second one up
    beside it. The action is named per guest rather than left to be inferred from the plan's shape.
    """
    observed = (
        RecordedStageState.recorded if last_reset is not None else RecordedStageState.undetermined
    )
    if isinstance(compiled, BlockedPlan):
        return ProxmoxResetPlanOut(
            state=state, last_observed=observed, blocked_reasons=_blocked_dicts(compiled)
        )
    return ProxmoxResetPlanOut(
        state=state,
        plan_hash=compiled.plan_hash,
        guests=[
            ProxmoxResetGuestOut(
                guest_ref=guest.guest_ref,
                name=guest.name,
                vmid=guest.vmid,
                team_ref=guest.ownership.team_ref or None,
                node_name=guest.node_name,
                intended_action="recreate",
            )
            for guest in compiled.workload.topology.guests
        ],
        last_observed=observed,
    )


# --- reconciliation ---------------------------------------------------------------


def reconciliation_out(
    request: CommandRecord | None, recorded: dict | None
) -> ProxmoxReconciliationOut:
    """Two independent facts: an operator asked, and a worker looked.

    Neither implies the other and neither is derived from the other. ``requested`` can be true while
    ``state`` is ``undetermined`` for as long as nothing consumes the request, and that is the
    current, accurate state of this system rather than an error.
    """
    return ProxmoxReconciliationOut(
        state=(
            RecordedStageState.recorded if recorded is not None else RecordedStageState.undetermined
        ),
        requested=request is not None,
        requested_at=request.at if request is not None else None,
        requested_by=request.requested_by if request is not None else None,
        enqueued=bool(request.enqueued) if request is not None else False,
        not_enqueued_reason=(
            request.not_enqueued_reason.value
            if request is not None and request.not_enqueued_reason is not None
            else None
        ),
        findings=_findings(recorded),
        observed_at=_moment((recorded or {}).get("observed_at")),
        detail=(recorded or {}).get("detail"),
    )


def _findings(recorded: dict | None) -> list | None:
    """``None`` (nothing recorded) must not decay into ``[]`` (recorded, and no drift found)."""
    if recorded is None:
        return None
    value = recorded.get("findings")
    if value is None:
        return None
    return list(value) if isinstance(value, (list, tuple)) else [value]


# --- evidence references ------------------------------------------------------------


def evidence_out(
    instance: RangeInstance,
    binding: ProxmoxBinding | None,
    compiled: CompiledRangePlan | BlockedPlan,
    *,
    verification: dict | None,
    residue: dict | None,
    reset: dict | None,
    teardown_ids: list[uuid.UUID],
) -> ProxmoxEvidenceOut:
    """Which evidence exists for this range and what identifies it. REFERENCES, never payloads.

    Every class is listed whether or not it exists, with ``present`` saying which. Omitting the
    absent ones would make "we have no residue proof" indistinguishable from "nobody asked about
    residue", and an operator assembling a record for an event needs the difference.
    """
    references: list[EvidenceReferenceOut] = [
        EvidenceReferenceOut(
            kind="discovery_snapshot",
            present=binding is not None and binding.snapshot_id is not None,
            reference=binding.snapshot_id if binding is not None else None,
            observed_at=binding.observed_at if binding is not None else None,
            detail=(
                None
                if binding is None
                else f"evidence hash {binding.snapshot_evidence_hash or 'not recorded'}"
            ),
        ),
        EvidenceReferenceOut(
            kind="desired_state_plan",
            present=not isinstance(compiled, BlockedPlan),
            reference=None if isinstance(compiled, BlockedPlan) else compiled.plan_hash,
        ),
        EvidenceReferenceOut(
            kind="destroy_plan",
            present=not isinstance(compiled, BlockedPlan),
            reference=None if isinstance(compiled, BlockedPlan) else compiled.destroy_hash,
        ),
        EvidenceReferenceOut(
            kind="verification_report",
            present=verification is not None,
            reference=(verification or {}).get("report_ref"),
            observed_at=_moment((verification or {}).get("observed_at")),
            detail=(verification or {}).get("infrastructure_outcome"),
        ),
        EvidenceReferenceOut(
            kind="reset_dispositions",
            present=reset is not None,
            observed_at=_moment((reset or {}).get("observed_at")),
            detail=(reset or {}).get("detail"),
        ),
        EvidenceReferenceOut(
            kind="residue_proof",
            present=residue is not None,
            observed_at=_moment((residue or {}).get("observed_at")),
            # The worker's verdict verbatim. ``unproven`` is a verdict, never folded into ``clean``.
            detail=(residue or {}).get("verdict"),
        ),
    ]
    return ProxmoxEvidenceOut(
        range_id=instance.id,
        references=references,
        teardown_evidence_ids=list(teardown_ids),
    )


def _moment(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
