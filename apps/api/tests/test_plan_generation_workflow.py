"""B1B-PR5A §11/§12 — the durable real-plan-generation workflow STOPS at the seal (ADR-022).

Proves the enqueue-only dispatch discipline and the worker orchestration: it loads authoritative
records, evaluates combined readiness, and refuses (recording a bounded, secret-free attempt +
audit) — NEVER reaching ``completed``, because no plan executes.
"""

from __future__ import annotations

from secp_api.config import Settings
from secp_api.dispatch import (
    OUTBOX_PENDING,
    InlineDispatcher,
    TemporalDispatcher,
)
from secp_api.enums import (
    AuditAction,
    PlanGenerationAttemptStatus,
    WorkflowKind,
)
from secp_api.models import WorkflowDispatchOutbox, WorkflowRun
from secp_api.plan_activation_models import RealPlanGenerationAttempt
from secp_api.safety import InlineExecutionForbidden
from secp_worker.plan_gen.orchestration import run_plan_generation


def _temporal_settings() -> Settings:
    return Settings(app_env="test", workflow_dispatch_mode="temporal")


def test_inline_dispatch_of_real_plan_generation_is_forbidden(session, lab_env):
    env = lab_env()
    dispatcher = InlineDispatcher()
    try:
        dispatcher.dispatch_real_plan_generation(session, env.manifest.id)
        raise AssertionError("inline dispatch must be forbidden")
    except InlineExecutionForbidden:
        pass


def test_temporal_dispatch_enqueues_only_a_run_and_outbox_row(session, lab_env):
    env = lab_env()
    dispatcher = TemporalDispatcher(_temporal_settings())
    run = dispatcher.dispatch_real_plan_generation(session, env.manifest.id)
    session.flush()

    assert run.kind == WorkflowKind.real_plan_generation
    stored = session.get(WorkflowRun, run.id)
    assert stored is not None
    outbox = (
        session.query(WorkflowDispatchOutbox)
        .filter(WorkflowDispatchOutbox.workflow_run_id == run.id)
        .one()
    )
    assert outbox.workflow == "RealPlanGenerationWorkflow"
    assert outbox.status == OUTBOX_PENDING
    # Only ids cross into the Temporal argument — no secret, credential, dossier, or capability.
    assert set(outbox.args) == {"manifest_id", "workflow_run_id"}
    assert outbox.args["manifest_id"] == str(env.manifest.id)


def test_orchestration_refuses_when_not_ready_and_records_a_refused_attempt(session, lab_env):
    env = lab_env()
    # No approved dossier or plan-generation authorization exists, so combined readiness is not
    # current. The worker refuses, records a bounded attempt, and STOPS — never 'completed'.
    result = run_plan_generation(session, manifest_id=env.manifest.id)
    assert result.outcome == PlanGenerationAttemptStatus.refused.value
    assert result.reason_code  # a bounded reason code

    attempts = session.query(RealPlanGenerationAttempt).all()
    assert len(attempts) == 1
    attempt = attempts[0]
    assert attempt.status == PlanGenerationAttemptStatus.refused
    assert attempt.provisioning_manifest_id == env.manifest.id
    # THIS unreadiness refusal path never reaches 'running' or 'completed' — it terminates at
    # 'refused'. (B1B-PR5B expanded the global lifecycle enum to
    # requested/running/completed/refused/failed/recovery_required; the exact closed set is asserted
    # in the dedicated PR5B attempt-lifecycle test, test_plan_execution_lease.py.)
    assert result.outcome != PlanGenerationAttemptStatus.completed.value
    assert result.outcome == PlanGenerationAttemptStatus.refused.value


def test_orchestration_emits_started_and_refused_audits_but_never_completed(session, lab_env):
    env = lab_env()
    run_plan_generation(session, manifest_id=env.manifest.id)
    session.flush()  # the worker's session_scope commits; flush to make pending audits queryable
    from secp_api.models import AuditEvent

    actions = {
        e.action
        for e in session.query(AuditEvent)
        .filter(AuditEvent.resource_id == str(env.manifest.id))
        .all()
    }
    assert AuditAction.plan_generation_started.value in actions
    assert AuditAction.plan_generation_refused.value in actions
    # This refusal path emits NO completion audit (only started + refused). B1B-PR5B added
    # plan-execution completion audit actions to the enum, but none is emitted on a refusal.
    assert not any("plan_generation" in a and "completed" in a for a in actions)


def test_orchestration_on_a_missing_manifest_refuses_without_an_attempt(session):
    import uuid

    result = run_plan_generation(session, manifest_id=uuid.uuid4())
    assert result.outcome == PlanGenerationAttemptStatus.refused.value
    assert session.query(RealPlanGenerationAttempt).count() == 0


def test_a_duplicate_refusal_is_idempotent_and_preserves_prior_records(session, lab_env):
    from secp_api.models import AuditEvent

    env = lab_env()
    first = run_plan_generation(session, manifest_id=env.manifest.id)
    session.flush()
    second = run_plan_generation(session, manifest_id=env.manifest.id)
    session.flush()

    assert first.outcome == second.outcome == PlanGenerationAttemptStatus.refused.value
    # The duplicate refusal (same operation fingerprint) collapses to ONE attempt row — the
    # SAVEPOINT rolled back only the duplicate insert, not the transaction.
    assert session.query(RealPlanGenerationAttempt).count() == 1
    # Both `started` audits survive the idempotent rollback (the full session never rolled back).
    started = (
        session.query(AuditEvent)
        .filter(
            AuditEvent.resource_id == str(env.manifest.id),
            AuditEvent.action == AuditAction.plan_generation_started.value,
        )
        .count()
    )
    assert started == 2
