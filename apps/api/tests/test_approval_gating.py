"""AC6.1/6.2 — apply is refused unless the plan is explicitly approved (ADR-004)."""

from __future__ import annotations

import pytest
from secp_api.enums import AuditAction, LifecycleState, PlanStatus
from secp_api.errors import ApprovalRequiredError
from secp_api.models import AuditEvent


def _setup_submitted(session, principal, valid_definition):
    from secp_api.services import catalog, exercises, planning

    template = catalog.create_template(session, principal, name="T", slug="t-gate")
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=valid_definition
    )
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="x"
    )
    exercises.validate_exercise(session, principal, exercise.id)
    plan = planning.generate_plan(session, principal, exercise.id)
    planning.submit_plan(session, principal, plan.id)
    session.commit()
    return exercise, plan


def test_deploy_refused_without_approval(session, principal, valid_definition):
    from secp_api.services import exercises

    exercise, _plan = _setup_submitted(session, principal, valid_definition)
    with pytest.raises(ApprovalRequiredError):
        exercises.start_exercise(session, principal, exercise.id)

    # Exercise must NOT have advanced past awaiting_approval.
    refreshed = exercises.get_exercise(session, principal, exercise.id)
    assert refreshed.lifecycle_state == LifecycleState.awaiting_approval


def test_refused_apply_is_audited(session, principal, valid_definition):
    from secp_api.services import exercises

    exercise, _plan = _setup_submitted(session, principal, valid_definition)
    with pytest.raises(ApprovalRequiredError):
        exercises.start_exercise(session, principal, exercise.id)

    # The refusal is recorded even though the main transaction rolled back.
    refusals = (
        session.query(AuditEvent).filter(AuditEvent.action == AuditAction.apply_refused.value).all()
    )
    assert len(refusals) >= 1
    assert refusals[0].outcome == "denied"


def test_deploy_succeeds_after_approval(session, principal, valid_definition):
    from secp_api.services import exercises, planning

    exercise, plan = _setup_submitted(session, principal, valid_definition)
    planning.approve_plan(session, principal, plan.id, "ok")
    run = exercises.start_exercise(session, principal, exercise.id)
    session.commit()

    assert run.status.value == "completed"
    refreshed = exercises.get_exercise(session, principal, exercise.id)
    assert refreshed.lifecycle_state == LifecycleState.running
    instances = exercises.list_instances(session, principal, exercise.id)
    assert len(instances) == 2  # one per team
    assert all(i.lifecycle_state == LifecycleState.running for i in instances)


def test_plan_pins_version_hash_on_approval(session, principal, valid_definition):
    from secp_api.services import planning

    exercise, plan = _setup_submitted(session, principal, valid_definition)
    approved = planning.approve_plan(session, principal, plan.id, "ok")
    assert approved.status == PlanStatus.approved
    assert approved.approved_content_hash == approved.version_content_hash
    assert approved.decided_by == principal.user_id
