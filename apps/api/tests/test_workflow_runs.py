"""AC6.4 — WorkflowRun records exist for each executed workflow."""

from __future__ import annotations

from secp_api.enums import WorkflowKind, WorkflowStatus
from secp_api.models import EnvironmentInstance, WorkflowRun


def test_deploy_creates_completed_workflow_run(session, principal, running_exercise):
    exercise = running_exercise()
    runs = session.query(WorkflowRun).filter(WorkflowRun.exercise_id == exercise.id).all()
    deploy_runs = [r for r in runs if r.kind == WorkflowKind.deploy]
    assert len(deploy_runs) == 1
    assert deploy_runs[0].status == WorkflowStatus.completed
    assert deploy_runs[0].finished_at is not None
    assert deploy_runs[0].dispatch_mode == "inline"


def test_reset_and_destroy_create_workflow_runs(session, principal, running_exercise):
    from secp_api.services import exercises

    exercise = running_exercise()
    instance = (
        session.query(EnvironmentInstance)
        .filter(EnvironmentInstance.exercise_id == exercise.id)
        .first()
    )
    exercises.reset_instance(session, principal, exercise.id, instance.id)
    exercises.destroy_exercise(session, principal, exercise.id)
    session.commit()

    kinds = {
        r.kind for r in session.query(WorkflowRun).filter(WorkflowRun.exercise_id == exercise.id)
    }
    assert {WorkflowKind.deploy, WorkflowKind.reset, WorkflowKind.destroy} <= kinds

    reset_run = (
        session.query(WorkflowRun)
        .filter(
            WorkflowRun.exercise_id == exercise.id,
            WorkflowRun.kind == WorkflowKind.reset,
        )
        .first()
    )
    assert reset_run.target_instance_id == instance.id
