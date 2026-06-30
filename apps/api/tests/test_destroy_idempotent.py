"""AC5.5 — destroy is idempotent and safe to retry (Charter Invariant 15)."""

from __future__ import annotations

from secp_api.enums import LifecycleState, WorkflowKind
from secp_api.models import (
    EnvironmentInstance,
    EnvironmentNetwork,
    EnvironmentNode,
    EnvironmentTopologyEdge,
    WorkflowRun,
)


def test_destroy_tears_down_all_instances(session, principal, running_exercise):
    from secp_api.services import exercises

    exercise = running_exercise()
    exercises.destroy_exercise(session, principal, exercise.id)
    session.commit()

    refreshed = exercises.get_exercise(session, principal, exercise.id)
    assert refreshed.lifecycle_state == LifecycleState.destroyed
    instances = (
        session.query(EnvironmentInstance)
        .filter(EnvironmentInstance.exercise_id == exercise.id)
        .all()
    )
    assert all(i.lifecycle_state == LifecycleState.destroyed for i in instances)

    # Simulated resources are cleared.
    for inst in instances:
        assert (
            session.query(EnvironmentNode).filter(EnvironmentNode.instance_id == inst.id).count()
            == 0
        )
        assert (
            session.query(EnvironmentNetwork)
            .filter(EnvironmentNetwork.instance_id == inst.id)
            .count()
            == 0
        )
        assert (
            session.query(EnvironmentTopologyEdge)
            .filter(EnvironmentTopologyEdge.instance_id == inst.id)
            .count()
            == 0
        )


def test_destroy_is_idempotent(session, principal, running_exercise):
    from secp_api.services import exercises

    exercise = running_exercise()
    exercises.destroy_exercise(session, principal, exercise.id)
    session.commit()
    # Second destroy must not raise and must leave state destroyed.
    run = exercises.destroy_exercise(session, principal, exercise.id)
    session.commit()
    assert run.kind == WorkflowKind.destroy
    assert run.detail.get("idempotent_noop") is True
    refreshed = exercises.get_exercise(session, principal, exercise.id)
    assert refreshed.lifecycle_state == LifecycleState.destroyed


def test_repeated_destroy_records_workflow_runs(session, principal, running_exercise):
    from secp_api.services import exercises

    exercise = running_exercise()
    exercises.destroy_exercise(session, principal, exercise.id)
    exercises.destroy_exercise(session, principal, exercise.id)
    session.commit()
    runs = (
        session.query(WorkflowRun)
        .filter(
            WorkflowRun.exercise_id == exercise.id,
            WorkflowRun.kind == WorkflowKind.destroy,
        )
        .all()
    )
    assert len(runs) == 2  # both attempts recorded; second is a no-op
