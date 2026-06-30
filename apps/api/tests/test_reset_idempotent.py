"""AC5.4 — reset is an idempotent state-machine operation (Charter Invariant 14)."""

from __future__ import annotations

from secp_api.enums import LifecycleState
from secp_api.models import EnvironmentInstance, EnvironmentNode
from secp_worker.resource_port import SqlAlchemyResourcePort


def _topology_snapshot(session, instance_id):
    port = SqlAlchemyResourcePort(session)
    return port.read_instance_topology(str(instance_id)).model_dump()


def test_reset_restores_identical_baseline(session, principal, running_exercise):
    from secp_api.services import exercises

    exercise = running_exercise()
    instance = (
        session.query(EnvironmentInstance)
        .filter(EnvironmentInstance.exercise_id == exercise.id)
        .order_by(EnvironmentInstance.team_index)
        .first()
    )
    before = _topology_snapshot(session, instance.id)

    exercises.reset_instance(session, principal, exercise.id, instance.id)
    session.commit()
    after_first = _topology_snapshot(session, instance.id)

    exercises.reset_instance(session, principal, exercise.id, instance.id)
    session.commit()
    after_second = _topology_snapshot(session, instance.id)

    # Idempotent: baseline is identical regardless of how many resets ran.
    assert before == after_first == after_second


def test_reset_returns_instance_to_running(session, principal, running_exercise):
    from secp_api.services import exercises

    exercise = running_exercise()
    instance = (
        session.query(EnvironmentInstance)
        .filter(EnvironmentInstance.exercise_id == exercise.id)
        .first()
    )
    exercises.reset_instance(session, principal, exercise.id, instance.id)
    session.commit()
    session.refresh(instance)
    assert instance.lifecycle_state == LifecycleState.running


def test_reset_does_not_duplicate_nodes(session, principal, running_exercise):
    from secp_api.services import exercises

    exercise = running_exercise()
    instance = (
        session.query(EnvironmentInstance)
        .filter(EnvironmentInstance.exercise_id == exercise.id)
        .first()
    )

    def node_count():
        return (
            session.query(EnvironmentNode)
            .filter(EnvironmentNode.instance_id == instance.id)
            .count()
        )

    original = node_count()
    for _ in range(3):
        exercises.reset_instance(session, principal, exercise.id, instance.id)
        session.commit()
    assert node_count() == original
