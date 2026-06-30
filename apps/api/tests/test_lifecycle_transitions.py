"""AC3 — lifecycle state machine: legal transitions pass, illegal ones rejected."""

from __future__ import annotations

import pytest
from secp_api.enums import LifecycleState as S
from secp_api.errors import InvalidTransitionError
from secp_api.lifecycle import EXERCISE_TRANSITIONS, is_permitted, transition

LEGAL = [
    (S.draft, S.validated),
    (S.validated, S.planned),
    (S.planned, S.awaiting_approval),
    (S.awaiting_approval, S.approved),
    (S.approved, S.deploying),
    (S.deploying, S.running),
    (S.running, S.resetting),
    (S.resetting, S.running),
    (S.running, S.destroying),
    (S.destroying, S.destroyed),
    (S.awaiting_approval, S.validated),  # rejection path
]

ILLEGAL = [
    (S.draft, S.running),  # cannot skip the gate
    (S.draft, S.approved),
    (S.validated, S.approved),  # must go through awaiting_approval
    (S.planned, S.running),
    (S.awaiting_approval, S.running),
    (S.destroyed, S.running),  # terminal
    (S.running, S.approved),  # cannot go backwards into approval
    (S.approved, S.running),  # must deploy first
]


@pytest.mark.parametrize("current,target", LEGAL)
def test_legal_transitions_permitted(current, target):
    assert is_permitted(current, target)
    assert transition(current, target) == target


@pytest.mark.parametrize("current,target", ILLEGAL)
def test_illegal_transitions_rejected(current, target):
    assert not is_permitted(current, target)
    with pytest.raises(InvalidTransitionError):
        transition(current, target)


def test_self_transition_is_not_permitted():
    assert not is_permitted(S.running, S.running)


def test_destroyed_is_terminal():
    assert EXERCISE_TRANSITIONS[S.destroyed] == frozenset()


def test_service_rejects_illegal_transition(session, principal, valid_definition):
    """An exercise in 'draft' cannot be deployed (service-level enforcement)."""
    from secp_api.services import catalog, exercises

    template = catalog.create_template(session, principal, name="T", slug="t-illegal")
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=valid_definition
    )
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name="x"
    )
    session.commit()
    # Deploy with no approved plan and exercise still in draft must be refused.
    with pytest.raises(Exception) as excinfo:
        exercises.start_exercise(session, principal, exercise.id)
    assert excinfo.type.__name__ in ("ApprovalRequiredError", "InvalidTransitionError")
