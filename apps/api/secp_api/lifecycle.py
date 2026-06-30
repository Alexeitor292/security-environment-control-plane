"""The authoritative lifecycle state machine (Charter §6; design §7, §9).

A single transition table defines permitted moves. ``transition`` rejects illegal
moves with :class:`InvalidTransitionError` and changes nothing; callers audit the
transition when it succeeds.
"""

from __future__ import annotations

from secp_api.enums import LifecycleState as S
from secp_api.errors import InvalidTransitionError

# Permitted transitions for an Exercise (the full lifecycle).
EXERCISE_TRANSITIONS: dict[S, frozenset[S]] = {
    S.draft: frozenset({S.validated, S.failed}),
    S.validated: frozenset({S.planned, S.draft, S.failed}),
    S.planned: frozenset({S.awaiting_approval, S.validated, S.failed}),
    S.awaiting_approval: frozenset({S.approved, S.validated, S.failed}),
    S.approved: frozenset({S.deploying, S.failed}),
    S.deploying: frozenset({S.running, S.failed}),
    S.running: frozenset({S.resetting, S.destroying, S.failed}),
    S.resetting: frozenset({S.running, S.failed}),
    S.destroying: frozenset({S.destroyed, S.failed}),
    S.destroyed: frozenset(),  # terminal
    S.failed: frozenset({S.destroying, S.draft}),  # cleanup or restart
}

# Permitted transitions for a single EnvironmentInstance (subset of the above).
INSTANCE_TRANSITIONS: dict[S, frozenset[S]] = {
    S.deploying: frozenset({S.running, S.failed}),
    S.running: frozenset({S.resetting, S.destroying, S.failed}),
    S.resetting: frozenset({S.running, S.failed}),
    S.destroying: frozenset({S.destroyed, S.failed}),
    S.destroyed: frozenset(),
    S.failed: frozenset({S.destroying}),
}

TERMINAL_STATES = frozenset({S.destroyed})


def is_permitted(
    current: S, target: S, table: dict[S, frozenset[S]] = EXERCISE_TRANSITIONS
) -> bool:
    if current == target:
        return False
    return target in table.get(current, frozenset())


def transition(current: S, target: S, table: dict[S, frozenset[S]] = EXERCISE_TRANSITIONS) -> S:
    """Return ``target`` if the move is permitted, else raise.

    This is a pure function; persistence/audit is the caller's responsibility so
    the transition and its audit event commit atomically.
    """
    if not is_permitted(current, target, table):
        raise InvalidTransitionError(f"illegal transition {current.value} -> {target.value}")
    return target
