"""Provisioning-operation lifecycle state machine (SECP-002B-0, ADR-011/012).

One durable ProvisioningOperation per manifest moves through these states as the
fake runner performs dry-run / apply / destroy. Illegal transitions are rejected.
"""

from __future__ import annotations

from secp_api.enums import ProvisioningStatus as S
from secp_api.errors import InvalidTransitionError

PROVISIONING_TRANSITIONS: dict[S, frozenset[S]] = {
    S.manifest_generated: frozenset({S.pending_approval, S.queued, S.failed}),
    S.pending_approval: frozenset({S.queued, S.failed}),
    S.queued: frozenset({S.dry_run_completed, S.applying, S.destroy_queued, S.failed}),
    S.dry_run_completed: frozenset({S.queued, S.applying, S.failed}),
    S.applying: frozenset({S.applied, S.failed}),
    S.applied: frozenset({S.destroy_queued, S.queued, S.failed}),
    S.failed: frozenset({S.queued, S.destroy_queued}),
    S.destroy_queued: frozenset({S.destroyed, S.failed}),
    S.destroyed: frozenset(),  # terminal
}

TERMINAL_STATES = frozenset({S.destroyed})


def is_permitted(current: S, target: S) -> bool:
    if current == target:
        return False
    return target in PROVISIONING_TRANSITIONS.get(current, frozenset())


def transition(current: S, target: S) -> S:
    if not is_permitted(current, target):
        raise InvalidTransitionError(
            f"illegal provisioning transition {current.value} -> {target.value}"
        )
    return target
