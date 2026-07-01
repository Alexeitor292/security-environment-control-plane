"""Provisioning-operation lifecycle state machine (SECP-002B-0, ADR-011/012).

One durable ProvisioningOperation per manifest moves through these states as the
fake runner performs dry-run / apply / destroy. Illegal transitions are rejected.
"""

from __future__ import annotations

from secp_api.enums import ProvisioningStatus as S
from secp_api.errors import InvalidTransitionError

PROVISIONING_TRANSITIONS: dict[S, frozenset[S]] = {
    S.manifest_generated: frozenset(
        {
            S.pending_approval,
            S.queued,
            S.dry_run_completed,
            S.destroy_dry_run_completed,
            S.failed,
        }
    ),
    S.pending_approval: frozenset({S.queued, S.failed}),
    S.queued: frozenset(
        {
            S.dry_run_completed,
            S.destroy_dry_run_completed,
            S.applying,
            S.destroy_queued,
            S.failed,
        }
    ),
    # Real (B1-A) dry runs record a change set that must be human-approved before
    # apply/destroy. ``awaiting_change_set_approval`` is a durable pause point.
    S.dry_run_completed: frozenset(
        {S.queued, S.awaiting_change_set_approval, S.applying, S.failed}
    ),
    S.destroy_dry_run_completed: frozenset(
        {S.queued, S.awaiting_change_set_approval, S.destroy_queued, S.failed}
    ),
    S.awaiting_change_set_approval: frozenset({S.applying, S.destroy_queued, S.failed}),
    S.applying: frozenset({S.applied, S.failed}),
    S.applied: frozenset({S.destroy_queued, S.queued, S.destroy_dry_run_completed, S.failed}),
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
