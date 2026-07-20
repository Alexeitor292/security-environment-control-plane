"""Fixed database write-fence operations for the PR5F split activation boundary.

The controller migration and the current API become live before the ordinary worker is recreated.
Until the signed worker result is returned and authenticated, the database must reject the new
Ed25519 identity mechanism: either host may still need to restore code that cannot deserialize it.

This module exposes only three fixed operations. ``engage`` serializes against writers, installs and
validates the exact PostgreSQL CHECK constraint, and refuses if incompatible state already exists.
``release`` first repeats that proof and then removes the constraint in the same transaction.
``observe`` reads only the exact named constraint on the exact current-schema relation and returns
one closed state.  The CLI emits one bounded, closed JSON shape and never prints an underlying
database error or catalog detail.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from typing import Literal, cast

from sqlalchemy import text
from sqlalchemy.orm import Session

from secp_api.db import session_scope

ROLLBACK_FENCE_NAME = "ck_worker_identity_pr5f_ed25519_rollback_fence"

_LOCK_TABLE = text("LOCK TABLE worker_identity_registration IN ACCESS EXCLUSIVE MODE")
_DROP_FENCE = text(
    f"ALTER TABLE worker_identity_registration DROP CONSTRAINT IF EXISTS {ROLLBACK_FENCE_NAME}"
)
_INSTALL_FENCE = text(
    "ALTER TABLE worker_identity_registration "
    f"ADD CONSTRAINT {ROLLBACK_FENCE_NAME} "
    "CHECK (mechanism::text IS DISTINCT FROM 'ed25519_signed_nonce'::text) NOT VALID"
)
_VALIDATE_FENCE = text(
    f"ALTER TABLE worker_identity_registration VALIDATE CONSTRAINT {ROLLBACK_FENCE_NAME}"
)
_INCOMPATIBLE_STATE = text(
    """
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM worker_identity_registration
        WHERE mechanism = 'ed25519_signed_nonce'
    ) THEN 1 ELSE 0 END
    """
)

# This catalog probe returns only a closed state.  It never exposes a schema name, relation oid,
# constraint expression, row value, or database error.  An engaged result requires exactly one
# validated, nondeferrable CHECK with the repository-owned name, on exactly the ``mechanism``
# column of the current-schema relation, and with the exact normalized predicate installed above.
# A missing target relation or any catalog ambiguity is unverified; only an existing target
# relation with no named constraint is released.
_EXPECTED_NORMALIZED_EXPRESSION = "mechanism::textISDISTINCTFROM'ed25519_signed_nonce'::text"
_OBSERVE_FENCE_STATE = text(
    f"""
    WITH target AS (
        SELECT to_regclass(
            CASE
                WHEN current_schema() IS NULL THEN NULL
                ELSE quote_ident(current_schema()) || '.worker_identity_registration'
            END
        ) AS relation_oid
    ),
    mechanism_column AS (
        SELECT attribute.attnum
        FROM pg_catalog.pg_attribute AS attribute
        CROSS JOIN target
        WHERE attribute.attrelid = target.relation_oid
          AND attribute.attname = 'mechanism'
          AND NOT attribute.attisdropped
    ),
    named_constraint AS (
        SELECT constraint_row.*
        FROM pg_catalog.pg_constraint AS constraint_row
        CROSS JOIN target
        WHERE constraint_row.conrelid = target.relation_oid
          AND constraint_row.conname = '{ROLLBACK_FENCE_NAME}'
    )
    SELECT CASE
        WHEN (SELECT relation_oid FROM target) IS NULL THEN 'unverified'
        WHEN (SELECT count(*) FROM named_constraint) = 0 THEN 'released'
        WHEN (SELECT count(*) FROM named_constraint) = 1
         AND COALESCE(
            (
                SELECT bool_and(
                    constraint_row.contype = 'c'
                    AND constraint_row.convalidated
                    AND NOT constraint_row.condeferrable
                    AND NOT constraint_row.condeferred
                    AND NOT constraint_row.connoinherit
                    AND constraint_row.conkey = ARRAY[
                        (SELECT attnum FROM mechanism_column)
                    ]::smallint[]
                    AND regexp_replace(
                        replace(
                            replace(
                                pg_catalog.pg_get_expr(
                                    constraint_row.conbin,
                                    constraint_row.conrelid,
                                    false
                                ),
                                '(',
                                ''
                            ),
                            ')',
                            ''
                        ),
                        '[[:space:]]+',
                        '',
                        'g'
                    ) = :expected_expr
                )
                FROM named_constraint AS constraint_row
            ),
            false
         ) THEN 'engaged'
        ELSE 'unverified'
    END
    """
)

RollbackFenceState = Literal["engaged", "released", "unverified"]


class RollbackFenceError(RuntimeError):
    """A closed refusal to change or trust the PR5F rollback fence."""


def _require_postgresql(session: Session) -> None:
    if session.get_bind().dialect.name != "postgresql":
        raise RollbackFenceError("rollback_fence_postgresql_required")


def engage_rollback_fence(session: Session) -> None:
    """Atomically install, canonicalize, and validate the Ed25519 rollback fence."""

    _require_postgresql(session)
    # ACCESS EXCLUSIVE orders this transaction against every insert/update already in flight. The
    # drop/re-add repairs only the repository-owned stable constraint name and is safe because the
    # table stays locked until commit. NOT VALID constrains new tuples immediately; the query gives
    # a deliberate closed refusal for existing rows before the explicit whole-table validation.
    session.execute(_LOCK_TABLE)
    session.execute(_DROP_FENCE)
    session.execute(_INSTALL_FENCE)
    if session.execute(_INCOMPATIBLE_STATE).scalar_one() != 0:
        raise RollbackFenceError("rollback_fence_incompatible_state")
    session.execute(_VALIDATE_FENCE)


def release_rollback_fence(session: Session) -> None:
    """Release the fence only after re-proving its exact constraint and compatible contents."""

    _require_postgresql(session)
    engage_rollback_fence(session)
    session.execute(_DROP_FENCE)


def observe_rollback_fence(session: Session) -> RollbackFenceState:
    """Return only an exact live fence state; every ambiguous catalog posture is unverified."""

    _require_postgresql(session)
    # The expected normalized predicate contains single quotes, so it is bound as a parameter (never
    # interpolated into the SQL text) — the driver quotes it safely and the comparison stays exact.
    state = session.execute(
        _OBSERVE_FENCE_STATE, {"expected_expr": _EXPECTED_NORMALIZED_EXPRESSION}
    ).scalar_one()
    if state not in {"engaged", "released"}:
        return "unverified"
    return cast(RollbackFenceState, state)


def _report(*, action: str, observation_complete: bool, state: str) -> str:
    return json.dumps(
        {
            "action": action,
            "observation_complete": observation_complete,
            "rollback_fence_state": state,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = tuple(sys.argv[1:] if argv is None else argv)
    action = (
        args[0] if len(args) == 1 and args[0] in {"engage", "observe", "release"} else "invalid"
    )
    if action == "invalid":
        print(_report(action=action, observation_complete=False, state="unverified"))
        return 2
    try:
        with session_scope() as session:
            if action == "engage":
                engage_rollback_fence(session)
                state: RollbackFenceState = "engaged"
            elif action == "release":
                release_rollback_fence(session)
                state = "released"
            else:
                state = observe_rollback_fence(session)
    except Exception:
        print(_report(action=action, observation_complete=False, state="unverified"))
        return 2
    if state == "unverified":
        print(_report(action=action, observation_complete=False, state=state))
        return 2
    print(_report(action=action, observation_complete=True, state=state))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the fixed container command
    raise SystemExit(main())


__all__ = [
    "ROLLBACK_FENCE_NAME",
    "RollbackFenceError",
    "RollbackFenceState",
    "engage_rollback_fence",
    "main",
    "observe_rollback_fence",
    "release_rollback_fence",
]
