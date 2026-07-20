"""Bounded controller rollback-compatibility probe for SECP-PR5F.

The pre-PR5F controller cannot deserialize the new Ed25519 worker-identity mechanism.  A completed
deployment may therefore restore the prior controller image only while no durable identity has
crossed that compatibility boundary.  This module reads one closed aggregate existence fact from the
controller database and emits one fixed-shape, secret-free JSON document.  It performs no mutation.
"""

from __future__ import annotations

import json

from sqlalchemy import text
from sqlalchemy.orm import Session

from secp_api.db import session_scope

_INCOMPATIBLE_STATE = text(
    """
    SELECT CASE WHEN
        EXISTS (
            SELECT 1 FROM worker_identity_registration
            WHERE mechanism = 'ed25519_signed_nonce'
        )
    THEN 1 ELSE 0 END
    """
)


def controller_rollback_compatible(session: Session) -> bool:
    """Return true only when the pre-PR5F API can still read all PR5F-touched identity rows."""

    incompatible = session.execute(_INCOMPATIBLE_STATE).scalar_one()
    return incompatible == 0


def _report(*, observation_complete: bool, rollback_compatible: bool) -> str:
    return json.dumps(
        {
            "observation_complete": observation_complete,
            "rollback_compatible": rollback_compatible,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def main() -> int:
    try:
        with session_scope() as session:
            compatible = controller_rollback_compatible(session)
    except Exception:
        print(_report(observation_complete=False, rollback_compatible=False))
        return 2
    print(_report(observation_complete=True, rollback_compatible=compatible))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the fixed container probe
    raise SystemExit(main())


__all__ = ["controller_rollback_compatible", "main"]
