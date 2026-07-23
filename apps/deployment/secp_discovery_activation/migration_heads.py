"""The code-owned controller Alembic migration-head compatibility window (SECP-PR5H-A, ADR-027).

``ControllerOffer.controller_migration_head`` is a validated field of a **signed** record, so adding
an Alembic migration cannot simply replace the pinned value: every already-issued PR5F offer would
stop validating and every controller would need a lockstep upgrade.  Instead the pin is widened into
a **bounded rolling-upgrade window** — deliberately NOT an accept-any-head policy:

* :data:`ACCEPTED_CONTROLLER_MIGRATION_HEADS` contains EXACTLY two values (the legacy PR5F head and
  the current PR5H head) and is used ONLY to *validate* an already-issued signed artifact, or an
  observed live controller, during the window;
* :data:`ISSUED_CONTROLLER_MIGRATION_HEAD` is single-valued — a newly issued offer ALWAYS declares
  only the current head, and issuance additionally REQUIRES the observed live head to equal it;
* anything else — an unknown, malformed, older, future or branched head — refuses closed.

Accepting an old signed artifact **never** implies that the PR5H enrollment persistence exists.
That is a separate, independently observed property: the control plane keeps its own
``RUNTIME_REQUIRED_MIGRATION_HEAD`` (see ``secp_api.worker_enrollment_schema``) and must confirm the
LIVE database head before any enrollment repository / CAS / nonce-ledger / recovery operation.
Signed-artifact compatibility and live-schema readiness are intentionally different questions.

The exact-head binding is preserved everywhere: a declared head must still equal the OBSERVED head,
so an old-head offer only validates against an old-head controller and a downgrade substitution is
refused rather than silently accepted.

Removing the legacy head requires a later **explicit deprecation PR**, once every issued PR5F offer
has expired or been retired.  This module is the single place that definition lives.
"""

from __future__ import annotations

from typing import Final, Literal, get_args

#: The signed-record field type.  Declared FIRST so the constants below carry it (a Literal cannot
#: be built from names); :func:`accepted_heads_match_literal` proves it never drifts from the tuple.
ControllerMigrationHead = Literal["d8f1a2b3c4e5", "b6e2f4a9c1d7"]

#: SECP-PR5F (B8 production activation) — the legacy head, accepted only during the window.
LEGACY_CONTROLLER_MIGRATION_HEAD: Final[ControllerMigrationHead] = "d8f1a2b3c4e5"

#: SECP-PR5H-A (durable worker-enrollment foundation) — the current head.
CURRENT_CONTROLLER_MIGRATION_HEAD: Final[ControllerMigrationHead] = "b6e2f4a9c1d7"

#: The BOUNDED compatibility window: exactly the two heads above, in upgrade order.
ACCEPTED_CONTROLLER_MIGRATION_HEADS: Final[tuple[str, ...]] = (
    LEGACY_CONTROLLER_MIGRATION_HEAD,
    CURRENT_CONTROLLER_MIGRATION_HEAD,
)

#: A newly issued ControllerOffer declares ONLY this head (never the legacy one).
ISSUED_CONTROLLER_MIGRATION_HEAD: Final[ControllerMigrationHead] = "b6e2f4a9c1d7"


def is_accepted_controller_migration_head(value: object) -> bool:
    """True only for a head inside the bounded window; everything else refuses closed."""
    return isinstance(value, str) and value in ACCEPTED_CONTROLLER_MIGRATION_HEADS


def accepted_heads_match_literal() -> bool:
    """The ``ControllerMigrationHead`` Literal and the accepted tuple must never drift apart."""
    return tuple(get_args(ControllerMigrationHead)) == ACCEPTED_CONTROLLER_MIGRATION_HEADS


__all__ = [
    "ACCEPTED_CONTROLLER_MIGRATION_HEADS",
    "CURRENT_CONTROLLER_MIGRATION_HEAD",
    "ISSUED_CONTROLLER_MIGRATION_HEAD",
    "LEGACY_CONTROLLER_MIGRATION_HEAD",
    "ControllerMigrationHead",
    "accepted_heads_match_literal",
    "is_accepted_controller_migration_head",
]
