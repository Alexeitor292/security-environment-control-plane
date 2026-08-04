"""Which tier this run is, and the refusal that keeps a skipped container tier from reading as
acceptance.

The harness has two tiers:

``hermetic`` (the default)
    Contract tests. They create no host and contact nothing, so they run in the ordinary CI shards.
    A green hermetic run says the harness's own contracts hold. It says NOTHING about the product on
    a real host, and it produces no evidence document, so there is nothing for a reader to mistake
    for an acceptance result.

``container`` (declared explicitly, by the acceptance workflow)
    The real thing: disposable hosts, real installed packages, real systemd, real nested Docker.

THE PROPERTY THIS MODULE EXISTS FOR
-----------------------------------
**A green run with the container tier skipped must never be readable as acceptance.** A skipped test
body proves nothing about itself, but it is rendered as a small ``s`` next to a passing run, and
every reader downstream of that render sees green. Three mechanisms together, because any one of
them alone has a hole:

1. When the container tier is DECLARED, an absent container runtime is a hard
   :class:`~secp_acceptance.AcceptanceError` — never a skip. The run fails loudly with a bounded
   reason code instead of quietly proving nothing.
2. When the container tier is declared, the tier must also be WITNESSED: each container-tier body
   records that it actually executed, and a session-final hook fails the session if a declared tier
   left no witness. This is what catches the case mechanism 1 cannot — a body that never ran at all,
   because it was deselected, renamed, filtered by ``-k``, or lost in a collection error.
3. When the container tier is NOT declared, its tests are DESELECTED rather than skipped. A
   deselected test is absent from the report; a skipped one is a green tick with a footnote.

Mechanism 2 is the one worth reading twice, because it is the only one that fails when the harness
itself is the thing that broke.

SCOPE OF THE WITNESS
--------------------
The witness is process-local. The CI corpus is sharded by FILE, so every test in the container-tier
module lands in one shard and therefore one process, and :func:`witnessed` sees them all. A future
change that splits the container tier across FILES would break that assumption silently, so
:func:`assert_tier_witnessed` requires the witness to name every stage the tier declares rather than
merely being non-empty.
"""

from __future__ import annotations

import os

from secp_acceptance import AcceptanceError

#: The environment variable a run uses to declare its tier. Declaring is deliberately explicit and
#: opt-IN: a developer running ``pytest`` gets the hermetic tier, and only the acceptance workflow
#: (or an operator who means it) asks for the container tier. The inverse default — container tier
#: unless suppressed — would make every ordinary shard fail for want of a privileged nested daemon,
#: and the pressure to suppress it would land right back on a skip.
ENV_TIER = "SECP_ACCEPTANCE_TIER"

TIER_HERMETIC = "hermetic"
TIER_CONTAINER = "container"
TIERS: frozenset[str] = frozenset({TIER_HERMETIC, TIER_CONTAINER})

#: The stages the container tier must witness. Named individually so a partially-executed tier is
#: distinguishable from a fully-executed one — "some container test ran" is not the claim.
#:
#: ``worker_image_probed`` covers the interpreter measurement, which needs the outer runtime but no
#: fleet. It is listed because a declared tier that built hosts and never probed the image would
#: otherwise be indistinguishable from a complete one, and that probe is the only place the pinned
#: worker health interpreter is checked against a real image rather than against another constant.
#: The installation witnesses mark that a stage's body EXECUTED, not that it succeeded. That
#: distinction is deliberate: a controller the harness could not bring up records five ``unproven``
#: checks and is a real, reviewable result, whereas a controller stage that never ran leaves nothing
#: at all — and it is only the second case this witness can see. Tying a witness to success would
#: collapse the two and make a silently-absent stage indistinguishable from a failing one.
CONTAINER_TIER_STAGES: tuple[str, ...] = (
    "fleet_created",
    "fleet_proved",
    "fleet_destroyed",
    "worker_image_probed",
    "release_built",
    "packages_installed",
    "controller_attempted",
    "worker_install_attempted",
)

_witnessed: set[str] = set()


def declared_tier() -> str:
    """The tier this run declared. An unrecognised value REFUSES rather than defaulting.

    Defaulting an unknown value to ``hermetic`` would turn a typo in the acceptance workflow
    (``SECP_ACCEPTANCE_TIER=containers``) into a silently downgraded run that still exits green —
    precisely the failure this module exists to prevent.
    """
    raw = os.environ.get(ENV_TIER)
    if raw is None or raw == "":
        return TIER_HERMETIC
    if raw not in TIERS:
        raise AcceptanceError("acceptance_tier_undeclared")
    return raw


def container_tier_required() -> bool:
    return declared_tier() == TIER_CONTAINER


def require_container_runtime_or_refuse() -> str:
    """Prove the container runtime is usable, or REFUSE. Never skips, never returns falsely.

    Called at the top of the container tier. When the tier was declared and Docker is not there,
    this raises and the run fails with ``acceptance_container_runtime_unavailable`` — the operator
    sees an outage of the acceptance environment, which is true, rather than a green run that
    measured nothing.
    """
    if not container_tier_required():
        # Refuse to run the container tier implicitly. A body that reached here without the tier
        # being declared is a bug in the gating, not an invitation to build hosts anyway.
        raise AcceptanceError("acceptance_tier_undeclared")
    from secp_acceptance.shell import require_container_runtime

    return require_container_runtime()


def witness(stage: str) -> None:
    """Record that a container-tier stage ACTUALLY executed."""
    if stage not in CONTAINER_TIER_STAGES:
        raise AcceptanceError("acceptance_tier_unknown_witness")
    _witnessed.add(stage)


def witnessed() -> frozenset[str]:
    return frozenset(_witnessed)


def reset_witness() -> None:
    """Clear the witness. For the hermetic tests OF this module only."""
    _witnessed.clear()


def missing_witnesses() -> tuple[str, ...]:
    return tuple(stage for stage in CONTAINER_TIER_STAGES if stage not in _witnessed)


def assert_tier_witnessed() -> None:
    """Fail when a DECLARED container tier left no witness, or only a partial one.

    This is the check that a skip cannot satisfy. If the container tier was declared and its bodies
    did not run — deselected, filtered, renamed, or lost to a collection error — the session fails
    here even though every collected test passed.
    """
    if not container_tier_required():
        return
    missing = missing_witnesses()
    if missing:
        raise AcceptanceError("acceptance_container_tier_not_executed")


__all__ = [
    "CONTAINER_TIER_STAGES",
    "ENV_TIER",
    "TIERS",
    "TIER_CONTAINER",
    "TIER_HERMETIC",
    "assert_tier_witnessed",
    "container_tier_required",
    "declared_tier",
    "missing_witnesses",
    "require_container_runtime_or_refuse",
    "reset_witness",
    "witness",
    "witnessed",
]
