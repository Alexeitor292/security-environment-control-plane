"""The scheduled driver for the durable worker-enrollment expiry sweep (SECP WS-B R3).

``worker_enrollment_recovery`` implements the sweep itself — correctly, and with every property a
background job needs — but until now nothing called it outside tests, so ``recovery_required`` was
unreachable in a running deployment and any recovery view would have been a dead view. This module
is the missing caller: it takes the per-organization :func:`drain_expired` and drives it across
every organization, so the lifecycle actually advances in production.

It is deliberately thin. Every durable guarantee stays where it already lives:

* per-candidate isolation, the ``FOR UPDATE SKIP LOCKED`` lock, the ``(revision, state_digest)``
  compare-and-swap, and the corrupt-row preservation are all :mod:`worker_enrollment_recovery`'s;
* ``drain_expired`` already walks its keyset cursor to a code-owned ``max_passes`` bound, so the
  work this module adds per organization is bounded before it starts.

**Organization scoping is preserved exactly.** The sweep is per-organization by construction; this
driver enumerates organizations and calls the org-scoped sweep once for each. It never issues a
cross-organization query and never widens the sweep's own filter — organization remains the only
authorization boundary, and a sweep of one organization can neither observe nor transition another
organization's rows.

**No authorization decision is made here, because there is no actor.** This is an unattended
scheduled job driven by the platform, not an operator request: it takes a ``sessionmaker``, not a
``Principal``. It therefore performs no RBAC check — there is no principal to check — and it
deliberately exposes no way for a caller to name an organization. An OPERATOR-triggered lifecycle
route is a different thing entirely and must carry its own explicit ``actor.require(...)``.

**Ordinary queue only.** Nothing here is controlled-live: it contacts no provider, opens no
outbound connection, runs no OpenTofu, touches no host, and reads no credential. It is a pure
database lifecycle transition and belongs on the ordinary task queue. See
``secp_worker.temporal_app`` for the activity that calls it and ``secp_worker.main`` for the
registration, which is on the shipped ordinary queue only.

Only bounded aggregate counts are reported. No enrollment id, organization id, reason string or row
detail is ever returned or logged.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from secp_api.models import Organization
from secp_api.services.worker_enrollment_recovery import (
    DEFAULT_MAX_PASSES,
    DEFAULT_SWEEP_BATCH,
    RecoverySweepResult,
    drain_expired,
)

_LOG = logging.getLogger("secp.enrollment.recovery_sweep")

#: A hard, code-owned ceiling on how many organizations ONE run will sweep. Reaching it is reported
#: truthfully via ``organizations_truncated`` rather than silently ignored: the remaining
#: organizations are swept by a later run, and an operator can see that the bound was hit.
DEFAULT_MAX_ORGANIZATIONS: Final = 1000


@dataclass(frozen=True)
class ScheduledSweepReport:
    """One scheduled run's aggregate outcome across every organization it covered.

    Identifier-free by construction: it carries counts only, so a naive ``log.info(report)`` cannot
    emit an enrollment id, an organization id, or a reason string. (The per-organization
    :class:`RecoverySweepResult` already keeps its keyset cursor out of ``repr`` for the same
    reason; this report does not carry a cursor at all.)
    """

    #: Organizations whose sweep COMPLETED. An organization whose sweep raised is counted in
    #: ``organizations_failed`` instead, never here — the field name says "swept", so counting an
    #: attempt would contradict it in the one report that exists to be truthful.
    organizations: int
    examined: int
    recovered: int
    skipped: int
    conflicts: int
    corrupt: int
    #: Per-CANDIDATE failures, summed from the per-organization sweeps.
    failed: int
    #: True when the run stopped at :data:`DEFAULT_MAX_ORGANIZATIONS` with organizations still
    #: unswept. Not an error — the next scheduled run continues — but it is reported rather than
    #: hidden, because a permanently truncated run means enrollments in the tail never recover.
    organizations_truncated: bool = False
    #: Organizations whose sweep raised and was isolated. Kept SEPARATE from ``failed`` on purpose:
    #: previously an entire tenant failing was byte-identical to one poison row, so an organization
    #: failing persistently — a bad connection, a migration mid-flight, a schema gate — reported
    #: ``failed: 1`` forever while that tenant was never swept at all, and nothing distinguished it.
    organizations_failed: int = 0
    #: The bounded EXCEPTION TYPE NAMES seen across failing organizations, sorted and de-duplicated.
    #: A type name is code-owned and carries no tenant identifier, enrollment id, reason string or
    #: connection detail — so it is safe to log, while still saying *what kind* of failure to go
    #: look for. This is the diagnosis hook: without it the isolation works but is unobservable.
    failure_kinds: tuple[str, ...] = ()

    def as_log_fields(self) -> dict[str, int | bool | str]:
        """The surfaceable log/metric projection. Counts, one flag, and bounded type names — never
        an identifier."""
        return {
            "organizations": self.organizations,
            "organizations_failed": self.organizations_failed,
            "examined": self.examined,
            "recovered": self.recovered,
            "skipped": self.skipped,
            "conflicts": self.conflicts,
            "corrupt": self.corrupt,
            "failed": self.failed,
            "organizations_truncated": self.organizations_truncated,
            "failure_kinds": ",".join(self.failure_kinds),
        }


def _report_progress(on_progress: Callable[[], None] | None) -> None:
    """Signal that one organization finished, for a caller that wants liveness (a Temporal
    heartbeat).

    Never lets progress reporting affect the sweep: a heartbeat that raises — an expired activity,
    a missing context — must not abort a run that is otherwise making forward progress, and must
    not be mistaken for an organization failure.
    """
    if on_progress is None:
        return
    try:
        on_progress()
    except Exception:  # noqa: BLE001 - liveness reporting is never worth failing the sweep for
        pass


def _organization_ids(session: Session, *, limit: int) -> list[uuid.UUID]:
    """Every organization id, in a stable order, up to ``limit``.

    Ordered by primary key so the traversal is deterministic and a truncated run always covers the
    same prefix — which makes "the tail never gets swept" an observable, diagnosable condition
    rather than a random one.
    """
    return list(
        session.execute(select(Organization.id).order_by(Organization.id).limit(limit))
        .scalars()
        .all()
    )


def sweep_all_organizations(
    session_factory: sessionmaker,
    *,
    now: str,
    batch_size: int = DEFAULT_SWEEP_BATCH,
    max_passes: int = DEFAULT_MAX_PASSES,
    max_organizations: int = DEFAULT_MAX_ORGANIZATIONS,
    on_progress: Callable[[], None] | None = None,
) -> ScheduledSweepReport:
    """Drain due, active enrollments to ``recovery_required`` for every organization.

    ``session_factory`` is a :class:`sessionmaker`, not a :class:`Session`, and that is load-bearing
    all the way down: the organization enumeration runs in its own short session, and each
    organization's sweep opens fresh sessions per candidate. Nothing depends on process memory, so a
    freshly restarted worker sweeps identically to a long-lived one.

    One organization's failure must never stop the run. A sweep raising for organization A would
    otherwise leave organizations B..Z unswept until the next scheduled run — and if A's failure is
    persistent, permanently. Each organization is therefore isolated: an unexpected error is counted
    as ``failed`` and the run continues. That mirrors the per-candidate poison isolation the sweep
    already provides one level down.
    """
    bounded_organizations = max(1, min(int(max_organizations), DEFAULT_MAX_ORGANIZATIONS))
    with session_factory() as reader:
        # read one past the bound so truncation is DETECTED rather than assumed from a full page
        organization_ids = _organization_ids(reader, limit=bounded_organizations + 1)
    truncated = len(organization_ids) > bounded_organizations
    organization_ids = organization_ids[:bounded_organizations]

    totals = dict(examined=0, recovered=0, skipped=0, conflicts=0, corrupt=0, failed=0)
    swept = 0
    organizations_failed = 0
    failure_kinds: set[str] = set()
    for organization_id in organization_ids:
        try:
            result = drain_expired(
                session_factory,
                organization_id=organization_id,
                now=now,
                batch_size=batch_size,
                max_passes=max_passes,
            )
        except Exception as exc:  # noqa: BLE001 - one organization must not abort the whole run
            # Isolated, and now OBSERVABLE. Counted on its own axis rather than folded into the
            # per-candidate ``failed`` counter: an entire tenant failing was previously
            # indistinguishable from a single poison row, so a persistent per-organization failure
            # reported ``failed: 1`` forever while that tenant was never swept.
            #
            # Still not reported as corruption — an unexpected error is not evidence that any row is
            # corrupt, and mislabelling it would be untruthful. Nothing was committed here.
            #
            # The exception TYPE NAME is recorded (never the message, which can carry a connection
            # string, a path or a tenant identifier) and logged with the organization COUNT only.
            organizations_failed += 1
            failure_kinds.add(type(exc).__name__)
            _report_progress(on_progress)  # a failing org is still progress through the run
            _LOG.warning(
                "enrollment recovery sweep: an organization failed and was isolated (kind=%s); "
                "the run continues",
                type(exc).__name__,
            )
            continue
        swept += 1
        totals["examined"] += result.examined
        totals["recovered"] += result.recovered
        totals["skipped"] += result.skipped
        totals["conflicts"] += result.conflicts
        totals["corrupt"] += result.corrupt
        totals["failed"] += result.failed
        _report_progress(on_progress)

    return ScheduledSweepReport(
        organizations=swept,
        organizations_truncated=truncated,
        organizations_failed=organizations_failed,
        failure_kinds=tuple(sorted(failure_kinds)),
        **totals,
    )


__all__ = [
    "DEFAULT_MAX_ORGANIZATIONS",
    "RecoverySweepResult",
    "ScheduledSweepReport",
    "sweep_all_organizations",
]
