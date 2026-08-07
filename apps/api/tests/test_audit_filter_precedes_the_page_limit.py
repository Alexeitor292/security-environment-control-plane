"""``GET /api/v1/audit?exercise_id=…`` filtered AFTER cutting the page, so it answered wrongly.

WHAT WAS WRONG
---------------
``list_audit_events`` applied ``.limit(200)`` in SQL, ordered newest-first, and then filtered by
exercise in Python. That answers a different question from the one asked: not *"the most recent
events about this exercise"* but *"the events about this exercise among the organization's most
recent 200 rows"*.

The route does not expose ``limit``, so the trigger was never a small page — it was an organization
with more than 200 audit rows, which is every organization after a short while. An exercise whose
events had scrolled past that window returned **nothing**.

WHY IT MATTERS MORE THAN AN ORDINARY PAGING BUG
------------------------------------------------
The failure mode is the reassuring one. An empty list reads as *"nothing was audited for this
exercise"* — a claim — when the truth is *"the filter ran after the page was cut"*. An audit
surface that says "nothing happened" when it means "I did not look" is worse than one that errors,
because the operator stops looking.
"""

from __future__ import annotations

import uuid

from secp_api import audit
from secp_api.enums import AuditAction
from secp_api.models import AuditEvent
from secp_api.services import topology


def _event(
    session, principal, *, resource_type: str, resource_id: str, data: dict | None = None
) -> None:
    audit.record(
        session,
        action=AuditAction.organization_created,
        resource_type=resource_type,
        resource_id=resource_id,
        organization_id=principal.organization_id,
        actor="test",
        data=data,
    )


def test_a_matching_event_survives_a_page_smaller_than_the_noise(session, principal):
    """The regression, in its exact measured shape.

    One matching event recorded FIRST so it is the oldest, then a pile of unrelated newer rows.
    Before the fix this returned the event at ``limit=200`` and nothing at ``limit=5`` — the same
    data, the same filter, two different answers, neither of them about the page size the caller
    cares about.
    """
    exercise_id = uuid.uuid4()
    _event(session, principal, resource_type="exercise", resource_id=str(exercise_id))
    session.flush()
    for _ in range(12):
        _event(session, principal, resource_type="organization", resource_id=str(uuid.uuid4()))
    session.commit()

    assert session.query(AuditEvent).count() >= 13, "the noise rows must actually exist"

    for limit in (200, 5, 1):
        found = topology.list_audit_events(session, principal, exercise_id=exercise_id, limit=limit)
        assert [str(e.resource_id) for e in found] == [str(exercise_id)], (
            f"at limit={limit} the matching event was dropped by unrelated newer rows; the filter "
            "is running after the page is cut, and the caller receives an empty list that reads as "
            "'nothing was audited for this exercise'"
        )


def test_the_limit_still_bounds_the_filtered_result(session, principal):
    """``limit`` must still mean something — the fix must not quietly become unbounded.

    The opposite repair (drop the limit so nothing is ever missed) is one line, goes green on the
    test above, and turns an audit read on an append-only ledger into an unbounded scan.
    """
    exercise_id = uuid.uuid4()
    for _ in range(9):
        _event(session, principal, resource_type="exercise", resource_id=str(exercise_id))
    session.commit()

    assert (
        len(topology.list_audit_events(session, principal, exercise_id=exercise_id, limit=4)) == 4
    )
    assert (
        len(topology.list_audit_events(session, principal, exercise_id=exercise_id, limit=99)) == 9
    )


def test_the_newest_matching_events_are_the_ones_kept(session, principal):
    """When the limit does bite, it must keep the NEWEST matches, not an arbitrary subset.

    Ordering is why the old code could not simply move the limit: filtering in SQL changes which
    rows the ordering applies to, and getting that backwards would return the OLDEST matches while
    still passing every count assertion above.

    Asserted with ``>=`` against the excluded rows rather than by naming which indices come back.
    ``created_at`` is a Python default, so several rows written in a tight loop can share a
    timestamp — and a test that pins exact identities would then fail for a reason that has nothing
    to do with the property, which is how a correct guard gets deleted for being flaky.
    """
    exercise_id = uuid.uuid4()
    for index in range(6):
        _event(
            session,
            principal,
            resource_type="exercise",
            resource_id=str(exercise_id),
            data={"index": index},
        )
        session.flush()
    session.commit()

    every = topology.list_audit_events(session, principal, exercise_id=exercise_id, limit=99)
    assert len(every) == 6
    assert [row.created_at for row in every] == sorted(
        (row.created_at for row in every), reverse=True
    ), "the result is not ordered newest-first"

    kept = topology.list_audit_events(session, principal, exercise_id=exercise_id, limit=2)
    assert len(kept) == 2
    kept_indices = {row.data.get("index") for row in kept}
    dropped = [row for row in every if row.data.get("index") not in kept_indices]
    assert len(dropped) == 4
    assert min(row.created_at for row in kept) >= max(row.created_at for row in dropped), (
        f"the limit kept indices {sorted(kept_indices)}, which are not the most recent matches — "
        "the limit is being applied against a different ordering than the caller expects"
    )


def test_an_exercise_with_no_events_still_returns_empty(session, principal):
    """The honest empty case must stay empty.

    Guarding the fix in the other direction: a filter that stopped narrowing would pass every test
    above while returning the whole organization's history for any exercise id.
    """
    _event(session, principal, resource_type="organization", resource_id=str(uuid.uuid4()))
    session.commit()
    assert topology.list_audit_events(session, principal, exercise_id=uuid.uuid4()) == []


def test_the_filter_does_not_escape_the_organization(session, principal, other_org_principal):
    """Scope is the principal's, and the exercise filter narrows within it rather than around it."""
    exercise_id = uuid.uuid4()
    _event(session, principal, resource_type="exercise", resource_id=str(exercise_id))
    session.commit()

    assert len(topology.list_audit_events(session, principal, exercise_id=exercise_id)) == 1
    assert topology.list_audit_events(session, other_org_principal, exercise_id=exercise_id) == []
