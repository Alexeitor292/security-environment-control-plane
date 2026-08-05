"""A range operation the worker cannot resolve must never report success.

This file exists because of an observed, reproduced product defect, not a hypothetical one. A reset
was dispatched to a worker polling the ``secp-orchestration`` queue against a DIFFERENT database.
The worker looked the operation up, did not find it, logged a warning and RETURNED — so:

* Temporal reported the workflow ``Completed``;
* the outbox row read ``submitted``, attempts 1, with no error;
* the operation stayed ``pending`` forever and the range stayed ``resetting`` forever;
* and both recovery paths refused, because ``resetting`` is not a state you may destroy or reset
  from::

      POST /ranges/{id}/destroy -> 409 cannot destroy a range in state 'resetting'
      POST /ranges/{id}/reset   -> 409 cannot reset a range in state 'resetting'

Direct ``UPDATE range_deployment_operation`` surgery was the only way out, while the containers
kept running.

The shared queue was the trigger, but the stranding is NOT environmental. Replica lag, a worker
pointed at the wrong deployment, or a crash between dispatch and execution all reach the same dead
end: work that cannot be resolved reports success, and the range is wedged in an in-flight state
with no operator-reachable way out.

Two halves are pinned here.

**Fail truthfully.** A missing operation, a missing range, or an argument that resolves to another
environment's rows raises a bounded, classified error. The activity never returns normally, so the
workflow can never be ``Completed``. Where the operation row IS reachable the failure is also
persisted, so an operator sees it without reading worker logs.

**Recover without SQL.** Staleness is derived from durable state (see
``ranges.operation_staleness``), the operation and range expose it, an authorized abandon endpoint
moves the range to ``recovery_required``, and every resource the range has ever created stays
enumerated — as live or ``unproven``, never absent. Absence is a claim only a working probe may
make.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import secp_api.range_models  # noqa: F401  (registers the range tables on Base before create_all)
from _range_fixtures import deploy_ready_range, provider_fixture
from secp_api.range_enums import (
    RangeOperationKind,
    RangeOperationStatus,
    RangeResourceState,
    RangeState,
    ResidueVerdict,
)
from secp_api.range_models import (
    RangeDeploymentOperation,
    RangeInstance,
    RangeLifecycleEvent,
    RangeProviderResource,
)
from secp_api.range_providers.base import (
    TeardownObservation,
    TeardownResourceOutcome,
    TeardownResult,
)
from secp_api.services import ranges
from secp_worker.range.execution import (
    RangeExecutionUnresolvable,
    execute_range_operation,
)
from sqlalchemy import delete, select

provider = pytest.fixture(provider_fixture)


def _reset_in_flight(session, principal, instance: RangeInstance) -> RangeDeploymentOperation:
    """Put the range where the live incident put it: a reset in flight, range ``resetting``."""
    _, operation = ranges.start_operation(session, principal, instance.id, RangeOperationKind.reset)
    session.commit()
    assert instance.state is RangeState.resetting
    assert operation.status is RangeOperationStatus.pending
    return operation


# --- 1. missing operation ---------------------------------------------------------------------


def test_missing_operation_raises_instead_of_reporting_success(session, principal, provider):
    """THE DEFECT. The worker cannot resolve the operation, so it must not report success.

    This is the exact live shape: the operation id is dispatched, the worker's database does not
    contain it, and before the fix ``execute_range_operation`` returned ``None`` — which the
    Temporal activity turned into ``range_operation_complete`` and Temporal turned into
    ``Completed``.
    """
    stranded_id = uuid.uuid4()

    with pytest.raises(RangeExecutionUnresolvable) as caught:
        execute_range_operation(session, stranded_id)

    assert caught.value.reason == "operation_not_found"
    # Bounded, not permanent: a not-found row is exactly what replica lag looks like, so the
    # activity layer is allowed to retry this one a bounded number of times.
    assert caught.value.retryable is True
    assert str(stranded_id) in str(caught.value)


# --- 2. missing range -------------------------------------------------------------------------


def test_missing_range_fails_the_operation_and_raises(session, principal, provider, engine):
    """The operation IS reachable but its range is not — so the failure is also PERSISTED.

    An operation whose range is not resolvable cannot be retried into existence, so this one is
    non-retryable. Because the operation row is in this database, the worker records an
    operator-visible failure before raising.

    Getting the database into this shape takes deliberate effort, and that is worth stating: the
    foreign key from ``range_deployment_operation`` to ``range_instance`` means a single healthy
    database cannot produce it. It is a PARTIAL-VISIBILITY condition — a replica that has the
    operation row but not yet the range row, or a worker reading a deployment where only some of
    the write replicated. So the FK is switched off on a dedicated connection (the same technique
    ``conftest`` uses to drop the FK cycle) to build the state a healthy schema forbids.
    """
    instance = deploy_ready_range(session, principal, provider)
    operation = _reset_in_flight(session, principal, instance)
    operation_id = operation.id
    range_id = instance.id
    session.commit()

    with engine.connect() as conn:
        # Must run on the raw DBAPI connection BEFORE any statement opens a transaction — SQLite
        # ignores ``PRAGMA foreign_keys`` inside one, which would make this silently a no-op.
        conn.connection.dbapi_connection.execute("PRAGMA foreign_keys=OFF")
        for model in (RangeLifecycleEvent, RangeProviderResource):
            conn.execute(delete(model).where(model.range_instance_id == range_id))
        conn.execute(delete(RangeInstance).where(RangeInstance.id == range_id))
        conn.commit()

    # Drop the identity map, or ``session.get`` answers from cache and the worker "finds" a range
    # that is no longer in the database. A fresh worker process has no cache; model that.
    session.expunge_all()

    with pytest.raises(RangeExecutionUnresolvable) as caught:
        execute_range_operation(session, operation_id)

    assert caught.value.reason == "range_not_found"
    assert caught.value.retryable is False

    session.expire_all()
    persisted = session.get(RangeDeploymentOperation, operation_id)
    assert persisted is not None
    assert persisted.status is RangeOperationStatus.failed
    assert persisted.failure_code == "range_not_found"
    assert persisted.finished_at is not None


# --- 3. wrong database / environment ------------------------------------------------------------


def test_operation_resolving_to_another_environments_rows_is_refused_untouched(
    session, principal, provider
):
    """A worker attached to the wrong deployment must refuse — and must not write.

    This is the trigger from the incident: two workers polling one ``secp-orchestration`` queue
    against two databases. The dispatcher stamps which rows the id denotes where it was created, so
    a worker that resolves it to something else knows.

    The refusal writes NOTHING. The row in front of this worker is its own database's legitimate
    operation, which merely shares an id; failing it would wedge a healthy range in order to report
    a problem with a foreign one. That is the shape of the original bug — collateral state written
    from a confused premise — and it is deliberately not repeated here.
    """
    instance = deploy_ready_range(session, principal, provider)
    operation = _reset_in_flight(session, principal, instance)
    operation_id = operation.id
    before_status = operation.status

    with pytest.raises(RangeExecutionUnresolvable) as caught:
        execute_range_operation(session, operation_id, expected_range_instance_id=uuid.uuid4())

    assert caught.value.reason == "environment_mismatch"
    # Never retryable: waiting cannot make this worker be attached to the other database.
    assert caught.value.retryable is False

    session.expire_all()
    untouched = session.get(RangeDeploymentOperation, operation_id)
    assert untouched.status is before_status
    assert untouched.failure_code is None
    assert untouched.finished_at is None
    assert session.get(RangeInstance, instance.id).state is RangeState.resetting


def test_operation_from_another_organization_is_refused(session, principal, provider):
    """The same check against the organization id, which is the coarser environment boundary."""
    instance = deploy_ready_range(session, principal, provider)
    operation = _reset_in_flight(session, principal, instance)

    with pytest.raises(RangeExecutionUnresolvable) as caught:
        execute_range_operation(session, operation.id, expected_organization_id=uuid.uuid4())

    assert caught.value.reason == "environment_mismatch"
    assert caught.value.retryable is False


# --- 4. worker crash after dispatch -------------------------------------------------------------


def _age(session, operation: RangeDeploymentOperation, minutes: int) -> None:
    """Backdate a range's operation history so the given operation's lease has genuinely expired.

    Backdating the ROWS rather than injecting a clock keeps the real derivation under test: the
    lease is computed from ``started_at`` and the per-step ``at`` stamps, and both are moved here
    exactly as the passage of time would have left them.

    EVERY operation on the range moves, not just this one. Shifting one row backwards would reorder
    the range's history — a reset aged past the deploy that preceded it stops being the range's
    newest operation, and ``current_operation`` would then report the long-finished deploy. Time
    passing does not reorder anything, so neither does this.
    """
    shift = timedelta(minutes=minutes)
    siblings = (
        session.execute(
            select(RangeDeploymentOperation).where(
                RangeDeploymentOperation.range_instance_id == operation.range_instance_id
            )
        )
        .scalars()
        .all()
    )
    for row in siblings:
        row.started_at = row.started_at - shift
        aged = []
        for original in row.steps or []:
            step = dict(original)
            at = step.get("at")
            if isinstance(at, str):
                parsed = datetime.fromisoformat(at)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=UTC)
                step["at"] = (parsed - shift).isoformat()
            aged.append(step)
        row.steps = aged
    session.commit()


def test_worker_crash_after_dispatch_becomes_visibly_stale(session, principal, provider):
    """A worker that dies mid-operation leaves no error anywhere — the LEASE is what notices.

    Nothing raises here, and that is the point: a crashed process does not get to report anything.
    The operation is left exactly as the dead worker left it, ``running`` with partial progress, and
    the only thing that distinguishes it from a slow operation is that its progress stopped.
    """
    instance = deploy_ready_range(session, principal, provider)
    operation = _reset_in_flight(session, principal, instance)

    # The worker picked it up, completed a step, and then the process died.
    operation.status = RangeOperationStatus.running
    operation.steps = [
        {
            "key": "preflight",
            "label": "preflight",
            "status": "succeeded",
            "detail": None,
            "at": datetime.now(UTC).isoformat(),
        },
        {
            "key": "start:dvwa",
            "label": "start dvwa",
            "status": "running",
            "detail": None,
            "at": None,
        },
    ]
    operation.total_steps = 2
    operation.completed_steps = 1
    session.commit()

    # While progress is recent the lease holds: a slow operation is not a stranded one.
    assert ranges.operation_staleness(operation).stale is False

    _age(session, operation, minutes=45)

    staleness = ranges.operation_staleness(operation)
    assert staleness.stale is True
    assert "stopped reporting progress" in staleness.reason
    assert instance.state is RangeState.resetting  # still wedged — until an operator acts


def test_never_picked_up_operation_names_the_queue_as_the_suspect(session, principal, provider):
    """A ``pending`` operation past its lease was never claimed by any worker, and says so.

    The distinction is diagnostic: ``running`` means a worker had it and stopped, while ``pending``
    means nothing ever claimed it — the signature of a queue with no worker on it, or a worker
    connected to a different database. That was the live incident.
    """
    instance = deploy_ready_range(session, principal, provider)
    operation = _reset_in_flight(session, principal, instance)
    _age(session, operation, minutes=45)

    staleness = ranges.operation_staleness(operation)
    assert staleness.stale is True
    assert "never picked up" in staleness.reason
    assert "different database" in staleness.reason


# --- 5. expired operation ------------------------------------------------------------------------


def test_worker_refuses_an_operation_whose_lease_expired(session, principal, provider):
    """A worker arriving after the lease expired must not start the work.

    This closes the race the recovery path would otherwise open. Once an operation is abandonable,
    an operator may abandon it at any instant; a worker that begins driving the provider now is a
    second writer on a range somebody is actively recovering.
    """
    instance = deploy_ready_range(session, principal, provider)
    operation = _reset_in_flight(session, principal, instance)
    operation_id = operation.id
    _age(session, operation, minutes=45)

    with pytest.raises(RangeExecutionUnresolvable) as caught:
        execute_range_operation(session, operation_id)

    assert caught.value.reason == "lease_expired"
    assert caught.value.retryable is False
    assert provider.destroy_calls == []  # the provider was never touched

    session.expire_all()
    refused = session.get(RangeDeploymentOperation, operation_id)
    assert refused.failure_code == "lease_expired"
    # And the range is no longer wedged: this worker KNOWS nothing will run the operation.
    assert session.get(RangeInstance, instance.id).state is RangeState.recovery_required


def test_worker_refuses_an_operation_already_resolved_without_it(session, principal, provider):
    """Abandoned first, worker wakes up second. It must not execute a resolved operation."""
    instance = deploy_ready_range(session, principal, provider)
    operation = _reset_in_flight(session, principal, instance)
    operation_id = operation.id
    _age(session, operation, minutes=45)
    ranges.abandon_operation(session, principal, operation_id)
    session.commit()

    with pytest.raises(RangeExecutionUnresolvable) as caught:
        execute_range_operation(session, operation_id)

    assert caught.value.reason == "operation_not_in_flight"
    assert caught.value.retryable is False


# --- 6. operator abandon -------------------------------------------------------------------------


def test_abandon_is_refused_while_the_lease_is_still_live(session, principal, provider):
    """You may not abandon an operation that might be executing — that is two writers on a range."""
    instance = deploy_ready_range(session, principal, provider)
    operation = _reset_in_flight(session, principal, instance)

    with pytest.raises(ranges.RangeOperationNotStaleError) as caught:
        ranges.abandon_operation(session, principal, operation.id)
    assert caught.value.http_status == 409

    # An operator who has checked can still say so explicitly.
    _, forced = ranges.abandon_operation(session, principal, operation.id, force=True)
    assert forced.status is RangeOperationStatus.unproven
    assert forced.failure_code == "abandoned_by_operator"


def test_abandon_requires_the_permission_that_would_have_started_the_operation(
    session, principal, provider
):
    """Reading a range must not be enough to abandon its operation.

    ``get_operation`` gates on ``exercise_operate``, which is the READ permission — everyone who
    can see a range holds it. Abandoning changes state and opens the range to destroy, so it takes
    the permission that would have let you request the operation in the first place.
    """
    from dataclasses import replace

    from secp_api.enums import Permission

    instance = deploy_ready_range(session, principal, provider)
    operation = _reset_in_flight(session, principal, instance)
    _age(session, operation, minutes=45)

    viewer = replace(principal, permissions=frozenset({Permission.exercise_operate}))
    with pytest.raises(Exception) as caught:
        ranges.abandon_operation(session, viewer, operation.id)
    assert caught.value.http_status == 403

    # The permission that starts a reset is the one that releases a stuck reset.
    resetter = replace(
        principal,
        permissions=frozenset({Permission.exercise_operate, Permission.exercise_reset}),
    )
    _, released = ranges.abandon_operation(session, resetter, operation.id)
    assert released.status is RangeOperationStatus.unproven


def test_operator_recovers_a_stranded_range_over_http_with_no_sql(session, principal, provider):
    """THE RECOVERY PATH, end to end over HTTP — the replacement for hand-written UPDATEs.

    Everything an operator needs is here: the operation reports that it is stale and why, the
    abandon endpoint releases it, the range becomes ``recovery_required``, and destroy — which was
    a 409 a moment ago — is accepted.
    """
    from fastapi.testclient import TestClient
    from secp_api.main import create_app

    instance = deploy_ready_range(session, principal, provider)
    operation = _reset_in_flight(session, principal, instance)
    operation_id = operation.id
    range_id = instance.id
    _age(session, operation, minutes=45)

    app = create_app()
    app.router.on_startup.clear()
    client = TestClient(app)

    # Before: wedged in ``resetting``, and destroy is refused BY THE STATE MACHINE — the dead end
    # from the incident. The code matters; a bare 409 would not distinguish this from any other
    # conflict.
    refused = client.post(f"/api/v1/ranges/{range_id}/destroy")
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "range_invalid_transition"

    # The operation SAYS it is stranded, without anyone reading a worker log.
    status = client.get(f"/api/v1/range-operations/{operation_id}").json()
    assert status["stale"] is True
    assert status["lease_expires_at"] is not None
    assert "never picked up" in status["stale_reason"]

    # And it is visible from the RANGE LIST, where an operator would actually look first. Without
    # this a stranded range is indistinguishable from a busy one until you open it.
    listed = next(row for row in client.get("/api/v1/ranges").json() if row["id"] == str(range_id))
    assert listed["current_operation"]["stale"] is True

    abandoned = client.post(f"/api/v1/range-operations/{operation_id}/abandon")
    assert abandoned.status_code == 200
    # ``unproven``, NOT ``failed``: nobody observed this operation fail. It stopped being
    # observable, which is a different and weaker claim.
    assert abandoned.json()["status"] == "unproven"
    assert abandoned.json()["failure_code"] == "abandoned_stale"

    recovered = client.get(f"/api/v1/ranges/{range_id}").json()
    assert recovered["state"] == "recovery_required"
    assert "no observable progress" in recovered["state_reason"]

    session.expire_all()
    assert ranges.get_range(session, principal, range_id).state is RangeState.recovery_required

    # And the way out is now open: destroy is no longer refused by the STATE MACHINE.
    #
    # It is still refused — with 403, not 409 — because these tests run the inline dispatcher, and
    # a range operation drives a real provider, which the API is never allowed to do (Charter
    # Invariants 6/7). That refusal is the architecture boundary doing its job and is unrelated to
    # the range being stranded: the transition itself is now legal. The destroy actually EXECUTING
    # from ``recovery_required`` is proved through the worker path in the two scenario-8 tests
    # below, which is the only place it can honestly be proved.
    reopened = client.post(f"/api/v1/ranges/{range_id}/destroy")
    assert reopened.status_code == 403
    assert "durable worker path" in reopened.json()["error"]["message"]
    assert reopened.json()["error"]["code"] != "range_invalid_transition"


# --- 7. resources remain enumerated ---------------------------------------------------------------


def test_abandon_retains_every_resource_and_marks_none_absent(session, principal, provider):
    """Execution disappearing is not evidence that anything was removed.

    This is the invariant a previous defect in this repo broke from the other direction: rows an
    operation failed to mention were quietly retired as removed, which narrowed the set the next
    teardown was asked about and produced a ``clean`` destroy with a container still running. So
    abandoning retires NOTHING. Resources that were observed responding drop to ``unproven`` —
    honest, since nobody is observing them any more — and stay in the range's live set.
    """
    instance = deploy_ready_range(session, principal, provider)
    before = ranges.list_resources(session, principal, instance.id)
    assert len(before) == 3
    assert all(row.state is RangeResourceState.verified for row in before)

    operation = _reset_in_flight(session, principal, instance)
    _age(session, operation, minutes=45)
    ranges.abandon_operation(session, principal, operation.id)
    session.commit()

    after = ranges.list_resources(session, principal, instance.id)
    assert {row.name for row in after} == {row.name for row in before}
    assert all(row.removed_at is None for row in after)
    assert all(row.state is RangeResourceState.unproven for row in after)
    # Nothing may claim absence: ``removed`` is writable only from a real teardown observation.
    assert not any(row.state is RangeResourceState.removed for row in after)


# --- 8. recovery destroy reaches ``clean`` only through real observations -------------------------


def test_recovery_destroy_cannot_reach_clean_when_the_probe_could_not_run(
    session, principal, provider
):
    """THE ONE THAT MUST NOT BE FAKED.

    A destroy after a recovery is the most tempting place in the system to report success: the
    range is already broken, nothing is watching, and "we tried to remove it and then saw nothing"
    reads like a clean teardown.

    It is not. The removal and the existence check share a failure mode — an unreachable Docker
    daemon makes both fail — so a probe that could not run reports "nothing found" for the SAME
    reason it removed nothing. That negative is not evidence of absence, and this repo has already
    shipped a false ``clean`` from exactly that confusion once.

    So: unreachable probe -> ``unproven`` -> ``recovery_required``. Never ``clean``, never
    ``destroyed``, and every resource stays enumerated for the next attempt.
    """
    instance = deploy_ready_range(session, principal, provider)
    operation = _reset_in_flight(session, principal, instance)
    _age(session, operation, minutes=45)
    ranges.abandon_operation(session, principal, operation.id)
    session.commit()

    # The daemon is unreachable, so the provider can neither remove nor confirm anything.
    provider.teardown = TeardownResult(
        probe_reachable=False,
        observations=(),
        reason="the docker daemon could not be reached, so nothing was proved absent",
    )
    _, destroy_op = ranges.start_operation(
        session, principal, instance.id, RangeOperationKind.destroy
    )
    session.commit()
    execute_range_operation(session, destroy_op.id)
    session.expire_all()

    instance = session.get(RangeInstance, instance.id)
    assert instance.state is RangeState.recovery_required
    assert instance.state is not RangeState.destroyed
    assert instance.residue_verdict is ResidueVerdict.unproven
    assert session.get(RangeDeploymentOperation, destroy_op.id).status is (
        RangeOperationStatus.unproven
    )

    # Still enumerated. A range whose teardown could not be observed still owns everything it
    # created, and the next destroy must be asked about all of it.
    survivors = ranges.list_resources(session, principal, instance.id)
    assert len(survivors) == 3
    assert all(row.removed_at is None for row in survivors)

    evidence = ranges.list_teardown_evidence(session, principal, instance.id)
    assert evidence[0].verdict is ResidueVerdict.unproven
    assert evidence[0].probe_reachable is False


def test_a_teardown_that_says_nothing_about_a_resource_cannot_report_clean(
    session, principal, provider
):
    """The OTHER way to fake a clean teardown: answer only about some of the set.

    A reachable probe that returns no observation for a resource has not proved that resource
    absent — it declined to look. Counting only what the provider chose to mention would score
    zero-present, zero-unproven and fall through to ``clean``.

    This is the same silent narrowing that once produced a ``clean`` destroy with a container and a
    network still running, arriving from the provider side instead of the row side. The abandon
    path retains every row so the recovery destroy is asked about all of them; that retention is
    worth nothing if the answer may quietly omit them.
    """
    instance = deploy_ready_range(session, principal, provider)
    operation = _reset_in_flight(session, principal, instance)
    _age(session, operation, minutes=45)
    ranges.abandon_operation(session, principal, operation.id)
    session.commit()

    live = ranges.list_resources(session, principal, instance.id)
    assert len(live) == 3
    spoken_for = live[0]

    # Reachable, confident, and quiet about two of the three resources.
    provider.teardown = TeardownResult(
        probe_reachable=True,
        observations=(
            TeardownObservation(
                kind=spoken_for.kind,
                name=spoken_for.name,
                external_id=spoken_for.external_id,
                outcome=TeardownResourceOutcome.removed,
                detail="confirmed absent",
            ),
        ),
    )
    _, destroy_op = ranges.start_operation(
        session, principal, instance.id, RangeOperationKind.destroy
    )
    session.commit()
    execute_range_operation(session, destroy_op.id)
    session.expire_all()

    instance = session.get(RangeInstance, instance.id)
    assert instance.residue_verdict is ResidueVerdict.unproven
    assert instance.state is RangeState.recovery_required
    assert instance.state is not RangeState.destroyed

    # The two it declined to answer for are unproven and still live; only the one it actually
    # proved absent is removed.
    by_name = {row.name: row for row in ranges.list_resources(session, principal, instance.id)}
    assert by_name[spoken_for.name].state is RangeResourceState.removed
    silent = [row for name, row in by_name.items() if name != spoken_for.name]
    assert len(silent) == 2
    assert all(row.state is RangeResourceState.unproven for row in silent)
    assert all(row.removed_at is None for row in silent)

    evidence = ranges.list_teardown_evidence(session, principal, instance.id)[0]
    assert evidence.unproven_count == 2
    assert "said nothing about 2 owned resource(s)" in evidence.reason


def test_recovery_destroy_reaches_clean_only_after_proving_each_resource_absent(
    session, principal, provider
):
    """The positive half: a WORKING probe that confirms each resource gone does reach ``clean``.

    Without this, the test above is satisfiable by a system that can never report success at all.
    Both halves together say what is actually required — ``clean`` follows an observation, and
    only an observation.

    It also pins the set: the destroy is asked about all three resources the abandoned range still
    owned, because abandoning retired none of them.
    """
    instance = deploy_ready_range(session, principal, provider)
    operation = _reset_in_flight(session, principal, instance)
    _age(session, operation, minutes=45)
    ranges.abandon_operation(session, principal, operation.id)
    session.commit()

    _, destroy_op = ranges.start_operation(
        session, principal, instance.id, RangeOperationKind.destroy
    )
    session.commit()
    execute_range_operation(session, destroy_op.id)
    session.expire_all()

    # The provider was handed the COMPLETE set the range ever created — nothing was lost to the
    # abandoned reset.
    assert len(provider.destroy_calls) == 1
    assert len(provider.destroy_calls[0][1]) == 3

    instance = session.get(RangeInstance, instance.id)
    assert instance.state is RangeState.destroyed
    assert instance.residue_verdict is ResidueVerdict.clean
    assert session.get(RangeDeploymentOperation, destroy_op.id).status is (
        RangeOperationStatus.succeeded
    )
    resources = ranges.list_resources(session, principal, instance.id)
    assert len(resources) == 3
    assert all(row.state is RangeResourceState.removed for row in resources)
    assert all(row.removed_at is not None for row in resources)
