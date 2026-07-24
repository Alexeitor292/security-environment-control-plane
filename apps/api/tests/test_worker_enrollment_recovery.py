"""Restart/crash recovery for durable worker enrollment (SECP-PR5H-A, ADR-027, Commit 5).

Portable (SQLite) coverage of the expiry sweep and crash/lost-response recovery. Fresh-process
safety is exercised by constructing a NEW service call on a NEW session for every recovery step
(nothing depends on process memory). The eight crash points of the transactional commit are injected
by monkeypatching each named stage of ``commit_transition`` to raise, and a SEPARATE verifying
session proves a pre-commit failure leaves no partial state / history / receipt / nonce. Concurrency
one-winner is proven on real PostgreSQL in the postgres-gated module.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from secp_api import worker_enrollment_contract as contract
from secp_api import worker_enrollment_repository as repo
from secp_api.auth import Principal
from secp_api.enums import Permission
from secp_api.errors import WorkerEnrollmentError
from secp_api.models import Base
from secp_api.seed import bootstrap_dev
from secp_api.services import worker_enrollment as svc
from secp_api.services import worker_enrollment_recovery as rec
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

CTRL_HEX = (b"\x11" * 32).hex()
CTRL_KEY = contract.sha256_digest_of_hex(CTRL_HEX)
WORKER_HEX = (b"\x22" * 32).hex()
WORKER_KEY = contract.sha256_digest_of_hex(WORKER_HEX)
RELEASE = "sha256:" + "a" * 64
OFFER_D = "sha256:" + "c" * 64
RESULT_D = "sha256:" + "d" * 64
TXN = "txn-0001"
CREATED = "2026-07-21T00:00:00Z"
EXPIRES = "2026-07-21T01:00:00Z"
NOW = "2026-07-21T00:10:00Z"
AFTER = "2026-07-21T02:00:00Z"
SITE = "rack-01.eu_a"


def _invitation(nonce: str, **over: object) -> contract.WorkerEnrollmentInvitation:
    kw: dict = dict(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_trust_anchor_hex=CTRL_HEX,
        controller_origin="https://ctrl.example.com",
        release_digest=RELEASE,
        transaction_id=TXN,
        nonce=nonce,
        created_at=CREATED,
        expires_at=EXPIRES,
    )
    kw.update(over)
    return contract.create_invitation(**kw)


def _expected(state: contract.EnrollmentState) -> svc.ExpectedRevision:
    return svc.ExpectedRevision(
        revision=state.revision,
        state_digest=state.digest(),
        sequence=state.sequence,
        predecessor_digest=state.predecessor_digest,
    )


@pytest.fixture
def factory():
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE alembic_version (version_num varchar(32) primary key)")
        conn.exec_driver_sql("INSERT INTO alembic_version VALUES ('b6e2f4a9c1d7')")
    yield sessionmaker(bind=engine, future=True)
    engine.dispose()


@pytest.fixture
def actor(factory) -> Principal:
    with factory() as s:
        p = bootstrap_dev(s)
        s.commit()
        return Principal(
            user_id=p.user_id,
            organization_id=p.organization_id,
            email=p.email,
            permissions=frozenset(Permission),
        )


def _open(factory, actor, *, nonce: str = "sha256:" + "b" * 64, site: str = SITE, **inv):
    with factory() as s:
        out = svc.create_invitation_and_open(
            s,
            actor,
            invitation=_invitation(nonce, **inv),
            invitation_created_at=CREATED,
            deployment_site_label=site,
            now=NOW,
        )
        s.commit()
        return out.state


def _bind(factory, actor, state):
    with factory() as s:
        out = svc.bind_worker(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            worker_installation_id="worker-bbbbbbbb",
            worker_key_id=WORKER_KEY,
            transaction_id=TXN,
            now=NOW,
            expected=_expected(state),
        )
        s.commit()
        return out.state


def _drive_to_healthy(factory, actor, state):
    state = _bind(factory, actor, state)
    with factory() as s:
        state = svc.record_offer(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            facts=contract.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY),
            now=NOW,
            expected=_expected(state),
        ).state
        s.commit()
    with factory() as s:
        state = svc.record_result(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            facts=contract.HandoffFacts("worker-result", RESULT_D, TXN, WORKER_KEY),
            now=NOW,
            expected=_expected(state),
        ).state
        s.commit()
    with factory() as s:
        state = svc.verify_release(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            release_digest=RELEASE,
            now=NOW,
            expected=_expected(state),
        ).state
        s.commit()
    with factory() as s:
        state = svc.mark_enrollment_healthy(
            s, actor, enrollment_id=state.enrollment_id, now=NOW, expected=_expected(state)
        ).state
        s.commit()
    return state


def _view(factory, actor, enrollment_id):
    with factory() as s:
        return svc.load_public_view(s, actor, enrollment_id=enrollment_id)


def _count(factory, table, enrollment_id):
    with factory() as s:
        return s.execute(
            text(f"SELECT count(*) FROM {table} WHERE enrollment_id=:e"), {"e": enrollment_id}
        ).scalar_one()


# --- expiry sweep -------------------------------------------------------------------------------


def test_sweep_recovers_a_due_active_enrollment_via_a_fresh_service(factory, actor):
    state = _open(factory, actor)
    # a fresh sweep (its own sessions) recovers the due active row to recovery_required
    result = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    assert (result.examined, result.recovered) == (1, 1)
    view = _view(factory, actor, state.enrollment_id)
    assert view["state"] == "recovery_required"
    assert view["refusal_reason"] == rec.SWEEP_REASON
    # history appended (rev 0 + rev 1), not rewritten
    assert _count(factory, "worker_enrollment_revision", state.enrollment_id) == 2


def test_sweep_is_idempotent_across_repeated_passes(factory, actor):
    state = _open(factory, actor)
    first = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    assert first.recovered == 1
    second = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    # already recovery_required -> not an active candidate -> examined 0, no new revision
    assert (second.examined, second.recovered) == (0, 0)
    assert _count(factory, "worker_enrollment_revision", state.enrollment_id) == 2


def test_sweep_does_not_touch_not_yet_due_rows(factory, actor):
    state = _open(factory, actor)
    result = rec.recover_expired(factory, organization_id=actor.organization_id, now=NOW)
    assert (result.examined, result.recovered) == (0, 0)
    assert _view(factory, actor, state.enrollment_id)["state"] == "invited"


def test_sweep_never_touches_healthy_or_terminal_rows(factory, actor):
    healthy = _drive_to_healthy(factory, actor, _open(factory, actor, nonce="sha256:" + "1" * 64))
    # a refused enrollment (terminal)
    refused = _open(factory, actor, nonce="sha256:" + "2" * 64, transaction_id="txn-ref")
    with factory() as s:
        svc.refuse_enrollment(
            s,
            actor,
            enrollment_id=refused.enrollment_id,
            reason="operator_refusal",
            expected=_expected(refused),
        )
        s.commit()
    result = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    assert result.recovered == 0  # neither healthy nor refused is active
    assert _view(factory, actor, healthy.enrollment_id)["state"] == "healthy"
    assert _view(factory, actor, refused.enrollment_id)["state"] == "refused"


def test_sweep_skips_a_revoked_invitation(factory, actor):
    state = _open(factory, actor)
    with factory() as s:
        s.execute(
            text(
                "UPDATE worker_enrollment_invitation SET revoked=1, revoked_at=:t"
                " WHERE enrollment_id=:e"
            ),
            {"t": "2026-07-21T00:05:00+00:00", "e": state.enrollment_id},
        )
        s.commit()
    result = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    # excluded in SQL, not merely examined-and-skipped: revocation is an ordinary operator action,
    # so such rows must never accumulate at the head of the ordered window and starve the sweep
    assert (result.examined, result.recovered) == (0, 0)
    assert _view(factory, actor, state.enrollment_id)["state"] == "invited"


def test_sweep_is_scoped_to_one_organization(factory, actor):
    from secp_api.models import Organization

    state = _open(factory, actor)
    with factory() as s:
        org2 = Organization(name="second-org", slug="second-org")
        s.add(org2)
        s.flush()
        other_org = org2.id
        s.commit()
    # a sweep for the OTHER org must not touch this org's due row
    result = rec.recover_expired(factory, organization_id=other_org, now=AFTER)
    assert (result.examined, result.recovered) == (0, 0)
    assert _view(factory, actor, state.enrollment_id)["state"] == "invited"


def test_sweep_preserves_a_corrupt_row_and_reports_it(factory, actor):
    state = _open(factory, actor)
    # corrupt the state digest so rehydration refuses; the row must be preserved, not recovered
    with factory() as s:
        s.execute(
            text("UPDATE worker_enrollment_state SET state_digest=:d WHERE enrollment_id=:e"),
            {"d": "sha256:" + "0" * 64, "e": state.enrollment_id},
        )
        s.commit()
    result = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    assert (result.recovered, result.corrupt) == (0, 1)
    # the row is preserved exactly as corrupted (still invited, still the forged digest)
    with factory() as s:
        row = s.execute(
            text("SELECT state, state_digest FROM worker_enrollment_state WHERE enrollment_id=:e"),
            {"e": state.enrollment_id},
        ).one()
    assert row.state == "invited" and row.state_digest == "sha256:" + "0" * 64


def test_every_examined_candidate_lands_in_exactly_one_category(factory, actor):
    """The aggregate report must account for every candidate exactly once — no silent drops."""
    _open(factory, actor, nonce="sha256:" + "a" * 64, transaction_id="txn-a")
    bad = _open(factory, actor, nonce="sha256:" + "b" * 64, transaction_id="txn-b")
    revoked = _open(factory, actor, nonce="sha256:" + "c" * 64, transaction_id="txn-c")
    with factory() as s:
        s.execute(
            text("UPDATE worker_enrollment_state SET state_digest=:d WHERE enrollment_id=:e"),
            {"d": "sha256:" + "0" * 64, "e": bad.enrollment_id},
        )
        s.execute(
            text(
                "UPDATE worker_enrollment_invitation SET revoked=1, revoked_at=:t"
                " WHERE enrollment_id=:e"
            ),
            {"t": "2026-07-21T00:05:00+00:00", "e": revoked.enrollment_id},
        )
        s.commit()
    result = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    # the revoked row is excluded in SQL, so only the good + corrupt rows are examined
    assert result.examined == 2
    assert result.total == result.examined
    assert (result.recovered, result.corrupt, result.skipped) == (1, 1, 0)


def test_sweep_makes_forward_progress_past_permanently_unrecoverable_rows(factory, actor):
    """Regression: a corrupt row is preserved forever, so without a keyset cursor it would sit at
    the head of every ordered window and starve every valid due enrollment behind it."""
    # two corrupt rows that sort FIRST (earlier expiry), then a perfectly valid due enrollment
    blocked = []
    for i in (1, 2):
        st = _open(
            factory,
            actor,
            nonce="sha256:" + f"{i:064x}",
            transaction_id=f"txn-{i}",
            expires_at="2026-07-21T00:30:00Z",
        )
        blocked.append(st)
    victim = _open(
        factory,
        actor,
        nonce="sha256:" + f"{9:064x}",
        transaction_id="txn-9",
        expires_at="2026-07-21T00:50:00Z",
    )
    with factory() as s:
        for st in blocked:
            s.execute(
                text("UPDATE worker_enrollment_state SET state_digest=:d WHERE enrollment_id=:e"),
                {"d": "sha256:" + "0" * 64, "e": st.enrollment_id},
            )
        s.commit()

    # a single bounded pass sees only the two poisoned rows and recovers nothing...
    first = rec.recover_expired(
        factory, organization_id=actor.organization_id, now=AFTER, batch_size=2
    )
    assert (first.examined, first.recovered, first.corrupt) == (2, 0, 2)
    assert first.next_cursor is not None  # a full window: more may lie behind it
    # ...and following the cursor advances past them to the valid row
    second = rec.recover_expired(
        factory,
        organization_id=actor.organization_id,
        now=AFTER,
        batch_size=2,
        after=first.next_cursor,
    )
    assert second.recovered == 1
    assert _view(factory, actor, victim.enrollment_id)["state"] == "recovery_required"


def test_drain_walks_the_cursor_and_is_bounded(factory, actor):
    """``drain_expired`` follows the cursor so the queue drains, within a code-owned cap."""
    blocked = []
    for i in (1, 2):
        st = _open(
            factory,
            actor,
            nonce="sha256:" + f"{i:064x}",
            transaction_id=f"txn-{i}",
            expires_at="2026-07-21T00:30:00Z",
        )
        blocked.append(st)
    victim = _open(
        factory,
        actor,
        nonce="sha256:" + f"{9:064x}",
        transaction_id="txn-9",
        expires_at="2026-07-21T00:50:00Z",
    )
    with factory() as s:
        for st in blocked:
            s.execute(
                text("UPDATE worker_enrollment_state SET state_digest=:d WHERE enrollment_id=:e"),
                {"d": "sha256:" + "0" * 64, "e": st.enrollment_id},
            )
        s.commit()
    drained = rec.drain_expired(
        factory, organization_id=actor.organization_id, now=AFTER, batch_size=2
    )
    assert drained.recovered == 1 and drained.corrupt == 2
    assert drained.total == drained.examined
    assert _view(factory, actor, victim.enrollment_id)["state"] == "recovery_required"


def test_an_unexpected_error_is_reported_as_failed_not_corrupt(factory, actor, monkeypatch):
    """Truthful categories: an unexpected error is NOT evidence of row corruption."""
    _open(factory, actor)

    def _boom(*_a, **_k):
        raise RuntimeError("transient infrastructure fault")

    monkeypatch.setattr(repo, "verify_history_consistent", _boom)
    result = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    assert (result.failed, result.corrupt, result.recovered) == (1, 0, 0)
    assert result.total == result.examined


def test_one_poisoned_row_does_not_mark_valid_rows_recovered(factory, actor):
    good = _open(factory, actor, nonce="sha256:" + "a" * 64, transaction_id="txn-good")
    bad = _open(factory, actor, nonce="sha256:" + "b" * 64, transaction_id="txn-bad")
    with factory() as s:
        s.execute(
            text("UPDATE worker_enrollment_state SET state_digest=:d WHERE enrollment_id=:e"),
            {"d": "sha256:" + "0" * 64, "e": bad.enrollment_id},
        )
        s.commit()
    result = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    assert result.recovered == 1 and result.corrupt == 1
    assert _view(factory, actor, good.enrollment_id)["state"] == "recovery_required"


def test_sweep_batch_size_is_bounded(factory, actor):
    for i in range(5):
        _open(factory, actor, nonce="sha256:" + f"{i:064x}"[:64], transaction_id=f"txn-{i}")
    result = rec.recover_expired(
        factory, organization_id=actor.organization_id, now=AFTER, batch_size=2
    )
    assert result.examined == 2  # never more than the bounded batch
    # a caller-supplied batch above the code-owned cap is clamped, not honored
    big = rec.recover_expired(
        factory, organization_id=actor.organization_id, now=AFTER, batch_size=10_000
    )
    assert big.examined <= rec.DEFAULT_SWEEP_BATCH


def test_sweep_refuses_when_schema_not_ready(factory, actor):
    _open(factory, actor)
    with factory() as s:
        s.execute(text("UPDATE alembic_version SET version_num='d8f1a2b3c4e5'"))
        s.commit()
    with pytest.raises(WorkerEnrollmentError) as ei:
        rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    assert ei.value.code == "enrollment_schema_unavailable"


# --- lost-response recovery (fresh process) ------------------------------------------------------


def test_exact_retry_after_restart_recovers_via_receipt(factory, actor):
    """A committed bind whose response was lost: an exact retry on a FRESH service/session returns
    the committed revision without a second history row or re-consuming the nonce."""
    state = _open(factory, actor)
    _bind(factory, actor, state)  # committed
    before_hist = _count(factory, "worker_enrollment_revision", state.enrollment_id)
    # fresh session + fresh service call, exact same bind, using the ORIGINAL expected token
    with factory() as s:
        out = svc.bind_worker(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            worker_installation_id="worker-bbbbbbbb",
            worker_key_id=WORKER_KEY,
            transaction_id=TXN,
            now=NOW,
            expected=_expected(state),
        )
        s.commit()
    assert out.deduplicated and out.committed_revision == 1
    assert _count(factory, "worker_enrollment_revision", state.enrollment_id) == before_hist
    # nonce consumed exactly once
    with factory() as s:
        consumed = s.execute(
            text(
                "SELECT count(*) FROM worker_enrollment_invitation"
                " WHERE consumed=1 AND enrollment_id=:e"
            ),
            {"e": state.enrollment_id},
        ).scalar_one()
    assert consumed == 1


def _retry_step(factory, actor, step: str, prior_state, current_state):
    """Replay ``step`` exactly, from a FRESH session, using the token the client first sent
    (``prior_state`` == the state before the step committed). Returns the outcome."""
    with factory() as s:
        expected = _expected(prior_state)
        if step == "record_controller_offer":
            out = svc.record_offer(
                s,
                actor,
                enrollment_id=current_state.enrollment_id,
                facts=contract.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY),
                now=NOW,
                expected=expected,
            )
        elif step == "record_worker_result":
            out = svc.record_result(
                s,
                actor,
                enrollment_id=current_state.enrollment_id,
                facts=contract.HandoffFacts("worker-result", RESULT_D, TXN, WORKER_KEY),
                now=NOW,
                expected=expected,
            )
        elif step == "mark_verified":
            out = svc.verify_release(
                s,
                actor,
                enrollment_id=current_state.enrollment_id,
                release_digest=RELEASE,
                now=NOW,
                expected=expected,
            )
        else:
            out = svc.mark_enrollment_healthy(
                s, actor, enrollment_id=current_state.enrollment_id, now=NOW, expected=expected
            )
        s.commit()
        return out


@pytest.mark.parametrize(
    "step",
    ["record_controller_offer", "record_worker_result", "mark_verified", "mark_healthy"],
)
def test_exact_retry_of_each_step_after_restart_is_idempotent(factory, actor, step):
    """For every worker step: commit it, then a fresh-session exact retry (with the stale token the
    client first sent) recovers the committed revision with NO new history row."""
    prior = _open(factory, actor)
    prior = _bind(factory, actor, prior)  # -> worker_bound (rev 1), the base for the offer step

    # advance to just before ``step``, remembering the pre-step state (the token first sent)
    if step in ("record_worker_result", "mark_verified", "mark_healthy"):
        with factory() as s:
            current = svc.record_offer(
                s,
                actor,
                enrollment_id=prior.enrollment_id,
                facts=contract.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY),
                now=NOW,
                expected=_expected(prior),
            ).state
            s.commit()
        prior = current
    if step in ("mark_verified", "mark_healthy"):
        with factory() as s:
            current = svc.record_result(
                s,
                actor,
                enrollment_id=prior.enrollment_id,
                facts=contract.HandoffFacts("worker-result", RESULT_D, TXN, WORKER_KEY),
                now=NOW,
                expected=_expected(prior),
            ).state
            s.commit()
        prior = current
    if step == "mark_healthy":
        with factory() as s:
            current = svc.verify_release(
                s,
                actor,
                enrollment_id=prior.enrollment_id,
                release_digest=RELEASE,
                now=NOW,
                expected=_expected(prior),
            ).state
            s.commit()
        prior = current

    # commit ``step`` once
    committed = _retry_step(factory, actor, step, prior, prior)
    assert committed.deduplicated is False
    hist = _count(factory, "worker_enrollment_revision", prior.enrollment_id)

    # a fresh-session exact retry (same stale token) is a dedup no-op
    retried = _retry_step(factory, actor, step, prior, prior)
    assert retried.deduplicated is True
    assert retried.committed_revision == committed.committed_revision
    assert _count(factory, "worker_enrollment_revision", prior.enrollment_id) == hist


# --- crash-point atomicity (8 injection points) --------------------------------------------------


def _bind_call(session, actor, state):
    return svc.bind_worker(
        session,
        actor,
        enrollment_id=state.enrollment_id,
        worker_installation_id="worker-bbbbbbbb",
        worker_key_id=WORKER_KEY,
        transaction_id=TXN,
        now=NOW,
        expected=_expected(state),
    )


def _assert_no_partial_bind(factory, actor, state):
    """After a rolled-back bind: still INVITED at rev 0, nonce unconsumed, one history row, no
    receipts, no worker identity. Read via RAW SQL so the check never routes through a function a
    crash-point test may have monkeypatched."""
    with factory() as s:
        row = s.execute(
            text(
                "SELECT state, revision, worker_key_id FROM worker_enrollment_state"
                " WHERE enrollment_id=:e"
            ),
            {"e": state.enrollment_id},
        ).one()
        consumed = s.execute(
            text("SELECT consumed FROM worker_enrollment_invitation WHERE enrollment_id=:e"),
            {"e": state.enrollment_id},
        ).scalar_one()
    assert row.state == "invited"
    assert row.revision == 0
    assert row.worker_key_id == ""
    assert not consumed
    assert _count(factory, "worker_enrollment_revision", state.enrollment_id) == 1
    assert _count(factory, "worker_enrollment_step_receipt", state.enrollment_id) == 0


class _Boom(RuntimeError):
    pass


@pytest.mark.parametrize(
    "crash_point",
    [
        "before_lock",
        "after_load",
        "after_history_validation",
        "after_transition_before_history_insert",
        "after_history_insert_before_cas",
        "after_cas_before_receipt",
        "after_receipt_before_commit",
    ],
)
def test_precommit_crash_rolls_back_all_effects(factory, actor, monkeypatch, crash_point):
    """Every PRE-commit crash point leaves no partial state/history/receipt/nonce. Each stage of the
    transactional bind is made to raise; a fresh verifying session proves the rollback is total."""
    state = _open(factory, actor)

    real_load = repo.load_for_update
    real_verify = repo.verify_history_consistent
    real_append = repo._append_history
    real_cas = repo._cas_head
    real_receipt = repo._write_step_receipt

    if crash_point == "before_lock":
        monkeypatch.setattr(repo, "load_for_update", lambda *a, **k: (_ for _ in ()).throw(_Boom()))
    elif crash_point == "after_load":

        def _load_then_boom(session, enrollment_id):
            real_load(session, enrollment_id)
            raise _Boom()

        monkeypatch.setattr(repo, "load_for_update", _load_then_boom)
    elif crash_point == "after_history_validation":

        def _verify_then_boom(session, enrollment_id, s):
            real_verify(session, enrollment_id, s)
            raise _Boom()

        monkeypatch.setattr(repo, "verify_history_consistent", _verify_then_boom)
    elif crash_point == "after_transition_before_history_insert":
        monkeypatch.setattr(repo, "_append_history", lambda *a, **k: (_ for _ in ()).throw(_Boom()))
    elif crash_point == "after_history_insert_before_cas":

        def _append_then_boom(session, new_state):
            real_append(session, new_state)
            raise _Boom()

        monkeypatch.setattr(repo, "_append_history", _append_then_boom)
    elif crash_point == "after_cas_before_receipt":

        def _cas_then_boom(session, enrollment_id, prior, new_state):
            real_cas(session, enrollment_id, prior, new_state)
            raise _Boom()

        monkeypatch.setattr(repo, "_cas_head", _cas_then_boom)
    elif crash_point == "after_receipt_before_commit":

        def _receipt_then_boom(session, enrollment_id, step, input_digest, new_state):
            real_receipt(session, enrollment_id, step, input_digest, new_state)
            raise _Boom()

        monkeypatch.setattr(repo, "_write_step_receipt", _receipt_then_boom)

    with factory() as s:
        with pytest.raises((_Boom, WorkerEnrollmentError)):
            _bind_call(s, actor, state)
        s.rollback()

    _assert_no_partial_bind(factory, actor, state)


def test_postcommit_lost_response_recovers_idempotently(factory, actor):
    """The 8th crash point: the transaction COMMITTED but the response was lost before returning.
    A fresh-session exact retry recovers to the committed revision with no repeated effects."""
    state = _open(factory, actor)
    # commit the bind, then simulate the response being lost (we simply discard the return value)
    with factory() as s:
        _bind_call(s, actor, state)
        s.commit()  # committed; "response lost" here
    hist_after_commit = _count(factory, "worker_enrollment_revision", state.enrollment_id)
    # fresh service/session retries the exact same request
    with factory() as s:
        out = svc.bind_worker(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            worker_installation_id="worker-bbbbbbbb",
            worker_key_id=WORKER_KEY,
            transaction_id=TXN,
            now=NOW,
            expected=_expected(state),
        )
        s.commit()
    assert out.deduplicated and out.committed_revision == 1
    assert _count(factory, "worker_enrollment_revision", state.enrollment_id) == hist_after_commit


# --- lifecycle lost-response recovery (revision-history exact retry, no step receipt) ------------
#
# refuse()/require_recovery() are internal LIFECYCLE transitions: they carry no worker step receipt
# (that ledger is at-least-once dedup for the five externally delivered worker protocol steps).
# Their durable outcome record is the append-only revision-history row, and an exact retry is
# recognised from it under strictly bounded conditions.


def _lifecycle_call(factory, actor, kind, state, reason):
    with factory() as s:
        fn = svc.recover_enrollment if kind == "recover" else svc.refuse_enrollment
        out = fn(
            s, actor, enrollment_id=state.enrollment_id, reason=reason, expected=_expected(state)
        )
        s.commit()
        return out


@pytest.mark.parametrize(
    ("kind", "terminal"), [("recover", "recovery_required"), ("refuse", "refused")]
)
def test_lifecycle_lost_response_exact_retry_is_deduplicated(factory, actor, kind, terminal):
    state = _open(factory, actor)
    committed = _lifecycle_call(factory, actor, kind, state, "operator_action")
    assert committed.deduplicated is False and committed.committed_revision == 1
    assert _view(factory, actor, state.enrollment_id)["state"] == terminal
    hist = _count(factory, "worker_enrollment_revision", state.enrollment_id)

    # response lost -> fresh session, same request, same now-stale token
    retried = _lifecycle_call(factory, actor, kind, state, "operator_action")
    assert retried.deduplicated is True
    assert retried.committed_revision == committed.committed_revision
    assert _count(factory, "worker_enrollment_revision", state.enrollment_id) == hist


@pytest.mark.parametrize("kind", ["recover", "refuse"])
def test_a_different_reason_is_not_an_exact_lifecycle_retry(factory, actor, kind):
    state = _open(factory, actor)
    _lifecycle_call(factory, actor, kind, state, "operator_action")
    with pytest.raises(WorkerEnrollmentError) as ei:
        _lifecycle_call(factory, actor, kind, state, "a_different_reason")
    assert ei.value.code == "enrollment_revision_conflict"


def test_a_different_terminal_target_is_not_an_exact_lifecycle_retry(factory, actor):
    state = _open(factory, actor)
    _lifecycle_call(factory, actor, "refuse", state, "operator_action")  # -> refused
    # the SAME reason and token, but asking for the other terminal, is not this operation's retry
    with pytest.raises(WorkerEnrollmentError) as ei:
        _lifecycle_call(factory, actor, "recover", state, "operator_action")
    assert ei.value.code == "enrollment_revision_conflict"


def test_a_token_older_than_the_immediate_predecessor_refuses(factory, actor):
    state = _open(factory, actor)  # rev 0
    bound = _bind(factory, actor, state)  # rev 1
    _lifecycle_call(factory, actor, "recover", bound, "operator_action")  # rev 2
    # a token from rev 0 is NOT the immediate predecessor of rev 2
    with pytest.raises(WorkerEnrollmentError) as ei:
        _lifecycle_call(factory, actor, "recover", state, "operator_action")
    assert ei.value.code == "enrollment_revision_conflict"


def test_a_later_revision_prevents_serving_an_old_lifecycle_request_as_a_retry(factory, actor):
    state = _open(factory, actor)  # rev 0
    refused = _lifecycle_call(factory, actor, "refuse", state, "operator_action").state  # rev 1
    # refused -> recovery_required is a live edge, so a later revision can exist
    _lifecycle_call(factory, actor, "recover", refused, "operator_action")  # rev 2
    # the ORIGINAL refuse request must no longer be served as a retry (head is no longer its result)
    with pytest.raises(WorkerEnrollmentError) as ei:
        _lifecycle_call(factory, actor, "refuse", state, "operator_action")
    assert ei.value.code == "enrollment_revision_conflict"


def test_a_missing_predecessor_history_row_refuses(factory, actor):
    state = _open(factory, actor)
    _lifecycle_call(factory, actor, "recover", state, "operator_action")  # rev 1
    with factory() as s:
        s.execute(
            text("DELETE FROM worker_enrollment_revision WHERE enrollment_id=:e AND revision=0"),
            {"e": state.enrollment_id},
        )
        s.commit()
    with pytest.raises(WorkerEnrollmentError) as ei:
        _lifecycle_call(factory, actor, "recover", state, "operator_action")
    # the broken chain is caught by history verification before any retry can be served
    assert ei.value.code == "enrollment_history_inconsistent"


def test_a_corrupted_predecessor_history_row_refuses(factory, actor):
    state = _open(factory, actor)
    _lifecycle_call(factory, actor, "recover", state, "operator_action")  # rev 1
    with factory() as s:
        s.execute(
            text(
                "UPDATE worker_enrollment_revision SET state_digest=:d"
                " WHERE enrollment_id=:e AND revision=0"
            ),
            {"d": "sha256:" + "0" * 64, "e": state.enrollment_id},
        )
        s.commit()
    with pytest.raises(WorkerEnrollmentError) as ei:
        _lifecycle_call(factory, actor, "recover", state, "operator_action")
    assert ei.value.code == "enrollment_history_inconsistent"


def test_being_terminal_alone_does_not_make_a_request_a_retry(factory, actor):
    """A row that reached the terminal by the SWEEP (a different reason) must not satisfy an
    operator's lifecycle request just because the state matches."""
    state = _open(factory, actor)
    rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    assert _view(factory, actor, state.enrollment_id)["refusal_reason"] == rec.SWEEP_REASON
    with pytest.raises(WorkerEnrollmentError) as ei:
        _lifecycle_call(factory, actor, "recover", state, "operator_action")
    assert ei.value.code == "enrollment_revision_conflict"


# --- explicit final property confirmations (Commit 5 acceptance) ---------------------------------


def test_cursor_ordering_and_strict_greater_than_semantics(factory, actor):
    """Keyset pagination is exactly (expires_at_ts, enrollment_id), strictly greater-than, and the
    cursor advances from the LAST EXAMINED row (not the last successfully transitioned one)."""
    early = _open(
        factory,
        actor,
        nonce="sha256:" + f"{1:064x}",
        transaction_id="txn-1",
        expires_at="2026-07-21T00:30:00Z",
    )
    late = _open(
        factory,
        actor,
        nonce="sha256:" + f"{2:064x}",
        transaction_id="txn-2",
        expires_at="2026-07-21T00:50:00Z",
    )
    # corrupt the FIRST row so it is examined but never transitioned; the cursor must still advance
    with factory() as s:
        s.execute(
            text("UPDATE worker_enrollment_state SET state_digest=:d WHERE enrollment_id=:e"),
            {"d": "sha256:" + "0" * 64, "e": early.enrollment_id},
        )
        s.commit()
    first = rec.recover_expired(
        factory, organization_id=actor.organization_id, now=AFTER, batch_size=1
    )
    assert (first.examined, first.recovered, first.corrupt) == (1, 0, 1)
    assert first.next_cursor is not None
    # the cursor names the examined (corrupt) row, ordered by (expires_at_ts, enrollment_id)
    cursor_ts, cursor_id = first.next_cursor
    assert cursor_id == early.enrollment_id
    assert repo.parse_canonical_utc(early.expires_at) == repo._as_utc(cursor_ts)
    # strictly greater-than: the same cursor never re-returns its own row
    second = rec.recover_expired(
        factory,
        organization_id=actor.organization_id,
        now=AFTER,
        batch_size=1,
        after=first.next_cursor,
    )
    assert second.recovered == 1
    assert _view(factory, actor, late.enrollment_id)["state"] == "recovery_required"


def test_batch_and_pass_caps_are_code_owned_and_cannot_be_raised_by_a_caller(factory, actor):
    for i in range(3):
        _open(
            factory,
            actor,
            nonce="sha256:" + f"{i:064x}",
            transaction_id=f"txn-{i}",
            expires_at="2026-07-21T00:30:00Z",
        )
    # a caller asking for a huge batch is clamped to the code-owned cap, never raised
    result = rec.recover_expired(
        factory, organization_id=actor.organization_id, now=AFTER, batch_size=10**9
    )
    assert result.examined <= rec.DEFAULT_SWEEP_BATCH
    drained = rec.drain_expired(
        factory, organization_id=actor.organization_id, now=AFTER, batch_size=1, max_passes=10**9
    )
    assert drained.total == drained.examined
    assert drained.examined <= rec.DEFAULT_SWEEP_BATCH * rec.DEFAULT_MAX_PASSES


@pytest.mark.parametrize(
    "tamper",
    ["state_text", "state_shadow", "invitation_shadow"],
)
def test_all_three_expiry_representations_are_anchored(factory, actor, tamper):
    """canonical state expires_at == invitation expires_at, and both shadow columns are that same
    UTC instant. Tampering ANY one of the three refuses closed."""
    state = _open(factory, actor)
    with factory() as s:
        if tamper == "state_text":
            forged = replace(state, expires_at="2099-01-01T00:00:00Z")
            s.execute(
                text(
                    "UPDATE worker_enrollment_state SET expires_at=:x, expires_at_ts=:xt,"
                    " state_digest=:d WHERE enrollment_id=:e"
                ),
                {
                    "x": "2099-01-01T00:00:00Z",
                    "xt": "2099-01-01T00:00:00+00:00",
                    "d": forged.digest(),
                    "e": state.enrollment_id,
                },
            )
            s.execute(
                text(
                    "UPDATE worker_enrollment_revision SET state_digest=:d"
                    " WHERE enrollment_id=:e AND revision=0"
                ),
                {"d": forged.digest(), "e": state.enrollment_id},
            )
        elif tamper == "state_shadow":
            s.execute(
                text("UPDATE worker_enrollment_state SET expires_at_ts=:t WHERE enrollment_id=:e"),
                {"t": "2099-01-01T00:00:00+00:00", "e": state.enrollment_id},
            )
        else:
            s.execute(
                text(
                    "UPDATE worker_enrollment_invitation SET expires_at_ts=:t"
                    " WHERE enrollment_id=:e"
                ),
                {"t": "2099-01-01T00:00:00+00:00", "e": state.enrollment_id},
            )
        s.commit()
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(s, actor, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"


def test_sweep_writes_no_worker_step_receipt(factory, actor):
    """The sweep's durable record is the revision-history row; the step-receipt ledger is reserved
    for the five externally delivered worker protocol steps."""
    state = _open(factory, actor)
    result = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    assert result.recovered == 1
    assert _count(factory, "worker_enrollment_step_receipt", state.enrollment_id) == 0
    # exactly one appended revision for the recovery
    assert _count(factory, "worker_enrollment_revision", state.enrollment_id) == 2
