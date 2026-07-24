"""Real-PostgreSQL restart/crash recovery proof (SECP-PR5H-A, ADR-027, Commit 5).

Runs only when ``SECP_TEST_POSTGRES_URL`` is set. Proves, with FRESH sessions and genuinely
overlapping transactions, that recovery is entirely persistence-driven: restart at every lifecycle
step, lost-response recovery at every step, exact retry after restart, concurrent expiry sweep with
exactly one winner, idempotent sweep retry, a stale sweeper losing the CAS safely, rollback leaving
no partial revision/receipt, corrupt-row preservation, cross-org isolation, and terminal/healthy
rows never being swept.
"""

from __future__ import annotations

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from secp_api import worker_enrollment_contract as contract
from secp_api import worker_enrollment_repository as repo
from secp_api.auth import Principal
from secp_api.enums import Permission
from secp_api.errors import WorkerEnrollmentError
from secp_api.models import Base, Organization
from secp_api.seed import bootstrap_dev
from secp_api.services import worker_enrollment as svc
from secp_api.services import worker_enrollment_recovery as rec
from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL recovery tests"
)

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
def pg():
    assert PG_URL
    engine = create_engine(PG_URL, future=True)
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        conn.exec_driver_sql("CREATE SCHEMA public")
        conn.exec_driver_sql("CREATE TABLE alembic_version (version_num varchar(32) primary key)")
        conn.exec_driver_sql(
            f"INSERT INTO alembic_version VALUES ('{RUNTIME_REQUIRED_MIGRATION_HEAD}')"
        )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, future=True)
    with factory() as s:
        p = bootstrap_dev(s)
        s.commit()
        actor = Principal(
            user_id=p.user_id,
            organization_id=p.organization_id,
            email=p.email,
            permissions=frozenset(Permission),
        )
        org2 = Organization(name="second-org", slug="second-org")
        s.add(org2)
        s.commit()
        actor2 = Principal(
            user_id=uuid.uuid4(),
            organization_id=org2.id,
            email="b@example.test",
            permissions=frozenset(Permission),
        )
    try:
        yield factory, actor, actor2
    finally:
        engine.dispose()


def _open(factory, actor, *, nonce: str, site: str = SITE, **inv):
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


def _offer(factory, actor, state):
    with factory() as s:
        out = svc.record_offer(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            facts=contract.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY),
            now=NOW,
            expected=_expected(state),
        )
        s.commit()
        return out.state


def _result(factory, actor, state):
    with factory() as s:
        out = svc.record_result(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            facts=contract.HandoffFacts("worker-result", RESULT_D, TXN, WORKER_KEY),
            now=NOW,
            expected=_expected(state),
        )
        s.commit()
        return out.state


def _verify(factory, actor, state):
    with factory() as s:
        out = svc.verify_release(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            release_digest=RELEASE,
            now=NOW,
            expected=_expected(state),
        )
        s.commit()
        return out.state


def _view(factory, actor, enrollment_id):
    with factory() as s:
        return svc.load_public_view(s, actor, enrollment_id=enrollment_id)


def _hist(factory, enrollment_id):
    with factory() as s:
        return s.execute(
            text("SELECT count(*) FROM worker_enrollment_revision WHERE enrollment_id=:e"),
            {"e": enrollment_id},
        ).scalar_one()


# --- restart after each lifecycle step (fresh session sees the committed state) ------------------


def test_restart_after_each_step_sees_the_committed_state(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    assert _view(factory, actor, state.enrollment_id)["state"] == "invited"
    state = _bind(factory, actor, state)
    assert _view(factory, actor, state.enrollment_id)["state"] == "worker_bound"
    state = _offer(factory, actor, state)
    assert _view(factory, actor, state.enrollment_id)["state"] == "offer_transported"
    state = _result(factory, actor, state)
    assert _view(factory, actor, state.enrollment_id)["state"] == "result_transported"
    state = _verify(factory, actor, state)
    assert _view(factory, actor, state.enrollment_id)["state"] == "verified"


# --- lost response after commit at every step: fresh exact retry is idempotent -------------------


def _retry(factory, actor, step: str, prior):
    """Replay ``step`` exactly from a FRESH committed session, using the token first sent."""
    with factory() as s:
        expected = _expected(prior)
        if step == "bind":
            out = svc.bind_worker(
                s,
                actor,
                enrollment_id=prior.enrollment_id,
                worker_installation_id="worker-bbbbbbbb",
                worker_key_id=WORKER_KEY,
                transaction_id=TXN,
                now=NOW,
                expected=expected,
            )
        elif step == "offer":
            out = svc.record_offer(
                s,
                actor,
                enrollment_id=prior.enrollment_id,
                facts=contract.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY),
                now=NOW,
                expected=expected,
            )
        elif step == "result":
            out = svc.record_result(
                s,
                actor,
                enrollment_id=prior.enrollment_id,
                facts=contract.HandoffFacts("worker-result", RESULT_D, TXN, WORKER_KEY),
                now=NOW,
                expected=expected,
            )
        else:
            out = svc.verify_release(
                s,
                actor,
                enrollment_id=prior.enrollment_id,
                release_digest=RELEASE,
                now=NOW,
                expected=expected,
            )
        s.commit()
        return out


def test_lost_response_after_commit_recovers_idempotently_at_every_step(pg):
    factory, actor, _ = pg
    s0 = _open(factory, actor, nonce="sha256:" + "b" * 64)
    s1 = _bind(factory, actor, s0)
    s2 = _offer(factory, actor, s1)
    s3 = _result(factory, actor, s2)
    _verify(factory, actor, s3)
    # each step's response is "lost"; a fresh exact retry with the token first sent is a dedup no-op
    hist = _hist(factory, s0.enrollment_id)
    for step, prior in (("bind", s0), ("offer", s1), ("result", s2), ("verify", s3)):
        out = _retry(factory, actor, step, prior)
        assert out.deduplicated is True, step
    # combined, those retries added not one extra history row
    assert _hist(factory, s0.enrollment_id) == hist


# --- concurrent expiry sweep: exactly one winner -------------------------------------------------


def test_concurrent_expiry_sweep_has_exactly_one_winner(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    barrier = Barrier(2)

    def sweep(_i: int) -> int:
        barrier.wait(timeout=15)
        result = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
        return result.recovered

    with ThreadPoolExecutor(max_workers=2) as pool:
        recovered_counts = list(pool.map(sweep, [0, 1]))
    assert sum(recovered_counts) == 1, recovered_counts  # exactly one sweeper recovered the row
    assert _view(factory, actor, state.enrollment_id)["state"] == "recovery_required"
    assert _hist(factory, state.enrollment_id) == 2  # open + exactly one recovery revision


def test_sweep_retry_is_idempotent_on_real_pg(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    first = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    second = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    assert first.recovered == 1 and second.recovered == 0
    assert _hist(factory, state.enrollment_id) == 2


def test_stale_sweeper_cas_loses_safely(pg):
    """The CAS backstop: a sweeper holding STALE ``(revision, state_digest)`` coordinates (because
    another writer advanced the row after it snapshotted) must lose the compare-and-swap and create
    no revision — proving the CAS, not the lock alone, is authoritative."""
    from secp_api.worker_enrollment_contract import require_recovery
    from secp_api.worker_enrollment_repository import RepositoryRefusal

    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)

    # snapshot the row at revision 0 (a detached, now-stale LoadedEnrollment)
    with factory() as s:
        stale = repo.load_for_update(s, state.enrollment_id)
        s.rollback()
    assert stale is not None and stale.expected_revision == 0

    # another writer advances the row to revision 1
    _bind(factory, actor, state)

    # the stale sweeper attempts its recovery CAS against the now-obsolete rev-0 coordinates
    with factory() as s:
        new_state = require_recovery(stale.state, rec.SWEEP_REASON)
        with pytest.raises(RepositoryRefusal) as ei:
            repo.commit_transition(
                s, prior=stale, new_state=new_state, step=None, input_digest=None
            )
        s.rollback()
    assert ei.value.reason_code == "enrollment_revision_conflict"

    # history holds only open(0) + bind(1); the stale sweeper wrote nothing, no gaps or dupes
    with factory() as s:
        revs = (
            s.execute(
                text(
                    "SELECT revision FROM worker_enrollment_revision WHERE enrollment_id=:e"
                    " ORDER BY revision"
                ),
                {"e": state.enrollment_id},
            )
            .scalars()
            .all()
        )
    assert revs == [0, 1]
    assert _view(factory, actor, state.enrollment_id)["state"] == "worker_bound"


# --- rollback / corruption / isolation / terminals -----------------------------------------------


def test_sweep_rollback_leaves_no_partial_revision_or_receipt(pg, monkeypatch):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    real_cas = repo._cas_head

    def _cas_then_boom(session, enrollment_id, prior, new_state):
        real_cas(session, enrollment_id, prior, new_state)
        raise RuntimeError("crash after CAS, before commit")

    monkeypatch.setattr(repo, "_cas_head", _cas_then_boom)
    result = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    # the poisoned transition rolled back; the sweep counted it corrupt, wrote nothing
    assert result.recovered == 0
    monkeypatch.undo()
    assert _view(factory, actor, state.enrollment_id)["state"] == "invited"
    assert _hist(factory, state.enrollment_id) == 1  # only the open revision survives


def test_corrupt_row_is_preserved_by_the_sweep(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    with factory() as s:
        s.execute(
            text("UPDATE worker_enrollment_state SET state_digest=:d WHERE enrollment_id=:e"),
            {"d": "sha256:" + "0" * 64, "e": state.enrollment_id},
        )
        s.commit()
    result = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    assert result.corrupt == 1 and result.recovered == 0
    with factory() as s:
        digest = s.execute(
            text("SELECT state_digest FROM worker_enrollment_state WHERE enrollment_id=:e"),
            {"e": state.enrollment_id},
        ).scalar_one()
    assert digest == "sha256:" + "0" * 64  # preserved, not repaired


def test_cross_org_sweep_cannot_recover_another_orgs_row(pg):
    factory, actor, actor2 = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    result = rec.recover_expired(factory, organization_id=actor2.organization_id, now=AFTER)
    assert (result.examined, result.recovered) == (0, 0)
    assert _view(factory, actor, state.enrollment_id)["state"] == "invited"


def test_healthy_and_terminal_rows_are_not_swept(pg):
    factory, actor, _ = pg
    # healthy (default transaction id, since the _bind/_offer/... helpers use it)
    h = _open(factory, actor, nonce="sha256:" + "1" * 64)
    h = _verify(
        factory, actor, _result(factory, actor, _offer(factory, actor, _bind(factory, actor, h)))
    )
    with factory() as s:
        h = svc.mark_enrollment_healthy(
            s, actor, enrollment_id=h.enrollment_id, now=NOW, expected=_expected(h)
        ).state
        s.commit()
    # already recovery_required (distinct nonce; transaction id may match — enrollment_id differs)
    r = _open(factory, actor, nonce="sha256:" + "2" * 64)
    rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    before = _hist(factory, r.enrollment_id)
    # a second sweep must not re-touch the healthy row or the already-recovered one
    result = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    assert result.recovered == 0
    assert _view(factory, actor, h.enrollment_id)["state"] == "healthy"
    assert _hist(factory, r.enrollment_id) == before


# --- lifecycle lost-response recovery on real PostgreSQL ----------------------------------------


def _lifecycle(factory, actor, kind, state, reason):
    """One lifecycle call in its own FRESH session — nothing carries over in process memory."""
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
def test_lifecycle_lost_response_recovers_from_postgres_state_alone(pg, kind, terminal):
    """Restart semantics: the retry is served purely from persisted PostgreSQL rows — the revision
    history — with no process memory, cache or retained request object involved."""
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    committed = _lifecycle(factory, actor, kind, state, "operator_action")
    assert committed.deduplicated is False
    assert _view(factory, actor, state.enrollment_id)["state"] == terminal
    hist = _hist(factory, state.enrollment_id)

    # simulate a full restart: brand-new engine + sessionmaker over the SAME database
    restarted = sessionmaker(bind=create_engine(PG_URL, future=True), autoflush=False, future=True)
    with restarted() as s:
        fn = svc.recover_enrollment if kind == "recover" else svc.refuse_enrollment
        out = fn(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            reason="operator_action",
            expected=_expected(state),
        )
        s.commit()
    assert out.deduplicated is True
    assert out.committed_revision == committed.committed_revision
    assert _hist(factory, state.enrollment_id) == hist  # no second history row


def test_lifecycle_retry_refuses_when_a_later_revision_exists_on_real_pg(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    refused = _lifecycle(factory, actor, "refuse", state, "operator_action").state
    _lifecycle(factory, actor, "recover", refused, "operator_action")  # a later revision
    with pytest.raises(WorkerEnrollmentError) as ei:
        _lifecycle(factory, actor, "refuse", state, "operator_action")
    assert ei.value.code == "enrollment_revision_conflict"


def test_sweep_forward_progress_past_preserved_corrupt_rows_on_real_pg(pg):
    """Regression for the starvation defect: permanently-unrecoverable rows must not occupy the head
    of every window forever."""
    factory, actor, _ = pg
    blocked = [
        _open(
            factory,
            actor,
            nonce="sha256:" + f"{i:064x}",
            transaction_id=f"txn-{i}",
            expires_at="2026-07-21T00:30:00Z",
        )
        for i in (1, 2)
    ]
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
    assert _view(factory, actor, victim.enrollment_id)["state"] == "recovery_required"


def test_skip_locked_row_is_skipped_then_recovered_after_the_lock_releases(pg):
    """SKIP LOCKED semantics on real PostgreSQL: a due row whose lock is held by another transaction
    is classified SKIPPED (never corrupt/failed), stays eligible, and is recovered by a later
    invocation once the lock releases."""
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)

    holder = factory()
    try:
        # hold a genuine row lock in an independent transaction
        locked = holder.execute(
            text(
                "SELECT enrollment_id FROM worker_enrollment_state"
                " WHERE enrollment_id=:e FOR UPDATE"
            ),
            {"e": state.enrollment_id},
        ).scalar_one()
        assert locked == state.enrollment_id

        blocked = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
        # examined, but skipped because the lock is held — NOT corrupt and NOT failed
        assert blocked.examined == 1
        assert blocked.skipped == 1
        assert (blocked.recovered, blocked.corrupt, blocked.failed) == (0, 0, 0)
        assert blocked.total == blocked.examined
        # still untouched and still eligible
        assert _view(factory, actor, state.enrollment_id)["state"] == "invited"
    finally:
        holder.rollback()  # release the lock
        holder.close()

    after_release = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    assert after_release.recovered == 1
    assert _view(factory, actor, state.enrollment_id)["state"] == "recovery_required"
    assert _hist(factory, state.enrollment_id) == 2


def test_sweep_writes_no_step_receipt_on_real_pg(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    assert (
        rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER).recovered
        == 1
    )
    with factory() as s:
        receipts = s.execute(
            text("SELECT count(*) FROM worker_enrollment_step_receipt WHERE enrollment_id=:e"),
            {"e": state.enrollment_id},
        ).scalar_one()
    assert receipts == 0
    assert _hist(factory, state.enrollment_id) == 2  # exactly one appended recovery revision
