"""Real-PostgreSQL concurrency proof for durable worker enrollment (SECP-PR5H-A, ADR-027).

Runs only when ``SECP_TEST_POSTGRES_URL`` is set (CI provisions a PostgreSQL service). Unlike the
portable SQLite suite, every race here uses INDEPENDENT sessions on separate connections with a real
``Barrier`` so the two transactions genuinely overlap in the database — a sequential test labelled
"concurrency" would not prove the CAS / row-lock / unique-constraint guarantees.

Proven here: exactly-one-winner for concurrent binds and concurrent transitions from one revision;
stale-revision / stale-digest / wrong-predecessor refusals; duplicate-nonce and concurrent-nonce
single-winner; exact-retry with no second history row; conflicting-retry refusal; cross-org / cross-
site isolation; participant-key/installation collision and corrupt-digest/broken-chain rehydration
refusals; rollback atomicity leaving no partial state/nonce/revision/receipt; and that the live
schema head is exactly ``b6e2f4a9c1d7``.
"""

from __future__ import annotations

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest
from secp_api import worker_enrollment_contract as contract
from secp_api.auth import Principal
from secp_api.enums import Permission
from secp_api.errors import WorkerEnrollmentError
from secp_api.models import Base, Organization
from secp_api.seed import bootstrap_dev
from secp_api.services import worker_enrollment as svc
from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL enrollment concurrency tests"
)

CTRL_HEX = (b"\x11" * 32).hex()
CTRL_KEY = contract.sha256_digest_of_hex(CTRL_HEX)
WORKER_HEX = (b"\x22" * 32).hex()
WORKER_KEY = contract.sha256_digest_of_hex(WORKER_HEX)
OTHER_HEX = (b"\x33" * 32).hex()
OTHER_KEY = contract.sha256_digest_of_hex(OTHER_HEX)
RELEASE = "sha256:" + "a" * 64
OFFER_D = "sha256:" + "c" * 64
RESULT_D = "sha256:" + "d" * 64
TXN = "txn-0001"
CREATED = "2026-07-21T00:00:00Z"
EXPIRES = "2026-07-21T01:00:00Z"
NOW = "2026-07-21T00:10:00Z"
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


def _open(factory, actor, *, nonce: str, site: str = SITE, **inv) -> contract.EnrollmentState:
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


def _bind(factory, actor, state, **over) -> contract.EnrollmentState:
    with factory() as s:
        out = svc.bind_worker(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            worker_installation_id=over.get("worker_installation_id", "worker-bbbbbbbb"),
            worker_key_id=over.get("worker_key_id", WORKER_KEY),
            transaction_id=TXN,
            now=NOW,
            expected=_expected(state),
        )
        s.commit()
        return out.state


def test_live_schema_head_is_exactly_the_required_head(pg):
    factory, actor, _ = pg
    with factory() as s:
        head = s.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    assert head == RUNTIME_REQUIRED_MIGRATION_HEAD == "b6e2f4a9c1d7"


def test_two_concurrent_binds_exactly_one_commits(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    barrier = Barrier(2)

    def attempt(worker: tuple[str, str]) -> str:
        install, key = worker
        with factory() as s:
            barrier.wait(timeout=15)
            try:
                svc.bind_worker(
                    s,
                    actor,
                    enrollment_id=state.enrollment_id,
                    worker_installation_id=install,
                    worker_key_id=key,
                    transaction_id=TXN,
                    now=NOW,
                    expected=_expected(state),
                )
                s.commit()
                return "committed"
            except WorkerEnrollmentError as exc:
                s.rollback()
                return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(
            pool.map(attempt, [("worker-bbbbbbbb", WORKER_KEY), ("worker-cccccccc", OTHER_KEY)])
        )
    assert outcomes.count("committed") == 1, outcomes
    # the loser refused with a bounded conflict code, never a partial write
    loser = [o for o in outcomes if o != "committed"][0]
    assert loser in (
        "enrollment_revision_conflict",
        "enrollment_invitation_conflict",
        "enrollment_invitation_consumed",
    )
    with factory() as s:
        consumed = s.execute(
            text(
                "SELECT count(*) FROM worker_enrollment_invitation"
                " WHERE consumed AND enrollment_id=:e"
            ),
            {"e": state.enrollment_id},
        ).scalar_one()
        revs = s.execute(
            text("SELECT count(*) FROM worker_enrollment_revision WHERE enrollment_id=:e"),
            {"e": state.enrollment_id},
        ).scalar_one()
    assert consumed == 1  # consumed exactly once
    assert revs == 2  # revision 0 (open) + exactly one advance


def test_two_concurrent_transitions_from_one_revision_exactly_one_commits(pg):
    factory, actor, _ = pg
    state = _bind(factory, actor, _open(factory, actor, nonce="sha256:" + "b" * 64))
    barrier = Barrier(2)

    def attempt(which: str) -> str:
        with factory() as s:
            barrier.wait(timeout=15)
            try:
                # two DIFFERENT next steps racing from the same worker_bound revision
                if which == "offer":
                    svc.record_offer(
                        s,
                        actor,
                        enrollment_id=state.enrollment_id,
                        facts=contract.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY),
                        now=NOW,
                        expected=_expected(state),
                    )
                else:
                    svc.refuse_enrollment(
                        s,
                        actor,
                        enrollment_id=state.enrollment_id,
                        reason="operator_refusal",
                        expected=_expected(state),
                    )
                s.commit()
                return "committed:" + which
            except WorkerEnrollmentError as exc:
                s.rollback()
                return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, ["offer", "refuse"]))
    committed = [o for o in outcomes if o.startswith("committed")]
    assert len(committed) == 1, outcomes
    losers = [o for o in outcomes if not o.startswith("committed")]
    assert losers == ["enrollment_revision_conflict"], outcomes
    with factory() as s:
        revs = s.execute(
            text("SELECT count(*) FROM worker_enrollment_revision WHERE enrollment_id=:e"),
            {"e": state.enrollment_id},
        ).scalar_one()
    assert revs == 3  # open + bind + exactly one of {offer, refuse}


def test_concurrent_creation_with_same_nonce_one_winner(pg):
    factory, actor, _ = pg
    nonce = "sha256:" + "7" * 64
    barrier = Barrier(2)

    def attempt(txn: str) -> str:
        with factory() as s:
            barrier.wait(timeout=15)
            try:
                svc.create_invitation_and_open(
                    s,
                    actor,
                    invitation=_invitation(nonce, transaction_id=txn),
                    invitation_created_at=CREATED,
                    deployment_site_label=SITE,
                    now=NOW,
                )
                s.commit()
                return "committed"
            except WorkerEnrollmentError as exc:
                s.rollback()
                return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, ["txn-a", "txn-b"]))
    assert outcomes.count("committed") == 1, outcomes
    assert "enrollment_creation_conflict" in outcomes, outcomes
    with factory() as s:
        n = s.execute(
            text("SELECT count(*) FROM worker_enrollment_invitation WHERE invitation_id=:n"),
            {"n": nonce},
        ).scalar_one()
    assert n == 1


def test_stale_revision_refuses(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    bound = _bind(factory, actor, state)  # now at rev 1
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.record_offer(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            facts=contract.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY),
            now=NOW,
            expected=_expected(state),  # stale rev-0 token
        )
    assert ei.value.code == "enrollment_revision_conflict"
    assert bound.revision == 1


def test_stale_state_digest_refuses(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    bad = svc.ExpectedRevision(
        revision=0, state_digest="sha256:" + "0" * 64, sequence=0, predecessor_digest=""
    )
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.bind_worker(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            worker_installation_id="worker-bbbbbbbb",
            worker_key_id=WORKER_KEY,
            transaction_id=TXN,
            now=NOW,
            expected=bad,
        )
    assert ei.value.code == "enrollment_revision_conflict"


def test_wrong_predecessor_refuses(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    bad = replace(_expected(state), predecessor_digest="sha256:" + "e" * 64)
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.bind_worker(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            worker_installation_id="worker-bbbbbbbb",
            worker_key_id=WORKER_KEY,
            transaction_id=TXN,
            now=NOW,
            expected=bad,
        )
    assert ei.value.code == "enrollment_revision_conflict"


def test_exact_retry_returns_committed_revision_without_second_history_row(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    _bind(factory, actor, state)
    with factory() as s:
        before = s.execute(text("SELECT count(*) FROM worker_enrollment_revision")).scalar_one()
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
        after = s.execute(text("SELECT count(*) FROM worker_enrollment_revision")).scalar_one()
    assert out.deduplicated and out.committed_revision == 1
    assert after == before


def test_conflicting_retry_refuses(pg):
    factory, actor, _ = pg
    state = _bind(factory, actor, _open(factory, actor, nonce="sha256:" + "b" * 64))
    with factory() as s:
        svc.record_offer(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            facts=contract.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY),
            now=NOW,
            expected=_expected(state),
        )
        s.commit()
        from secp_api import worker_enrollment_repository as repo

        offered = repo.load_read_only(s, state.enrollment_id).state
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.record_offer(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            facts=contract.HandoffFacts("controller-offer", "sha256:" + "9" * 64, TXN, CTRL_KEY),
            now=NOW,
            expected=_expected(offered),
        )
    assert ei.value.code in ("enrollment_replay", "enrollment_wrong_state")


def test_cross_org_and_cross_site_isolation(pg):
    factory, actor, actor2 = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64, site=SITE)
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(s, actor2, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_forbidden"
    # same site label under a different org is independently allowed
    state2 = _open(
        factory, actor2, nonce="sha256:" + "e" * 64, site=SITE, transaction_id="txn-org2"
    )
    with factory() as s:
        assert (
            svc.load_public_view(s, actor2, enrollment_id=state2.enrollment_id)["state"]
            == "invited"
        )
    # a worker-claimed site that disagrees refuses after authoritative selection
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            claimed_scope=svc.ClaimedScope(deployment_site_label="rack-99.wrong"),
        )
    assert ei.value.code == "enrollment_scope_mismatch"


def _corrupt(factory, enrollment_id: str, **cols) -> None:
    assigns = ", ".join(f"{k}=:{k}" for k in cols)
    with factory() as s:
        s.execute(
            text(f"UPDATE worker_enrollment_state SET {assigns} WHERE enrollment_id=:e"),
            {**cols, "e": enrollment_id},
        )
        s.commit()


def test_participant_key_collision_in_persisted_row_refuses_on_rehydration(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    bound = _bind(factory, actor, state)
    forged = replace(bound, worker_key_id=CTRL_KEY)
    _corrupt(factory, bound.enrollment_id, worker_key_id=CTRL_KEY, state_digest=forged.digest())
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(s, actor, enrollment_id=bound.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"


def test_participant_installation_collision_in_persisted_row_refuses(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    bound = _bind(factory, actor, state)
    forged = replace(bound, worker_installation_id=bound.controller_installation_id)
    _corrupt(
        factory,
        bound.enrollment_id,
        worker_installation_id=bound.controller_installation_id,
        state_digest=forged.digest(),
    )
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(s, actor, enrollment_id=bound.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"


def test_state_org_disagreeing_with_invitation_refuses_on_real_pg(pg):
    factory, actor, actor2 = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    # tamper ONLY the state row's org to actor2's org; the invitation still says actor's org
    with factory() as s:
        s.execute(
            text("UPDATE worker_enrollment_state SET organization_id=:o WHERE enrollment_id=:e"),
            {"o": actor2.organization_id, "e": state.enrollment_id},
        )
        s.commit()
    # actor2 must NOT gain access via the tampered org — the invitation cross-check refuses corrupt
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(s, actor2, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"


def test_corrupt_state_digest_refuses(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    _corrupt(factory, state.enrollment_id, state_digest="sha256:" + "0" * 64)
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(s, actor, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"


def test_broken_revision_chain_refuses(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    _bind(factory, actor, state)
    with factory() as s:
        s.execute(
            text("DELETE FROM worker_enrollment_revision WHERE enrollment_id=:e AND revision=0"),
            {"e": state.enrollment_id},
        )
        s.commit()
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(s, actor, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_history_inconsistent"


def test_receipt_pointing_to_missing_revision_refuses(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    bound = _bind(factory, actor, state)
    # forge a receipt whose input_digest MATCHES what verify_release will compute, so the service
    # consults it — but whose recorded revision (99) does not exist in history
    forged_input = svc._input_digest("mark_verified", {"release_digest": RELEASE})
    with factory() as s:
        s.execute(
            text(
                "INSERT INTO worker_enrollment_step_receipt "
                "(id, enrollment_id, step, input_digest, resulting_revision,"
                " resulting_state_digest, recorded_at)"
                " VALUES (:id,:e,'mark_verified',:d, 99, :rd, now())"
            ),
            {
                "id": uuid.uuid4(),
                "e": bound.enrollment_id,
                "d": forged_input,
                "rd": "sha256:" + "2" * 64,
            },
        )
        s.commit()
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.verify_release(
            s,
            actor,
            enrollment_id=bound.enrollment_id,
            release_digest=RELEASE,
            now=NOW,
            expected=_expected(bound),
        )
    assert ei.value.code in ("enrollment_history_inconsistent", "enrollment_receipt_conflict")


def test_receipt_with_wrong_recorded_digest_refuses(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    bound = _bind(factory, actor, state)
    # a receipt that points at a REAL revision (0) but records the WRONG digest for it -> conflict
    forged_input = svc._input_digest("mark_verified", {"release_digest": RELEASE})
    with factory() as s:
        s.execute(
            text(
                "INSERT INTO worker_enrollment_step_receipt "
                "(id, enrollment_id, step, input_digest, resulting_revision,"
                " resulting_state_digest, recorded_at)"
                " VALUES (:id,:e,'mark_verified',:d, 0, :rd, now())"
            ),
            {
                "id": uuid.uuid4(),
                "e": bound.enrollment_id,
                "d": forged_input,
                "rd": "sha256:" + "2" * 64,  # not the real revision-0 digest
            },
        )
        s.commit()
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.verify_release(
            s,
            actor,
            enrollment_id=bound.enrollment_id,
            release_digest=RELEASE,
            now=NOW,
            expected=_expected(bound),
        )
    assert ei.value.code == "enrollment_receipt_conflict"


def test_rollback_of_failed_transition_leaves_no_partial_effects(pg):
    factory, actor, _ = pg
    state = _open(factory, actor, nonce="sha256:" + "b" * 64)
    with factory() as s:
        try:
            # worker key == controller key: the pure transition refuses, the whole tx must roll back
            svc.bind_worker(
                s,
                actor,
                enrollment_id=state.enrollment_id,
                worker_installation_id="worker-bbbbbbbb",
                worker_key_id=CTRL_KEY,
                transaction_id=TXN,
                now=NOW,
                expected=_expected(state),
            )
            s.commit()
            committed = True
        except WorkerEnrollmentError as exc:
            s.rollback()
            committed = exc.code
    assert committed == "enrollment_worker_mismatch"
    with factory() as s:
        consumed = s.execute(
            text("SELECT consumed FROM worker_enrollment_invitation WHERE enrollment_id=:e"),
            {"e": state.enrollment_id},
        ).scalar_one()
        revs = s.execute(
            text("SELECT count(*) FROM worker_enrollment_revision WHERE enrollment_id=:e"),
            {"e": state.enrollment_id},
        ).scalar_one()
        receipts = s.execute(
            text("SELECT count(*) FROM worker_enrollment_step_receipt WHERE enrollment_id=:e"),
            {"e": state.enrollment_id},
        ).scalar_one()
    assert not consumed and revs == 1 and receipts == 0
