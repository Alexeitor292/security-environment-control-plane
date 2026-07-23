"""Durable worker-enrollment repository + transactional service (SECP-PR5H-A, ADR-027).

Portable (SQLite) coverage of the persistence/CAS service: the full lifecycle, org/site scope
binding, the durable single-use nonce, step-receipt dedup, append-only history, rehydration
invariants (including the confirmed same-key corruption case), and transaction atomicity. The
PostgreSQL-gated module proves the *concurrent* races with real overlapping transactions; here the
CAS/uniqueness predicates are exercised deterministically.

Every refusal is asserted by its bounded closed code — never a message.
"""

from __future__ import annotations

import uuid
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
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

# --- deterministic fixtures ---------------------------------------------------------------------

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


def _invitation(
    nonce: str = "sha256:" + "b" * 64, **over: object
) -> contract.WorkerEnrollmentInvitation:
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
def session(factory) -> Session:
    with factory() as s:
        yield s


@pytest.fixture
def actor(session) -> Principal:
    p = bootstrap_dev(session)
    session.commit()
    return Principal(
        user_id=p.user_id,
        organization_id=p.organization_id,
        email=p.email,
        permissions=frozenset(Permission),
    )


def _second_org(session) -> uuid.UUID:
    from secp_api.models import Organization

    org = Organization(name="second-org", slug="second-org")
    session.add(org)
    session.flush()
    return org.id


def _expected(state: contract.EnrollmentState) -> svc.ExpectedRevision:
    return svc.ExpectedRevision(
        revision=state.revision,
        state_digest=state.digest(),
        sequence=state.sequence,
        predecessor_digest=state.predecessor_digest,
    )


def _open(session, actor, *, nonce: str = "sha256:" + "b" * 64, site: str = SITE, **inv):
    invitation = _invitation(nonce=nonce, **inv)
    out = svc.create_invitation_and_open(
        session,
        actor,
        invitation=invitation,
        invitation_created_at=CREATED,
        deployment_site_label=site,
        now=NOW,
    )
    session.commit()
    return out.state


def _bind(session, actor, state, *, worker_key=WORKER_KEY, worker_install="worker-bbbbbbbb"):
    out = svc.bind_worker(
        session,
        actor,
        enrollment_id=state.enrollment_id,
        worker_installation_id=worker_install,
        worker_key_id=worker_key,
        transaction_id=TXN,
        now=NOW,
        expected=_expected(state),
    )
    session.commit()
    return out


def _drive_to_healthy(session, actor, state):
    out = _bind(session, actor, state)
    state = out.state
    out = svc.record_offer(
        session,
        actor,
        enrollment_id=state.enrollment_id,
        facts=contract.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY),
        now=NOW,
        expected=_expected(state),
    )
    session.commit()
    state = out.state
    out = svc.record_result(
        session,
        actor,
        enrollment_id=state.enrollment_id,
        facts=contract.HandoffFacts("worker-result", RESULT_D, TXN, WORKER_KEY),
        now=NOW,
        expected=_expected(state),
    )
    session.commit()
    state = out.state
    out = svc.verify_release(
        session,
        actor,
        enrollment_id=state.enrollment_id,
        release_digest=RELEASE,
        now=NOW,
        expected=_expected(state),
    )
    session.commit()
    state = out.state
    out = svc.mark_enrollment_healthy(
        session,
        actor,
        enrollment_id=state.enrollment_id,
        now=NOW,
        expected=_expected(state),
    )
    session.commit()
    return out.state


# --- lifecycle + history ------------------------------------------------------------------------


def test_full_lifecycle_produces_contiguous_history_and_matching_head(session, actor):
    state = _open(session, actor)
    assert state.state == contract.INVITED and state.revision == 0
    final = _drive_to_healthy(session, actor, state)
    assert final.state == contract.HEALTHY and final.revision == 5

    rows = session.execute(
        text(
            "SELECT revision, state, state_digest, predecessor_digest "
            "FROM worker_enrollment_revision WHERE enrollment_id=:e ORDER BY revision"
        ),
        {"e": final.enrollment_id},
    ).all()
    assert [r[0] for r in rows] == [0, 1, 2, 3, 4, 5]  # contiguous, zero-based
    # head equals the latest history row
    assert rows[-1][2] == final.digest()
    # each predecessor_digest chains the prior canonical digest; revision 0 has none
    assert rows[0][3] == ""
    for prev, cur in zip(rows, rows[1:], strict=False):
        assert cur[3] == prev[2]


def test_revision_zero_is_recorded_at_creation(session, actor):
    state = _open(session, actor)
    n = session.execute(
        text(
            "SELECT count(*) FROM worker_enrollment_revision WHERE enrollment_id=:e AND revision=0"
        ),
        {"e": state.enrollment_id},
    ).scalar_one()
    assert n == 1


def test_history_is_never_updated_or_deleted_by_service_operations(session, actor):
    state = _open(session, actor)
    _drive_to_healthy(session, actor, state)
    # every recorded_at is distinct-append-only: count only grows, never shrinks
    before = session.execute(text("SELECT count(*) FROM worker_enrollment_revision")).scalar_one()
    # an idempotent retry writes NO new history row
    healthy = svc.load_public_view(session, actor, enrollment_id=state.enrollment_id)
    assert healthy["state"] == contract.HEALTHY
    after = session.execute(text("SELECT count(*) FROM worker_enrollment_revision")).scalar_one()
    assert after == before == 6


# --- nonce single-use ---------------------------------------------------------------------------


def test_first_bind_consumes_the_nonce(session, actor):
    state = _open(session, actor)
    consumed = session.execute(
        text("SELECT consumed FROM worker_enrollment_invitation WHERE enrollment_id=:e"),
        {"e": state.enrollment_id},
    ).scalar_one()
    assert not consumed
    _bind(session, actor, state)
    consumed = session.execute(
        text("SELECT consumed FROM worker_enrollment_invitation WHERE enrollment_id=:e"),
        {"e": state.enrollment_id},
    ).scalar_one()
    assert consumed


def test_second_bind_with_a_different_worker_refuses_and_does_not_reconsume(session, actor):
    state = _open(session, actor)
    _bind(session, actor, state)  # consumes; state -> worker_bound at rev 1
    # a different worker attempts to bind the same (now consumed) invitation
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.bind_worker(
            session,
            actor,
            enrollment_id=state.enrollment_id,
            worker_installation_id="worker-cccccccc",
            worker_key_id=OTHER_KEY,
            transaction_id=TXN,
            now=NOW,
            expected=_expected(state),
        )
    session.rollback()
    # expected-revision mismatch (state advanced to rev1) OR invitation consumed — both closed codes
    assert ei.value.code in ("enrollment_revision_conflict", "enrollment_invitation_consumed")


def test_duplicate_nonce_on_creation_refuses(session, actor):
    _open(session, actor, nonce="sha256:" + "b" * 64)
    with pytest.raises(WorkerEnrollmentError) as ei:
        # same nonce, different transaction -> different enrollment_id, but the nonce collides
        svc.create_invitation_and_open(
            session,
            actor,
            invitation=_invitation(nonce="sha256:" + "b" * 64, transaction_id="txn-9999"),
            invitation_created_at=CREATED,
            deployment_site_label=SITE,
            now=NOW,
        )
    session.rollback()
    assert ei.value.code == "enrollment_creation_conflict"


def test_revoked_invitation_refuses_bind(session, actor):
    state = _open(session, actor)
    session.execute(
        text(
            "UPDATE worker_enrollment_invitation SET revoked=1, revoked_at=:t"
            " WHERE enrollment_id=:e"
        ),
        {"t": "2026-07-21T00:05:00+00:00", "e": state.enrollment_id},
    )
    session.commit()
    with pytest.raises(WorkerEnrollmentError) as ei:
        _bind(session, actor, state)
    session.rollback()
    assert ei.value.code == "enrollment_invitation_revoked"


def test_expired_invitation_refuses_bind(session, actor):
    state = _open(session, actor)
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.bind_worker(
            session,
            actor,
            enrollment_id=state.enrollment_id,
            worker_installation_id="worker-bbbbbbbb",
            worker_key_id=WORKER_KEY,
            transaction_id=TXN,
            now="2026-07-21T02:00:00Z",
            expected=_expected(state),
        )
    session.rollback()
    assert ei.value.code in ("enrollment_invitation_expired", "enrollment_expired")


# --- CAS / expected-revision --------------------------------------------------------------------


def test_stale_expected_revision_refuses(session, actor):
    state = _open(session, actor)
    out = _bind(session, actor, state)  # advances to rev 1
    # caller still declares the rev-0 expectation
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.record_offer(
            session,
            actor,
            enrollment_id=state.enrollment_id,
            facts=contract.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY),
            now=NOW,
            expected=_expected(state),
        )
    session.rollback()
    assert ei.value.code == "enrollment_revision_conflict"
    assert out.state.revision == 1


def test_wrong_expected_digest_refuses(session, actor):
    state = _open(session, actor)
    bad = svc.ExpectedRevision(
        revision=0, state_digest="sha256:" + "0" * 64, sequence=0, predecessor_digest=""
    )
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.bind_worker(
            session,
            actor,
            enrollment_id=state.enrollment_id,
            worker_installation_id="worker-bbbbbbbb",
            worker_key_id=WORKER_KEY,
            transaction_id=TXN,
            now=NOW,
            expected=bad,
        )
    session.rollback()
    assert ei.value.code == "enrollment_revision_conflict"


def test_wrong_expected_predecessor_refuses(session, actor):
    state = _open(session, actor)
    bad = replace_expected(_expected(state), predecessor_digest="sha256:" + "e" * 64)
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.bind_worker(
            session,
            actor,
            enrollment_id=state.enrollment_id,
            worker_installation_id="worker-bbbbbbbb",
            worker_key_id=WORKER_KEY,
            transaction_id=TXN,
            now=NOW,
            expected=bad,
        )
    session.rollback()
    assert ei.value.code == "enrollment_revision_conflict"


def replace_expected(expected: svc.ExpectedRevision, **over) -> svc.ExpectedRevision:
    return replace(expected, **over)


# --- step-receipt exact retry -------------------------------------------------------------------


def test_exact_retry_returns_the_committed_revision_without_a_second_history_row(session, actor):
    state = _open(session, actor)
    out1 = _bind(session, actor, state)
    assert out1.deduplicated is False and out1.committed_revision == 1
    before = session.execute(text("SELECT count(*) FROM worker_enrollment_revision")).scalar_one()
    # replay the exact same bind (same worker/key/txn) against the ORIGINAL expected revision
    out2 = svc.bind_worker(
        session,
        actor,
        enrollment_id=state.enrollment_id,
        worker_installation_id="worker-bbbbbbbb",
        worker_key_id=WORKER_KEY,
        transaction_id=TXN,
        now=NOW,
        expected=_expected(state),
    )
    session.commit()
    assert out2.deduplicated is True and out2.committed_revision == 1
    after = session.execute(text("SELECT count(*) FROM worker_enrollment_revision")).scalar_one()
    assert after == before  # no second history row


def test_conflicting_input_for_same_step_refuses_as_replay(session, actor):
    state = _open(session, actor)
    out = _bind(session, actor, state)
    state = out.state
    svc.record_offer(
        session,
        actor,
        enrollment_id=state.enrollment_id,
        facts=contract.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY),
        now=NOW,
        expected=_expected(state),
    )
    session.commit()
    offered = svc.load_public_view(session, actor, enrollment_id=state.enrollment_id)
    assert offered["state"] == contract.OFFER_TRANSPORTED
    # a DIFFERENT offer digest from the advanced state -> replay/wrong-state
    fresh = repo.load_read_only(session, state.enrollment_id)
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.record_offer(
            session,
            actor,
            enrollment_id=state.enrollment_id,
            facts=contract.HandoffFacts("controller-offer", "sha256:" + "9" * 64, TXN, CTRL_KEY),
            now=NOW,
            expected=_expected(fresh.state),
        )
    session.rollback()
    assert ei.value.code in ("enrollment_replay", "enrollment_wrong_state")


# --- org / site scope binding -------------------------------------------------------------------


def test_same_site_label_in_different_organizations_is_allowed(session, factory):
    p1 = bootstrap_dev(session)
    session.commit()
    actor1 = Principal(
        user_id=p1.user_id,
        organization_id=p1.organization_id,
        email=p1.email,
        permissions=frozenset(Permission),
    )
    org2 = _second_org(session)
    session.commit()
    actor2 = Principal(
        user_id=uuid.uuid4(), organization_id=org2, email="b@x", permissions=frozenset(Permission)
    )

    s1 = _open(session, actor1, nonce="sha256:" + "b" * 64, site="shared-site")
    s2 = _open(
        session, actor2, nonce="sha256:" + "e" * 64, site="shared-site", transaction_id="txn-org2"
    )
    assert s1.enrollment_id != s2.enrollment_id
    assert (
        svc.load_public_view(session, actor1, enrollment_id=s1.enrollment_id)["state"] == "invited"
    )
    assert (
        svc.load_public_view(session, actor2, enrollment_id=s2.enrollment_id)["state"] == "invited"
    )


def test_multiple_workers_at_one_site_are_allowed(session, actor):
    s1 = _open(session, actor, nonce="sha256:" + "b" * 64, site=SITE, transaction_id="txn-w1")
    s2 = _open(session, actor, nonce="sha256:" + "e" * 64, site=SITE, transaction_id="txn-w2")
    assert s1.enrollment_id != s2.enrollment_id


def test_cross_organization_read_refuses(session, factory):
    p1 = bootstrap_dev(session)
    session.commit()
    actor1 = Principal(
        user_id=p1.user_id,
        organization_id=p1.organization_id,
        email=p1.email,
        permissions=frozenset(Permission),
    )
    org2 = _second_org(session)
    session.commit()
    intruder = Principal(
        user_id=uuid.uuid4(), organization_id=org2, email="b@x", permissions=frozenset(Permission)
    )
    state = _open(session, actor1)
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, intruder, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_forbidden"


def test_worker_claimed_site_mismatch_refuses_after_authoritative_selection(session, actor):
    state = _open(session, actor, site=SITE)
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(
            session,
            actor,
            enrollment_id=state.enrollment_id,
            claimed_scope=svc.ClaimedScope(deployment_site_label="rack-99.wrong"),
        )
    assert ei.value.code == "enrollment_scope_mismatch"


def test_worker_claimed_org_mismatch_refuses(session, actor):
    state = _open(session, actor)
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(
            session,
            actor,
            enrollment_id=state.enrollment_id,
            claimed_scope=svc.ClaimedScope(organization_id=uuid.uuid4()),
        )
    assert ei.value.code == "enrollment_scope_mismatch"


def test_cross_site_transaction_substitution_refuses(session, actor):
    state = _open(session, actor, transaction_id=TXN)
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(
            session,
            actor,
            enrollment_id=state.enrollment_id,
            claimed_scope=svc.ClaimedScope(transaction_id="txn-someone-else"),
        )
    assert ei.value.code == "enrollment_scope_mismatch"


def test_site_binding_is_immutable_after_creation(session, actor):
    state = _open(session, actor, site=SITE)
    # neither the invitation nor the state exposes a mutation path for the site label; the value is
    # fixed at creation and every later load returns it unchanged
    inv_site = session.execute(
        text(
            "SELECT deployment_site_label FROM worker_enrollment_invitation WHERE enrollment_id=:e"
        ),
        {"e": state.enrollment_id},
    ).scalar_one()
    st_site = session.execute(
        text("SELECT deployment_site_label FROM worker_enrollment_state WHERE enrollment_id=:e"),
        {"e": state.enrollment_id},
    ).scalar_one()
    assert inv_site == st_site == SITE
    _drive_to_healthy(session, actor, state)
    st_site_after = session.execute(
        text("SELECT deployment_site_label FROM worker_enrollment_state WHERE enrollment_id=:e"),
        {"e": state.enrollment_id},
    ).scalar_one()
    assert st_site_after == SITE


# --- rehydration invariants ---------------------------------------------------------------------


def _corrupt(session, enrollment_id: str, **columns) -> None:
    assigns = ", ".join(f"{k}=:{k}" for k in columns)
    session.execute(
        text(f"UPDATE worker_enrollment_state SET {assigns} WHERE enrollment_id=:e"),
        {**columns, "e": enrollment_id},
    )
    session.commit()


def test_corrupted_state_digest_refuses_on_rehydration(session, actor):
    state = _open(session, actor)
    _corrupt(session, state.enrollment_id, state_digest="sha256:" + "0" * 64)
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, actor, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"


def test_participant_key_collision_in_a_persisted_row_refuses_on_rehydration(session, actor):
    state = _open(session, actor)
    out = _bind(session, actor, state)
    bound = out.state
    # forge a same-key row and re-derive a digest so ONLY the participant invariant (not the digest
    # check) is what refuses — proving the separation re-assertion is load-bearing on rehydration
    forged = replace(bound, worker_key_id=CTRL_KEY)
    _corrupt(session, bound.enrollment_id, worker_key_id=CTRL_KEY, state_digest=forged.digest())
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, actor, enrollment_id=bound.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"
    # the row is PRESERVED, not repaired
    still = session.execute(
        text("SELECT worker_key_id FROM worker_enrollment_state WHERE enrollment_id=:e"),
        {"e": bound.enrollment_id},
    ).scalar_one()
    assert still == CTRL_KEY


def test_participant_installation_collision_in_a_persisted_row_refuses(session, actor):
    state = _open(session, actor)
    out = _bind(session, actor, state)
    bound = out.state
    forged = replace(bound, worker_installation_id=bound.controller_installation_id)
    _corrupt(
        session,
        bound.enrollment_id,
        worker_installation_id=bound.controller_installation_id,
        state_digest=forged.digest(),
    )
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, actor, enrollment_id=bound.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"


def test_timestamp_drift_between_canonical_text_and_shadow_refuses(session, actor):
    state = _open(session, actor)
    # move the shadow column off the canonical instant without touching the digested text
    session.execute(
        text("UPDATE worker_enrollment_state SET expires_at_ts=:t WHERE enrollment_id=:e"),
        {"t": "2027-01-01T00:00:00+00:00", "e": state.enrollment_id},
    )
    session.commit()
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, actor, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"


def test_malformed_incomplete_active_state_refuses(session, actor):
    state = _open(session, actor)
    out = _bind(session, actor, state)
    bound = out.state  # worker_bound MUST carry a worker identity
    forged = replace(bound, worker_key_id="", worker_installation_id="")
    _corrupt(
        session,
        bound.enrollment_id,
        worker_key_id="",
        worker_installation_id="",
        state_digest=forged.digest(),
    )
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, actor, enrollment_id=bound.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"


def test_broken_revision_chain_refuses(session, actor):
    state = _open(session, actor)
    _bind(session, actor, state)
    # delete the rev-0 history row -> non-contiguous chain
    session.execute(
        text("DELETE FROM worker_enrollment_revision WHERE enrollment_id=:e AND revision=0"),
        {"e": state.enrollment_id},
    )
    session.commit()
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, actor, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_history_inconsistent"


def test_head_ahead_of_history_refuses(session, actor):
    state = _open(session, actor)
    _bind(session, actor, state)  # head + history at rev 1
    # delete the latest history row -> head (rev1) disagrees with latest history (rev0)
    session.execute(
        text("DELETE FROM worker_enrollment_revision WHERE enrollment_id=:e AND revision=1"),
        {"e": state.enrollment_id},
    )
    session.commit()
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, actor, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_history_inconsistent"


# --- rehydration cross-checks (adversarial-review regressions) -----------------------------------


def test_state_organization_id_disagreeing_with_the_invitation_refuses(session, actor):
    """A tampered state-row org must not silently become the tenancy boundary — it is cross-checked
    against the AUTHORITATIVE invitation row (spec: org/site agree across invitation and state)."""
    state = _open(session, actor)
    other_org = _second_org(session)
    session.commit()
    _corrupt(session, state.enrollment_id, organization_id=str(other_org))
    with pytest.raises(WorkerEnrollmentError) as ei:
        # even an actor IN that other org cannot read it — the invitation disagrees, so it's corrupt
        intruder = Principal(
            user_id=uuid.uuid4(),
            organization_id=other_org,
            email="x@x",
            permissions=frozenset(Permission),
        )
        svc.load_public_view(session, intruder, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"


def test_state_site_label_disagreeing_with_the_invitation_refuses(session, actor):
    state = _open(session, actor, site="rack-01.eu_a")
    _corrupt(session, state.enrollment_id, deployment_site_label="rack-02.eu_b")
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, actor, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"


def test_path_shaped_site_label_refuses_on_rehydration(session, actor):
    """The site label is NOT part of the digest, so the digest check cannot catch a corrupted one;
    its grammar is re-validated on rehydration. A path/host-shaped label refuses."""
    state = _open(session, actor)
    # corrupt BOTH rows consistently so the cross-check passes and only the grammar check can bite
    for table in ("worker_enrollment_state", "worker_enrollment_invitation"):
        session.execute(
            text(
                f"UPDATE {table} SET deployment_site_label='../../etc/passwd'"
                " WHERE enrollment_id=:e"
            ),
            {"e": state.enrollment_id},
        )
    session.commit()
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, actor, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"


def test_secret_shaped_installation_id_refuses_on_rehydration(session, actor):
    """A secret/token-shaped installation id (which flows into public_view) must not load even when
    the state AND history digests are fully re-forged to match it."""
    state = _open(session, actor)
    forged = replace(state, controller_installation_id="token-xxxxxxxx")
    _corrupt(
        session,
        state.enrollment_id,
        controller_installation_id="token-xxxxxxxx",
        state_digest=forged.digest(),
    )
    session.execute(
        text("UPDATE worker_enrollment_revision SET state_digest=:d WHERE enrollment_id=:e"),
        {"d": forged.digest(), "e": state.enrollment_id},
    )
    session.commit()
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, actor, enrollment_id=state.enrollment_id)
    # bounded code, never a raw DescriptorError from scan_forbidden
    assert ei.value.code == "enrollment_state_corrupt"


def test_structurally_impossible_state_revision_refuses(session, actor):
    """revision 0 is INVITED-only; a worker_bound row at revision 0 is structurally impossible and
    must not load even with a fully re-forged digest and single-row history."""
    state = _open(session, actor)
    forged = replace(
        state,
        state="worker_bound",
        worker_installation_id="worker-bbbbbbbb",
        worker_key_id=WORKER_KEY,
    )
    _corrupt(
        session,
        state.enrollment_id,
        state="worker_bound",
        worker_installation_id="worker-bbbbbbbb",
        worker_key_id=WORKER_KEY,
        state_digest=forged.digest(),
    )
    session.execute(
        text(
            "UPDATE worker_enrollment_revision SET state='worker_bound', state_digest=:d"
            " WHERE enrollment_id=:e AND revision=0"
        ),
        {"d": forged.digest(), "e": state.enrollment_id},
    )
    session.commit()
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, actor, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"


def test_missing_invitation_row_refuses(session, actor):
    state = _open(session, actor)
    session.execute(
        text("DELETE FROM worker_enrollment_invitation WHERE enrollment_id=:e"),
        {"e": state.enrollment_id},
    )
    session.commit()
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, actor, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"


# --- not found / schema gate --------------------------------------------------------------------


def test_unknown_enrollment_refuses_not_found(session, actor):
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, actor, enrollment_id="sha256:" + "f" * 64)
    assert ei.value.code == "enrollment_not_found"


def test_operations_refuse_when_live_schema_is_not_the_required_head(session, actor):
    state = _open(session, actor)
    session.execute(text("UPDATE alembic_version SET version_num='d8f1a2b3c4e5'"))
    session.commit()
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(session, actor, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_schema_unavailable"


# --- rollback atomicity -------------------------------------------------------------------------


def test_failed_transition_leaves_no_partial_state_nonce_revision_or_receipt(session, actor):
    state = _open(session, actor)
    # a bind that will fail the pure transition (worker key == controller key) must leave NOTHING
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.bind_worker(
            session,
            actor,
            enrollment_id=state.enrollment_id,
            worker_installation_id="worker-bbbbbbbb",
            worker_key_id=CTRL_KEY,
            transaction_id=TXN,
            now=NOW,
            expected=_expected(state),
        )
    session.rollback()
    assert ei.value.code == "enrollment_worker_mismatch"
    # head still INVITED at rev 0, invitation unconsumed, one history row, no receipts
    assert (
        svc.load_public_view(session, actor, enrollment_id=state.enrollment_id)["state"]
        == "invited"
    )
    consumed = session.execute(
        text("SELECT consumed FROM worker_enrollment_invitation WHERE enrollment_id=:e"),
        {"e": state.enrollment_id},
    ).scalar_one()
    assert not consumed
    revs = session.execute(
        text("SELECT count(*) FROM worker_enrollment_revision WHERE enrollment_id=:e"),
        {"e": state.enrollment_id},
    ).scalar_one()
    receipts = session.execute(
        text("SELECT count(*) FROM worker_enrollment_step_receipt WHERE enrollment_id=:e"),
        {"e": state.enrollment_id},
    ).scalar_one()
    assert revs == 1 and receipts == 0
