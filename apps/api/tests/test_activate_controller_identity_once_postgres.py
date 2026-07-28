"""Real-PostgreSQL controller-identity activation durable-idempotency fence (SECP-PR5H-B2 C3).

Runs ONLY when ``SECP_TEST_POSTGRES_URL`` is set (CI provisions PostgreSQL); it never skips in the
fence. It proves the exact-operation durable idempotency of the activation one-shot AGAINST A REAL
PostgreSQL — not the portable SQLite stand-in the hermetic suite uses:

  * a first execution commits the controller identity + the durable receipt row atomically (no
    activation without receipt);
  * an exact replay returns the BYTE-EQUIVALENT stored receipt and inserts nothing (even after the
    freshness window has expired);
  * a missed initial receipt lookup (a lost/stale read) is recovered under the advisory lock: the
    locked authoritative re-read inside ``_first_execution`` finds THIS operation's committed
    receipt and replays it byte-for-byte (no second INSERT), while a new/different operation id and
    a changed operation-digest still conflict;
  * genuine concurrent same-operation execution is a single winner — the shared advisory lock
    SERIALIZES the two transactions, so the loser observes the committed receipt and replays it
    (exactly one durable row) WITHOUT a raw ``IntegrityError`` (that recovery path is retained only
    for dialects / edge races that actually reach the UNIQUE constraint);
  * a tampered stored receipt (its digest no longer matches) refuses ``activation-state-corrupt``;
  * the durable receipt table is WRITE-ONCE at the privilege boundary: the dedicated least-privilege
    ``secp_enrollment_signer`` runtime role (SELECT on the one identity table only) has NO privilege
    on the receipt table at all — it can neither SELECT, UPDATE nor DELETE it.

It contacts only the ephemeral job-local database and no deployment infrastructure.
"""

from __future__ import annotations

import os
import threading
from datetime import UTC, datetime

import pytest
from secp_api import activate_controller_identity_once as mod
from secp_api.controller_identity_dev import build_test_verified_controller_identity
from secp_api.controller_identity_models import ControllerIdentityActivationReceipt
from secp_api.models import Base
from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD
from secp_commissioning.canonical import canonical_json, sha256_bytes
from secp_commissioning.enrollment_signer_role import (
    ENROLLMENT_SIGNER_DB_GRANTS,
    ENROLLMENT_SIGNER_DB_ROLE,
)
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import sessionmaker

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run the activation durable-idempotency fence"
)

_SCHEMA = mod.CONTROLLER_IDENTITY_ACTIVATION_SCHEMA
_T0 = "2026-07-28T00:00:00Z"
_FRESH = datetime(2026, 7, 28, 0, 1, 0, tzinfo=UTC)  # 60s after _T0
_STALE = datetime(2026, 7, 28, 2, 0, 0, tzinfo=UTC)  # 2h after _T0
_ROLE = ENROLLMENT_SIGNER_DB_ROLE
_ROLE_PW = "activation-writeonce-test-pw"  # noqa: S105 - a throwaway CI-local test role password


def _handoff(
    proof, *, operation_id="op-1", expected_row=None, expected_token=None, **over
) -> bytes:
    fields = {f: getattr(proof, f) for f in mod._IDENTITY_FIELDS}
    env = {
        "schema": _SCHEMA,
        "operation_id": operation_id,
        "candidate_digest": sha256_bytes(
            canonical_json({f: fields[f] for f in mod._IDENTITY_FIELDS}).encode()
        ),
        "expected_predecessor_row_id": expected_row,
        "expected_predecessor_activation_token": expected_token,
        "generation": 0,
        "handoff_created_at": _T0,
        **fields,
    }
    env.update(over)
    return canonical_json(env).encode()


@pytest.fixture
def pg():
    assert PG_URL
    admin = create_engine(PG_URL, future=True)
    ac = create_engine(PG_URL, future=True, isolation_level="AUTOCOMMIT")
    with ac.connect() as conn:
        _drop_role(conn)
    with admin.begin() as conn:
        conn.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        conn.exec_driver_sql("CREATE SCHEMA public")
    Base.metadata.create_all(admin)
    with admin.begin() as conn:  # RESTORE the alembic-head marker the later "live head" step reads
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS alembic_version (version_num varchar(32) primary key)"
        )
        conn.exec_driver_sql("DELETE FROM alembic_version")
        conn.exec_driver_sql(
            f"INSERT INTO alembic_version VALUES ('{RUNTIME_REQUIRED_MIGRATION_HEAD}')"
        )
    factory = sessionmaker(bind=admin, autoflush=False, future=True)
    try:
        yield admin, ac, factory
    finally:
        with ac.connect() as conn:
            _drop_role(conn)
        admin.dispose()
        ac.dispose()


def _drop_role(conn) -> None:
    exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": _ROLE}).scalar()
    if exists:
        conn.exec_driver_sql(f"DROP OWNED BY {_ROLE}")
        conn.exec_driver_sql(f"DROP ROLE {_ROLE}")


def _run(factory, raw, *, now=_FRESH):
    return mod.run_activation(read_handoff=lambda: raw, session_factory=factory, now=now)


def _count(factory) -> int:
    with factory() as s:
        return len(s.execute(select(ControllerIdentityActivationReceipt)).scalars().all())


_A = build_test_verified_controller_identity()
_B = build_test_verified_controller_identity(
    controller_installation_id="controller-b0000001", controller_trust_anchor_hex="22" * 32
)


def test_first_execution_commits_activation_and_receipt_atomically(pg):
    _admin, _ac, factory = pg
    code, receipt = _run(factory, _handoff(_A))
    assert code == mod.EXIT_OK and receipt["created"] is True
    assert receipt["resulting_status"] == "active" and _count(factory) == 1
    with factory() as s:
        active = s.execute(
            text("SELECT count(*) FROM controller_enrollment_identity WHERE status = 'active'")
        ).scalar()
        assert active == 1


def test_exact_replay_is_byte_equivalent_even_after_freshness_expiry(pg):
    _admin, _ac, factory = pg
    _, r1 = _run(factory, _handoff(_A, operation_id="op-r"))
    code, r2 = _run(factory, _handoff(_A, operation_id="op-r"), now=_STALE)  # stale replay
    assert code == mod.EXIT_OK
    assert canonical_json(r1) == canonical_json(r2) and _count(factory) == 1


def _force_initial_lookup_miss(monkeypatch):
    """Force ONLY run_activation's first (pre-lock) ``_load_receipt`` to miss, so the one-shot
    enters ``_first_execution`` even though the receipt already exists — exercising the locked
    authoritative re-read. Every subsequent ``_load_receipt`` (the re-read) is the real query."""
    original = mod._load_receipt
    state = {"first": True}

    def _patched(session, operation_id):
        if state["first"]:
            state["first"] = False
            return None
        return original(session, operation_id)

    monkeypatch.setattr(mod, "_load_receipt", _patched)


def test_missed_initial_lookup_replays_via_locked_reread(pg, monkeypatch):
    _admin, _ac, factory = pg
    _, winner = _run(factory, _handoff(_A, operation_id="op-race"))  # the true writer committed
    assert _count(factory) == 1
    # a lost/stale initial lookup: inside _first_execution the candidate is already active, so the
    # locked authoritative re-read finds THIS operation's committed receipt and replays it
    # byte-for-byte — no second INSERT (so no IntegrityError) and no new durable row.
    _force_initial_lookup_miss(monkeypatch)
    code, replay = _run(factory, _handoff(_A, operation_id="op-race"))
    assert code == mod.EXIT_OK
    assert canonical_json(replay) == canonical_json(winner)  # the winner's exact stored bytes
    assert _count(factory) == 1  # the re-read mutated nothing


def test_missed_initial_lookup_with_new_operation_id_still_conflicts(pg, monkeypatch):
    _admin, _ac, factory = pg
    _run(factory, _handoff(_A, operation_id="op-first"))  # candidate _A is now active
    _force_initial_lookup_miss(monkeypatch)
    # a DIFFERENT operation id whose candidate merely happens to be active cannot claim replay: the
    # locked re-read finds no receipt for op-second, so it is refused, not replayed.
    code, payload = _run(factory, _handoff(_A, operation_id="op-second"))
    assert code == mod.EXIT_OPERATION_CONFLICT
    assert payload["reason_code"] == "activation_candidate_already_active"
    assert _count(factory) == 1


def test_missed_initial_lookup_with_mismatched_operation_digest_conflicts(pg, monkeypatch):
    _admin, _ac, factory = pg
    _run(factory, _handoff(_A, operation_id="op-x"))  # generation 0
    _force_initial_lookup_miss(monkeypatch)
    # same operation id + same (active) candidate but a CHANGED binding (generation): the locked
    # re-read finds the receipt, but _exact_replay rejects the operation-digest mismatch — a changed
    # operation never silently replays.
    code, payload = _run(factory, _handoff(_A, operation_id="op-x", generation=7))
    assert code == mod.EXIT_OPERATION_CONFLICT
    assert payload["reason_code"] == "activation_operation_conflict"
    assert _count(factory) == 1


def test_genuine_concurrent_same_operation_is_a_single_winner(pg):
    _admin, _ac, factory = pg
    raw = _handoff(_A, operation_id="op-concurrent")
    barrier = threading.Barrier(2)
    results: dict[str, tuple] = {}
    errors: dict[str, BaseException] = {}

    def worker(name: str) -> None:
        try:
            barrier.wait(
                timeout=15
            )  # release both together so they truly race on the advisory lock
            results[name] = mod.run_activation(
                read_handoff=lambda: raw, session_factory=factory, now=_FRESH
            )
        except BaseException as exc:  # noqa: BLE001 - capture ANY error (incl a raw IntegrityError)
            errors[name] = exc

    threads = [threading.Thread(target=worker, args=(n,)) for n in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=45)
    assert not any(t.is_alive() for t in threads), "a concurrent activation worker hung"
    assert not errors, errors  # the advisory lock serializes: NO raw IntegrityError surfaces
    assert {results["a"][0], results["b"][0]} == {mod.EXIT_OK}  # both succeed
    assert canonical_json(results["a"][1]) == canonical_json(results["b"][1])  # byte-equivalent
    assert _count(factory) == 1  # exactly one durable receipt — a single winner


def test_tampered_receipt_refuses_state_corrupt(pg):
    _admin, _ac, factory = pg
    _run(factory, _handoff(_A, operation_id="op-c"))
    with factory() as s:
        row = s.execute(select(ControllerIdentityActivationReceipt)).scalars().one()
        row.receipt_json = row.receipt_json.replace("active", "revoked")  # digest now stale
        s.commit()
    code, payload = _run(factory, _handoff(_A, operation_id="op-c"))
    assert code == mod.EXIT_STATE_CORRUPT
    assert payload["reason_code"] == "controller_activation_state_corrupt"


def test_receipt_table_is_unreachable_by_the_least_privilege_runtime_role(pg):
    """Write-once at the privilege boundary: the dedicated runtime role is granted SELECT on the ONE
    identity table only, so it has NO privilege on the durable receipt table — it cannot read,
    update or delete it. No ordinary runtime path can mutate a committed receipt."""
    _admin, ac, factory = pg
    _run(factory, _handoff(_A, operation_id="op-w"))
    with ac.connect() as conn:
        conn.exec_driver_sql(
            f"CREATE ROLE {_ROLE} LOGIN PASSWORD '{_ROLE_PW}' "
            "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
        )
        for stmt in ENROLLMENT_SIGNER_DB_GRANTS:  # USAGE on schema + SELECT on the identity table
            conn.exec_driver_sql(stmt)
    role_engine = create_engine(
        make_url(PG_URL)
        .set(username=_ROLE, password=_ROLE_PW)
        .render_as_string(hide_password=False),
        future=True,
    )
    try:
        for stmt in (
            "SELECT * FROM controller_identity_activation_receipt LIMIT 1",
            "UPDATE controller_identity_activation_receipt SET generation = generation",
            "DELETE FROM controller_identity_activation_receipt",
        ):
            with role_engine.connect() as conn:
                with pytest.raises(ProgrammingError):  # InsufficientPrivilege
                    conn.execute(text(stmt))
    finally:
        role_engine.dispose()
