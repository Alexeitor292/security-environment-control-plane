"""The request-scoped transaction must be the ONLY commit point — on SQLite as well as PostgreSQL.

pysqlite's legacy transaction handling emits an implicit ``BEGIN`` only for statements it
recognizes as DML.  It does **not** recognize ``SAVEPOINT``.  So a ``Session.begin_nested()`` taken
before any INSERT/UPDATE/DELETE on that connection becomes the OUTERMOST savepoint with no
enclosing transaction — and SQLite *commits* an outermost savepoint on ``RELEASE``.  The nested
block's writes become durable at ``RELEASE``, before the caller commits, and the caller's later
``rollback()`` cannot undo them.

That silently breaks the boundary ``worker_enrollment_repository`` documents ("everything here is
one uncommitted transaction the caller owns"; "a pre-commit failure leaves NOTHING behind") for
every ``begin_nested()`` call site in the API — and the whole Python suite runs on SQLite, so the
environment does not supply the premise those assertions rest on.

``_make_engine`` fixes this by beginning a real transaction whenever a ``SAVEPOINT`` would
otherwise be the outermost one.  The fix is deliberately narrow: emitting ``BEGIN`` for *every*
transaction instead would make read-only work hold SHARED until commit and deadlock concurrent
writers (measured: 56 pre-existing API tests fail that way with "database is locked").

Both tests below measure **SQLite specifically** and assert the dialect they are measuring, so
neither can pass vacuously on another engine and read as coverage.  PostgreSQL needs none of this:
psycopg opens a transaction before the first statement, so a savepoint is always nested there.
"""

from __future__ import annotations

import secrets
import sqlite3

import pytest
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from secp_api.db import _make_engine


def _sqlite_engine(tmp_path, name="boundary.db"):
    """A file-backed SQLite engine built exactly as production/dev builds one."""
    path = (tmp_path / name).as_posix()
    engine = _make_engine(f"sqlite+pysqlite:///{path}")
    # Engine awareness: this test measures pysqlite's transaction handling and nothing else.
    assert engine.dialect.name == "sqlite", f"expected sqlite, got {engine.dialect.name}"
    assert engine.dialect.driver == "pysqlite", f"expected pysqlite, got {engine.dialect.driver}"
    return engine, path


def _committed_rows(path: str, sql: str, params: tuple = ()) -> int:
    """An INDEPENDENT connection, outside SQLAlchemy: it can only ever see COMMITTED data."""
    conn = sqlite3.connect(path, timeout=5.0)
    try:
        return conn.execute(sql, params).fetchone()[0]
    except sqlite3.OperationalError as exc:  # pragma: no cover - would mean a lock, not isolation
        pytest.fail(f"independent reader could not read (this is a lock, not isolation): {exc}")
    finally:
        conn.close()


def test_releasing_a_savepoint_does_not_commit_on_sqlite(tmp_path):
    """RELEASE must release, not commit — and the caller's rollback must still undo the work."""
    engine, path = _sqlite_engine(tmp_path)
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE boundary_t (id INTEGER PRIMARY KEY, v TEXT)")

    session = sessionmaker(bind=engine, autoflush=False, future=True)()
    try:
        with session.begin_nested():  # emits SAVEPOINT
            session.execute(text("INSERT INTO boundary_t (id, v) VALUES (1, 'nested')"))
            inside = _committed_rows(path, "SELECT count(*) FROM boundary_t WHERE id=1")
        # block exit emits RELEASE SAVEPOINT
        after_release = _committed_rows(path, "SELECT count(*) FROM boundary_t WHERE id=1")

        session.rollback()  # the caller abandons its transaction
        after_rollback = _committed_rows(path, "SELECT count(*) FROM boundary_t WHERE id=1")
    finally:
        session.close()

    assert inside == 0, "a savepoint's writes must not be durable while the savepoint is open"
    assert after_release == 0, (
        "RELEASE SAVEPOINT committed the nested write: pysqlite never opened an enclosing "
        "transaction, so the savepoint was outermost and SQLite committed it on RELEASE"
    )
    assert after_rollback == 0, (
        "the caller's rollback() could not undo work released from a savepoint — the "
        "request-scoped transaction is not the only commit point on this engine"
    )

    # Positive control: the independent reader is NOT blind. A real commit must be visible to it,
    # otherwise the three zeros above would prove nothing.
    session = sessionmaker(bind=engine, autoflush=False, future=True)()
    try:
        session.execute(text("INSERT INTO boundary_t (id, v) VALUES (2, 'committed')"))
        session.commit()
    finally:
        session.close()
    assert _committed_rows(path, "SELECT count(*) FROM boundary_t WHERE id=2") == 1, (
        "the independent reader cannot see committed data, so it is not a valid oracle"
    )


def test_savepoint_rollback_still_discards_only_the_nested_work(tmp_path):
    """The savepoint must keep doing its job: a nested rollback discards the nested write and
    leaves the caller's other staged rows intact (the reason begin_nested() is used at all)."""
    engine, path = _sqlite_engine(tmp_path, "nested.db")
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE nested_t (id INTEGER PRIMARY KEY, v TEXT)")

    session = sessionmaker(bind=engine, autoflush=False, future=True)()
    try:
        session.execute(text("INSERT INTO nested_t (id, v) VALUES (1, 'outer')"))
        with pytest.raises(RuntimeError):
            with session.begin_nested():
                session.execute(text("INSERT INTO nested_t (id, v) VALUES (2, 'speculative')"))
                raise RuntimeError("collision")
        session.commit()
    finally:
        session.close()

    assert _committed_rows(path, "SELECT count(*) FROM nested_t WHERE id=1") == 1
    assert _committed_rows(path, "SELECT count(*) FROM nested_t WHERE id=2") == 0


def test_sqlite_foreign_keys_stay_enforced(tmp_path):
    """``_make_engine`` also sets ``PRAGMA foreign_keys=ON``; turning off pysqlite's implicit
    BEGIN must not cost that (a PRAGMA is ignored inside an open transaction)."""
    engine, _ = _sqlite_engine(tmp_path, "fk.db")
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1

    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE fk_parent (id INTEGER PRIMARY KEY)")
        conn.exec_driver_sql(
            "CREATE TABLE fk_child (id INTEGER PRIMARY KEY, "
            "parent_id INTEGER REFERENCES fk_parent(id))"
        )
    with pytest.raises(Exception, match="FOREIGN KEY"):
        with engine.begin() as conn:
            conn.exec_driver_sql("INSERT INTO fk_child (id, parent_id) VALUES (1, 999)")


def test_enrollment_create_is_not_durable_until_the_caller_commits(engine, session, principal):
    """End to end on the real service path: ``create_supported_invitation`` isolates its insert in
    a SAVEPOINT (``services/worker_enrollment.py``). Nothing it writes may become durable before
    the caller commits, and the caller's rollback must leave NOTHING behind."""
    from secp_api.services import worker_enrollment as svc
    from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD

    assert engine.dialect.name == "sqlite" and engine.dialect.driver == "pysqlite"
    path = engine.url.database
    assert path, "expected a file-backed SQLite database"

    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS alembic_version (version_num varchar(32) primary key)"
        )
        conn.exec_driver_sql("DELETE FROM alembic_version")
        conn.exec_driver_sql(
            f"INSERT INTO alembic_version VALUES ('{RUNTIME_REQUIRED_MIGRATION_HEAD}')"
        )

    def durable(enrollment_id: str) -> int:
        return _committed_rows(
            path,
            "SELECT count(*) FROM worker_enrollment_state WHERE enrollment_id=?",
            (enrollment_id,),
        )

    result = svc.create_supported_invitation(
        session,
        principal,
        idempotency_key=secrets.token_urlsafe(24),
        deployment_site_label="rack-01.eu_a",
        ttl_seconds=3600,
        created_at="2026-01-01T00:00:00+00:00",
        expires_at="2026-01-01T01:00:00+00:00",
    )
    eid = result.enrollment_id

    assert durable(eid) == 0, (
        "the enrollment became durable at RELEASE SAVEPOINT, before the caller committed — "
        "the caller no longer owns the transaction boundary"
    )

    session.rollback()
    assert durable(eid) == 0, (
        "a pre-commit rollback left the enrollment behind, contradicting the boundary "
        "worker_enrollment_repository documents"
    )

    # Positive control: the same call, committed, IS durable — so the zeros above are the
    # transaction boundary holding, not the write silently failing.
    kept = svc.create_supported_invitation(
        session,
        principal,
        idempotency_key=secrets.token_urlsafe(24),
        deployment_site_label="rack-01.eu_a",
        ttl_seconds=3600,
        created_at="2026-01-01T00:00:00+00:00",
        expires_at="2026-01-01T01:00:00+00:00",
    )
    session.commit()
    assert durable(kept.enrollment_id) == 1
