"""Database engine and session management.

SQLAlchemy 2.0, synchronous. SQLite for tests/zero-dependency local runs;
PostgreSQL in the dev Docker stack. The model layer is portable across both.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from secp_api.config import get_settings

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def _make_engine(database_url: str) -> Engine:
    connect_args: dict = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    engine = create_engine(
        database_url,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )
    if database_url.startswith("sqlite"):
        # Enforce foreign keys on SQLite (off by default).
        from sqlalchemy import event

        @event.listens_for(engine, "connect")
        def _fk_pragma(dbapi_conn, _record):  # type: ignore[no-untyped-def]
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        @event.listens_for(engine, "before_cursor_execute")
        def _begin_before_savepoint(  # type: ignore[no-untyped-def]
            conn, cursor, statement, parameters, context, executemany
        ):
            """Make sure a SAVEPOINT is never the OUTERMOST transaction on SQLite.

            pysqlite's legacy mode emits an implicit ``BEGIN`` only for statements it recognizes
            as DML.  It does **not** recognize ``SAVEPOINT``.  So a ``Session.begin_nested()``
            taken before any INSERT/UPDATE/DELETE on that connection opens the savepoint in
            autocommit — and SQLite *commits* an outermost savepoint on ``RELEASE``.  The nested
            block's writes become durable at ``RELEASE``, before the caller commits, and the
            caller's later ``rollback()`` cannot undo them.

            Beginning a real transaction first keeps the savepoint nested, so ``RELEASE``
            releases and the caller's transaction stays the only commit point.

            Deliberately narrow: this fires ONLY for ``SAVEPOINT``, so read-only and ordinary
            DML transactions keep pysqlite's existing behaviour and hold no lock they did not
            hold before.  Emitting ``BEGIN`` for every transaction instead would make read-only
            work hold SHARED to commit and deadlock concurrent writers.

            PostgreSQL needs none of this: psycopg opens a transaction before the first
            statement, so a savepoint is always nested there already.
            """
            if not statement.lstrip().upper().startswith("SAVEPOINT"):
                return
            dbapi_conn = conn.connection.dbapi_connection
            if not dbapi_conn.in_transaction:
                # raw DBAPI execute: does not re-enter this event, and leaves pysqlite's own
                # bookkeeping consistent (it defers to sqlite3_get_autocommit()).
                dbapi_conn.execute("BEGIN")

    return engine


def get_engine() -> Engine:
    global _engine, _SessionLocal
    if _engine is None:
        _engine = _make_engine(get_settings().database_url)
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, future=True)
    return _engine


def get_sessionmaker() -> sessionmaker[Session]:
    get_engine()
    assert _SessionLocal is not None
    return _SessionLocal


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session scope: commit on success, rollback on error."""
    factory = get_sessionmaker()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency: a request-scoped session (commit/rollback handled here)."""
    factory = get_sessionmaker()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def reset_engine_for_tests(database_url: str) -> Engine:
    """Rebind the global engine/sessionmaker to a fresh database (test helper)."""
    global _engine, _SessionLocal
    _engine = _make_engine(database_url)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, future=True)
    return _engine
