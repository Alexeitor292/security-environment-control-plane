"""Real-PostgreSQL SCRAM dedicated-role provisioning fence (SECP-PR5H-B2, commit 2b-2).

Runs ONLY when ``SECP_TEST_POSTGRES_URL`` is set (CI provisions PostgreSQL); it never skips in the
fence. It proves the 2b-2 provisioning path end to end against a real PostgreSQL:

  * the ``secp_enrollment_signer`` role is provisioned by applying EXACTLY the reviewed
    ``render_signer_role_sql(...)`` statements, whose password value is the locally-computed
    SCRAM-SHA-256 VERIFIER (never the plaintext);
  * a client authenticates with the PLAINTEXT that produced that verifier — the authoritative proof
    that :func:`scram_sha256_verifier` matches PostgreSQL's own SCRAM derivation (a wrong
    PBKDF2/HMAC
    chain fails to authenticate here);
  * a WRONG plaintext is rejected (SCRAM is really enforced, not a no-op);
  * the provisioned role is exactly least-privilege: SELECT on the one identity table, no
    INSERT/UPDATE/DELETE, no unrelated-table read, no table creation, and not
    superuser/createrole/createdb/bypassrls;
  * re-applying the statements is idempotent (a re-install does not fail on the existing role).

It contacts only the ephemeral job-local database and no deployment infrastructure.
"""

from __future__ import annotations

import os

import pytest
from secp_api.models import Base
from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD
from secp_management.enrollment_signer_db import (
    generate_signer_db_password,
    render_signer_role_sql,
    scram_sha256_verifier,
)
from secp_management.enrollment_signer_identity import ENROLLMENT_SIGNER_DB_ROLE as ROLE
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError, ProgrammingError

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL,
    reason="set SECP_TEST_POSTGRES_URL to run the SCRAM dedicated-role provisioning fence",
)


def _role_url(password: str) -> str:
    return (
        make_url(PG_URL).set(username=ROLE, password=password).render_as_string(hide_password=False)
    )


def _drop_role(conn) -> None:
    exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": ROLE}).scalar()
    if exists:
        conn.exec_driver_sql(f"DROP OWNED BY {ROLE}")
        conn.exec_driver_sql(f"DROP ROLE {ROLE}")


def _provision(ac, password: str) -> None:
    """Apply EXACTLY the reviewed provisioning statements (verifier password, never plaintext)."""
    verifier = scram_sha256_verifier(password)
    assert "SCRAM-SHA-256$" in verifier and password not in verifier  # plaintext never embedded
    with ac.connect() as conn:
        for stmt in render_signer_role_sql(verifier):
            conn.exec_driver_sql(stmt)


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
    # This fence drops + recreates the schema, so RESTORE the alembic-head marker the dedicated
    # PostgreSQL fence job's later "live Alembic head" step reads (mirrors the sibling *_postgres.py
    # fixtures) — its absence would fail that step with a bare UndefinedTable, not a real
    # regression.
    with admin.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS alembic_version (version_num varchar(32) primary key)"
        )
        conn.exec_driver_sql("DELETE FROM alembic_version")
        conn.exec_driver_sql(
            f"INSERT INTO alembic_version VALUES ('{RUNTIME_REQUIRED_MIGRATION_HEAD}')"
        )
    try:
        yield admin, ac
    finally:
        with ac.connect() as conn:
            _drop_role(conn)
        admin.dispose()
        ac.dispose()


def test_scram_verifier_authenticates_against_real_postgres(pg):
    _admin, ac = pg
    password = generate_signer_db_password()
    _provision(ac, password)
    role_engine = create_engine(_role_url(password), future=True)
    try:
        with role_engine.connect() as conn:
            assert conn.execute(text("SELECT 1")).scalar() == 1  # SCRAM verifier is correct
    finally:
        role_engine.dispose()


def test_wrong_password_is_rejected(pg):
    _admin, ac = pg
    _provision(ac, generate_signer_db_password())
    wrong = create_engine(_role_url(generate_signer_db_password()), future=True)
    try:
        with pytest.raises(OperationalError):  # SCRAM authentication really enforced
            with wrong.connect():
                pass
    finally:
        wrong.dispose()


def test_provisioned_role_is_exactly_least_privilege(pg):
    _admin, ac = pg
    password = generate_signer_db_password()
    _provision(ac, password)
    role_engine = create_engine(_role_url(password), future=True)
    other = next(t for t in Base.metadata.tables if t != "controller_enrollment_identity")
    try:
        with role_engine.connect() as conn:
            # SELECT on the one identity table is permitted
            conn.execute(text("SELECT count(*) FROM controller_enrollment_identity"))
        for stmt in (
            "INSERT INTO controller_enrollment_identity DEFAULT VALUES",
            "UPDATE controller_enrollment_identity SET verified = verified",
            "DELETE FROM controller_enrollment_identity",
            f"SELECT * FROM {other} LIMIT 1",
            "CREATE TABLE secp_signer_scratch (x int)",  # PG15+ PUBLIC has no CREATE on public
        ):
            with role_engine.connect() as conn:
                with pytest.raises(ProgrammingError):  # InsufficientPrivilege
                    conn.execute(text(stmt))
    finally:
        role_engine.dispose()


def test_role_flags_are_closed(pg):
    admin, ac = pg
    _provision(ac, generate_signer_db_password())
    with admin.connect() as conn:
        flags = conn.execute(
            text(
                "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolcanlogin "
                "FROM pg_roles WHERE rolname = :r"
            ),
            {"r": ROLE},
        ).one()
        assert flags == (False, False, False, False, True)  # a plain LOGIN role, nothing more


def test_provisioning_is_idempotent(pg):
    _admin, ac = pg
    password = generate_signer_db_password()
    _provision(ac, password)
    _provision(ac, password)  # re-install: the DO/IF-NOT-EXISTS guard must not fail on the role
    role_engine = create_engine(_role_url(password), future=True)
    try:
        with role_engine.connect() as conn:
            assert conn.execute(text("SELECT 1")).scalar() == 1
    finally:
        role_engine.dispose()
