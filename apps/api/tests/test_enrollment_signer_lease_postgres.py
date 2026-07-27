"""Real-PostgreSQL least-privilege signer-lease proof (SECP-PR5H-B1, C4).

Runs ONLY when ``SECP_TEST_POSTGRES_URL`` is set (CI provisions a PostgreSQL service); it never
skips in the fence. It proves the security claim the previous ``SELECT ... FOR UPDATE`` lease could
NOT keep: a DEDICATED ``secp_enrollment_signer`` role — a plain ``LOGIN`` role that is NOT a
superuser, owns nothing, and is granted ONLY ``CONNECT`` + schema ``USAGE`` + ``SELECT`` on the one
identity table — can actually acquire and hold the signing lease, because the lease now serializes
through the shared transaction-level ADVISORY lock (executable by PUBLIC) instead of a row lock that
PostgreSQL would refuse to a SELECT-only role.

Proven, all EXECUTING against a real PostgreSQL under the EXACT least-privilege role:
  * the signing lease succeeds under the role;
  * controller-identity rotation serializes behind an in-flight lease (the shared advisory lock is
    held exclusively for the lease's transaction) and the lock frees on release;
  * a real rotation succeeds once the lease exits;
  * the role CANNOT read an unrelated table, and CANNOT insert/update/delete the identity table;
  * the role is not a superuser / createrole / createdb and does not own the identity table.
"""

from __future__ import annotations

import os

import pytest
from secp_api.controller_identity_dev import build_test_verified_controller_identity
from secp_api.models import Base
from secp_api.services.controller_identity import activate_controller_identity
from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD
from secp_commissioning.controller_enrollment_signer import (
    ENROLLMENT_IDENTITY_ADVISORY_LOCK_KEY as LOCK_KEY,
)
from secp_management.enrollment_signer_identity import (
    ENROLLMENT_SIGNER_DB_GRANTS,
    DbActiveControllerSigningIdentityProvider,
)
from secp_management.enrollment_signer_identity import (
    ENROLLMENT_SIGNER_DB_ROLE as ROLE,
)
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import sessionmaker

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run the least-privilege signer-lease proof"
)

_ROLE_PW = "signer-least-privilege-test-pw"  # noqa: S105 - a throwaway CI-local test role password
_PROOF_ID = "enrkp:" + "a" * 64  # a grammar-valid enrollment-key proof id for the lease type


def _role_url() -> str:
    return (
        make_url(PG_URL).set(username=ROLE, password=_ROLE_PW).render_as_string(hide_password=False)
    )


def _drop_role(conn) -> None:
    exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": ROLE}).scalar()
    if exists:
        conn.exec_driver_sql(f"DROP OWNED BY {ROLE}")  # revokes every privilege granted to the role
        conn.exec_driver_sql(f"DROP ROLE {ROLE}")


def _seed_active_identity(engine, *, anchor: str = "11" * 32) -> None:
    factory = sessionmaker(bind=engine, autoflush=False, future=True)
    with factory() as s:
        activate_controller_identity(
            s,
            build_test_verified_controller_identity(
                controller_trust_anchor_hex=anchor, enrollment_key_proof_id=_PROOF_ID
            ),
        )
        s.commit()


@pytest.fixture
def pg():
    assert PG_URL
    admin = create_engine(PG_URL, future=True)
    ac = create_engine(PG_URL, future=True, isolation_level="AUTOCOMMIT")
    db = make_url(PG_URL).database
    with ac.connect() as conn:
        _drop_role(conn)
    with admin.begin() as conn:
        conn.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        conn.exec_driver_sql("CREATE SCHEMA public")
    Base.metadata.create_all(admin)
    # This fence step drops + recreates the schema, so RESTORE the alembic head marker the fence's
    # subsequent "live Alembic head" proof reads (mirrors the sibling *_postgres.py fixtures) — its
    # absence would fail that later step with a bare UndefinedTable, not a real regression.
    with admin.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS alembic_version (version_num varchar(32) primary key)"
        )
        conn.exec_driver_sql("DELETE FROM alembic_version")
        conn.exec_driver_sql(
            f"INSERT INTO alembic_version VALUES ('{RUNTIME_REQUIRED_MIGRATION_HEAD}')"
        )
    with ac.connect() as conn:
        # a plain LOGIN role: not a superuser, cannot create roles/dbs, owns nothing
        conn.exec_driver_sql(
            f"CREATE ROLE {ROLE} LOGIN PASSWORD '{_ROLE_PW}' "
            "NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"
        )
        conn.exec_driver_sql(f"GRANT CONNECT ON DATABASE {db} TO {ROLE}")
        for stmt in ENROLLMENT_SIGNER_DB_GRANTS:  # USAGE on schema + SELECT on the identity table
            conn.exec_driver_sql(stmt)
    role_engine = create_engine(_role_url(), future=True)
    try:
        yield admin, role_engine
    finally:
        role_engine.dispose()
        with ac.connect() as conn:
            _drop_role(conn)
        admin.dispose()
        ac.dispose()


def test_signing_lease_succeeds_under_the_exact_least_privilege_role(pg):
    admin, role = pg
    _seed_active_identity(admin)
    provider = DbActiveControllerSigningIdentityProvider(role)
    with provider.lease() as lease:
        assert lease.controller_installation_id == "controller-dev0001"
        assert lease.enrollment_key_proof_id == _PROOF_ID
        assert lease.controller_key_id.startswith("sha256:")


def test_rotation_serializes_behind_an_active_signing_lease(pg):
    admin, role = pg
    _seed_active_identity(admin)
    provider = DbActiveControllerSigningIdentityProvider(role)
    with provider.lease():
        # while the lease holds pg_advisory_xact_lock(LOCK_KEY) for its transaction, NO other
        # session can take the same lock — so a rotation (which takes it) would block behind us.
        with admin.connect() as conn:
            got = conn.execute(
                text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": LOCK_KEY}
            ).scalar()
            assert got is False
    # the lease released -> the shared lock is free again, so a rotation could now acquire it
    with admin.connect() as conn:
        got = conn.execute(text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": LOCK_KEY}).scalar()
        assert got is True


def test_release_permits_a_real_rotation(pg):
    admin, role = pg
    _seed_active_identity(admin)
    provider = DbActiveControllerSigningIdentityProvider(role)
    with provider.lease():
        pass  # acquire + release the lease (and its advisory lock)
    _seed_active_identity(admin, anchor="22" * 32)  # a real rotation acquires the same lock
    with admin.connect() as conn:
        active = conn.execute(
            text("SELECT count(*) FROM controller_enrollment_identity WHERE status = 'active'")
        ).scalar()
        assert active == 1


def test_the_role_cannot_read_an_unrelated_table(pg):
    admin, role = pg
    _seed_active_identity(admin)
    other = next(t for t in Base.metadata.tables if t != "controller_enrollment_identity")
    with role.connect() as conn:
        with pytest.raises(ProgrammingError):  # InsufficientPrivilege
            conn.execute(text(f"SELECT * FROM {other} LIMIT 1"))


def test_the_role_cannot_write_the_identity_table(pg):
    admin, role = pg
    _seed_active_identity(admin)
    for stmt in (
        "INSERT INTO controller_enrollment_identity DEFAULT VALUES",
        "UPDATE controller_enrollment_identity SET verified = verified",
        "DELETE FROM controller_enrollment_identity",
    ):
        with role.connect() as conn:
            with pytest.raises(ProgrammingError):  # InsufficientPrivilege (checked before columns)
                conn.execute(text(stmt))


def test_the_role_is_not_superuser_and_owns_nothing(pg):
    admin, role = pg
    with admin.connect() as conn:
        flags = conn.execute(
            text(
                "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls "
                "FROM pg_roles WHERE rolname = :r"
            ),
            {"r": ROLE},
        ).one()
        assert flags == (False, False, False, False)
        owner = conn.execute(
            text(
                "SELECT tableowner FROM pg_tables "
                "WHERE tablename = 'controller_enrollment_identity'"
            )
        ).scalar()
        assert owner != ROLE
