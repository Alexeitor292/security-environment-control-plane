"""Real-PostgreSQL finalization dedicated-role proof + reobservation (SECP-PR5H-B2, 2b-3b-iii).

Runs ONLY when ``SECP_TEST_POSTGRES_URL`` is set (CI provisions PostgreSQL); it never skips in the
fence. It proves the 2b-3b-iii DB paths against a real PostgreSQL under the EXACT dedicated
least-privilege ``secp_enrollment_signer`` role:

  * ``build_signer_role_engine`` (the fixed-coordinate dedicated-role Engine builder) authenticates
    with the SCRAM plaintext and pins the UTC session TimeZone;
  * the role can take the shared advisory lock (executable by PUBLIC) — the
  ``_prove_dedicated_role``
    behavior — with NO extra grant;
  * a wrong plaintext is rejected (auth really enforced);
  * the management-plane ACTIVE-identity reobservation returns the exact active identity facts as
  the
    dedicated role over raw SQL (no ``secp_api`` import).

It contacts only the ephemeral job-local database and no deployment infrastructure.
"""

from __future__ import annotations

import os

import pytest
from secp_api.controller_identity_dev import build_test_verified_controller_identity
from secp_api.models import Base
from secp_api.services.controller_identity import activate_controller_identity
from secp_commissioning.controller_enrollment_signer import ENROLLMENT_IDENTITY_ADVISORY_LOCK_KEY
from secp_management.enrollment_signer_db import (
    ENROLLMENT_SIGNER_DB_ROLE,
    build_signer_role_engine,
    generate_signer_db_password,
    render_signer_role_sql,
    scram_sha256_verifier,
)
from secp_management.enrollment_signer_identity import DbActiveControllerSigningIdentityProvider
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run the finalization dedicated-role fence"
)
_PROOF_ID = "enrkp:" + "a" * 64


def _drop_role(conn) -> None:
    if conn.execute(
        text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": ENROLLMENT_SIGNER_DB_ROLE}
    ).scalar():
        conn.exec_driver_sql(f"DROP OWNED BY {ENROLLMENT_SIGNER_DB_ROLE}")
        conn.exec_driver_sql(f"DROP ROLE {ENROLLMENT_SIGNER_DB_ROLE}")


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
    password = generate_signer_db_password()
    with (
        ac.connect() as conn
    ):  # provision the dedicated role exactly as the reviewed SQL renders it
        for stmt in render_signer_role_sql(scram_sha256_verifier(password)):
            conn.exec_driver_sql(stmt)
    with sessionmaker(bind=admin, future=True)() as s:  # seed the single ACTIVE identity
        activate_controller_identity(
            s, build_test_verified_controller_identity(enrollment_key_proof_id=_PROOF_ID)
        )
        s.commit()
    try:
        yield password
    finally:
        with ac.connect() as conn:
            _drop_role(conn)
        admin.dispose()
        ac.dispose()


def test_build_signer_role_engine_authenticates_and_takes_the_advisory_lock(pg):
    engine = build_signer_role_engine(pg, base_url=PG_URL)
    try:
        with engine.begin() as conn:
            assert conn.execute(text("SELECT current_user")).scalar() == ENROLLMENT_SIGNER_DB_ROLE
            # the SELECT-only role can take the shared lock (executable by PUBLIC) — no extra grant
            conn.execute(
                text("SELECT pg_advisory_xact_lock(:k)"),
                {"k": ENROLLMENT_IDENTITY_ADVISORY_LOCK_KEY},
            )
            assert conn.execute(text("SHOW timezone")).scalar().upper() == "UTC"
    finally:
        engine.dispose()


def test_wrong_plaintext_is_rejected(pg):
    engine = build_signer_role_engine(generate_signer_db_password(), base_url=PG_URL)
    try:
        with pytest.raises(OperationalError):
            with engine.begin():
                pass
    finally:
        engine.dispose()


def test_dedicated_role_reobserves_the_active_identity(pg):
    engine = build_signer_role_engine(pg, base_url=PG_URL)
    try:
        with DbActiveControllerSigningIdentityProvider(engine).lease() as lease:
            assert lease.controller_installation_id == "controller-dev0001"
            assert lease.enrollment_key_proof_id == _PROOF_ID
            assert lease.controller_key_id.startswith("sha256:")
            assert "|" in lease.activation_token and str(lease.row_id) in lease.activation_token
    finally:
        engine.dispose()


def test_dedicated_role_cannot_write_the_identity_table(pg):
    engine = build_signer_role_engine(pg, base_url=PG_URL)
    try:
        from sqlalchemy.exc import ProgrammingError

        with pytest.raises(ProgrammingError):  # SELECT-only: writes refuse
            with engine.begin() as conn:
                conn.execute(text("UPDATE controller_enrollment_identity SET verified = verified"))
    finally:
        engine.dispose()
