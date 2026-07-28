"""Real-PostgreSQL enrollment-signer provisioning one-shot + hostile-repair fence (SECP-PR5H-B2 C4).

Runs ONLY when ``SECP_TEST_POSTGRES_URL`` is set (CI provisions PostgreSQL); it never skips in the
fence. It drives the ACTUAL provisioning one-shot (``run_provision`` over the injected reader seam +
a real admin engine) and proves, all executing against a real PostgreSQL under the dedicated role:

  * the one-shot creates the role; a client authenticates with the PLAINTEXT that produced the
    handed-off SCRAM verifier (the verifier derivation matches PostgreSQL's own), a wrong plaintext
    is rejected, and re-provisioning ROTATES the credential (the old plaintext then fails, the new
    works);
  * the provisioned role is exactly least-privilege: SELECT on the one identity table; no
    INSERT/UPDATE/DELETE; no unrelated-table read; no table creation; closed attributes INCLUDING
    ``NOINHERIT`` + ``NOREPLICATION``;
  * ``SET ROLE`` to a privileged role is refused (no membership escalation path) and ``RESET ROLE``
    cannot reveal an admin — the session role remains the signer;
  * a pre-existing HOSTILE role is normalized completely: role memberships in BOTH directions are
    revoked, and sequence / function privileges are stripped;
  * a hostile role that OWNS an object is REFUSED (``provision_role_owns_objects``) — the one-shot
    does not silently keep the foothold — and the owned object is left intact for the operator.

It contacts only the ephemeral job-local database and no deployment infrastructure.
"""

from __future__ import annotations

import os

import pytest
from secp_api import provision_enrollment_signer_role_once as mod
from secp_api.models import Base
from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD
from secp_commissioning.canonical import canonical_json
from secp_commissioning.enrollment_signer_role import (
    ENROLLMENT_SIGNER_DB_ROLE,
    generate_signer_db_password,
    scram_sha256_verifier,
)
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError, ProgrammingError

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run the signer provisioning + repair fence"
)

_ROLE = ENROLLMENT_SIGNER_DB_ROLE
_GROUP = "secp_test_hostile_group"
_CHILD = "secp_test_hostile_child"
_PRIV = "secp_test_privileged"


def _role_url(password: str) -> str:
    return (
        make_url(PG_URL)
        .set(username=_ROLE, password=password)
        .render_as_string(hide_password=False)
    )


def _create_stale_signer(conn) -> None:
    """Pre-seed a plain LOGIN signer role, as a hostile predecessor install could have left it."""
    conn.exec_driver_sql(
        f"CREATE ROLE {_ROLE} LOGIN PASSWORD 'stale-pw' "
        "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
    )


def _handoff(verifier: str, *, operation_id="op-prov") -> bytes:
    return canonical_json(
        {
            "schema": mod._HANDOFF_SCHEMA,
            "operation_id": operation_id,
            "scram_verifier": verifier,
            "created_at": "2026-07-28T00:00:00Z",
        }
    ).encode()


def _provision(admin, password: str, *, operation_id="op-prov"):
    verifier = scram_sha256_verifier(password)
    assert password not in verifier  # the plaintext is never embedded, only the verifier
    return mod.run_provision(
        read_handoff=lambda: _handoff(verifier, operation_id=operation_id), engine=admin
    )


def _drop_roles(conn) -> None:
    for role in (_ROLE, _GROUP, _CHILD, _PRIV):
        exists = conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}
        ).scalar()
        if exists:
            conn.exec_driver_sql(f'DROP OWNED BY "{role}"')
            conn.exec_driver_sql(f'DROP ROLE "{role}"')


@pytest.fixture
def pg():
    assert PG_URL
    admin = create_engine(PG_URL, future=True)
    ac = create_engine(PG_URL, future=True, isolation_level="AUTOCOMMIT")
    with ac.connect() as conn:
        _drop_roles(conn)
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
    try:
        yield admin, ac
    finally:
        with ac.connect() as conn:
            _drop_roles(conn)
        admin.dispose()
        ac.dispose()


def _flag(admin, column: str) -> bool:
    with admin.connect() as conn:
        return bool(
            conn.execute(
                text(f"SELECT {column} FROM pg_roles WHERE rolname = :r"), {"r": _ROLE}
            ).scalar()
        )


def test_one_shot_creates_role_and_scram_plaintext_authenticates(pg):
    admin, _ac = pg
    password = generate_signer_db_password()
    code, receipt = _provision(admin, password)
    assert code == mod.EXIT_OK
    assert receipt["can_login"] and receipt["owns_nothing"] and receipt["no_memberships"]
    role_engine = create_engine(_role_url(password), future=True)
    try:
        with role_engine.connect() as conn:
            assert conn.execute(text("SELECT 1")).scalar() == 1  # SCRAM verifier is correct
    finally:
        role_engine.dispose()


def test_wrong_plaintext_is_rejected(pg):
    admin, _ac = pg
    _provision(admin, generate_signer_db_password())
    wrong = create_engine(_role_url(generate_signer_db_password()), future=True)
    try:
        with pytest.raises(OperationalError):  # SCRAM really enforced
            with wrong.connect():
                pass
    finally:
        wrong.dispose()


def test_credential_rotation_invalidates_the_old_plaintext(pg):
    admin, _ac = pg
    pw1 = generate_signer_db_password()
    pw2 = generate_signer_db_password()
    _provision(admin, pw1, operation_id="op-1")
    _provision(admin, pw2, operation_id="op-2")  # re-provision rotates the SCRAM password
    old = create_engine(_role_url(pw1), future=True)
    new = create_engine(_role_url(pw2), future=True)
    try:
        with pytest.raises(OperationalError):
            with old.connect():
                pass
        with new.connect() as conn:
            assert conn.execute(text("SELECT 1")).scalar() == 1
    finally:
        old.dispose()
        new.dispose()


def test_provisioned_role_is_exactly_least_privilege(pg):
    admin, _ac = pg
    password = generate_signer_db_password()
    _provision(admin, password)
    other = next(t for t in Base.metadata.tables if t != "controller_enrollment_identity")
    role_engine = create_engine(_role_url(password), future=True)
    try:
        with role_engine.connect() as conn:
            conn.execute(text("SELECT count(*) FROM controller_enrollment_identity"))  # permitted
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


def test_role_attributes_are_closed_including_noinherit_and_noreplication(pg):
    admin, _ac = pg
    _provision(admin, generate_signer_db_password())
    with admin.connect() as conn:
        flags = conn.execute(
            text(
                "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication, "
                "rolinherit, rolcanlogin FROM pg_roles WHERE rolname = :r"
            ),
            {"r": _ROLE},
        ).one()
    # closed: not super/createrole/createdb/bypassrls/replication/inherit; only LOGIN is true
    assert flags == (False, False, False, False, False, False, True)


def test_set_role_to_a_privileged_role_is_refused_and_reset_cannot_reveal_admin(pg):
    admin, ac = pg
    password = generate_signer_db_password()
    _provision(admin, password)
    with ac.connect() as conn:
        conn.exec_driver_sql(f'CREATE ROLE "{_PRIV}" NOLOGIN CREATEDB CREATEROLE')
    other = next(t for t in Base.metadata.tables if t != "controller_enrollment_identity")
    role_engine = create_engine(_role_url(password), future=True)
    try:
        with role_engine.connect() as conn:
            with pytest.raises(ProgrammingError):  # not a member -> SET ROLE refused
                conn.execute(text(f'SET ROLE "{_PRIV}"'))
        with role_engine.connect() as conn:
            conn.execute(text("RESET ROLE"))
            assert conn.execute(text("SELECT current_user")).scalar() == _ROLE
            with pytest.raises(ProgrammingError):  # RESET did not reveal any broader privilege
                conn.execute(text(f"SELECT * FROM {other} LIMIT 1"))
    finally:
        role_engine.dispose()


def test_hostile_memberships_in_both_directions_are_repaired(pg):
    admin, ac = pg
    with ac.connect() as conn:
        _create_stale_signer(conn)
        conn.exec_driver_sql(f'CREATE ROLE "{_GROUP}" NOLOGIN')
        conn.exec_driver_sql(f'CREATE ROLE "{_CHILD}" NOLOGIN')
        conn.exec_driver_sql(f'GRANT "{_GROUP}" TO {_ROLE}')  # signer is a MEMBER of the group
        conn.exec_driver_sql(f'GRANT {_ROLE} TO "{_CHILD}"')  # child can SET ROLE into the signer
    code, receipt = _provision(admin, generate_signer_db_password())
    assert code == mod.EXIT_OK and receipt["no_memberships"] is True
    with admin.connect() as conn:
        remaining = conn.execute(
            text(
                "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r "
                "ON (m.member = r.oid OR m.roleid = r.oid) WHERE r.rolname = :r"
            ),
            {"r": _ROLE},
        ).scalar()
        assert remaining == 0  # every membership, both directions, revoked


def test_hostile_sequence_and_function_privileges_are_stripped(pg):
    admin, ac = pg
    with ac.connect() as conn:
        _create_stale_signer(conn)
        conn.exec_driver_sql("CREATE SEQUENCE secp_test_hostile_seq")
        conn.exec_driver_sql(f"GRANT USAGE, SELECT ON SEQUENCE secp_test_hostile_seq TO {_ROLE}")
        conn.exec_driver_sql(
            "CREATE FUNCTION secp_test_hostile_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'"
        )
        # PUBLIC gets EXECUTE by default; revoke it so the role's DIRECT grant is the only path
        conn.exec_driver_sql("REVOKE EXECUTE ON FUNCTION secp_test_hostile_fn() FROM PUBLIC")
        conn.exec_driver_sql(f"GRANT EXECUTE ON FUNCTION secp_test_hostile_fn() TO {_ROLE}")
    with admin.connect() as conn:  # precondition: the hostile privileges are really present
        assert conn.execute(
            text("SELECT has_sequence_privilege(:r, 'secp_test_hostile_seq', 'USAGE')"),
            {"r": _ROLE},
        ).scalar()
        assert conn.execute(
            text("SELECT has_function_privilege(:r, 'secp_test_hostile_fn()', 'EXECUTE')"),
            {"r": _ROLE},
        ).scalar()
    code, _ = _provision(admin, generate_signer_db_password())
    assert code == mod.EXIT_OK
    with admin.connect() as conn:
        assert not conn.execute(
            text("SELECT has_sequence_privilege(:r, 'secp_test_hostile_seq', 'USAGE')"),
            {"r": _ROLE},
        ).scalar()
        assert not conn.execute(
            text("SELECT has_function_privilege(:r, 'secp_test_hostile_fn()', 'EXECUTE')"),
            {"r": _ROLE},
        ).scalar()


def test_hostile_owned_object_is_refused_not_silently_kept(pg):
    admin, ac = pg
    with ac.connect() as conn:
        _create_stale_signer(conn)
        conn.exec_driver_sql("CREATE TABLE secp_test_owned (x int)")
        conn.exec_driver_sql(f"ALTER TABLE secp_test_owned OWNER TO {_ROLE}")
    code, payload = _provision(admin, generate_signer_db_password())
    assert code == mod.EXIT_ROLE_POSTURE_INVALID
    assert payload["reason_code"] == "provision_role_owns_objects"
    with admin.connect() as conn:  # refused, not silently dropped: the owned object is still there
        owner = conn.execute(
            text("SELECT tableowner FROM pg_tables WHERE tablename = 'secp_test_owned'")
        ).scalar()
        assert owner == _ROLE
