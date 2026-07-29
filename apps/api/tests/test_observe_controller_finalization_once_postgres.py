"""Real-PostgreSQL controller-finalization DB-state observation fence (SECP-PR5H-B2, 2b-3c-c).

Runs ONLY when ``SECP_TEST_POSTGRES_URL`` is set (CI provisions PostgreSQL); it never skips in the
fence. Everything the hermetic suite has to inject — the ``pg_roles`` / ``pg_auth_members`` /
``pg_class`` / ``pg_authid`` catalog observation, ``has_*_privilege`` evaluation, ``aclexplode``,
``to_regclass`` — is exercised here for real, driving the ACTUAL one-shot (``run_observation``
over a live admin engine) against a live database, and it proves:

  * a clean database is a PROVEN absence (``absent``, exit 0) and the printed projection is exactly
    the five canonical fields the reviewed management parser pins;
  * the role the REAL provisioning one-shot creates observes ``exact`` in every dimension — the
    closed attribute set, zero memberships in either direction, zero owned objects, schema USAGE
    without CREATE, SELECT-only on the ONE identity table, no reach into the write-once receipt
    table, and a SCRAM LOGIN credential posture derived WITHOUT reading one verifier byte;
  * every live privilege / membership / ownership / attribute / credential DRIFT is detected;
  * the ACTIVE identity, its exact public binding fields, and the durable activation GENERATION are
    observed through the real activation one-shot's own durable receipt;
  * CONFLICTING (>1 active) rows and a CORRUPT stored receipt fail closed with a non-zero exit and
    NO five-field projection line;
  * the observation MUTATES NOTHING (roles, grants, tables, rows and the durable receipt are
    byte-identical afterwards) and leaks no password, verifier, or DSN.

It contacts only the ephemeral job-local database and no deployment infrastructure.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime

import pytest
from secp_api import activate_controller_identity_once as activation
from secp_api import observe_controller_finalization_once as mod
from secp_api import provision_enrollment_signer_role_once as provisioning
from secp_api.controller_identity_dev import build_test_verified_controller_identity
from secp_api.models import Base
from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD
from secp_commissioning.canonical import canonical_json, sha256_bytes
from secp_commissioning.enrollment_signer_role import (
    ENROLLMENT_SIGNER_DB_ROLE,
    generate_signer_db_password,
    scram_sha256_verifier,
)
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run the finalization DB-observation fence"
)

_ROLE = ENROLLMENT_SIGNER_DB_ROLE
_GROUP = "secp_test_observe_group"
_CHILD = "secp_test_observe_child"
_T0 = "2026-07-28T00:00:00Z"
_NOW = datetime(2026, 7, 28, 0, 1, 0, tzinfo=UTC)

_A = build_test_verified_controller_identity()
_B = build_test_verified_controller_identity(
    controller_installation_id="controller-b0000001", controller_trust_anchor_hex="22" * 32
)


def _drop_roles(conn) -> None:
    for role in (_ROLE, _GROUP, _CHILD):
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
    factory = sessionmaker(bind=admin, autoflush=False, future=True)
    try:
        yield admin, ac, factory
    finally:
        with ac.connect() as conn:
            _drop_roles(conn)
        admin.dispose()
        ac.dispose()


def _shadow_readable(admin) -> bool:
    """Whether THIS connection may read the shadow catalog. CI's ``POSTGRES_USER`` is a superuser,
    so the credential posture is normally provable; a non-superuser admin makes it ``unobservable``,
    which the observer must fail CLOSED on (never "exact"). Branching on the observed capability
    keeps the fence deterministic and skip-free either way."""
    try:
        with admin.connect() as conn:
            conn.execute(text("SELECT 1 FROM pg_authid LIMIT 1"))
    except Exception:
        return False
    return True


def _provision(admin, password: str | None = None) -> str:
    secret = password or generate_signer_db_password()
    verifier = scram_sha256_verifier(secret)
    raw = canonical_json(
        {
            "schema": provisioning._HANDOFF_SCHEMA,
            "operation_id": "op-observe-fence",
            "scram_verifier": verifier,
            "created_at": _T0,
        }
    ).encode()
    code, receipt = provisioning.run_provision(read_handoff=lambda: raw, engine=admin)
    assert code == provisioning.EXIT_OK, receipt
    return secret


def _handoff(proof, *, operation_id: str = "op-1", **over) -> bytes:
    fields = {f: getattr(proof, f) for f in activation._IDENTITY_FIELDS}
    env: dict[str, object] = {
        "schema": activation.CONTROLLER_IDENTITY_ACTIVATION_SCHEMA,
        "operation_id": operation_id,
        "candidate_digest": sha256_bytes(canonical_json(dict(fields)).encode()),
        "expected_predecessor_row_id": None,
        "expected_predecessor_activation_token": None,
        "generation": 0,
        "handoff_created_at": _T0,
        **fields,
    }
    env.update(over)
    return canonical_json(env).encode()


def _activate(factory, proof, **over) -> dict:
    code, receipt = activation.run_activation(
        read_handoff=lambda: _handoff(proof, **over), session_factory=factory, now=_NOW
    )
    assert code == activation.EXIT_OK, receipt
    return receipt


def _observe(admin):
    return mod.run_observation(engine=admin)


# --------------------------------------------------------------------------- absence + exactness


def test_a_clean_database_is_a_proven_absence(pg):
    admin, _ac, _factory = pg
    code, payload = _observe(admin)
    assert code == mod.EXIT_OK
    assert payload["observed_state"] == "absent"
    assert payload["role_state"] == "absent" and payload["identity_state"] == "absent"
    assert payload["role_present"] is False and payload["active_identity_present"] is False
    assert payload["activation_generation"] is None
    assert payload["role_credential_posture"] == "absent"
    projection = mod.compat_projection(payload)
    assert set(projection) == set(mod.COMPAT_FIELDS)
    assert projection["role_name"] == _ROLE
    # byte-canonical, exactly what the reviewed management parser re-canonicalizes and compares
    assert canonical_json(json.loads(canonical_json(projection))) == canonical_json(projection)


def test_the_really_provisioned_role_observes_exact_in_every_dimension(pg):
    admin, _ac, _factory = pg
    _provision(admin)
    code, payload = _observe(admin)
    assert code == mod.EXIT_OK
    assert payload["role_present"] is True
    # the closed attribute set the reviewed provisioning SQL pins
    assert payload["role_attr_login"] is True
    for attribute in (
        "superuser",
        "createrole",
        "createdb",
        "bypassrls",
        "inherit",
        "replication",
    ):
        assert payload[f"role_attr_{attribute}"] is False, attribute
    assert payload["role_member_of_count"] == 0 and payload["role_members_count"] == 0
    assert payload["role_owned_objects"] == 0
    assert payload["role_priv_schema_usage"] is True
    assert payload["role_priv_schema_create"] is False
    assert payload["role_priv_identity_select"] is True
    assert payload["role_priv_identity_insert"] is False
    assert payload["role_priv_identity_update"] is False
    assert payload["role_priv_identity_delete"] is False
    assert payload["role_priv_receipt_any"] is False  # the write-once receipt table is unreachable
    assert payload["role_priv_other_tables_readable"] == 0
    assert payload["role_priv_sequences_privileged"] == 0
    assert payload["role_priv_routines_granted"] == 0
    if _shadow_readable(admin):
        assert payload["role_credential_posture"] == "scram_login"
        assert payload["role_credential_compatible"] is True
        assert payload["role_state"] == "exact" and payload["observed_state"] == "exact"
    else:  # an UNPROVABLE credential is never "exact" — fail closed, and say why
        assert payload["role_credential_posture"] == "unobservable"
        assert payload["role_credential_compatible"] is False
        assert payload["role_state"] == "drifted"


def test_a_role_with_no_password_is_not_credential_compatible(pg):
    admin, ac, _factory = pg
    _provision(admin)
    with ac.connect() as conn:
        conn.exec_driver_sql(f"ALTER ROLE {_ROLE} PASSWORD NULL")
    _code, payload = _observe(admin)
    if _shadow_readable(admin):
        assert payload["role_credential_posture"] == "no_password"
    assert payload["role_credential_compatible"] is False
    assert payload["role_state"] == "drifted"


# --------------------------------------------------------------------------- live drift detection


@pytest.mark.parametrize(
    "statement,field,expected",
    [
        (
            "GRANT INSERT ON controller_enrollment_identity TO {role}",
            "role_priv_identity_insert",
            True,
        ),
        (
            "GRANT UPDATE ON controller_enrollment_identity TO {role}",
            "role_priv_identity_update",
            True,
        ),
        (
            "GRANT DELETE ON controller_enrollment_identity TO {role}",
            "role_priv_identity_delete",
            True,
        ),
        (
            "GRANT SELECT ON controller_identity_activation_receipt TO {role}",
            "role_priv_receipt_any",
            True,
        ),
        ("GRANT CREATE ON SCHEMA public TO {role}", "role_priv_schema_create", True),
        ("REVOKE USAGE ON SCHEMA public FROM {role}", "role_priv_schema_usage", False),
        (
            "REVOKE SELECT ON controller_enrollment_identity FROM {role}",
            "role_priv_identity_select",
            False,
        ),
        ("ALTER ROLE {role} CREATEDB", "role_attr_createdb", True),
        ("ALTER ROLE {role} CREATEROLE", "role_attr_createrole", True),
        ("ALTER ROLE {role} REPLICATION", "role_attr_replication", True),
        ("ALTER ROLE {role} INHERIT", "role_attr_inherit", True),
        ("ALTER ROLE {role} NOLOGIN", "role_attr_login", False),
    ],
)
def test_live_privilege_and_attribute_drift_is_detected(pg, statement, field, expected):
    admin, ac, _factory = pg
    _provision(admin)
    with ac.connect() as conn:
        conn.exec_driver_sql(statement.format(role=_ROLE))
    code, payload = _observe(admin)
    assert code == mod.EXIT_OK  # drift is reported, never fatal
    assert payload[field] is expected
    assert payload["role_state"] == "drifted"
    assert payload["observed_state"] == "drifted"
    assert payload["role_present"] is True  # still unambiguously PRESENT


def test_live_memberships_in_both_directions_are_counted(pg):
    admin, ac, _factory = pg
    _provision(admin)
    with ac.connect() as conn:
        conn.exec_driver_sql(f'CREATE ROLE "{_GROUP}" NOLOGIN')
        conn.exec_driver_sql(f'CREATE ROLE "{_CHILD}" NOLOGIN')
        conn.exec_driver_sql(f'GRANT "{_GROUP}" TO {_ROLE}')  # the signer is a MEMBER of the group
        conn.exec_driver_sql(f'GRANT {_ROLE} TO "{_CHILD}"')  # the child can SET ROLE into it
    _code, payload = _observe(admin)
    assert payload["role_member_of_count"] == 1
    assert payload["role_members_count"] == 1
    assert payload["role_state"] == "drifted"


def test_a_live_owned_object_is_counted(pg):
    admin, ac, _factory = pg
    _provision(admin)
    with ac.connect() as conn:
        conn.exec_driver_sql("CREATE TABLE secp_test_observed_owned (x int)")
        conn.exec_driver_sql(f"ALTER TABLE secp_test_observed_owned OWNER TO {_ROLE}")
    _code, payload = _observe(admin)
    assert payload["role_owned_objects"] >= 1
    assert payload["role_state"] == "drifted"


def test_live_sequence_and_routine_grants_are_counted(pg):
    admin, ac, _factory = pg
    _provision(admin)
    with ac.connect() as conn:
        conn.exec_driver_sql("CREATE SEQUENCE secp_test_observed_seq")
        conn.exec_driver_sql(f"GRANT USAGE ON SEQUENCE secp_test_observed_seq TO {_ROLE}")
        conn.exec_driver_sql(
            "CREATE FUNCTION secp_test_observed_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'"
        )
        conn.exec_driver_sql(f"GRANT EXECUTE ON FUNCTION secp_test_observed_fn() TO {_ROLE}")
    _code, payload = _observe(admin)
    assert payload["role_priv_sequences_privileged"] == 1
    assert payload["role_priv_routines_granted"] == 1  # DIRECT grants only, never PUBLIC's default
    assert payload["role_state"] == "drifted"


def test_the_public_execute_default_is_not_mistaken_for_a_grant(pg):
    """PostgreSQL grants EXECUTE on every function to PUBLIC by default; the observation counts only
    DIRECT ACL entries, so an ordinary function must not manufacture a false drift."""
    admin, ac, _factory = pg
    _provision(admin)
    with ac.connect() as conn:
        conn.exec_driver_sql(
            "CREATE FUNCTION secp_test_public_default_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'"
        )
    _code, payload = _observe(admin)
    assert payload["role_priv_routines_granted"] == 0


def test_an_unrelated_readable_table_is_counted(pg):
    admin, ac, _factory = pg
    _provision(admin)
    other = next(t for t in Base.metadata.tables if t != "controller_enrollment_identity")
    with ac.connect() as conn:
        conn.exec_driver_sql(f"GRANT SELECT ON {other} TO {_ROLE}")
    _code, payload = _observe(admin)
    assert payload["role_priv_other_tables_readable"] == 1
    assert payload["role_state"] == "drifted"


# --------------------------------------------------------------------------- identity + generation


def test_the_active_identity_and_durable_generation_are_observed(pg):
    admin, _ac, factory = pg
    _provision(admin)
    receipt = _activate(factory, _A)
    code, payload = _observe(admin)
    assert code == mod.EXIT_OK
    assert payload["identity_state"] == "exact"
    assert payload["activation_receipt_state"] == "exact"
    assert payload["active_identity_present"] is True
    assert payload["activation_generation"] == 0
    assert payload["identity_active_rows"] == 1
    assert payload["identity_row_id"] == receipt["resulting_row_id"]
    assert payload["identity_activation_token"] == receipt["activation_token"]
    assert payload["identity_public_state_digest"] == receipt["resulting_public_state_digest"]
    for field in mod._IDENTITY_PUBLIC_FIELDS:
        assert payload[f"identity_{field}"] == getattr(_A, field)


def test_the_generation_tracks_a_real_rotation(pg):
    admin, _ac, factory = pg
    first = _activate(factory, _A)
    _activate(
        factory,
        _B,
        operation_id="op-2",
        expected_predecessor_row_id=first["resulting_row_id"],
        expected_predecessor_activation_token=first["activation_token"],
        generation=1,
    )
    _code, payload = _observe(admin)
    assert payload["activation_generation"] == 1
    assert payload["identity_controller_installation_id"] == _B.controller_installation_id
    assert payload["activation_receipt_rows"] == 2


def test_an_active_identity_with_no_durable_receipt_is_drift(pg):
    admin, _ac, factory = pg
    _activate(factory, _A)
    with admin.begin() as conn:
        conn.exec_driver_sql("DELETE FROM controller_identity_activation_receipt")
    code, payload = _observe(admin)
    assert code == mod.EXIT_OK
    assert payload["observed_state"] == "drifted"
    assert payload["activation_receipt_state"] == "absent"
    assert payload["activation_generation"] is None


# --------------------------------------------------------------------------- fail-closed states


def test_conflicting_active_identities_fail_closed(pg):
    admin, _ac, factory = pg
    first = _activate(factory, _A)
    _activate(
        factory,
        _B,
        operation_id="op-2",
        expected_predecessor_row_id=first["resulting_row_id"],
        expected_predecessor_activation_token=first["activation_token"],
        generation=1,
    )
    with admin.begin() as conn:  # manufacture the state the CHECK constraints exist to prevent
        conn.exec_driver_sql(
            "ALTER TABLE controller_enrollment_identity "
            "DROP CONSTRAINT ck_cei_active_marker_pairing"
        )
        conn.exec_driver_sql(
            "ALTER TABLE controller_enrollment_identity DROP CONSTRAINT ck_cei_superseded_pairing"
        )
        conn.exec_driver_sql(
            "UPDATE controller_enrollment_identity SET status = 'active' WHERE status='superseded'"
        )
    code, payload = _observe(admin)
    assert code == mod.EXIT_CONFLICTING
    assert payload["observed_state"] == "conflicting"
    assert payload["identity_active_rows"] == 2
    assert payload["identity_row_id"] is None and payload["activation_generation"] is None


def test_a_tampered_stored_receipt_fails_closed(pg):
    admin, _ac, factory = pg
    _activate(factory, _A)
    with admin.begin() as conn:
        conn.exec_driver_sql(
            "UPDATE controller_identity_activation_receipt "
            "SET receipt_json = replace(receipt_json, 'active', 'revoked')"
        )
    code, payload = _observe(admin)
    assert code == mod.EXIT_STATE_CORRUPT
    assert payload["observed_state"] == "corrupt"
    assert payload["activation_receipt_state"] == "corrupt"
    assert payload["activation_generation"] is None


def test_a_missing_identity_table_fails_closed_rather_than_reporting_an_absence(pg):
    admin, _ac, _factory = pg
    with admin.begin() as conn:
        conn.exec_driver_sql("DROP TABLE controller_identity_activation_receipt")
        conn.exec_driver_sql("DROP TABLE controller_enrollment_identity")
    code, payload = _observe(admin)
    assert code == mod.EXIT_DB_ERROR
    assert payload == {"reason_code": "finalization_observation_db_error"}


# --------------------------------------------------------------------------- read-only + leakage


def _snapshot(admin) -> dict[str, object]:
    with admin.connect() as conn:
        return {
            "roles": conn.execute(text("SELECT count(*) FROM pg_roles")).scalar(),
            "tables": conn.execute(
                text("SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")
            ).scalar(),
            "attrs": conn.execute(
                text(
                    "SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, "
                    "rolinherit, rolreplication FROM pg_roles WHERE rolname = :r"
                ),
                {"r": _ROLE},
            ).one_or_none(),
            "acl": conn.execute(
                text(
                    "SELECT relacl::text FROM pg_class WHERE relname = "
                    "'controller_enrollment_identity'"
                )
            ).scalar(),
            "identities": conn.execute(
                text("SELECT count(*) FROM controller_enrollment_identity")
            ).scalar(),
            "receipts": conn.execute(
                text("SELECT receipt_json FROM controller_identity_activation_receipt")
            )
            .scalars()
            .all(),
        }


def test_the_observation_mutates_absolutely_nothing(pg):
    admin, _ac, factory = pg
    _provision(admin)
    _activate(factory, _A)
    before = _snapshot(admin)
    for _ in range(3):  # repeated observation is idempotent and inert
        code, _payload = _observe(admin)
        assert code == mod.EXIT_OK
    assert _snapshot(admin) == before


def test_the_live_receipt_leaks_no_password_verifier_or_dsn(pg):
    admin, _ac, factory = pg
    password = _provision(admin)
    _activate(factory, _A)
    _code, payload = _observe(admin)
    blob = canonical_json(payload)
    assert password not in blob
    assert scram_sha256_verifier(password, salt=b"x" * 16)[:20] not in blob
    assert str(PG_URL) not in blob
    for forbidden in (
        "SCRAM-SHA-256$",
        "rolpassword",
        "password",
        "verifier",
        "postgresql",
        "psycopg",
        "secp:",
        "@",
    ):
        assert forbidden not in blob, forbidden
    assert blob.count("://") == 1  # only the identity's own public https origin


def test_the_live_receipt_is_canonical_bounded_and_closed(pg):
    admin, _ac, factory = pg
    _provision(admin)
    _activate(factory, _A)
    _code, payload = _observe(admin)
    encoded = canonical_json(payload)
    assert canonical_json(json.loads(encoded)) == encoded
    assert len(encoded.encode("utf-8")) <= mod._MAX_RECEIPT_BYTES
    assert set(payload) == (set(mod._ObservationReceipt.model_fields) - {"schema_id"}) | {"schema"}
    for value in payload.values():
        assert value is None or isinstance(value, bool | int | str)
