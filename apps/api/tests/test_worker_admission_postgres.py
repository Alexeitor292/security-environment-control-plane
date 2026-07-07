"""SECP-B6 MB-1 item-2 — PostgreSQL enforces control-plane authority over discovery admissions.

Minting a durable, one-time ``worker_discovery_admission`` AND every status transition is a
CONTROL-PLANE authority. Because the worker shares the database, the ORM ``before_flush`` guard is
insufficient — a worker DB role that bypasses the ORM could forge an ``admitted`` record. The
migration installs a BEFORE-ROW trigger that denies INSERT/UPDATE/DELETE to any role that is not a
member of ``secp_control_plane``. These tests issue RAW SQL as a restricted worker role (holding the
table grants, so only the TRIGGER can stop it) and prove every write is denied, while the
control-plane role's writes pass the trigger.

Run against a real PostgreSQL by setting ``SECP_TEST_POSTGRES_URL``; skipped otherwise so the
default suite stays hermetic (SQLite exercises the ORM guard).
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, text

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL admission-authority tests"
)

_INSERT_SQL = text(
    """
    INSERT INTO worker_discovery_admission (
        id, organization_id, worker_registration_id, identity_version, discovery_job_id,
        enrollment_id, execution_target_id, onboarding_id, live_read_authorization_id,
        authorization_version, endpoint_binding_hash, purpose, nonce, status,
        issued_at, expires_at, created_at, updated_at
    ) VALUES (
        :id, :org, :reg, 1, :job, :enr, :tgt, :onb, :auth, 1, :ebh, :purpose, :nonce, :status,
        :ts, :exp, :ts, :ts
    )
    """
)


def _dummy_row(status: str) -> dict:
    now = datetime.now(UTC)
    return {
        "id": uuid.uuid4(),
        "org": uuid.uuid4(),
        "reg": uuid.uuid4(),
        "job": uuid.uuid4(),
        "enr": uuid.uuid4(),
        "tgt": uuid.uuid4(),
        "onb": uuid.uuid4(),
        "auth": uuid.uuid4(),
        "ebh": "sha256:" + "ab" * 32,
        "purpose": "target_discovery_live_read_only",
        "nonce": uuid.uuid4().hex + uuid.uuid4().hex,
        "status": status,
        "ts": now,
        "exp": now + timedelta(seconds=90),
    }


@pytest.fixture(scope="module")
def pg_engine():
    assert PG_URL
    engine = create_engine(PG_URL, future=True)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))

    from alembic import command
    from alembic.config import Config
    from secp_api.config import get_settings

    api_dir = __import__("pathlib").Path(__file__).resolve().parents[1]
    previous_db_url = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = PG_URL
    get_settings.cache_clear()
    cfg = Config(str(api_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_dir / "migrations"))
    cfg.set_main_option("sqlalchemy.url", PG_URL)
    command.upgrade(cfg, "head")

    # The connecting (control-plane) role must be a member of secp_control_plane so its writes pass
    # the trigger — this mirrors the production API DB role (deploy config grants this membership).
    with engine.begin() as conn:
        conn.execute(text("GRANT secp_control_plane TO CURRENT_USER"))

    yield engine
    engine.dispose()
    if previous_db_url is None:
        os.environ.pop("SECP_DATABASE_URL", None)
    else:
        os.environ["SECP_DATABASE_URL"] = previous_db_url
    get_settings.cache_clear()


# Idempotent teardown: revoke every dependency then drop, guarded so it is safe on a fresh DB and
# after a partially-completed setup (CI robustness).
_DROP_WORKER_ROLE_SQL = text(
    """
    DO $$
    BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'secp_test_worker') THEN
            EXECUTE 'REVOKE ALL PRIVILEGES ON worker_discovery_admission FROM secp_test_worker';
            EXECUTE 'REVOKE ALL PRIVILEGES ON SCHEMA public FROM secp_test_worker';
            EXECUTE 'REVOKE secp_test_worker FROM CURRENT_USER';
            EXECUTE 'DROP ROLE secp_test_worker';
        END IF;
    END
    $$;
    """
)


@pytest.fixture
def worker_role(pg_engine):
    """A restricted worker DB role: NOT a member of secp_control_plane, but granted every table DML
    privilege so only the trigger (never a missing GRANT) is what denies its writes. Membership in
    the role is granted to the connecting user so it can ``SET ROLE`` to it."""
    with pg_engine.begin() as conn:
        conn.execute(_DROP_WORKER_ROLE_SQL)
        conn.execute(text("CREATE ROLE secp_test_worker NOLOGIN"))
        conn.execute(text("GRANT USAGE ON SCHEMA public TO secp_test_worker"))
        conn.execute(
            text(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON worker_discovery_admission "
                "TO secp_test_worker"
            )
        )
        conn.execute(text("GRANT secp_test_worker TO CURRENT_USER"))
    yield "secp_test_worker"
    with pg_engine.begin() as conn:
        conn.execute(_DROP_WORKER_ROLE_SQL)


def _seed_admitted_row(conn, status: str = "admitted") -> uuid.UUID:
    """Insert a REAL admitted row for the worker mutation tests, as the control-plane (superuser)
    role, bypassing the guard trigger + FK checks via ``session_replication_role = replica`` so the
    row exists without needing the full FK chain. The worker-role UPDATE/DELETE below then hit the
    (re-enabled) guard trigger."""
    row = _dummy_row(status)
    conn.execute(text("SET session_replication_role = replica"))
    conn.execute(_INSERT_SQL, row)
    conn.execute(text("SET session_replication_role = DEFAULT"))
    return row["id"]


def test_trigger_and_control_plane_role_installed(pg_engine):
    with pg_engine.connect() as conn:
        role = conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = 'secp_control_plane'")
        ).first()
        assert role is not None
        # tgenabled 'A' == ENABLE ALWAYS: the guard fires even under session_replication_role=
        # replica, so a role that could set replica mode still cannot bypass the authority check.
        tgenabled = conn.execute(
            text(
                "SELECT tgenabled FROM pg_trigger "
                "WHERE tgname = 'trg_worker_discovery_admission_guard'"
            )
        ).scalar_one_or_none()
        assert tgenabled == "A"


def test_worker_role_cannot_insert_admitted(pg_engine, worker_role):
    # The mandatory proof: a raw worker-role INSERT of status='admitted' is denied by the TRIGGER
    # (which fires BEFORE the FK check), even though the worker role holds INSERT privilege.
    with pytest.raises(Exception) as exc:  # noqa: PT011  (driver-specific DBAPIError subclass)
        with pg_engine.begin() as conn:
            conn.execute(text("SET ROLE secp_test_worker"))
            conn.execute(_INSERT_SQL, _dummy_row("admitted"))
    assert "control-plane authority" in str(exc.value).lower()


def test_worker_role_cannot_insert_challenged(pg_engine, worker_role):
    with pytest.raises(Exception) as exc:  # noqa: PT011
        with pg_engine.begin() as conn:
            conn.execute(text("SET ROLE secp_test_worker"))
            conn.execute(_INSERT_SQL, _dummy_row("challenged"))
    assert "control-plane authority" in str(exc.value).lower()


def test_control_plane_role_passes_trigger_to_fk(pg_engine):
    # A control-plane member (the connecting role) gets PAST the trigger — the only thing that stops
    # this dummy-FK insert is the foreign-key constraint, proving the trigger did not block it.
    with pytest.raises(Exception) as exc:  # noqa: PT011
        with pg_engine.begin() as conn:
            conn.execute(_INSERT_SQL, _dummy_row("challenged"))
    msg = str(exc.value).lower()
    assert "control-plane authority" not in msg
    assert "foreign key" in msg or "violates foreign key" in msg or "23503" in msg


def test_worker_role_cannot_update_admitted(pg_engine, worker_role):
    with pg_engine.begin() as conn:
        admission_id = _seed_admitted_row(conn)
    with pytest.raises(Exception) as exc:  # noqa: PT011
        with pg_engine.begin() as conn:
            conn.execute(text("SET ROLE secp_test_worker"))
            conn.execute(
                text("UPDATE worker_discovery_admission SET status = 'consumed' WHERE id = :id"),
                {"id": admission_id},
            )
    assert "control-plane authority" in str(exc.value).lower()
    # The row is unchanged — the worker could not forge a transition.
    with pg_engine.connect() as conn:
        status = conn.execute(
            text("SELECT status FROM worker_discovery_admission WHERE id = :id"),
            {"id": admission_id},
        ).scalar_one()
        assert status == "admitted"


def test_worker_role_cannot_delete_admission(pg_engine, worker_role):
    with pg_engine.begin() as conn:
        admission_id = _seed_admitted_row(conn)
    with pytest.raises(Exception) as exc:  # noqa: PT011
        with pg_engine.begin() as conn:
            conn.execute(text("SET ROLE secp_test_worker"))
            conn.execute(
                text("DELETE FROM worker_discovery_admission WHERE id = :id"),
                {"id": admission_id},
            )
    assert "control-plane authority" in str(exc.value).lower()
    with pg_engine.connect() as conn:
        still_there = conn.execute(
            text("SELECT 1 FROM worker_discovery_admission WHERE id = :id"),
            {"id": admission_id},
        ).first()
        assert still_there is not None


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
