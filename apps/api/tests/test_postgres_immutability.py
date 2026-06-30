"""Hardening §3 — verify immutability guarantees at the PostgreSQL level.

These tests confirm the charter's immutability invariants are enforced by the
DATABASE (the migration-installed triggers), not only by application services or
SQLite. They bypass the ORM and issue raw SQL so only the DB trigger can stop the
mutation.

Run against a real PostgreSQL by setting ``SECP_TEST_POSTGRES_URL`` (the harness
docs show the exact command). Skipped otherwise so the default suite stays
hermetic.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, text

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL immutability tests"
)


@pytest.fixture(scope="module")
def pg_engine():
    assert PG_URL
    # Clean slate, then apply migrations (proves migrations apply to empty PG too).
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

    yield engine
    engine.dispose()
    # Restore env so we never pollute other tests' settings.
    if previous_db_url is None:
        os.environ.pop("SECP_DATABASE_URL", None)
    else:
        os.environ["SECP_DATABASE_URL"] = previous_db_url
    get_settings.cache_clear()


def _now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def seeded_version(pg_engine):
    """Insert org/template/version + an audit event via raw SQL (no ORM guard)."""
    org_id, tmpl_id, ver_id, audit_id = (uuid.uuid4() for _ in range(4))
    with pg_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO organization (id, name, slug, created_at) "
                "VALUES (:id, 'Org', :slug, :ts)"
            ),
            {"id": org_id, "slug": f"org-{org_id.hex[:8]}", "ts": _now()},
        )
        conn.execute(
            text(
                "INSERT INTO environment_template "
                "(id, organization_id, name, slug, display_name, description, created_at) "
                "VALUES (:id, :org, 'T', :slug, 'T', '', :ts)"
            ),
            {"id": tmpl_id, "org": org_id, "slug": f"t-{tmpl_id.hex[:8]}", "ts": _now()},
        )
        conn.execute(
            text(
                "INSERT INTO environment_version "
                "(id, organization_id, template_id, version_number, api_version, "
                " spec, content_hash, created_at) "
                "VALUES (:id, :org, :tmpl, 1, 'controlplane.security/v1alpha1', "
                " :spec, :hash, :ts)"
            ),
            {
                "id": ver_id,
                "org": org_id,
                "tmpl": tmpl_id,
                "spec": '{"a": 1}',
                "hash": "sha256:abc",
                "ts": _now(),
            },
        )
        conn.execute(
            text(
                "INSERT INTO audit_event "
                "(id, organization_id, actor, action, resource_type, outcome, data, created_at) "
                "VALUES (:id, :org, 'system', 'test.event', 'thing', 'success', :data, :ts)"
            ),
            {"id": audit_id, "org": org_id, "data": "{}", "ts": _now()},
        )
    return {"version_id": ver_id, "audit_id": audit_id}


def _expect_immutable_error(engine, sql, params):
    with pytest.raises(Exception) as excinfo:  # psycopg raises; surfaced by SQLAlchemy
        with engine.begin() as conn:
            conn.execute(text(sql), params)
    assert "immutable" in str(excinfo.value).lower()


def test_version_spec_update_blocked_at_db(pg_engine, seeded_version):
    _expect_immutable_error(
        pg_engine,
        "UPDATE environment_version SET spec = :s WHERE id = :id",
        {"s": '{"a": 2}', "id": seeded_version["version_id"]},
    )


def test_version_hash_update_blocked_at_db(pg_engine, seeded_version):
    _expect_immutable_error(
        pg_engine,
        "UPDATE environment_version SET content_hash = :h WHERE id = :id",
        {"h": "sha256:zzz", "id": seeded_version["version_id"]},
    )


def test_version_number_update_blocked_at_db(pg_engine, seeded_version):
    _expect_immutable_error(
        pg_engine,
        "UPDATE environment_version SET version_number = 99 WHERE id = :id",
        {"id": seeded_version["version_id"]},
    )


def test_audit_event_update_blocked_at_db(pg_engine, seeded_version):
    _expect_immutable_error(
        pg_engine,
        "UPDATE audit_event SET outcome = 'tampered' WHERE id = :id",
        {"id": seeded_version["audit_id"]},
    )


def test_audit_event_delete_blocked_at_db(pg_engine, seeded_version):
    _expect_immutable_error(
        pg_engine,
        "DELETE FROM audit_event WHERE id = :id",
        {"id": seeded_version["audit_id"]},
    )


def test_version_nonprotected_update_allowed(pg_engine, seeded_version):
    # The trigger must be precise: updating a NON-protected column is permitted,
    # proving it does not simply block every update.
    new_creator = uuid.uuid4()
    with pg_engine.begin() as conn:
        conn.execute(
            text("UPDATE environment_version SET created_by = :c WHERE id = :id"),
            {"c": new_creator, "id": seeded_version["version_id"]},
        )
        row = conn.execute(
            text("SELECT created_by FROM environment_version WHERE id = :id"),
            {"id": seeded_version["version_id"]},
        ).scalar_one()
    assert str(row) == str(new_creator)


def test_migration_created_expected_tables(pg_engine):
    from sqlalchemy import inspect

    tables = set(inspect(pg_engine).get_table_names())
    assert {"environment_version", "audit_event", "alembic_version"} <= tables
