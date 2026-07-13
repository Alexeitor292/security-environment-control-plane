"""PostgreSQL migration tests for OIDC subject uniqueness (ADR-017, migration f2b8c1d4a9e7).

Proves on a real PostgreSQL that the partial unique index allows multiple NULL subjects, forbids
duplicate non-null subjects, fails closed (without printing any subject value) when pre-existing
duplicates exist, and round-trips through downgrade/re-upgrade with exactly one Alembic head.

Skipped unless ``SECP_TEST_POSTGRES_URL`` is set.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from secp_api.config import get_settings
from secp_api.models import Organization, User
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")
HEAD = "f2b8c1d4a9e7"
DOWN = "b2c9e5a1f4d7"
INDEX_NAME = "uq_app_user_subject"

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL migration tests"
)


def _cfg() -> Config:
    api_dir = Path(__file__).resolve().parents[1]
    cfg = Config(str(api_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_dir / "migrations"))
    cfg.set_main_option("sqlalchemy.url", str(PG_URL))
    return cfg


@pytest.fixture
def pg_engine():
    assert PG_URL
    engine = create_engine(PG_URL, future=True)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    previous = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = PG_URL
    get_settings.cache_clear()
    yield engine
    engine.dispose()
    if previous is None:
        os.environ.pop("SECP_DATABASE_URL", None)
    else:
        os.environ["SECP_DATABASE_URL"] = previous
    get_settings.cache_clear()


def _org(conn) -> uuid.UUID:
    oid = uuid.uuid4()
    conn.execute(
        Organization.__table__.insert().values(id=oid, name="Org", slug=f"org-{oid.hex[:10]}")
    )
    return oid


def _user(conn, org_id, subject) -> None:
    conn.execute(
        User.__table__.insert().values(
            id=uuid.uuid4(),
            organization_id=org_id,
            email=f"{uuid.uuid4().hex[:10]}@t.test",
            display_name="U",
            subject=subject,
        )
    )


def _has_index(engine) -> bool:
    return INDEX_NAME in {ix["name"] for ix in inspect(engine).get_indexes("app_user")}


def test_single_head():
    script = ScriptDirectory.from_config(_cfg())
    assert [r for r in script.get_heads()] == [HEAD]


def test_upgrade_allows_unique_and_multiple_nulls_but_rejects_duplicate(pg_engine):
    command.upgrade(_cfg(), HEAD)
    assert _has_index(pg_engine)
    with pg_engine.begin() as conn:
        org = _org(conn)
        _user(conn, org, "sub-a")
        _user(conn, org, "sub-b")
        _user(conn, org, None)  # first NULL subject
        _user(conn, org, None)  # a second NULL subject is permitted
    # a duplicate non-null subject (globally) is rejected.
    with pytest.raises(IntegrityError), pg_engine.begin() as conn:
        _user(conn, _org(conn), "sub-a")


def test_migration_fails_closed_on_preexisting_duplicates_without_leaking(pg_engine):
    command.upgrade(_cfg(), DOWN)  # before the unique index
    secret_subject = "DUP-SECRET-SUBJECT-VALUE"
    with pg_engine.begin() as conn:
        org = _org(conn)
        _user(conn, org, secret_subject)
        _user(conn, org, secret_subject)  # allowed while the index is absent
    with pytest.raises(RuntimeError) as exc:
        command.upgrade(_cfg(), HEAD)
    message = str(exc.value)
    assert secret_subject not in message  # NO subject value is printed on failure
    assert "1" in message  # only a count of colliding groups
    assert not _has_index(pg_engine)  # the index was not created


def test_downgrade_removes_index_and_reupgrade_restores(pg_engine):
    command.upgrade(_cfg(), HEAD)
    assert _has_index(pg_engine)
    command.downgrade(_cfg(), DOWN)
    assert not _has_index(pg_engine)
    command.upgrade(_cfg(), HEAD)
    assert _has_index(pg_engine)
