"""PR5H-A migration proof on REAL PostgreSQL (SECP-PR5H-A, ADR-027).

The portable round-trip proof runs on SQLite; this module proves the same migration is a clean,
reversible, retryable round trip on the engine that actually ships, and that the live Alembic head
is exactly ``a1d4f7c2e9b6``. It is one of the targets of the exact-head PostgreSQL no-skip CI
gate, so a PostgreSQL outage fails the build instead of silently skipping.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run the PostgreSQL migration proof"
)

API_DIR = Path(__file__).resolve().parents[1]
HEAD = "a1d4f7c2e9b6"
DOWN_REVISION = "d8f1a2b3c4e5"
ENROLLMENT_TABLES = {
    "worker_enrollment_invitation",
    "worker_enrollment_state",
    "worker_enrollment_revision",
    "worker_enrollment_step_receipt",
    "controller_enrollment_identity",  # PR5H-B1 F3 (added by c2f8e1a4b6d9, dropped on downgrade)
    "worker_enrollment_signed_offer",  # PR5H-B1 Phase 3 (added by c2f8e1a4b6d9; dropped on down)
    "controller_identity_activation_receipt",  # PR5H-B2 (added by a1d4f7c2e9b6; dropped on down)
}


@pytest.fixture
def pg_config():
    assert PG_URL
    engine = create_engine(PG_URL, future=True)
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        conn.exec_driver_sql("CREATE SCHEMA public")

    from secp_api.config import get_settings

    previous = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = PG_URL
    get_settings.cache_clear()

    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", PG_URL)
    try:
        yield cfg, engine
    finally:
        engine.dispose()
        if previous is None:
            os.environ.pop("SECP_DATABASE_URL", None)
        else:
            os.environ["SECP_DATABASE_URL"] = previous
        get_settings.cache_clear()


def _live_head(engine) -> str | None:
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()


def test_upgrade_to_head_creates_the_four_tables_on_postgres(pg_config) -> None:
    cfg, engine = pg_config
    command.upgrade(cfg, "head")
    tables = set(inspect(engine).get_table_names())
    assert ENROLLMENT_TABLES <= tables, sorted(ENROLLMENT_TABLES - tables)
    assert _live_head(engine) == HEAD


def test_live_alembic_head_is_exactly_a1d4f7c2e9b6(pg_config) -> None:
    cfg, engine = pg_config
    command.upgrade(cfg, "head")
    assert _live_head(engine) == HEAD


def test_upgrade_downgrade_upgrade_round_trip_on_postgres(pg_config) -> None:
    cfg, engine = pg_config
    command.upgrade(cfg, "head")
    before = set(inspect(engine).get_table_names())

    command.downgrade(cfg, DOWN_REVISION)
    after_down = set(inspect(engine).get_table_names())
    # the downgrade removes exactly the four PR5H-A tables and nothing else
    assert before - after_down == ENROLLMENT_TABLES
    assert not (after_down - before)
    assert _live_head(engine) == DOWN_REVISION

    command.upgrade(cfg, "head")
    assert set(inspect(engine).get_table_names()) == before
    assert _live_head(engine) == HEAD


def test_real_constraints_exist_on_postgres(pg_config) -> None:
    """The durable single-use nonce key and the CAS/dedup uniqueness bite on the shipped engine."""
    cfg, engine = pg_config
    command.upgrade(cfg, "head")
    inspector = inspect(engine)

    invitation = {
        tuple(c["column_names"])
        for c in inspector.get_unique_constraints("worker_enrollment_invitation")
    }
    assert ("invitation_id",) in invitation

    revision = {
        tuple(c["column_names"])
        for c in inspector.get_unique_constraints("worker_enrollment_revision")
    }
    assert ("enrollment_id", "revision") in revision

    receipt = {
        tuple(c["column_names"])
        for c in inspector.get_unique_constraints("worker_enrollment_step_receipt")
    }
    assert ("enrollment_id", "step", "input_digest") in receipt
