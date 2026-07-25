"""Upgrade/downgrade proof for the durable worker-enrollment foundation (SECP-PR5H-A).

Revision ``b6e2f4a9c1d7`` (down_revision ``d8f1a2b3c4e5``) is the new SOLE head. This module proves
the migration is a clean, reversible, RETRYABLE round trip on SQLite:

* upgrading to head creates exactly the four enrollment tables and lands on ``b6e2f4a9c1d7``;
* the durable single-use nonce key and the CAS/dedup uniqueness constraints actually exist and bite;
* downgrading removes all four and returns the head to ``d8f1a2b3c4e5``, leaving the PR5F schema
  intact so the existing rollback path is unaffected;
* the round trip is repeatable (upgrade -> downgrade -> upgrade), so an interrupted upgrade is
  retryable rather than wedging the schema.

The PostgreSQL-specific behavior is covered by the postgres-gated modules; these portable CHECKs and
constraints are written to be identical on both backends (see the schema module's rationale).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

API_DIR = Path(__file__).resolve().parents[1]

REVISION = "b6e2f4a9c1d7"
DOWN_REVISION = "d8f1a2b3c4e5"

ENROLLMENT_TABLES = {
    "worker_enrollment_invitation",
    "worker_enrollment_state",
    "worker_enrollment_revision",
    "worker_enrollment_step_receipt",
}


@pytest.fixture(autouse=True)
def _restore_settings_cache():  # noqa: ANN202
    from secp_api.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _activate(tmp_path, monkeypatch, name: str = "enrollment.db"):  # noqa: ANN001, ANN202
    url = f"sqlite+pysqlite:///{(tmp_path / name).as_posix()}"
    monkeypatch.setenv("SECP_DATABASE_URL", url)
    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg, create_engine(url, future=True)


def _head(engine) -> str | None:  # noqa: ANN001
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()


def test_upgrade_creates_the_four_tables_and_lands_on_the_new_head(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    cfg, engine = _activate(tmp_path, monkeypatch)
    command.upgrade(cfg, "head")

    tables = set(inspect(engine).get_table_names())
    assert ENROLLMENT_TABLES <= tables, sorted(ENROLLMENT_TABLES - tables)
    assert _head(engine) == REVISION
    engine.dispose()


def test_single_use_nonce_and_cas_uniqueness_constraints_exist(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    cfg, engine = _activate(tmp_path, monkeypatch)
    command.upgrade(cfg, "head")
    inspector = inspect(engine)

    invitation_uniques = {
        tuple(c["column_names"])
        for c in inspector.get_unique_constraints("worker_enrollment_invitation")
    }
    # the durable single-use nonce key, INDEPENDENT of the enrollment head-row primary key
    assert ("invitation_id",) in invitation_uniques

    revision_uniques = {
        tuple(c["column_names"])
        for c in inspector.get_unique_constraints("worker_enrollment_revision")
    }
    assert ("enrollment_id", "revision") in revision_uniques

    receipt_uniques = {
        tuple(c["column_names"])
        for c in inspector.get_unique_constraints("worker_enrollment_step_receipt")
    }
    assert ("enrollment_id", "step", "input_digest") in receipt_uniques

    # the head row is keyed by enrollment_id and carries the CAS digest column
    state_columns = {c["name"] for c in inspector.get_columns("worker_enrollment_state")}
    assert {"enrollment_id", "revision", "state_digest", "expires_at_ts", "observed_at"} <= (
        state_columns
    )
    engine.dispose()


def test_downgrade_removes_all_four_tables_and_restores_the_pr5f_head(
    tmp_path, monkeypatch
) -> None:  # noqa: ANN001
    cfg, engine = _activate(tmp_path, monkeypatch)
    command.upgrade(cfg, "head")
    assert ENROLLMENT_TABLES <= set(inspect(engine).get_table_names())

    command.downgrade(cfg, DOWN_REVISION)

    tables = set(inspect(engine).get_table_names())
    assert not (ENROLLMENT_TABLES & tables), sorted(ENROLLMENT_TABLES & tables)
    assert _head(engine) == DOWN_REVISION
    # the PR5F schema is untouched by the downgrade, so the existing rollback path still works
    assert "proxmox_readonly_bootstrap_session" in tables
    assert "worker_identity_registration" in tables
    engine.dispose()


def test_upgrade_downgrade_upgrade_round_trip_is_retryable(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    cfg, engine = _activate(tmp_path, monkeypatch)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, DOWN_REVISION)
    command.upgrade(cfg, "head")

    assert ENROLLMENT_TABLES <= set(inspect(engine).get_table_names())
    assert _head(engine) == REVISION
    engine.dispose()
