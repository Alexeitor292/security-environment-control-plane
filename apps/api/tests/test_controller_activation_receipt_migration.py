"""Dedicated up/down proof for the C3 activation-receipt migration (SECP-PR5H-B2 C3).

Revision ``a1d4f7c2e9b6`` (down_revision ``c2f8e1a4b6d9``) is the new SOLE head. It adds exactly ONE
durable, write-once table. This module proves the a1d4 STEP in isolation on SQLite:

* at the predecessor head ``c2f8e1a4b6d9`` the receipt table does not yet exist;
* upgrading to ``a1d4f7c2e9b6`` creates ``controller_identity_activation_receipt`` with the
  ``UNIQUE(operation_id)`` write-once key and BOTH predecessor + resulting foreign keys into the one
  controller-identity table, and lands the head on ``a1d4f7c2e9b6``;
* downgrading to ``c2f8e1a4b6d9`` drops ONLY that table (the controller-identity table and the
  PR5H-A enrollment tables are untouched), so the existing rollback path is unaffected;
* the a1d4 round trip is repeatable (upgrade -> downgrade -> upgrade), so an interrupted upgrade is
  retryable rather than wedging the schema.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

API_DIR = Path(__file__).resolve().parents[1]

HEAD = "a1d4f7c2e9b6"
PREDECESSOR = "c2f8e1a4b6d9"
RECEIPT_TABLE = "controller_identity_activation_receipt"
IDENTITY_TABLE = "controller_enrollment_identity"
PR5H_A_TABLES = {
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


def _activate(tmp_path, monkeypatch):  # noqa: ANN001, ANN202
    url = f"sqlite+pysqlite:///{(tmp_path / 'activation-receipt.db').as_posix()}"
    monkeypatch.setenv("SECP_DATABASE_URL", url)
    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg, create_engine(url, future=True)


def _head(engine) -> str | None:  # noqa: ANN001
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()


def test_receipt_absent_at_predecessor_head(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    cfg, engine = _activate(tmp_path, monkeypatch)
    command.upgrade(cfg, PREDECESSOR)
    assert RECEIPT_TABLE not in set(inspect(engine).get_table_names())
    assert IDENTITY_TABLE in set(inspect(engine).get_table_names())
    assert _head(engine) == PREDECESSOR
    engine.dispose()


def test_upgrade_adds_the_write_once_receipt_table_and_lands_on_the_new_head(
    tmp_path, monkeypatch
) -> None:  # noqa: ANN001
    cfg, engine = _activate(tmp_path, monkeypatch)
    command.upgrade(cfg, HEAD)
    inspector = inspect(engine)
    assert RECEIPT_TABLE in set(inspector.get_table_names())
    assert _head(engine) == HEAD

    # the write-once UNIQUE(operation_id) key
    uniques = {tuple(c["column_names"]) for c in inspector.get_unique_constraints(RECEIPT_TABLE)}
    assert ("operation_id",) in uniques

    # both predecessor + resulting FKs reference the ONE controller-identity table
    fks = inspector.get_foreign_keys(RECEIPT_TABLE)
    referred = sorted((fk["referred_table"], tuple(fk["constrained_columns"])) for fk in fks)
    assert referred == [
        (IDENTITY_TABLE, ("expected_predecessor_row_id",)),
        (IDENTITY_TABLE, ("resulting_row_id",)),
    ]

    columns = {c["name"] for c in inspector.get_columns(RECEIPT_TABLE)}
    assert {
        "operation_id",
        "operation_digest",
        "candidate_digest",
        "resulting_activation_token",
        "resulting_public_state_digest",
        "receipt_json",
        "receipt_digest",
        "recorded_at",
    } <= columns
    engine.dispose()


def test_downgrade_drops_only_the_receipt_table(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    cfg, engine = _activate(tmp_path, monkeypatch)
    command.upgrade(cfg, HEAD)
    assert RECEIPT_TABLE in set(inspect(engine).get_table_names())

    command.downgrade(cfg, PREDECESSOR)

    tables = set(inspect(engine).get_table_names())
    assert RECEIPT_TABLE not in tables
    assert IDENTITY_TABLE in tables  # the controller-identity table is untouched
    assert PR5H_A_TABLES <= tables  # the PR5H-A enrollment tables are untouched
    assert _head(engine) == PREDECESSOR
    engine.dispose()


def test_a1d4_round_trip_is_retryable(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    cfg, engine = _activate(tmp_path, monkeypatch)
    command.upgrade(cfg, HEAD)
    command.downgrade(cfg, PREDECESSOR)
    command.upgrade(cfg, HEAD)
    assert RECEIPT_TABLE in set(inspect(engine).get_table_names())
    assert _head(engine) == HEAD
    engine.dispose()
