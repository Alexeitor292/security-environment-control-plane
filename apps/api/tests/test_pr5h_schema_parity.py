"""PR5H-A schema parity guard: the Alembic migration and the SQLAlchemy ORM must agree exactly.

Two schemas exist for the same four tables — one produced by running the real migration, one by
``Base.metadata.create_all``. Unit tests build on the ORM while PostgreSQL runs the migration, so a
silent divergence would mean the tests never exercise the shipped schema.

This guard **executes the real migration** and introspects both databases, rather than comparing
source strings. It also pins the head chain and proves no second recovery migration and no recovery
step-receipt vocabulary were introduced.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from secp_api.models import Base
from sqlalchemy import create_engine, inspect

API_DIR = Path(__file__).resolve().parents[1]
HEAD = "b6e2f4a9c1d7"
DOWN_REVISION = "d8f1a2b3c4e5"

ENROLLMENT_TABLES = (
    "worker_enrollment_invitation",
    "worker_enrollment_state",
    "worker_enrollment_revision",
    "worker_enrollment_step_receipt",
)


def _alembic_config(url: str) -> Config:
    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


@pytest.fixture(autouse=True)
def _settings_cache():
    """Each test picks up its OWN SECP_DATABASE_URL — a stale cached settings object would silently
    point a migration at another test's database."""
    from secp_api.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(scope="module")
def migrated_and_orm(tmp_path_factory):
    """(migration_inspector, orm_inspector) over two independent SQLite databases.

    Module-scoped: running the whole migration chain once, rather than per parametrized case, keeps
    this guard cheap enough to sit in every CI shard."""
    import os

    from secp_api.config import get_settings

    tmp_path = tmp_path_factory.mktemp("pr5h_schema_parity")
    migrated_url = f"sqlite+pysqlite:///{(tmp_path / 'migrated.db').as_posix()}"
    previous = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = migrated_url
    get_settings.cache_clear()
    command.upgrade(_alembic_config(migrated_url), "head")
    migrated_engine = create_engine(migrated_url, future=True)

    orm_engine = create_engine(
        f"sqlite+pysqlite:///{(tmp_path / 'orm.db').as_posix()}", future=True
    )
    Base.metadata.create_all(orm_engine)
    try:
        yield inspect(migrated_engine), inspect(orm_engine)
    finally:
        migrated_engine.dispose()
        orm_engine.dispose()
        if previous is None:
            os.environ.pop("SECP_DATABASE_URL", None)
        else:
            os.environ["SECP_DATABASE_URL"] = previous
        get_settings.cache_clear()


# --- table / column / constraint parity ----------------------------------------------------------


def test_migration_and_orm_define_the_same_four_tables(migrated_and_orm) -> None:
    migrated, orm = migrated_and_orm
    for table in ENROLLMENT_TABLES:
        assert table in migrated.get_table_names(), f"{table} missing from the migration"
        assert table in orm.get_table_names(), f"{table} missing from the ORM"


@pytest.mark.parametrize("table", ENROLLMENT_TABLES)
def test_column_names_order_and_nullability_agree(migrated_and_orm, table: str) -> None:
    migrated, orm = migrated_and_orm
    m_cols = migrated.get_columns(table)
    o_cols = orm.get_columns(table)
    # declaration-sensitive order matters: the state row carries the 17 contract fields in order
    assert [c["name"] for c in m_cols] == [c["name"] for c in o_cols], table
    assert {c["name"]: bool(c["nullable"]) for c in m_cols} == {
        c["name"]: bool(c["nullable"]) for c in o_cols
    }, f"{table}: nullability differs"


@pytest.mark.parametrize("table", ENROLLMENT_TABLES)
def test_primary_keys_agree(migrated_and_orm, table: str) -> None:
    migrated, orm = migrated_and_orm
    assert (
        migrated.get_pk_constraint(table)["constrained_columns"]
        == (orm.get_pk_constraint(table)["constrained_columns"])
    ), table


@pytest.mark.parametrize("table", ENROLLMENT_TABLES)
def test_foreign_keys_agree(migrated_and_orm, table: str) -> None:
    migrated, orm = migrated_and_orm

    def norm(inspector):
        return sorted(
            (tuple(fk["constrained_columns"]), fk["referred_table"], tuple(fk["referred_columns"]))
            for fk in inspector.get_foreign_keys(table)
        )

    assert norm(migrated) == norm(orm), table


@pytest.mark.parametrize("table", ENROLLMENT_TABLES)
def test_unique_constraints_agree(migrated_and_orm, table: str) -> None:
    migrated, orm = migrated_and_orm

    def norm(inspector):
        return sorted(tuple(uc["column_names"]) for uc in inspector.get_unique_constraints(table))

    assert norm(migrated) == norm(orm), table


@pytest.mark.parametrize("table", ENROLLMENT_TABLES)
def test_check_constraints_agree(migrated_and_orm, table: str) -> None:
    migrated, orm = migrated_and_orm

    def norm(inspector):
        # compare by NAME set: SQLite reports the rendered sqltext with incidental whitespace
        return sorted(cc["name"] for cc in inspector.get_check_constraints(table) if cc.get("name"))

    assert norm(migrated) == norm(orm), f"{table}: CHECK constraint names differ"


@pytest.mark.parametrize("table", ENROLLMENT_TABLES)
def test_indexes_agree(migrated_and_orm, table: str) -> None:
    migrated, orm = migrated_and_orm

    def norm(inspector):
        return sorted(
            (ix["name"], tuple(ix["column_names"]), bool(ix.get("unique")))
            for ix in inspector.get_indexes(table)
        )

    assert norm(migrated) == norm(orm), table


def test_tenancy_and_shadow_columns_exist_in_both(migrated_and_orm) -> None:
    migrated, orm = migrated_and_orm
    for inspector in (migrated, orm):
        for table in ("worker_enrollment_invitation", "worker_enrollment_state"):
            names = {c["name"] for c in inspector.get_columns(table)}
            assert {"organization_id", "deployment_site_label", "expires_at_ts"} <= names, table
        state = {c["name"] for c in inspector.get_columns("worker_enrollment_state")}
        assert {"state_digest", "observed_at", "expires_at_ts"} <= state


# --- head chain ----------------------------------------------------------------------------


def test_b6e2f4a9c1d7_is_the_sole_head_with_the_exact_down_revision() -> None:
    script = ScriptDirectory.from_config(_alembic_config("sqlite+pysqlite:///:memory:"))
    heads = tuple(script.get_heads())
    assert heads == (HEAD,), f"expected the sole head {HEAD}, found {heads}"
    assert script.get_revision(HEAD).down_revision == DOWN_REVISION


def test_only_one_pr5h_migration_exists_and_it_adds_no_recovery_step() -> None:
    """No second (recovery) migration, and the receipt vocabulary stays the five worker steps."""
    from secp_api.worker_enrollment_models import WORKER_ENROLLMENT_STEPS

    versions = API_DIR / "migrations" / "versions"
    pr5h = sorted(p.name for p in versions.glob("*worker_enrollment*"))
    assert pr5h == ["b6e2f4a9c1d7_worker_enrollment_foundation.py"], pr5h
    assert WORKER_ENROLLMENT_STEPS == (
        "bind_worker_identity",
        "record_controller_offer",
        "record_worker_result",
        "mark_verified",
        "mark_healthy",
    )
    assert not [s for s in WORKER_ENROLLMENT_STEPS if "recover" in s or "refuse" in s]


def test_accepted_issued_and_runtime_heads_are_unchanged() -> None:
    import sys

    sys.path.insert(0, str(API_DIR.parent / "deployment"))
    from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD
    from secp_discovery_activation.migration_heads import (
        ACCEPTED_CONTROLLER_MIGRATION_HEADS,
        ISSUED_CONTROLLER_MIGRATION_HEAD,
    )

    # the bounded rolling window stays exactly two values
    assert ACCEPTED_CONTROLLER_MIGRATION_HEADS == (DOWN_REVISION, HEAD)
    # issuance and live-schema readiness are new-head-only
    assert ISSUED_CONTROLLER_MIGRATION_HEAD == HEAD
    assert RUNTIME_REQUIRED_MIGRATION_HEAD == HEAD


def test_downgrade_removes_only_the_four_pr5h_tables(tmp_path, monkeypatch) -> None:
    url = f"sqlite+pysqlite:///{(tmp_path / 'down.db').as_posix()}"
    monkeypatch.setenv("SECP_DATABASE_URL", url)
    cfg = _alembic_config(url)
    command.upgrade(cfg, "head")
    engine = create_engine(url, future=True)
    before = set(inspect(engine).get_table_names())

    command.downgrade(cfg, DOWN_REVISION)
    after = set(inspect(engine).get_table_names())

    assert before - after == set(ENROLLMENT_TABLES), "downgrade removed more than the PR5H tables"
    assert not (after - before)
    engine.dispose()


def test_upgrade_downgrade_upgrade_round_trip_is_stable(tmp_path, monkeypatch) -> None:
    url = f"sqlite+pysqlite:///{(tmp_path / 'rt.db').as_posix()}"
    monkeypatch.setenv("SECP_DATABASE_URL", url)
    cfg = _alembic_config(url)
    command.upgrade(cfg, "head")
    engine = create_engine(url, future=True)
    first = sorted(inspect(engine).get_table_names())

    command.downgrade(cfg, DOWN_REVISION)
    command.upgrade(cfg, "head")
    assert sorted(inspect(engine).get_table_names()) == first
    engine.dispose()
