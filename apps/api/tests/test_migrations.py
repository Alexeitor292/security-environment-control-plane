"""AC2.4 — the Alembic migration applies cleanly to an empty database."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

API_DIR = Path(__file__).resolve().parents[1]

EXPECTED_TABLES = {
    "organization",
    "app_user",
    "role",
    "user_role_assignment",
    "team",
    "environment_template",
    "environment_version",
    "exercise",
    "environment_instance",
    "deployment_plan",
    "workflow_run",
    "workflow_dispatch_outbox",
    "plugin",
    "artifact",
    "audit_event",
    "environment_network",
    "environment_node",
    "environment_topology_edge",
    "execution_target",
    "provider_inventory_snapshot",
    "provider_inventory_resource",
    "address_space_policy",
    "network_reservation",
}


def test_migration_upgrades_empty_database(tmp_path, monkeypatch):
    db_path = (tmp_path / "migrate.db").as_posix()
    url = f"sqlite+pysqlite:///{db_path}"
    monkeypatch.setenv("SECP_DATABASE_URL", url)

    from secp_api.config import get_settings

    get_settings.cache_clear()

    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)

    command.upgrade(cfg, "head")

    engine = create_engine(url)
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    workflow_fks = inspector.get_foreign_keys("workflow_run")
    engine.dispose()
    get_settings.cache_clear()

    missing = EXPECTED_TABLES - tables
    assert not missing, f"migration missing tables: {missing}"
    assert "alembic_version" in tables
    assert any(
        fk["referred_table"] == "provider_inventory_snapshot"
        and fk["constrained_columns"] == ["snapshot_id"]
        for fk in workflow_fks
    )
