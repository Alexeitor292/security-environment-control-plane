"""PR5F migration rollback fencing is ordered and remains fail closed."""

from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Protocol

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

_MIGRATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "migrations"
    / "versions"
    / "d8f1a2b3c4e5_b8_production_activation.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location("pr5f_activation_migration", _MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _ScalarResult:
    def __init__(self, value: int) -> None:
        self._value = value

    def scalar_one(self) -> int:
        return self._value


class _NamedColumn(Protocol):
    name: str


class _FakeBind:
    def __init__(
        self,
        actions: list[tuple[str, str]],
        *,
        incompatible: int = 0,
        duplicate_bound: int = 0,
    ) -> None:
        self.dialect = SimpleNamespace(name="postgresql")
        self._actions = actions
        self._incompatible = incompatible
        self._duplicate_bound = duplicate_bound

    def execute(self, statement: object) -> _ScalarResult:
        rendered = str(statement)
        self._actions.append(("query", rendered))
        if "GROUP BY execution_target_id, onboarding_id" in rendered:
            return _ScalarResult(self._duplicate_bound)
        return _ScalarResult(self._incompatible)


class _FakeDowngradeOp:
    def __init__(self, *, incompatible: int = 0) -> None:
        self.actions: list[tuple[str, str]] = []
        self.bind = _FakeBind(self.actions, incompatible=incompatible)

    def get_bind(self) -> _FakeBind:
        return self.bind

    def execute(self, statement: object) -> None:
        self.actions.append(("execute", str(statement)))

    def drop_index(self, name: str, *, table_name: str) -> None:
        self.actions.append(("drop_index", f"{table_name}.{name}"))

    def drop_column(self, table_name: str, column_name: str) -> None:
        self.actions.append(("drop_column", f"{table_name}.{column_name}"))


class _FakeUpgradeOp:
    def __init__(self, *, duplicate_bound: int = 0) -> None:
        self.actions: list[tuple[str, str]] = []
        self.bind = _FakeBind(self.actions, duplicate_bound=duplicate_bound)

    def get_bind(self) -> _FakeBind:
        return self.bind

    def execute(self, statement: object) -> None:
        self.actions.append(("execute", str(statement)))

    def add_column(self, table_name: str, column: _NamedColumn) -> None:
        self.actions.append(("add_column", f"{table_name}.{column.name}"))

    def create_index(
        self,
        name: str,
        table_name: str,
        columns: list[str],
        *,
        unique: bool,
        sqlite_where: object,
        postgresql_where: object,
    ) -> None:
        del columns, unique, sqlite_where, postgresql_where
        self.actions.append(("create_index", f"{table_name}.{name}"))


def test_postgres_downgrade_fences_new_ed25519_writes_before_observation(monkeypatch) -> None:
    migration = _load_migration()
    fake = _FakeDowngradeOp()
    monkeypatch.setattr(migration, "op", fake)

    migration.downgrade()

    assert fake.actions[:5] == [
        ("execute", migration._LOCK_ROLLBACK_FENCE_TABLE_SQL),
        ("execute", migration._DROP_ROLLBACK_FENCE_SQL),
        ("execute", migration._INSTALL_ROLLBACK_FENCE_SQL),
        ("query", str(migration._ROLLBACK_INCOMPATIBLE_IDENTITY)),
        ("execute", migration._VALIDATE_ROLLBACK_FENCE_SQL),
    ]
    first_schema_drop = next(
        index for index, action in enumerate(fake.actions) if action[0].startswith("drop_")
    )
    assert first_schema_drop > 4
    assert "NOT VALID" in migration._INSTALL_ROLLBACK_FENCE_SQL
    assert "IS DISTINCT FROM 'ed25519_signed_nonce'" in migration._INSTALL_ROLLBACK_FENCE_SQL


def test_postgres_downgrade_refuses_existing_ed25519_state_before_schema_drop(monkeypatch) -> None:
    migration = _load_migration()
    fake = _FakeDowngradeOp(incompatible=1)
    monkeypatch.setattr(migration, "op", fake)

    with pytest.raises(RuntimeError, match="Ed25519 worker identity state is present"):
        migration.downgrade()

    assert fake.actions[:4] == [
        ("execute", migration._LOCK_ROLLBACK_FENCE_TABLE_SQL),
        ("execute", migration._DROP_ROLLBACK_FENCE_SQL),
        ("execute", migration._INSTALL_ROLLBACK_FENCE_SQL),
        ("query", str(migration._ROLLBACK_INCOMPATIBLE_IDENTITY)),
    ]
    assert all(not action[0].startswith("drop_") for action in fake.actions)
    assert migration._VALIDATE_ROLLBACK_FENCE_SQL not in {
        value for kind, value in fake.actions if kind == "execute"
    }


def test_postgres_upgrade_leaves_validated_fence_after_pr5f_schema(monkeypatch) -> None:
    migration = _load_migration()
    fake = _FakeUpgradeOp()
    monkeypatch.setattr(migration, "op", fake)

    migration.upgrade()

    assert fake.actions[-5:] == [
        ("execute", migration._LOCK_ROLLBACK_FENCE_TABLE_SQL),
        ("execute", migration._DROP_ROLLBACK_FENCE_SQL),
        ("execute", migration._INSTALL_ROLLBACK_FENCE_SQL),
        ("query", str(migration._ROLLBACK_INCOMPATIBLE_IDENTITY)),
        ("execute", migration._VALIDATE_ROLLBACK_FENCE_SQL),
    ]
    assert any(action[0] == "create_index" for action in fake.actions[:-5])
    assert any(action == ("execute", migration._LEGACY_WRITE_COMPAT_SQL) for action in fake.actions)


def test_upgrade_refuses_duplicate_bound_state_before_any_ddl(monkeypatch) -> None:
    migration = _load_migration()
    fake = _FakeUpgradeOp(duplicate_bound=1)
    monkeypatch.setattr(migration, "op", fake)

    with pytest.raises(RuntimeError, match="duplicate bound bootstrap state is present"):
        migration.upgrade()

    assert fake.actions == [("query", str(migration._DUPLICATE_BOUND_TARGET))]


def test_sqlite_duplicate_refusal_preserves_schema_and_retryability(tmp_path, monkeypatch) -> None:
    """The intentional duplicate refusal must not strand SQLite at a partial d8 schema."""

    api_dir = Path(__file__).resolve().parents[1]
    database_path = tmp_path / "pr5f-duplicate-bound.db"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    monkeypatch.setenv("SECP_DATABASE_URL", database_url)

    from secp_api.config import get_settings

    get_settings.cache_clear()
    config = Config(str(api_dir / "alembic.ini"))
    config.set_main_option("script_location", str(api_dir / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "c4e2f9a1b7d3")

    engine = create_engine(database_url, future=True)
    now = "2026-07-19 00:00:00"
    target_id = str(uuid.uuid4())
    onboarding_id = str(uuid.uuid4())
    insert = text(
        """
        INSERT INTO proxmox_readonly_bootstrap_session (
            id, organization_id, execution_target_id, onboarding_id, account, pve_role,
            worker_ssh_public_key, worker_ssh_public_key_fingerprint, status, revision, ssh_port,
            host_key_fingerprint, host_public_key, endpoint_binding_hash,
            live_read_authorization_id, authorization_version, proof_summary, failure_code,
            expires_at, created_by, created_at, updated_at
        ) VALUES (
            :id, :organization_id, :execution_target_id, :onboarding_id,
            'secpdisc', 'SECPDiscoveryReadOnly', 'ssh-ed25519 AAAA', 'SHA256:public',
            'bound', 1, 22, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            :expires_at, NULL, :created_at, :updated_at
        )
        """
    )
    row_ids = (str(uuid.uuid4()), str(uuid.uuid4()))
    with engine.begin() as connection:
        for row_id in row_ids:
            connection.execute(
                insert,
                {
                    "id": row_id,
                    "organization_id": str(uuid.uuid4()),
                    "execution_target_id": target_id,
                    "onboarding_id": onboarding_id,
                    "expires_at": now,
                    "created_at": now,
                    "updated_at": now,
                },
            )

    with pytest.raises(RuntimeError, match="duplicate bound bootstrap state is present"):
        command.upgrade(config, "head")

    inspector = inspect(engine)
    assert "revision" not in {
        column["name"] for column in inspector.get_columns("worker_discovery_node")
    }
    assert "contact_state" not in {
        column["name"] for column in inspector.get_columns("discovery_snapshot")
    }
    assert "uq_proxmox_bootstrap_bound_target" not in {
        index["name"] for index in inspector.get_indexes("proxmox_readonly_bootstrap_session")
    }
    with engine.connect() as connection:
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == (
            "c4e2f9a1b7d3"
        )

    # Resolve only the synthetic duplicate and prove the exact same migration is retryable.
    with engine.begin() as connection:
        connection.execute(
            text("DELETE FROM proxmox_readonly_bootstrap_session WHERE id = :id"),
            {"id": row_ids[1]},
        )
    command.upgrade(config, "head")
    inspector = inspect(engine)
    assert "revision" in {
        column["name"] for column in inspector.get_columns("worker_discovery_node")
    }
    assert "contact_state" in {
        column["name"] for column in inspector.get_columns("discovery_snapshot")
    }
    with engine.connect() as connection:
        # the retried upgrade runs through to the CURRENT sole head (SECP-PR5H-A adds
        # b6e2f4a9c1d7 on top of the PR5F head), proving the fence is retryable end to end.
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == (
            "b6e2f4a9c1d7"
        )
    engine.dispose()
    get_settings.cache_clear()
