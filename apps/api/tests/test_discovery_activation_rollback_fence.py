"""The PR5F database write fence has only fixed, fail-closed operations."""

from __future__ import annotations

import importlib.util
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from secp_api import discovery_activation_rollback_fence as fence
from sqlalchemy.orm import Session


class _Result:
    def __init__(self, value: object = 0) -> None:
        self._value = value

    def scalar_one(self) -> object:
        return self._value


class _FakeSession:
    def __init__(
        self,
        *,
        dialect: str = "postgresql",
        incompatible: int = 0,
        fence_state: str = "engaged",
        failure: Exception | None = None,
    ) -> None:
        self.bind = SimpleNamespace(dialect=SimpleNamespace(name=dialect))
        self.incompatible = incompatible
        self.fence_state = fence_state
        self.failure = failure
        self.statements: list[str] = []
        self.parameters: list[object] = []

    def get_bind(self) -> object:
        return self.bind

    def execute(self, statement: object, parameters: object = None) -> _Result:
        # Mirrors sqlalchemy Session.execute(statement, params): the observe query binds
        # ``:expected_expr`` as a parameter, so the fake must accept (and record) it too.
        rendered = str(statement)
        self.statements.append(rendered)
        self.parameters.append(parameters)
        if self.failure is not None:
            raise self.failure
        if "SELECT CASE WHEN EXISTS" in rendered:
            return _Result(self.incompatible)
        if "WITH target AS" in rendered:
            return _Result(self.fence_state)
        return _Result()


def _session(fake: _FakeSession) -> Session:
    return cast(Session, fake)


def _normalized(statement: object) -> str:
    return " ".join(str(statement).split())


def test_engage_serializes_repairs_checks_and_validates_in_order() -> None:
    fake = _FakeSession()

    fence.engage_rollback_fence(_session(fake))

    assert [_normalized(statement) for statement in fake.statements] == [
        _normalized(fence._LOCK_TABLE),
        _normalized(fence._DROP_FENCE),
        _normalized(fence._INSTALL_FENCE),
        _normalized(fence._INCOMPATIBLE_STATE),
        _normalized(fence._VALIDATE_FENCE),
    ]


def test_engage_refuses_incompatible_state_without_validation_or_release() -> None:
    fake = _FakeSession(incompatible=1)

    with pytest.raises(fence.RollbackFenceError, match="rollback_fence_incompatible_state"):
        fence.engage_rollback_fence(_session(fake))

    assert _normalized(fence._VALIDATE_FENCE) not in map(_normalized, fake.statements)
    assert fake.statements[-1] == str(fence._INCOMPATIBLE_STATE)


def test_release_reproves_fence_and_compatibility_before_final_drop() -> None:
    fake = _FakeSession()

    fence.release_rollback_fence(_session(fake))

    assert fake.statements[-1] == str(fence._DROP_FENCE)
    assert fake.statements.count(str(fence._DROP_FENCE)) == 2
    assert fake.statements.index(str(fence._VALIDATE_FENCE)) < len(fake.statements) - 1


@pytest.mark.parametrize(
    ("database_state", "expected"),
    [("engaged", "engaged"), ("released", "released"), ("unexpected", "unverified")],
)
def test_observe_returns_only_closed_fence_states(database_state: str, expected: str) -> None:
    fake = _FakeSession(fence_state=database_state)

    assert fence.observe_rollback_fence(_session(fake)) == expected

    assert fake.statements == [str(fence._OBSERVE_FENCE_STATE)]
    # the quote-bearing expected predicate is bound as a parameter, never inlined into the SQL text
    assert fake.parameters == [{"expected_expr": fence._EXPECTED_NORMALIZED_EXPRESSION}]
    assert "'{_EXPECTED_NORMALIZED_EXPRESSION}'" not in str(fence._OBSERVE_FENCE_STATE)
    statement = fake.statements[0]
    assert "pg_catalog.pg_constraint" in statement
    assert "pg_catalog.pg_attribute" in statement
    assert fence.ROLLBACK_FENCE_NAME in statement
    assert "worker_identity_registration" in statement


def test_non_postgres_backend_refuses_before_sql() -> None:
    fake = _FakeSession(dialect="sqlite")

    with pytest.raises(fence.RollbackFenceError, match="rollback_fence_postgresql_required"):
        fence.engage_rollback_fence(_session(fake))

    with pytest.raises(fence.RollbackFenceError, match="rollback_fence_postgresql_required"):
        fence.observe_rollback_fence(_session(fake))

    assert fake.statements == []


def test_cli_outputs_only_closed_success_and_failure_shapes(monkeypatch, capsys) -> None:
    success = _FakeSession()

    @contextmanager
    def success_scope():
        yield _session(success)

    monkeypatch.setattr(fence, "session_scope", success_scope)
    assert fence.main(["engage"]) == 0
    assert capsys.readouterr().out == (
        '{"action":"engage","observation_complete":true,"rollback_fence_state":"engaged"}\n'
    )

    assert fence.main(["observe"]) == 0
    assert capsys.readouterr().out == (
        '{"action":"observe","observation_complete":true,"rollback_fence_state":"engaged"}\n'
    )

    unverified = _FakeSession(fence_state="unverified")

    @contextmanager
    def unverified_scope():
        yield _session(unverified)

    monkeypatch.setattr(fence, "session_scope", unverified_scope)
    assert fence.main(["observe"]) == 2
    assert capsys.readouterr().out == (
        '{"action":"observe","observation_complete":false,"rollback_fence_state":"unverified"}\n'
    )

    failure = _FakeSession(failure=RuntimeError("private-database-value"))

    @contextmanager
    def failure_scope():
        yield _session(failure)

    monkeypatch.setattr(fence, "session_scope", failure_scope)
    assert fence.main(["release"]) == 2
    output = capsys.readouterr().out
    assert output == (
        '{"action":"release","observation_complete":false,"rollback_fence_state":"unverified"}\n'
    )
    assert "private-database-value" not in output

    assert fence.main(["unexpected"]) == 2
    assert capsys.readouterr().out == (
        '{"action":"invalid","observation_complete":false,"rollback_fence_state":"unverified"}\n'
    )


def test_migration_and_runtime_helper_share_the_exact_fence_contract() -> None:
    migration_path = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "versions"
        / "d8f1a2b3c4e5_b8_production_activation.py"
    )
    spec = importlib.util.spec_from_file_location("pr5f_fence_migration", migration_path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    assert migration._ROLLBACK_FENCE_NAME == fence.ROLLBACK_FENCE_NAME
    assert _normalized(migration._LOCK_ROLLBACK_FENCE_TABLE_SQL) == _normalized(fence._LOCK_TABLE)
    assert _normalized(migration._DROP_ROLLBACK_FENCE_SQL) == _normalized(fence._DROP_FENCE)
    assert _normalized(migration._INSTALL_ROLLBACK_FENCE_SQL) == _normalized(fence._INSTALL_FENCE)
    assert _normalized(migration._VALIDATE_ROLLBACK_FENCE_SQL) == _normalized(fence._VALIDATE_FENCE)
