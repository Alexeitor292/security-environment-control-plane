"""The selected-worker binding: the migration, the write-once rule, and the dispatch gate.

ADR-030 condition 2 said the executing worker must equal the one the operation names. Nothing
named one, so the authority derivation refused every execution. ``e3b7a9c25f41`` adds the column
that closes it — and these tests are what stop the column becoming a field anyone can set to
anything.

The properties that matter are not "the column exists". They are:

* a NULL binding makes an operation UNDISPATCHABLE, not open to any worker;
* the write happens once and never moves;
* an exact retry keeps the binding it was authorized under;
* selection comes from the control plane, and there is nowhere for a caller to put a preference.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect
from test_pr5h_schema_parity import API_DIR, HEAD, PR5H_B2

REVISION = "e3b7a9c25f41"
TABLE = "provisioning_operation"
COLUMN = "worker_installation_id"


@pytest.fixture(autouse=True)
def _restore_settings_cache():  # noqa: ANN202
    """The migration tests point SECP_DATABASE_URL at their own file. Without clearing the cached
    Settings on both sides, a test that ran earlier leaves the URL bound and the next one inspects
    a database its migration never touched -- which shows up as NoSuchTableError, not as a wrong
    answer, and only when the tests run together."""
    from secp_api.config import get_settings
    from secp_api.db import reset_engine_for_tests

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
    # AND rebind the global engine. Clearing the settings cache alone leaves ``secp_api.db``'s
    # module-level engine pointed at whatever URL was last set — so a later test in the SAME worker
    # process reads a database this module's migration created and then deleted. That is invisible
    # locally, where these tests usually run alone, and shows up in CI as unrelated failures in
    # other files sharing the shard.
    reset_engine_for_tests(get_settings().database_url)


def _config(url: str) -> Config:
    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


# === the migration ================================================================================


def test_the_revision_sits_in_the_linear_chain_below_the_current_head():
    """Renamed: this revision WAS the sole head; ``7c2f4b8d1a6e`` now is.

    The property worth keeping is not "this is the head" — that expires every time a migration
    lands — but that this revision is still exactly where it was in a chain that stayed linear.
    Asserting it is the head would have to be edited on every future migration, and a test edited
    that often stops being read.
    """
    script = ScriptDirectory.from_config(_config("sqlite+pysqlite:///:memory:"))
    assert tuple(script.get_heads()) == (HEAD,)  # still exactly one head
    assert HEAD != REVISION  # ...and it is no longer this one
    assert script.get_revision(REVISION).down_revision == PR5H_B2
    assert script.get_revision(HEAD).down_revision == REVISION


def test_upgrade_adds_the_column_and_downgrade_removes_it(tmp_path, monkeypatch):
    """Both directions, on a real engine — not by reading the migration source."""
    url = f"sqlite+pysqlite:///{(tmp_path / 'sel.db').as_posix()}"
    monkeypatch.setenv("SECP_DATABASE_URL", url)
    cfg = _config(url)

    command.upgrade(cfg, REVISION)
    engine = create_engine(url, future=True)
    columns = {c["name"] for c in inspect(engine).get_columns(TABLE)}
    assert COLUMN in columns

    command.downgrade(cfg, PR5H_B2)
    engine.dispose()
    engine = create_engine(url, future=True)
    columns = {c["name"] for c in inspect(engine).get_columns(TABLE)}
    assert COLUMN not in columns
    # The table itself survives: this migration adds a column, it does not own the table.
    assert TABLE in set(inspect(engine).get_table_names())
    engine.dispose()


def test_the_round_trip_is_retryable(tmp_path, monkeypatch):
    """upgrade -> downgrade -> upgrade. A migration that only works once is one an operator cannot
    recover from."""
    url = f"sqlite+pysqlite:///{(tmp_path / 'round.db').as_posix()}"
    monkeypatch.setenv("SECP_DATABASE_URL", url)
    cfg = _config(url)
    command.upgrade(cfg, REVISION)
    command.downgrade(cfg, PR5H_B2)
    command.upgrade(cfg, REVISION)
    engine = create_engine(url, future=True)
    assert COLUMN in {c["name"] for c in inspect(engine).get_columns(TABLE)}
    engine.dispose()


def test_the_column_is_nullable_and_nothing_backfills_it(tmp_path, monkeypatch):
    """Historical rows have no selection anyone recorded, and inventing one would be fabricating an
    authorization record."""
    url = f"sqlite+pysqlite:///{(tmp_path / 'null.db').as_posix()}"
    monkeypatch.setenv("SECP_DATABASE_URL", url)
    command.upgrade(_config(url), REVISION)
    engine = create_engine(url, future=True)
    column = next(c for c in inspect(engine).get_columns(TABLE) if c["name"] == COLUMN)
    assert column["nullable"] is True
    assert column.get("default") in (None, "None")
    engine.dispose()

    source = (
        API_DIR
        / "migrations"
        / "versions"
        / f"{REVISION}_provisioning_operation_selected_worker.py"
    ).read_text(encoding="utf-8")
    for backfill in ("UPDATE ", "update(", "execute(", "server_default"):
        assert backfill not in source, backfill
