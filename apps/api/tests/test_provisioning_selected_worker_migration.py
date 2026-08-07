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

import uuid

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from secp_api.enums import ProvisioningOperationKind, ProvisioningStatus
from secp_api.immutability import ImmutableResourceError
from secp_api.models import ProvisioningOperation
from secp_api.services.provisioning_worker_selection import (
    SELECTION_REFUSAL_REASONS,
    ProvisioningWorkerSelectionRefused,
    assert_dispatchable,
    bind_provisioning_worker,
    select_provisioning_worker,
)
from sqlalchemy import create_engine, inspect
from sqlalchemy import inspect as sa_inspect
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

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _config(url: str) -> Config:
    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


# === the migration ================================================================================


def test_the_revision_is_the_sole_head_and_descends_from_the_previous_one():
    script = ScriptDirectory.from_config(_config("sqlite+pysqlite:///:memory:"))
    assert tuple(script.get_heads()) == (REVISION,)
    assert HEAD == REVISION
    assert script.get_revision(REVISION).down_revision == PR5H_B2


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


# === the binding, on real rows ====================================================================


def _operation(session, principal, **kw) -> ProvisioningOperation:
    from conftest import build_provisioning_env
    from secp_api.models import ProvisioningManifest

    env = build_provisioning_env(session, principal)
    manifest = ProvisioningManifest(
        organization_id=principal.organization_id,
        deployment_plan_id=env.plan.id,
        execution_target_id=env.target.id,
        target_config_hash=env.target.config_hash,
        content={"resources": []},
        content_hash="sha256:" + "c" * 64,
    )
    session.add(manifest)
    session.flush()
    op = ProvisioningOperation(
        organization_id=principal.organization_id,
        manifest_id=manifest.id,
        kind=kw.get("kind", ProvisioningOperationKind.apply),
        status=kw.get("status", ProvisioningStatus.manifest_generated),
        idempotency_key=kw.get("key", uuid.uuid4().hex),
    )
    session.add(op)
    session.flush()
    return op


def test_a_null_binding_makes_an_operation_undispatchable(session, principal):
    op = _operation(session, principal)
    assert op.worker_installation_id is None
    with pytest.raises(ProvisioningWorkerSelectionRefused, match="binding_absent"):
        assert_dispatchable(op)


def test_binding_then_dispatchable(session, principal):
    op = _operation(session, principal)
    bind_provisioning_worker(session, operation=op, worker_installation_id="wk-a")
    assert assert_dispatchable(op) == "wk-a"


def test_the_same_binding_twice_is_idempotent(session, principal):
    """A retried enqueue must not fail an operator who cannot tell whether the first attempt
    committed."""
    op = _operation(session, principal)
    first = bind_provisioning_worker(session, operation=op, worker_installation_id="wk-a")
    second = bind_provisioning_worker(session, operation=op, worker_installation_id="wk-a")
    assert first == second == "wk-a"


def test_a_different_binding_is_refused_not_silently_repointed(session, principal):
    """Re-selecting is a NEW operation, never an edit to an authorized one."""
    op = _operation(session, principal)
    bind_provisioning_worker(session, operation=op, worker_installation_id="wk-a")
    with pytest.raises(ProvisioningWorkerSelectionRefused, match="already_set"):
        bind_provisioning_worker(session, operation=op, worker_installation_id="wk-b")
    assert op.worker_installation_id == "wk-a"


def test_the_orm_layer_refuses_a_repoint_even_bypassing_the_service(session, principal):
    """The service is the only writer BY CONVENTION; this is the guard that does not depend on the
    convention being followed."""
    op = _operation(session, principal)
    bind_provisioning_worker(session, operation=op, worker_installation_id="wk-a")
    session.commit()

    op.worker_installation_id = "wk-b"
    with pytest.raises(ImmutableResourceError, match="write-once"):
        session.flush()
    session.rollback()


@pytest.mark.parametrize(
    "initial,new_value,allowed",
    [
        (None, "wk-a", True),  # the legitimate binding write
        ("wk-a", "wk-a", True),  # idempotent: a retried enqueue must not fail
        ("wk-a", "wk-b", False),  # a re-point of an authority that may already have been granted
        ("wk-a", None, False),  # clearing is a re-point to "anyone", which is worse, not better
    ],
)
def test_every_binding_transition_after_commit_and_expiration(
    session, principal, initial, new_value, allowed
):
    """The four transitions, driven through DIRECT ORM mutation with the instance EXPIRED.

    Expiration is the case that matters. Assigning to an expired attribute does not load the
    committed value unless the column declares ``active_history=True``, and without that the
    flush-time history reads ``deleted=()`` — so the guard sees no previous value and permits the
    re-point. This test failed exactly that way before the flag was added.
    """
    op = _operation(session, principal)
    if initial is not None:
        bind_provisioning_worker(session, operation=op, worker_installation_id=initial)
    session.commit()
    assert sa_inspect(op).expired is True, "the case under test requires an expired instance"

    op.worker_installation_id = new_value
    if allowed:
        session.flush()
        assert op.worker_installation_id == new_value
    else:
        with pytest.raises(ImmutableResourceError, match="write-once"):
            session.flush()
        session.rollback()


@pytest.mark.parametrize("new_value,allowed", [("wk-a", True), ("wk-b", False), (None, False)])
def test_every_binding_transition_after_a_fresh_reload(session, principal, new_value, allowed):
    """The same four rules through a row loaded fresh into a clean identity map — proving the
    invariant belongs to the MAPPING rather than to one session's in-memory state."""
    op = _operation(session, principal)
    bind_provisioning_worker(session, operation=op, worker_installation_id="wk-a")
    session.commit()
    operation_id = op.id
    session.expunge_all()

    reloaded = session.get(ProvisioningOperation, operation_id)
    reloaded.worker_installation_id = new_value
    if allowed:
        session.flush()
    else:
        with pytest.raises(ImmutableResourceError, match="write-once"):
            session.flush()
        session.rollback()


def test_the_column_declares_active_history():
    """Pinned structurally, because the flag has no visible effect until the exact expired-instance
    case — a future edit that removed it as noise would silently reopen the hole."""
    from sqlalchemy import inspect as _inspect

    attr = _inspect(ProvisioningOperation).attrs["worker_installation_id"]
    assert attr.active_history is True


def test_setting_a_binding_on_a_null_row_is_allowed_by_the_guard(session, principal):
    """One direction only: NULL -> value is the legitimate write; the guard must not block it."""
    op = _operation(session, principal)
    session.commit()
    op.worker_installation_id = "wk-a"
    session.flush()
    assert op.worker_installation_id == "wk-a"


def test_ordinary_lifecycle_columns_stay_mutable(session, principal):
    """The guard is scoped to the binding. Status, attempts and result are lifecycle state and a
    write-once rule over them would freeze the operation on creation."""
    op = _operation(session, principal)
    bind_provisioning_worker(session, operation=op, worker_installation_id="wk-a")
    session.commit()
    op.status = ProvisioningStatus.queued
    op.attempts = 1
    op.result = {"note": "x"}
    session.flush()
    assert op.status is ProvisioningStatus.queued


# === selection comes from the control plane =======================================================


def test_the_selection_surface_takes_no_worker_from_a_caller(session, principal):
    """Stronger than ignoring a caller's preference: there is nowhere to put one."""
    import inspect as _inspect

    params = set(_inspect.signature(select_provisioning_worker).parameters)
    assert params == {"session", "organization_id"}
    for banned in ("worker_installation_id", "worker", "preferred", "requested_by", "payload"):
        assert banned not in params, banned


def test_selection_refuses_when_no_worker_is_enrolled(session, principal):
    with pytest.raises(ProvisioningWorkerSelectionRefused, match="none_enrolled"):
        select_provisioning_worker(session, organization_id=principal.organization_id)


def test_every_refusal_reason_is_in_the_closed_set():
    with pytest.raises(ValueError, match="unknown provisioning worker selection reason"):
        ProvisioningWorkerSelectionRefused("something_new")
    assert len(SELECTION_REFUSAL_REASONS) == len(set(SELECTION_REFUSAL_REASONS))
    for reason in SELECTION_REFUSAL_REASONS:
        assert reason.startswith("provisioning_worker_"), reason
