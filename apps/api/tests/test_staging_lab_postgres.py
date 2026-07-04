"""SECP-002B-1B-9 — PostgreSQL integration tests for staging-lab concurrency + schema.

These prove the durable-lifecycle guarantees under REAL separate transactions (not one Python
session) and inspect the live PostgreSQL schema. Run against a real PostgreSQL by setting
``SECP_TEST_POSTGRES_URL``; skipped otherwise so the default suite stays hermetic.

Fake-only: no Proxmox/HTTP/socket/subprocess/secret. The worker consumer runs the fake executor.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL staging-lab tests"
)


def _now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture(scope="module")
def pg_engine():
    assert PG_URL
    engine = create_engine(PG_URL, future=True)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))

    from alembic import command
    from alembic.config import Config
    from secp_api.config import get_settings

    api_dir = __import__("pathlib").Path(__file__).resolve().parents[1]
    previous = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = PG_URL
    get_settings.cache_clear()
    cfg = Config(str(api_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_dir / "migrations"))
    cfg.set_main_option("sqlalchemy.url", PG_URL)
    command.upgrade(cfg, "head")

    yield engine
    engine.dispose()
    if previous is None:
        os.environ.pop("SECP_DATABASE_URL", None)
    else:
        os.environ["SECP_DATABASE_URL"] = previous
    get_settings.cache_clear()


@pytest.fixture
def pg_sessionmaker(pg_engine):
    return sessionmaker(bind=pg_engine, autoflush=False, future=True)


def _seed_org(pg_engine) -> uuid.UUID:
    org_id = uuid.uuid4()
    with pg_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO organization (id, name, slug, created_at) "
                "VALUES (:id, 'Org', :slug, :ts)"
            ),
            {"id": org_id, "slug": f"org-{org_id.hex[:8]}", "ts": _now()},
        )
    return org_id


def _principal(org_id: uuid.UUID):
    from secp_api.auth import Principal
    from secp_api.enums import Permission

    return Principal(
        user_id=uuid.uuid4(),
        organization_id=org_id,
        email="admin@local.test",
        permissions=frozenset(Permission),
    )


def _make_eligible_target(session: Session, principal) -> uuid.UUID:
    from secp_api.enums import (
        IsolationModel,
        OnboardingMode,
        OnboardingStatus,
        TargetStatus,
    )
    from secp_api.models import ExecutionTarget, TargetOnboarding
    from secp_api.services import staging_labs

    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={},
        config_hash="sha256:" + "ab" * 32,
        secret_ref=None,
        status=TargetStatus.active,
        scope_policy={},
        created_by=principal.user_id,
    )
    session.add(target)
    session.flush()
    session.add(
        TargetOnboarding(
            organization_id=principal.organization_id,
            execution_target_id=target.id,
            onboarding_mode=OnboardingMode.existing_environment,
            isolation_model=IsolationModel.logical,
            status=OnboardingStatus.active,
            declared_boundary={},
            boundary_hash="sha256:" + "cd" * 32,
            created_by=principal.user_id,
        )
    )
    session.flush()
    staging_labs.grant_substrate_eligibility(session, principal, execution_target_id=target.id)
    return target.id


def _awaiting_lab(session: Session, principal) -> uuid.UUID:
    from secp_api.services import staging_labs

    target_id = _make_eligible_target(session, principal)
    lab = staging_labs.create_staging_lab(session, principal, execution_target_id=target_id)
    staging_labs.generate_plan(session, principal, lab.id)
    staging_labs.submit_for_approval(session, principal, lab.id)
    return lab.id


def test_concurrent_approvals_only_one_row_approved(pg_engine, pg_sessionmaker):
    import secp_api.immutability  # noqa: F401  (register ORM guards)
    from secp_api.enums import StagingLabStatus
    from secp_api.models import StagingLab
    from secp_api.services import staging_labs

    org_id = _seed_org(pg_engine)
    principal = _principal(org_id)
    with pg_sessionmaker() as s0:
        lab_id = _awaiting_lab(s0, principal)
        s0.commit()
        plan_hash = s0.get(StagingLab, lab_id).plan_hash

    outcomes = []
    # Two real transactions racing to approve the same awaiting lab.
    s1 = pg_sessionmaker()
    s2 = pg_sessionmaker()
    try:
        for s in (s1, s2):
            try:
                staging_labs.approve_staging_lab(s, principal, lab_id, expected_plan_hash=plan_hash)
                s.commit()
                outcomes.append("ok")
            except Exception:
                s.rollback()
                outcomes.append("refused")
    finally:
        s1.close()
        s2.close()

    # Assert the DATABASE outcome: exactly one approval landed.
    with pg_engine.begin() as conn:
        status, cnt = conn.execute(
            text("SELECT status, count(*) FROM staging_lab WHERE id = :id GROUP BY status"),
            {"id": lab_id},
        ).one()
    assert status == StagingLabStatus.approved.value
    assert outcomes.count("ok") == 1


def test_concurrent_queue_only_one_active_work_item(pg_engine, pg_sessionmaker):
    import secp_api.immutability  # noqa: F401
    from secp_api.models import StagingLab
    from secp_api.services import staging_labs

    org_id = _seed_org(pg_engine)
    principal = _principal(org_id)
    with pg_sessionmaker() as s0:
        lab_id = _awaiting_lab(s0, principal)
        staging_labs.approve_staging_lab(
            s0, principal, lab_id, expected_plan_hash=s0.get(StagingLab, lab_id).plan_hash
        )
        s0.commit()

    s1, s2 = pg_sessionmaker(), pg_sessionmaker()
    ok = 0
    try:
        for s in (s1, s2):
            try:
                staging_labs.queue_simulation(s, principal, lab_id)
                s.commit()
                ok += 1
            except Exception:
                s.rollback()
    finally:
        s1.close()
        s2.close()

    with pg_engine.begin() as conn:
        active = conn.execute(
            text(
                "SELECT count(*) FROM staging_lab_work_item "
                "WHERE staging_lab_id = :id AND status IN ('queued','claimed')"
            ),
            {"id": lab_id},
        ).scalar_one()
    # Exactly one active work item — the scope/fingerprint uniqueness + partial index enforce it.
    assert active == 1
    assert ok >= 1


def test_postgres_skip_locked_prevents_competing_worker_completion(pg_engine, pg_sessionmaker):
    import secp_api.immutability  # noqa: F401
    from secp_api.enums import StagingLabStatus, StagingWorkStatus
    from secp_api.models import StagingLab
    from secp_api.services import staging_labs
    from secp_worker.staging_lab.consumer import claim_and_process_one

    # Keep this proof about one queued row. Earlier PostgreSQL tests intentionally leave an active
    # work item behind while checking the partial unique index; a real worker may claim that other
    # row, which is correct behavior but not what this SKIP LOCKED proof is asserting.
    with pg_engine.begin() as conn:
        conn.execute(text("DELETE FROM staging_lab_work_item"))

    org_id = _seed_org(pg_engine)
    principal = _principal(org_id)
    with pg_sessionmaker() as s0:
        lab_id = _awaiting_lab(s0, principal)
        staging_labs.approve_staging_lab(
            s0, principal, lab_id, expected_plan_hash=s0.get(StagingLab, lab_id).plan_hash
        )
        staging_labs.queue_simulation(s0, principal, lab_id)
        s0.commit()

    # Two worker transactions overlap on the single queued item. Worker 1 claims and completes
    # without committing yet, holding the row lock. Worker 2 must SKIP LOCKED and do nothing:
    # it cannot also claim or complete the same queued item.
    s1, s2 = pg_sessionmaker(), pg_sessionmaker()
    try:
        first = claim_and_process_one(s1)
        assert first is not None

        second = claim_and_process_one(s2)
        assert second is None
        s2.commit()

        # Until worker 1 commits, a third observer should still not see a committed completion.
        with pg_engine.begin() as conn:
            visible_completed = conn.execute(
                text(
                    "SELECT count(*) FROM staging_lab_work_item "
                    "WHERE staging_lab_id = :id AND status = :st"
                ),
                {"id": lab_id, "st": StagingWorkStatus.completed.value},
            ).scalar_one()
        assert visible_completed == 0

        s1.commit()
    finally:
        s1.close()
        s2.close()

    with pg_engine.begin() as conn:
        completed, claimed, lab_status = conn.execute(
            text(
                "SELECT "
                "count(*) FILTER (WHERE w.status = :completed), "
                "count(*) FILTER (WHERE w.status = :claimed), "
                "max(l.status) "
                "FROM staging_lab_work_item w "
                "JOIN staging_lab l ON l.id = w.staging_lab_id "
                "WHERE w.staging_lab_id = :id"
            ),
            {
                "id": lab_id,
                "completed": StagingWorkStatus.completed.value,
                "claimed": StagingWorkStatus.claimed.value,
            },
        ).one()
    assert completed == 1
    assert claimed == 0
    assert lab_status == StagingLabStatus.simulated_ready.value


def test_partial_unique_index_and_scope_constraint_exist(pg_engine):
    insp = inspect(pg_engine)
    indexes = {ix["name"]: ix for ix in insp.get_indexes("staging_lab_work_item")}
    assert "uq_staging_work_active" in indexes
    active = indexes["uq_staging_work_active"]
    assert active["unique"] is True
    # The partial predicate targets active (queued/claimed) rows.
    ddl = None
    with pg_engine.begin() as conn:
        ddl = conn.execute(
            text("SELECT indexdef FROM pg_indexes WHERE indexname = 'uq_staging_work_active'")
        ).scalar_one()
    assert "queued" in ddl and "claimed" in ddl

    uniques = {
        uc["name"]: set(uc["column_names"])
        for uc in insp.get_unique_constraints("staging_lab_work_item")
    }
    assert uniques.get("uq_staging_work_scope") == {
        "staging_lab_id",
        "operation_kind",
        "plan_hash",
        "plan_version",
    }
    assert "uq_staging_work_fingerprint" in uniques


def test_foreign_keys_enforce_organization_association(pg_engine):
    insp = inspect(pg_engine)
    fks = insp.get_foreign_keys("staging_lab_work_item")
    referred = {(fk["referred_table"], tuple(fk["constrained_columns"])) for fk in fks}
    assert ("organization", ("organization_id",)) in referred
    assert ("staging_lab", ("staging_lab_id",)) in referred


def test_downgrade_drops_staging_tables(pg_engine):
    from alembic import command
    from alembic.config import Config

    api_dir = __import__("pathlib").Path(__file__).resolve().parents[1]
    cfg = Config(str(api_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_dir / "migrations"))
    cfg.set_main_option("sqlalchemy.url", PG_URL)
    # Downgrade one step removes the staging tables; upgrade restores them (leave schema at head).
    command.downgrade(cfg, "-1")
    tables = set(inspect(pg_engine).get_table_names())
    assert "staging_lab_work_item" not in tables
    assert "staging_substrate_eligibility" not in tables
    assert "staging_lab" not in tables
    command.upgrade(cfg, "head")
    tables = set(inspect(pg_engine).get_table_names())
    assert {"staging_lab", "staging_lab_work_item", "staging_substrate_eligibility"} <= tables
