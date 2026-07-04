"""SECP-B2-0 — PostgreSQL integration tests for read-only preflight concurrency + schema.

Proves durable-lifecycle guarantees under REAL separate transactions (SKIP LOCKED claim) and
inspects the live schema. Run with ``SECP_TEST_POSTGRES_URL``; skipped otherwise. Fake-only: the
sealed resolver fails closed as ``credential_unavailable`` — no real connection is made.
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
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL preflight tests"
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


def _queued_preflight(session: Session, principal) -> uuid.UUID:
    from secp_api.enums import (
        IsolationModel,
        OnboardingMode,
        OnboardingStatus,
        TargetStatus,
    )
    from secp_api.models import ExecutionTarget, TargetOnboarding
    from secp_api.services import readonly_preflight, staging_labs

    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref="env:SECP_PROVIDER_SECRET__PF",
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
    auth = readonly_preflight.create_preflight_authorization(
        session, principal, execution_target_id=target.id
    )
    readonly_preflight.approve_preflight_authorization(session, principal, auth.id)
    return readonly_preflight.queue_preflight(
        session, principal, live_read_authorization_id=auth.id
    ).id


def test_skip_locked_prevents_competing_worker_claim(pg_engine, pg_sessionmaker):
    import secp_api.immutability  # noqa: F401
    from secp_worker.preflight.consumer import claim_and_process_one

    with pg_sessionmaker() as s0:
        pf_id = _queued_preflight(s0, _principal(_seed_org(pg_engine)))
        s0.commit()

    s1, s2 = pg_sessionmaker(), pg_sessionmaker()
    try:
        first = claim_and_process_one(s1)  # claims + processes, holding the row lock (uncommitted)
        assert first == pf_id
        second = claim_and_process_one(s2)  # must SKIP LOCKED and find nothing
        assert second is None
        s2.commit()
        s1.commit()
    finally:
        s1.close()
        s2.close()

    with pg_engine.begin() as conn:
        completed = conn.execute(
            text(
                "SELECT count(*) FROM readonly_staging_preflight "
                "WHERE id = :id AND status = 'completed' "
                "AND outcome_code = 'credential_unavailable'"
            ),
            {"id": pf_id},
        ).scalar_one()
    assert completed == 1


def test_committed_authorization_reaches_credential_unavailable(pg_engine, pg_sessionmaker):
    """On PostgreSQL the expiry stays timezone-aware after commit, so the verifier passes to the
    sealed resolver (credential_unavailable) rather than a malformed-expiry refusal."""
    import secp_api.immutability  # noqa: F401
    from secp_worker.preflight.consumer import claim_and_process_one

    with pg_sessionmaker() as s0:
        pf_id = _queued_preflight(s0, _principal(_seed_org(pg_engine)))
        s0.commit()
    with pg_sessionmaker() as sw:
        assert claim_and_process_one(sw) == pf_id
        sw.commit()
    with pg_engine.begin() as conn:
        outcome = conn.execute(
            text("SELECT outcome_code FROM readonly_staging_preflight WHERE id = :id"),
            {"id": pf_id},
        ).scalar_one()
    assert outcome == "credential_unavailable"


def test_schema_constraints_and_indexes(pg_engine):
    insp = inspect(pg_engine)
    uniques = {
        uc["name"]: set(uc["column_names"])
        for uc in insp.get_unique_constraints("readonly_staging_preflight")
    }
    assert uniques.get("uq_readonly_preflight_scope") == {
        "execution_target_id",
        "onboarding_id",
        "live_read_authorization_id",
        "authorization_version",
    }
    assert "uq_readonly_preflight_fingerprint" in uniques
    indexes = {ix["name"]: ix for ix in insp.get_indexes("readonly_staging_preflight")}
    assert indexes["uq_readonly_preflight_active"]["unique"] is True
    with pg_engine.begin() as conn:
        ddl = conn.execute(
            text("SELECT indexdef FROM pg_indexes WHERE indexname = 'uq_readonly_preflight_active'")
        ).scalar_one()
    assert "queued" in ddl and "claimed" in ddl and "running" in ddl
    referred = {
        (fk["referred_table"], tuple(fk["constrained_columns"]))
        for fk in insp.get_foreign_keys("readonly_staging_preflight")
    }
    assert ("organization", ("organization_id",)) in referred
    assert ("live_read_authorization", ("live_read_authorization_id",)) in referred


def test_downgrade_drops_preflight_table(pg_engine):
    from alembic import command
    from alembic.config import Config

    api_dir = __import__("pathlib").Path(__file__).resolve().parents[1]
    cfg = Config(str(api_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_dir / "migrations"))
    cfg.set_main_option("sqlalchemy.url", PG_URL)
    command.downgrade(cfg, "-1")
    assert "readonly_staging_preflight" not in set(inspect(pg_engine).get_table_names())
    command.upgrade(cfg, "head")
    assert "readonly_staging_preflight" in set(inspect(pg_engine).get_table_names())
