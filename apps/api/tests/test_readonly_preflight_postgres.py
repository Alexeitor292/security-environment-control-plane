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


def _alembic_cfg():
    from alembic.config import Config

    api_dir = __import__("pathlib").Path(__file__).resolve().parents[1]
    cfg = Config(str(api_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_dir / "migrations"))
    cfg.set_main_option("sqlalchemy.url", PG_URL)
    return cfg


def test_downgrade_removes_lease_then_preflight_in_order(pg_engine):
    """The lease migration (B2-3) sits on top of the preflight migration (B2-0). Downgrading one
    step removes ONLY resolution_lease and leaves readonly_staging_preflight; a further step down
    removes readonly_staging_preflight. Revisions are derived from the migration graph."""
    from alembic import command
    from alembic.script import ScriptDirectory

    cfg = _alembic_cfg()
    script = ScriptDirectory.from_config(cfg)
    heads = script.get_heads()
    assert len(heads) == 1, f"expected a single head, got {heads}"
    lease_rev = heads[0]  # B2-3
    preflight_rev = script.get_revision(lease_rev).down_revision  # B2-0
    assert isinstance(preflight_rev, str) and preflight_rev
    preflight_parent = script.get_revision(preflight_rev).down_revision
    assert isinstance(preflight_parent, str) and preflight_parent

    def tables() -> set[str]:
        return set(inspect(pg_engine).get_table_names())

    try:
        command.downgrade(cfg, preflight_rev)  # remove B2-3 only
        after_lease = tables()
        assert "resolution_lease" not in after_lease
        assert "readonly_staging_preflight" in after_lease

        command.downgrade(cfg, preflight_parent)  # remove B2-0 too
        after_preflight = tables()
        assert "readonly_staging_preflight" not in after_preflight
        assert "resolution_lease" not in after_preflight
    finally:
        command.upgrade(cfg, "head")

    restored = tables()
    assert {"readonly_staging_preflight", "resolution_lease"} <= restored


def test_resolution_lease_schema_and_constraints(pg_engine):
    insp = inspect(pg_engine)
    cols = {c["name"] for c in insp.get_columns("resolution_lease")}
    # No secret/reference/endpoint columns exist in the live schema.
    assert not (cols & {"secret_ref", "credential_ref", "secret", "endpoint", "base_url", "token"})
    uniques = {
        uc["name"]: tuple(uc["column_names"])
        for uc in insp.get_unique_constraints("resolution_lease")
    }
    assert uniques.get("uq_resolution_lease_operation") == (
        "live_read_authorization_id",
        "authorization_version",
        "operation_fingerprint",
    )
    referred = {
        (fk["referred_table"], tuple(fk["constrained_columns"]))
        for fk in insp.get_foreign_keys("resolution_lease")
    }
    assert ("live_read_authorization", ("live_read_authorization_id",)) in referred


def _make_substrate(session, principal):
    from secp_api.enums import IsolationModel, OnboardingMode, OnboardingStatus, TargetStatus
    from secp_api.models import ExecutionTarget, TargetOnboarding
    from secp_api.services import staging_labs

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
    return target.id


def test_renewal_after_prior_authorization_expires_gets_higher_version(pg_engine, pg_sessionmaker):
    import secp_api.immutability  # noqa: F401
    from secp_api.services import readonly_preflight

    principal = _principal(_seed_org(pg_engine))
    with pg_sessionmaker() as s:
        target_id = _make_substrate(s, principal)
        first = readonly_preflight.create_preflight_authorization(
            s, principal, execution_target_id=target_id
        )
        assert first.authorization_version == 1
        s.commit()
        first_id = first.id

    # Expire the first authorization at the DB layer (protected column; raw UPDATE, not ORM).
    with pg_engine.begin() as conn:
        conn.execute(
            text("UPDATE live_read_authorization SET authorization_expiry = :ts WHERE id = :id"),
            {"ts": _now() - __import__("datetime").timedelta(days=1), "id": first_id},
        )

    with pg_sessionmaker() as s:
        second = readonly_preflight.create_preflight_authorization(
            s, principal, execution_target_id=target_id
        )
        assert second.authorization_version == 2
        s.commit()

    with pg_engine.begin() as conn:
        versions = [
            r[0]
            for r in conn.execute(
                text(
                    "SELECT authorization_version FROM live_read_authorization "
                    "WHERE execution_target_id = :t ORDER BY authorization_version"
                ),
                {"t": target_id},
            ).all()
        ]
    assert versions == [1, 2]  # monotonic, no duplicate

    # And the DB unique constraint forbids a duplicate (target, onboarding, version).
    onboarding_id = None
    with pg_engine.begin() as conn:
        onboarding_id = conn.execute(
            text("SELECT onboarding_id FROM live_read_authorization WHERE id = :id"),
            {"id": first_id},
        ).scalar_one()
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        with pg_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO live_read_authorization "
                    "(id, organization_id, execution_target_id, onboarding_id, connection_hash, "
                    " boundary_hash, authorization_version, authorization_expiry, "
                    " collector_contract_version, endpoint_allowlist_version, evidence_source, "
                    " verification_level, status, revocation_reason_code, created_at) "
                    "VALUES (:id, :org, :t, :ob, 'sha256:x', 'sha256:y', 1, :exp, 'c', 'e', 's', "
                    " 'live_verified', 'draft', '', :ts)"
                ),
                {
                    "id": uuid.uuid4(),
                    "org": principal.organization_id,
                    "t": target_id,
                    "ob": onboarding_id,
                    "exp": _now(),
                    "ts": _now(),
                },
            )


def test_stale_terminal_cas_fails_closed_at_db(pg_engine, pg_sessionmaker):
    """A stale worker's terminal UPDATE (expecting an old revision) affects zero rows and cannot
    overwrite a newer state or write facts."""
    import secp_api.immutability  # noqa: F401
    from secp_api.enums import ReadonlyPreflightStatus

    principal = _principal(_seed_org(pg_engine))
    with pg_sessionmaker() as s:
        pf_id = _queued_preflight(s, principal)
        s.commit()
    # Move it to running@rev1, then a competing op advances it to rev6.
    with pg_engine.begin() as conn:
        conn.execute(
            text("UPDATE readonly_staging_preflight SET status='running', revision=1 WHERE id=:id"),
            {"id": pf_id},
        )
        conn.execute(
            text("UPDATE readonly_staging_preflight SET revision=6 WHERE id=:id"),
            {"id": pf_id},
        )
    # A stale terminal CAS expecting revision=1 affects zero rows.
    with pg_engine.begin() as conn:
        rowcount = conn.execute(
            text(
                "UPDATE readonly_staging_preflight "
                "SET status='completed', revision=2, outcome_code='ready', "
                "    readiness_facts='{\"api_reachable\": true}' "
                "WHERE id=:id AND status='running' AND revision=1"
            ),
            {"id": pf_id},
        ).rowcount
        status, outcome, facts = conn.execute(
            text(
                "SELECT status, outcome_code, readiness_facts "
                "FROM readonly_staging_preflight WHERE id=:id"
            ),
            {"id": pf_id},
        ).one()
    assert rowcount == 0
    assert status == ReadonlyPreflightStatus.running.value
    assert outcome is None
    assert facts is None


# --- SECP-B2-3: durable resolution-lease behavior under REAL separate transactions ---------------


def _seed_authorization(session: Session, principal) -> tuple[uuid.UUID, int, str]:
    """Seed a substrate + approved authorization; return (auth_id, version, fingerprint)."""
    from secp_api.services import readonly_preflight

    target_id = _make_substrate(session, principal)
    auth = readonly_preflight.create_preflight_authorization(
        session, principal, execution_target_id=target_id
    )
    readonly_preflight.approve_preflight_authorization(session, principal, auth.id)
    return auth.id, auth.authorization_version, "sha256:" + "ab" * 32


def test_lease_operation_uniqueness_enforced_at_db(pg_engine, pg_sessionmaker):
    from secp_worker.preflight.lease import OperationKey, acquire_lease

    principal = _principal(_seed_org(pg_engine))
    with pg_sessionmaker() as s:
        auth_id, version, fp = _seed_authorization(s, principal)
        s.commit()
        key = OperationKey(auth_id, version, fp)
        acquire_lease(
            s,
            organization_id=principal.organization_id,
            key=key,
            worker_identity_id="worker-a",
            authorization_expiry=_now() + __import__("datetime").timedelta(hours=1),
            now=_now(),
        )
        s.commit()

    # A raw duplicate insert for the same (auth, version, fingerprint) violates the unique key.
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        with pg_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO resolution_lease "
                    "(id, organization_id, live_read_authorization_id, authorization_version, "
                    " operation_fingerprint, lease_id, revision, status, attempt_count, "
                    " lease_expires_at, worker_identity_id, reason_code, created_at) "
                    "VALUES (:id, :org, :auth, :ver, :fp, :lease, 0, 'active', 0, "
                    " :exp, 'w', '', :ts)"
                ),
                {
                    "id": uuid.uuid4(),
                    "org": principal.organization_id,
                    "auth": auth_id,
                    "ver": version,
                    "fp": fp,
                    "lease": uuid.uuid4(),
                    "exp": _now(),
                    "ts": _now(),
                },
            )


def test_lease_budget_and_replay_are_durable_across_transactions(pg_engine, pg_sessionmaker):
    from secp_worker.preflight.lease import (
        RETRY_BUDGET,
        LeaseRefused,
        OperationKey,
        acquire_lease,
        begin_attempt,
    )

    principal = _principal(_seed_org(pg_engine))
    delta = __import__("datetime").timedelta
    with pg_sessionmaker() as s:
        auth_id, version, fp = _seed_authorization(s, principal)
        s.commit()
        key = OperationKey(auth_id, version, fp)
        lease = acquire_lease(
            s,
            organization_id=principal.organization_id,
            key=key,
            worker_identity_id="worker-a",
            authorization_expiry=_now() + delta(hours=1),
            now=_now(),
        )
        for _ in range(RETRY_BUDGET):
            begin_attempt(s, lease, now=_now())
        s.commit()

    # A DIFFERENT committed transaction (different worker identity) is refused: budget is durable.
    with pg_sessionmaker() as s:
        with pytest.raises(LeaseRefused) as exc:
            acquire_lease(
                s,
                organization_id=principal.organization_id,
                key=OperationKey(auth_id, version, fp),
                worker_identity_id="worker-b",
                authorization_expiry=_now() + delta(hours=1),
                now=_now() + delta(minutes=1),
            )
        from secp_api.enums import ResolutionLeaseReason

        assert exc.value.reason == ResolutionLeaseReason.retry_bound_exceeded

    # A NEW authorization version is a distinct operation key with a fresh budget.
    with pg_sessionmaker() as s:
        fresh = acquire_lease(
            s,
            organization_id=principal.organization_id,
            key=OperationKey(auth_id, version + 1, fp),
            worker_identity_id="worker-a",
            authorization_expiry=_now() + delta(hours=1),
            now=_now(),
        )
        assert fresh.attempt_count == 0
        s.commit()


def test_lease_expiry_preserves_budget_across_transactions(pg_engine, pg_sessionmaker):
    from secp_worker.preflight.lease import OperationKey, acquire_lease, begin_attempt

    principal = _principal(_seed_org(pg_engine))
    delta = __import__("datetime").timedelta
    with pg_sessionmaker() as s:
        auth_id, version, fp = _seed_authorization(s, principal)
        s.commit()
        key = OperationKey(auth_id, version, fp)
        lease = acquire_lease(
            s,
            organization_id=principal.organization_id,
            key=key,
            worker_identity_id="worker-a",
            authorization_expiry=_now() + delta(hours=6),
            now=_now(),
            lease_ttl_seconds=60,
        )
        begin_attempt(s, lease, now=_now())
        original_lease_id = lease.lease_id
        s.commit()

    # After the lease instance TTL elapsed, a fresh committed acquire re-issues a new lease id but
    # PRESERVES the durable attempt budget.
    with pg_sessionmaker() as s:
        reacquired = acquire_lease(
            s,
            organization_id=principal.organization_id,
            key=OperationKey(auth_id, version, fp),
            worker_identity_id="worker-b",
            authorization_expiry=_now() + delta(hours=6),
            now=_now() + delta(seconds=120),
            lease_ttl_seconds=60,
        )
        assert reacquired.lease_id != original_lease_id
        assert reacquired.attempt_count == 1
        s.commit()
