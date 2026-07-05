"""SECP-B2-4.5 — PostgreSQL integration for live-preflight evidence (schema, raw/Core-path DB
immutability trigger, downgrade). Run with ``SECP_TEST_POSTGRES_URL``; skipped otherwise.

Fake-only: no backend/target is contacted; the durable record is built from real durable parents via
the services + the durable writer, then the DB trigger is proven to block raw update/delete.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL live-preflight-evidence tests"
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


def _principal(org_id):
    from secp_api.auth import Principal
    from secp_api.enums import Permission

    return Principal(
        user_id=uuid.uuid4(), organization_id=org_id, email="a@b", permissions=frozenset(Permission)
    )


def _seed_row(pg_sessionmaker) -> uuid.UUID:
    """Build the full durable parent chain + one live-evidence row via the durable writer. Returns
    the live-evidence row id (committed)."""
    import secp_api.immutability  # noqa: F401
    from secp_api.enums import (
        IsolationModel,
        LivePreflightEvidenceStatus,
        OnboardingMode,
        OnboardingStatus,
        ResolutionLeaseStatus,
        ResolverActivationEvidenceKind,
        ResolverActivationEvidenceStatus,
        TargetStatus,
        WorkerIdentityEvidenceKind,
        WorkerIdentityEvidenceStatus,
        WorkerIdentityMechanism,
    )
    from secp_api.live_read_contract import (
        LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        PROXMOX_READONLY_POLICY_VERSION,
    )
    from secp_api.models import ExecutionTarget, Organization, ResolutionLease, TargetOnboarding
    from secp_api.resolver_activation_contract import RESOLVER_ADAPTER_CONTRACT_VERSION
    from secp_api.services import readonly_preflight, resolver_activation, staging_labs
    from secp_api.services import worker_identity as wi
    from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint
    from secp_worker.preflight.live_evidence_writer import (
        DurableLivePreflightEvidenceWriter,
        LivePreflightEvidenceContext,
    )

    with pg_sessionmaker() as s:
        org = Organization(name="O", slug=f"o-{uuid.uuid4().hex[:8]}")
        s.add(org)
        s.flush()
        principal = _principal(org.id)
        target = ExecutionTarget(
            organization_id=org.id,
            display_name="t",
            plugin_name="proxmox",
            config={"base_url": "x"},
            config_hash="sha256:" + "ab" * 32,
            secret_ref="vault:secp/x",
            status=TargetStatus.active,
            scope_policy={},
        )
        s.add(target)
        s.flush()
        s.add(
            TargetOnboarding(
                organization_id=org.id,
                execution_target_id=target.id,
                onboarding_mode=OnboardingMode.existing_environment,
                isolation_model=IsolationModel.logical,
                status=OnboardingStatus.active,
                declared_boundary={},
                boundary_hash="sha256:" + "cd" * 32,
            )
        )
        s.flush()
        staging_labs.grant_substrate_eligibility(s, principal, execution_target_id=target.id)
        auth = readonly_preflight.create_preflight_authorization(
            s, principal, execution_target_id=target.id
        )
        readonly_preflight.approve_preflight_authorization(s, principal, auth.id)
        pf = readonly_preflight.queue_preflight(s, principal, live_read_authorization_id=auth.id)
        act = resolver_activation.create_activation_authorization(s, principal, preflight_id=pf.id)
        for kind in ResolverActivationEvidenceKind:
            resolver_activation.record_evidence(
                s,
                principal,
                act.id,
                kind=kind,
                status=ResolverActivationEvidenceStatus.verified,
                proof_id="TKT-1",
                issuer="rev",
            )
        resolver_activation.approve_activation_authorization(s, principal, act.id)
        reg = wi.register_worker_identity(
            s,
            principal,
            mechanism=WorkerIdentityMechanism.mtls_workload_identity,
            identity_label="staging-worker-a",
            deployment_binding="deploy-01",
            verification_anchor_fingerprint=compute_verification_anchor_fingerprint("anchor-v1"),
        )
        for kind in WorkerIdentityEvidenceKind:
            wi.record_evidence(
                s,
                principal,
                reg.id,
                kind=kind,
                status=WorkerIdentityEvidenceStatus.verified,
                proof_id="TKT-1",
                issuer="rev",
            )
        wi.approve_worker_identity(s, principal, reg.id)
        lease = ResolutionLease(
            organization_id=org.id,
            live_read_authorization_id=pf.live_read_authorization_id,
            authorization_version=pf.authorization_version,
            operation_fingerprint=pf.operation_fingerprint,
            status=ResolutionLeaseStatus.active,
            attempt_count=1,
            lease_expires_at=_now() + timedelta(minutes=5),
            worker_identity_id="staging-worker-a",
            reason_code="",
        )
        s.add(lease)
        s.flush()
        ctx = LivePreflightEvidenceContext(
            organization_id=org.id,
            preflight_id=pf.id,
            execution_target_id=target.id,
            onboarding_id=pf.onboarding_id,
            live_read_authorization_id=pf.live_read_authorization_id,
            live_read_authorization_version=pf.authorization_version,
            resolver_activation_authorization_id=act.id,
            resolver_activation_authorization_version=act.authorization_version,
            worker_identity_registration_id=reg.id,
            worker_identity_version=reg.identity_version,
            resolution_lease_id=lease.id,
            operation_fingerprint=pf.operation_fingerprint,
            collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
            endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
            resolver_contract_version=RESOLVER_ADAPTER_CONTRACT_VERSION,
        )
        row = DurableLivePreflightEvidenceWriter().write(
            s,
            context=ctx,
            status=LivePreflightEvidenceStatus.passed,
            facts={"api_reachable": True, "node_count": 1},
            checks=[{"code": "tls_verified", "status": "passed"}],
            now=_now(),
        )
        s.commit()
        return row.id


def test_schema_is_secret_free(pg_engine):
    cols = {c["name"] for c in inspect(pg_engine).get_columns("live_preflight_evidence")}
    assert not (
        cols
        & {"endpoint", "base_url", "host", "hostname", "port", "secret", "token", "certificate"}
    )
    assert "evidence_hash" in cols and "payload" in cols


def test_db_trigger_blocks_update_and_delete(pg_engine, pg_sessionmaker):
    row_id = _seed_row(pg_sessionmaker)
    for sql in (
        "UPDATE live_preflight_evidence SET status = 'failed' WHERE id = :id",
        "DELETE FROM live_preflight_evidence WHERE id = :id",
    ):
        with pytest.raises(Exception) as exc:
            with pg_engine.begin() as conn:
                conn.execute(text(sql), {"id": row_id})
        assert "immutable" in str(exc.value).lower()


def test_downgrade_removes_live_preflight_evidence(pg_engine):
    import re
    from pathlib import Path

    from alembic import command
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    api_dir = __import__("pathlib").Path(__file__).resolve().parents[1]
    cfg = Config(str(api_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_dir / "migrations"))
    cfg.set_main_option("sqlalchemy.url", PG_URL)
    script = ScriptDirectory.from_config(cfg)
    rev = None
    for candidate in script.walk_revisions():
        src = Path(candidate.module.__file__).read_text(encoding="utf-8")
        if re.search(r'create_table\(\s*"live_preflight_evidence"', src):
            rev = candidate.revision
            break
    assert isinstance(rev, str)
    parent = script.get_revision(rev).down_revision
    assert isinstance(parent, str)

    def tables() -> set[str]:
        return set(inspect(pg_engine).get_table_names())

    try:
        assert "live_preflight_evidence" in tables()
        command.downgrade(cfg, parent)
        assert "live_preflight_evidence" not in tables()
    finally:
        command.upgrade(cfg, "head")
    assert "live_preflight_evidence" in tables()
