"""SECP-B2-4.1 — PostgreSQL integration for resolver-activation (schema, monotonic, concurrency).

Proves durable guarantees under REAL separate transactions and inspects the live schema. Run with
``SECP_TEST_POSTGRES_URL``; skipped otherwise. Fake-only: no backend/target is contacted.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL resolver-activation tests"
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


def _seed_work_item(session: Session):
    from secp_api.enums import (
        IsolationModel,
        LiveReadAuthorizationStatus,
        OnboardingMode,
        OnboardingStatus,
        ReadonlyPreflightStatus,
        TargetStatus,
    )
    from secp_api.live_read_contract import (
        LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        LIVE_READ_EVIDENCE_SOURCE,
        LIVE_VERIFIED_LEVEL,
        PROXMOX_READONLY_POLICY_VERSION,
    )
    from secp_api.models import (
        ExecutionTarget,
        LiveReadAuthorization,
        Organization,
        ReadonlyStagingPreflight,
        TargetOnboarding,
    )

    org = Organization(name="O", slug=f"o-{uuid.uuid4().hex[:8]}")
    session.add(org)
    session.flush()
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
    session.add(target)
    session.flush()
    ob = TargetOnboarding(
        organization_id=org.id,
        execution_target_id=target.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=IsolationModel.logical,
        status=OnboardingStatus.active,
        declared_boundary={},
        boundary_hash="sha256:" + "cd" * 32,
    )
    session.add(ob)
    session.flush()
    auth = LiveReadAuthorization(
        organization_id=org.id,
        execution_target_id=target.id,
        onboarding_id=ob.id,
        connection_hash="sha256:" + "ab" * 32,
        boundary_hash="sha256:" + "cd" * 32,
        authorization_version=1,
        authorization_expiry=_now() + timedelta(hours=2),
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        evidence_source=LIVE_READ_EVIDENCE_SOURCE,
        verification_level=LIVE_VERIFIED_LEVEL,
        status=LiveReadAuthorizationStatus.approved,
    )
    session.add(auth)
    session.flush()
    pf = ReadonlyStagingPreflight(
        organization_id=org.id,
        execution_target_id=target.id,
        onboarding_id=ob.id,
        live_read_authorization_id=auth.id,
        authorization_version=1,
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        # A globally-unique fingerprint per work item: ``operation_fingerprint`` is unique-
        # constrained on ``readonly_staging_preflight`` and the module-scoped schema persists rows
        # across tests, so a shared literal would collide on ``uq_readonly_preflight_fingerprint``.
        operation_fingerprint="sha256:" + uuid.uuid4().hex + uuid.uuid4().hex,
        status=ReadonlyPreflightStatus.running,
        revision=0,
    )
    session.add(pf)
    session.flush()
    return org.id, pf


def _principal(org_id):
    from secp_api.auth import Principal
    from secp_api.enums import Permission

    return Principal(
        user_id=uuid.uuid4(), organization_id=org_id, email="a@b", permissions=frozenset(Permission)
    )


def test_schema_is_secret_free_with_expected_constraints(pg_engine):
    insp = inspect(pg_engine)
    cols = {c["name"] for c in insp.get_columns("resolver_activation_authorization")}
    assert not (
        cols & {"secret", "secret_ref", "credential", "endpoint", "token", "vault", "host", "port"}
    )
    uniques = {
        u["name"]: tuple(u["column_names"])
        for u in insp.get_unique_constraints("resolver_activation_authorization")
    }
    assert uniques.get("uq_resolver_activation_target_onboarding_version") == (
        "execution_target_id",
        "onboarding_id",
        "authorization_version",
    )
    ev_cols = {c["name"] for c in insp.get_columns("resolver_activation_evidence")}
    assert not (ev_cols & {"secret", "credential", "endpoint", "token", "vault"})


def test_monotonic_version_unique_at_db(pg_engine, pg_sessionmaker):
    import secp_api.immutability  # noqa: F401
    from secp_api.services import resolver_activation as ra

    with pg_sessionmaker() as s:
        org_id, pf = _seed_work_item(s)
        s.commit()
        ra.create_activation_authorization(s, _principal(org_id), preflight_id=pf.id)
        s.commit()
        target_id, onboarding_id = pf.execution_target_id, pf.onboarding_id

    # A raw duplicate (target, onboarding, version=1) violates the unique key.
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        with pg_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO resolver_activation_authorization "
                    "(id, organization_id, execution_target_id, onboarding_id, "
                    " live_read_authorization_id, live_read_authorization_version, preflight_id, "
                    " operation_fingerprint, resolver_adapter_contract_version, purpose, "
                    " authorization_expiry, evidence_fingerprint, status, authorization_version, "
                    " revision, revocation_reason_code, created_at) "
                    "VALUES (:id, :org, :t, :ob, :lr, 1, :pf, 'sha256:x', 'c', 'p', :exp, '', "
                    " 'draft', 1, 0, '', :ts)"
                ),
                {
                    "id": uuid.uuid4(),
                    "org": _principal(org_id).organization_id,
                    "t": target_id,
                    "ob": onboarding_id,
                    "lr": pf.live_read_authorization_id,
                    "pf": pf.id,
                    "exp": _now(),
                    "ts": _now(),
                },
            )


def test_concurrent_approve_then_revoke_is_cas_safe(pg_engine, pg_sessionmaker):
    import secp_api.immutability  # noqa: F401
    from secp_api.enums import (
        ResolverActivationEvidenceKind,
        ResolverActivationEvidenceStatus,
        ResolverActivationStatus,
    )
    from secp_api.services import resolver_activation as ra

    with pg_sessionmaker() as s:
        org_id, pf = _seed_work_item(s)
        row = ra.create_activation_authorization(s, _principal(org_id), preflight_id=pf.id)
        for k in ResolverActivationEvidenceKind:
            ra.record_evidence(
                s,
                _principal(org_id),
                row.id,
                kind=k,
                status=ResolverActivationEvidenceStatus.verified,
                proof_id="TKT-1",
                issuer="rev",
            )
        s.commit()
        auth_id, rev = row.id, row.revision

    # A stale revoke expecting the pre-approval revision affects zero rows after an approval bumped
    # the revision (compare-and-swap).
    with pg_sessionmaker() as s:
        ra.approve_activation_authorization(s, _principal(org_id), auth_id)
        s.commit()
    with pg_engine.begin() as conn:
        rowcount = conn.execute(
            text(
                "UPDATE resolver_activation_authorization SET status='revoked', revision=:nr "
                "WHERE id=:id AND revision=:old"
            ),
            {"nr": rev + 1, "id": auth_id, "old": rev},
        ).rowcount
        status = conn.execute(
            text("SELECT status FROM resolver_activation_authorization WHERE id=:id"),
            {"id": auth_id},
        ).scalar_one()
    assert rowcount == 0
    assert status == ResolverActivationStatus.approved.value


def test_downgrade_removes_resolver_activation_tables(pg_engine):
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
    # Derive THIS feature's migration from the graph (robust to newer migrations stacked above it,
    # e.g. worker-identity); downgrading to its parent removes the resolver-activation tables.
    rev = None
    for candidate in script.walk_revisions():
        src = Path(candidate.module.__file__).read_text(encoding="utf-8")
        if re.search(r'create_table\(\s*"resolver_activation_authorization"', src):
            rev = candidate.revision
            break
    assert isinstance(rev, str)
    parent = script.get_revision(rev).down_revision
    assert isinstance(parent, str)

    def tables() -> set[str]:
        return set(inspect(pg_engine).get_table_names())

    both = {"resolver_activation_authorization", "resolver_activation_evidence"}
    try:
        assert both <= tables()
        command.downgrade(cfg, parent)  # removes resolver-activation tables (and anything above)
        assert both.isdisjoint(tables())
    finally:
        command.upgrade(cfg, "head")
    assert both <= tables()


def test_concurrent_expiration_and_create_no_double_active_or_double_audit(
    pg_engine, pg_sessionmaker, monkeypatch
):
    """Two racing creates against a work item whose single active (approved) authorization has
    expired: under REAL separate PostgreSQL transactions exactly one materializes it as ``expired``
    and creates the replacement draft; the loser fails closed (``lifecycle_conflict``). No second
    active row is created and the expiration audit event is emitted exactly once.

    ``authorization_expiry`` is immutable (DB trigger), so expiry is simulated by advancing the
    service clock past the row's expiry rather than back-dating the durable value."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    import secp_api.immutability  # noqa: F401
    from secp_api.enums import (
        ResolverActivationEvidenceKind,
        ResolverActivationEvidenceStatus,
        ResolverActivationStatus,
    )
    from secp_api.errors import ResolverActivationError
    from secp_api.models import ResolverActivationAuthorization
    from secp_api.services import resolver_activation as ra
    from sqlalchemy import select

    with pg_sessionmaker() as s:
        org_id, pf = _seed_work_item(s)
        row = ra.create_activation_authorization(s, _principal(org_id), preflight_id=pf.id)
        for k in ResolverActivationEvidenceKind:
            ra.record_evidence(
                s,
                _principal(org_id),
                row.id,
                kind=k,
                status=ResolverActivationEvidenceStatus.verified,
                proof_id="TKT-1",
                issuer="rev",
            )
        s.commit()
        ra.approve_activation_authorization(s, _principal(org_id), row.id)
        s.commit()
        old_id, pf_id = row.id, pf.id

    # Advance the service clock well past the approved authorization's canonical expiry. The row
    # stays 'approved' in the DB (cleanup not yet materialized) but ``_is_expired`` now reports True
    # for both racing creators.
    future = _now() + timedelta(days=2)
    monkeypatch.setattr(ra, "_utcnow", lambda: future)

    barrier = Barrier(2)

    def _create(_i: int):
        with pg_sessionmaker() as s:
            barrier.wait(timeout=10)
            try:
                created = ra.create_activation_authorization(
                    s, _principal(org_id), preflight_id=pf_id
                )
                s.commit()
                return ("ok", created.authorization_version)
            except ResolverActivationError as exc:
                s.rollback()
                return ("err", exc.code)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_create, [0, 1]))

    oks = [r for r in results if r[0] == "ok"]
    errs = [r for r in results if r[0] == "err"]
    assert len(oks) == 1, results
    assert len(errs) == 1 and errs[0][1] == "resolver_activation_lifecycle_conflict", results

    with pg_sessionmaker() as s:
        active = (
            s.execute(
                select(ResolverActivationAuthorization).where(
                    ResolverActivationAuthorization.preflight_id == pf_id,
                    ResolverActivationAuthorization.status.in_(
                        (ResolverActivationStatus.draft, ResolverActivationStatus.approved)
                    ),
                )
            )
            .scalars()
            .all()
        )
        assert len(active) == 1
        assert active[0].status == ResolverActivationStatus.draft
        assert s.get(ResolverActivationAuthorization, old_id).status == (
            ResolverActivationStatus.expired
        )
        expired_count = s.execute(
            text("SELECT count(*) FROM audit_event WHERE action = :a AND resource_id = :r"),
            {"a": "resolver_activation.expired", "r": str(old_id)},
        ).scalar_one()
        assert expired_count == 1


# --- FIX 2: DB-level (raw/Core-path) durable immutability -----------------------------------------


def _seed_approved_pg(pg_sessionmaker):
    """Seed a work item + a fully-approved authorization (via the service). Returns ids."""
    from secp_api.enums import ResolverActivationEvidenceKind, ResolverActivationEvidenceStatus
    from secp_api.models import ResolverActivationEvidence
    from secp_api.services import resolver_activation as ra
    from sqlalchemy import select

    with pg_sessionmaker() as s:
        org_id, pf = _seed_work_item(s)
        row = ra.create_activation_authorization(s, _principal(org_id), preflight_id=pf.id)
        for k in ResolverActivationEvidenceKind:
            ra.record_evidence(
                s,
                _principal(org_id),
                row.id,
                kind=k,
                status=ResolverActivationEvidenceStatus.verified,
                proof_id="TKT-1",
                issuer="rev",
            )
        s.commit()
        ra.approve_activation_authorization(s, _principal(org_id), row.id)
        s.commit()
        auth_id = row.id
        ev_id = (
            s.execute(
                select(ResolverActivationEvidence.id).where(
                    ResolverActivationEvidence.authorization_id == auth_id
                )
            )
            .scalars()
            .first()
        )
    return org_id, auth_id, ev_id


def _expect_db_immutable(pg_engine, sql, params):
    with pytest.raises(Exception) as exc:  # psycopg raises; surfaced by SQLAlchemy
        with pg_engine.begin() as conn:
            conn.execute(text(sql), params)
    msg = str(exc.value).lower()
    assert any(
        token in msg for token in ("immutable", "not allowed", "cannot be deleted", "set-once")
    ), msg


def test_db_trigger_blocks_binding_and_setonce_mutations(pg_engine, pg_sessionmaker):
    _org, auth_id, _ev = _seed_approved_pg(pg_sessionmaker)
    tbl = "resolver_activation_authorization"
    for col, val in (
        ("operation_fingerprint", "sha256:" + "00" * 32),
        ("authorization_expiry", _now() + timedelta(days=365)),
        ("authorization_version", 99),
        ("purpose", "something_else"),
        ("resolver_adapter_contract_version", "other/v9"),
        ("live_read_authorization_version", 42),
        ("approved_by", uuid.uuid4()),
        ("evidence_fingerprint", "sha256:tampered"),
    ):
        _expect_db_immutable(
            pg_engine, f"UPDATE {tbl} SET {col} = :v WHERE id = :id", {"v": val, "id": auth_id}
        )


def test_db_trigger_blocks_terminal_revival_and_delete(pg_engine, pg_sessionmaker):
    _org, auth_id, _ev = _seed_approved_pg(pg_sessionmaker)
    tbl = "resolver_activation_authorization"
    # approved -> draft (revival) is refused.
    _expect_db_immutable(
        pg_engine, f"UPDATE {tbl} SET status = 'draft' WHERE id = :id", {"id": auth_id}
    )
    # deletion is refused.
    _expect_db_immutable(pg_engine, f"DELETE FROM {tbl} WHERE id = :id", {"id": auth_id})
    # Revoke it, then prove a terminal row cannot be mutated further (e.g. revoked -> expired).
    with pg_engine.begin() as conn:
        conn.execute(
            text(
                f"UPDATE {tbl} SET status='revoked', revision=revision+1, revoked_at=:t, "
                "revocation_reason_code='operator' WHERE id=:id"
            ),
            {"t": _now(), "id": auth_id},
        )
    _expect_db_immutable(
        pg_engine, f"UPDATE {tbl} SET status = 'expired' WHERE id = :id", {"id": auth_id}
    )


def test_db_trigger_blocks_evidence_changes_after_approval(pg_engine, pg_sessionmaker):
    _org, auth_id, ev_id = _seed_approved_pg(pg_sessionmaker)
    tbl = "resolver_activation_evidence"
    _expect_db_immutable(
        pg_engine, f"UPDATE {tbl} SET proof_id = 'X' WHERE id = :id", {"id": ev_id}
    )
    _expect_db_immutable(pg_engine, f"DELETE FROM {tbl} WHERE id = :id", {"id": ev_id})
    _expect_db_immutable(
        pg_engine,
        f"INSERT INTO {tbl} (id, authorization_id, kind, status, proof_id, issuer, created_at) "
        "VALUES (:id, :aid, 'independent_adversarial_review', 'verified', 'X', 'Y', :ts)",
        {"id": uuid.uuid4(), "aid": auth_id, "ts": _now()},
    )


def test_db_triggers_permit_legitimate_service_lifecycle(pg_engine, pg_sessionmaker):
    """With the triggers installed, the full closed lifecycle via the service still succeeds and the
    approval facts are preserved through revocation."""
    from secp_api.enums import ResolverActivationStatus
    from secp_api.models import ResolverActivationAuthorization
    from secp_api.services import resolver_activation as ra

    _org, auth_id, _ev = _seed_approved_pg(pg_sessionmaker)
    with pg_sessionmaker() as s:
        row = s.get(ResolverActivationAuthorization, auth_id)
        assert row.status == ResolverActivationStatus.approved
        approved_by, approved_at, ev_fp = row.approved_by, row.approved_at, row.evidence_fingerprint
        ra.revoke_activation_authorization(s, _principal(_org), auth_id)
        s.commit()
        row = s.get(ResolverActivationAuthorization, auth_id)
        assert row.status == ResolverActivationStatus.revoked
        # Approval facts preserved through the revocation transition.
        assert row.approved_by == approved_by
        assert row.approved_at == approved_at
        assert row.evidence_fingerprint == ev_fp


def test_concurrent_expired_approve_persists_one_transition_and_audit(
    pg_engine, pg_sessionmaker, monkeypatch
):
    """Two concurrent approves of the SAME expired draft: both fail closed (invalid_state); exactly
    one materialized the durable expiry transition (mimicking the router's commit) and exactly one
    expiration audit persists."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from secp_api.enums import ResolverActivationStatus
    from secp_api.errors import ResolverActivationError
    from secp_api.models import ResolverActivationAuthorization
    from secp_api.services import resolver_activation as ra

    with pg_sessionmaker() as s:
        org_id, pf = _seed_work_item(s)
        draft = ra.create_activation_authorization(s, _principal(org_id), preflight_id=pf.id)
        s.commit()
        auth_id = draft.id

    future = _now() + timedelta(days=2)
    monkeypatch.setattr(ra, "_utcnow", lambda: future)
    barrier = Barrier(2)

    def _approve(_i: int):
        with pg_sessionmaker() as s:
            barrier.wait(timeout=10)
            try:
                ra.approve_activation_authorization(s, _principal(org_id), auth_id)
                s.commit()
                return ("ok", None, False)
            except ResolverActivationError as exc:
                durable = exc.durable_transition
                if durable:
                    s.commit()  # mimic the router: persist the durable expiry transition
                else:
                    s.rollback()
                return ("err", exc.code, durable)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_approve, [0, 1]))

    assert all(r[0] == "err" and r[1] == "resolver_activation_invalid_state" for r in results), (
        results
    )
    assert sum(1 for r in results if r[2]) == 1, results

    with pg_sessionmaker() as s:
        assert (
            s.get(ResolverActivationAuthorization, auth_id).status
            == ResolverActivationStatus.expired
        )
        n = s.execute(
            text("SELECT count(*) FROM audit_event WHERE action = :a AND resource_id = :r"),
            {"a": "resolver_activation.expired", "r": str(auth_id)},
        ).scalar_one()
        assert n == 1
