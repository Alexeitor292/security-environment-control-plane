"""SECP-B2-4.3 — PostgreSQL integration for worker-identity (schema, monotonic, concurrency, DB
immutability triggers, downgrade).

Proves durable guarantees under REAL separate transactions + the raw/Core-path DB triggers, and
inspects the live schema. Run with ``SECP_TEST_POSTGRES_URL``; skipped otherwise. Fake-only: no
worker is authenticated and no backend/target is contacted.
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
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL worker-identity tests"
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
    from secp_api.models import Organization

    org_id = uuid.uuid4()
    with pg_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO organization (id, name, slug, created_at) "
                "VALUES (:id, 'Org', :slug, :ts)"
            ),
            {"id": org_id, "slug": f"org-{org_id.hex[:8]}", "ts": _now()},
        )
    assert Organization is not None
    return org_id


def _principal(org_id):
    from secp_api.auth import Principal
    from secp_api.enums import Permission

    return Principal(
        user_id=uuid.uuid4(), organization_id=org_id, email="a@b", permissions=frozenset(Permission)
    )


def _register_approved(pg_sessionmaker, org_id, *, label="staging-worker-a"):
    from secp_api.enums import (
        WorkerIdentityEvidenceKind,
        WorkerIdentityEvidenceStatus,
        WorkerIdentityMechanism,
    )
    from secp_api.services import worker_identity as wi
    from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint

    with pg_sessionmaker() as s:
        row = wi.register_worker_identity(
            s,
            _principal(org_id),
            mechanism=WorkerIdentityMechanism.mtls_workload_identity,
            identity_label=label,
            deployment_binding="deploy-01",
            verification_anchor_fingerprint=compute_verification_anchor_fingerprint("anchor-v1"),
        )
        for kind in WorkerIdentityEvidenceKind:
            wi.record_evidence(
                s,
                _principal(org_id),
                row.id,
                kind=kind,
                status=WorkerIdentityEvidenceStatus.verified,
                proof_id="TKT-1",
                issuer="rev",
            )
        s.commit()
        wi.approve_worker_identity(s, _principal(org_id), row.id)
        s.commit()
        reg_id = row.id
        from secp_api.models import WorkerIdentityEvidence
        from sqlalchemy import select

        ev_id = (
            s.execute(
                select(WorkerIdentityEvidence.id).where(
                    WorkerIdentityEvidence.registration_id == reg_id
                )
            )
            .scalars()
            .first()
        )
    return reg_id, ev_id


def test_schema_is_secret_free_with_expected_constraints(pg_engine):
    insp = inspect(pg_engine)
    cols = {c["name"] for c in insp.get_columns("worker_identity_registration")}
    assert not (
        cols
        & {"certificate", "private_key", "key", "csr", "ca", "secret", "token", "endpoint", "host"}
    )
    assert "verification_anchor_fingerprint" in cols
    uniques = {
        u["name"]: tuple(u["column_names"])
        for u in insp.get_unique_constraints("worker_identity_registration")
    }
    assert uniques.get("uq_worker_identity_org_label_version") == (
        "organization_id",
        "identity_label",
        "identity_version",
    )
    ev_cols = {c["name"] for c in insp.get_columns("worker_identity_evidence")}
    assert not (ev_cols & {"certificate", "key", "secret", "token", "endpoint"})


def test_monotonic_version_unique_at_db(pg_engine, pg_sessionmaker):
    import secp_api.immutability  # noqa: F401  (register ORM guards)
    from sqlalchemy.exc import IntegrityError

    org_id = _seed_org(pg_engine)
    _register_approved(pg_sessionmaker, org_id)

    # A raw duplicate (org, label, version=1) violates the unique key.
    with pytest.raises(IntegrityError):
        with pg_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO worker_identity_registration "
                    "(id, organization_id, mechanism, identity_label, deployment_binding, "
                    " verification_anchor_fingerprint, identity_version, expiry, "
                    " evidence_fingerprint, status, revision, revocation_reason_code, created_at) "
                    "VALUES (:id, :org, 'mtls_workload_identity', 'staging-worker-a', 'deploy-01', "
                    " :fp, 1, :exp, '', 'draft', 0, '', :ts)"
                ),
                {
                    "id": uuid.uuid4(),
                    "org": org_id,
                    "fp": "sha256:" + "ab" * 32,
                    "exp": _now(),
                    "ts": _now(),
                },
            )


def test_concurrent_approve_then_revoke_is_cas_safe(pg_engine, pg_sessionmaker):
    import secp_api.immutability  # noqa: F401
    from secp_api.enums import WorkerIdentityStatus
    from secp_api.models import WorkerIdentityRegistration

    org_id = _seed_org(pg_engine)
    reg_id, _ev = _register_approved(pg_sessionmaker, org_id)

    with pg_sessionmaker() as s:
        rev = s.get(WorkerIdentityRegistration, reg_id).revision

    # A stale revoke expecting the pre-approval revision affects zero rows after approval bumped it.
    with pg_engine.begin() as conn:
        rowcount = conn.execute(
            text(
                "UPDATE worker_identity_registration SET status='revoked', revision=:nr, "
                "revoked_at=:t, revocation_reason_code='operator' WHERE id=:id AND revision=:old"
            ),
            {"nr": rev + 1, "t": _now(), "id": reg_id, "old": rev - 1},
        ).rowcount
    assert rowcount == 0
    with pg_sessionmaker() as s:
        assert s.get(WorkerIdentityRegistration, reg_id).status == WorkerIdentityStatus.approved


def _expect_db_immutable(pg_engine, sql, params):
    with pytest.raises(Exception) as exc:  # psycopg raises; surfaced by SQLAlchemy
        with pg_engine.begin() as conn:
            conn.execute(text(sql), params)
    msg = str(exc.value).lower()
    assert any(t in msg for t in ("immutable", "not allowed", "cannot be deleted", "set-once")), msg


def test_db_trigger_blocks_binding_and_setonce_mutations(pg_engine, pg_sessionmaker):
    org_id = _seed_org(pg_engine)
    reg_id, _ev = _register_approved(pg_sessionmaker, org_id)
    tbl = "worker_identity_registration"
    for col, val in (
        ("identity_label", "other-label"),
        ("deployment_binding", "other-deploy"),
        ("verification_anchor_fingerprint", "sha256:" + "00" * 32),
        ("identity_version", 99),
        ("expiry", _now() + timedelta(days=365)),
        ("mechanism", "other_mechanism"),
        ("approved_by", uuid.uuid4()),
        ("evidence_fingerprint", "sha256:tampered"),
    ):
        _expect_db_immutable(
            pg_engine, f"UPDATE {tbl} SET {col} = :v WHERE id = :id", {"v": val, "id": reg_id}
        )


def test_db_trigger_blocks_terminal_revival_and_delete(pg_engine, pg_sessionmaker):
    org_id = _seed_org(pg_engine)
    reg_id, _ev = _register_approved(pg_sessionmaker, org_id)
    tbl = "worker_identity_registration"
    _expect_db_immutable(
        pg_engine, f"UPDATE {tbl} SET status = 'draft' WHERE id = :id", {"id": reg_id}
    )
    _expect_db_immutable(pg_engine, f"DELETE FROM {tbl} WHERE id = :id", {"id": reg_id})
    with pg_engine.begin() as conn:
        conn.execute(
            text(
                f"UPDATE {tbl} SET status='revoked', revision=revision+1, revoked_at=:t, "
                "revocation_reason_code='operator' WHERE id=:id"
            ),
            {"t": _now(), "id": reg_id},
        )
    _expect_db_immutable(
        pg_engine, f"UPDATE {tbl} SET status = 'expired' WHERE id = :id", {"id": reg_id}
    )


def test_db_trigger_blocks_evidence_changes_after_approval(pg_engine, pg_sessionmaker):
    org_id = _seed_org(pg_engine)
    reg_id, ev_id = _register_approved(pg_sessionmaker, org_id)
    tbl = "worker_identity_evidence"
    _expect_db_immutable(
        pg_engine, f"UPDATE {tbl} SET proof_id = 'X' WHERE id = :id", {"id": ev_id}
    )
    _expect_db_immutable(pg_engine, f"DELETE FROM {tbl} WHERE id = :id", {"id": ev_id})
    _expect_db_immutable(
        pg_engine,
        f"INSERT INTO {tbl} (id, registration_id, kind, status, proof_id, issuer, created_at) "
        "VALUES (:id, :rid, 'rotation_revocation_review', 'verified', 'X', 'Y', :ts)",
        {"id": uuid.uuid4(), "rid": reg_id, "ts": _now()},
    )


def test_db_triggers_permit_legitimate_service_lifecycle(pg_engine, pg_sessionmaker):
    from secp_api.enums import WorkerIdentityStatus
    from secp_api.models import WorkerIdentityRegistration
    from secp_api.services import worker_identity as wi

    org_id = _seed_org(pg_engine)
    reg_id, _ev = _register_approved(pg_sessionmaker, org_id)
    with pg_sessionmaker() as s:
        row = s.get(WorkerIdentityRegistration, reg_id)
        approved_by, approved_at, ev_fp = row.approved_by, row.approved_at, row.evidence_fingerprint
        wi.revoke_worker_identity(s, _principal(org_id), reg_id)
        s.commit()
        row = s.get(WorkerIdentityRegistration, reg_id)
        assert row.status == WorkerIdentityStatus.revoked
        # Approval facts preserved through the revocation transition.
        assert row.approved_by == approved_by
        assert row.approved_at == approved_at
        assert row.evidence_fingerprint == ev_fp


def test_downgrade_removes_worker_identity_tables(pg_engine):
    from alembic import command
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    api_dir = __import__("pathlib").Path(__file__).resolve().parents[1]
    cfg = Config(str(api_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_dir / "migrations"))
    cfg.set_main_option("sqlalchemy.url", PG_URL)
    script = ScriptDirectory.from_config(cfg)
    head = script.get_heads()[0]
    parent = script.get_revision(head).down_revision
    assert isinstance(parent, str)

    def tables() -> set[str]:
        return set(inspect(pg_engine).get_table_names())

    both = {"worker_identity_registration", "worker_identity_evidence"}
    try:
        assert both <= tables()
        command.downgrade(cfg, parent)
        assert both.isdisjoint(tables())
    finally:
        command.upgrade(cfg, "head")
    assert both <= tables()
