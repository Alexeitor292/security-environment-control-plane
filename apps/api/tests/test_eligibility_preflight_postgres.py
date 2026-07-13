# ruff: noqa: E501  (raw SQL fixtures below are intentionally single-line for clarity)
"""SECP-002B-1B B1B-PR3 — PostgreSQL integration for the live-eligibility preflight migration.

Run with ``SECP_TEST_POSTGRES_URL``; skipped otherwise. Proves the additive migration
(``c7e1a9b3d5f2``) adds the live-eligibility binding columns + the partial-unique idempotency index
to ``target_preflight`` on PostgreSQL, that the partial-unique index enforces exact-once on non-null
fingerprints while leaving NULL (simulated) rows unconstrained, and that downgrade truthfully
removes exactly those columns/indexes. No target/backend is contacted.
"""

from __future__ import annotations

import os
import pathlib

import pytest
from sqlalchemy import create_engine, inspect, text

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL eligibility-migration tests"
)

_PRIOR_REVISION = "f2b8c1d4a9e7"
_HEAD = "c7e1a9b3d5f2"
_NEW_COLUMNS = {
    "operation_fingerprint",
    "eligibility_outcome",
    "eligibility_policy_version",
    "evidence_expires_at",
    "live_read_authorization_id",
    "live_read_authorization_version",
    "worker_identity_registration_id",
}
_UNIQUE_INDEX = "uq_target_preflight_eligibility_operation"


def _alembic_cfg():
    from alembic.config import Config

    api_dir = pathlib.Path(__file__).resolve().parents[1]
    cfg = Config(str(api_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_dir / "migrations"))
    cfg.set_main_option("sqlalchemy.url", PG_URL)
    return cfg


@pytest.fixture()
def pg_engine():
    assert PG_URL
    engine = create_engine(PG_URL, future=True)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    from alembic import command
    from secp_api.config import get_settings

    # The Alembic env resolves the DB URL from SECP_DATABASE_URL / get_settings(), so point both at
    # the test PostgreSQL before upgrading (otherwise the migration would target the default DB and
    # this engine would see no tables). Restore afterward.
    previous = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = PG_URL
    get_settings.cache_clear()
    try:
        command.upgrade(_alembic_cfg(), "head")
        yield engine
    finally:
        engine.dispose()
        if previous is None:
            os.environ.pop("SECP_DATABASE_URL", None)
        else:
            os.environ["SECP_DATABASE_URL"] = previous
        get_settings.cache_clear()


def _columns(engine) -> set[str]:
    return {c["name"] for c in inspect(engine).get_columns("target_preflight")}


def _indexes(engine) -> set[str]:
    return {i["name"] for i in inspect(engine).get_indexes("target_preflight")}


def test_upgrade_adds_live_eligibility_columns_and_index(pg_engine):
    assert _NEW_COLUMNS <= _columns(pg_engine)
    assert _UNIQUE_INDEX in _indexes(pg_engine)
    # No secret-bearing column name was introduced.
    for name in _NEW_COLUMNS:
        assert not any(tok in name for tok in ("secret", "token", "password", "credential"))


def test_partial_unique_index_enforces_exact_once_on_nonnull_fingerprint(pg_engine):
    # Seed the parents + preflight rows via the ORM (so every server/ORM default — timestamps,
    # enums — is applied); the DB-level PARTIAL-UNIQUE index is what we assert here.
    import secp_api.immutability  # noqa: F401  (registers the ORM immutability guards)
    from secp_api.enums import IsolationModel, OnboardingMode, OnboardingStatus
    from secp_api.models import ExecutionTarget, Organization, TargetOnboarding, TargetPreflight
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import Session

    def _pf(org_id, ob_id, fp, version):
        return TargetPreflight(
            organization_id=org_id,
            onboarding_id=ob_id,
            collector="provider_worker",
            verification_level="live_verified",
            collector_kind="provider_worker",
            collector_identity="w",
            evidence_version=version,
            target_config_hash="h",
            scope_policy_hash="sp",
            boundary_hash="bh",
            passed=False,
            checks=[],
            evidence_hash="eh",
            operation_fingerprint=fp,
        )

    with Session(pg_engine) as session:
        org = Organization(name="o", slug="o")
        session.add(org)
        session.flush()
        target = ExecutionTarget(
            organization_id=org.id,
            display_name="lab",
            plugin_name="proxmox",
            config={},
            config_hash="h",
        )
        session.add(target)
        session.flush()
        ob = TargetOnboarding(
            organization_id=org.id,
            execution_target_id=target.id,
            onboarding_mode=OnboardingMode.existing_environment,
            isolation_model=IsolationModel.physical,
            status=OnboardingStatus.active,
            declared_boundary={},
            boundary_hash="bh",
        )
        session.add(ob)
        session.flush()
        org_id, ob_id = org.id, ob.id
        # Two NULL-fingerprint (simulated) rows are permitted; one non-null fingerprint is accepted.
        session.add(_pf(org_id, ob_id, None, 1))
        session.add(_pf(org_id, ob_id, None, 2))
        session.add(_pf(org_id, ob_id, "sha256:" + "a" * 64, 3))
        session.commit()

    # A duplicate (onboarding_id, operation_fingerprint) is rejected by the partial-unique index.
    with pytest.raises(IntegrityError):
        with Session(pg_engine) as session:
            session.add(_pf(org_id, ob_id, "sha256:" + "a" * 64, 4))
            session.flush()


def test_downgrade_removes_exactly_the_new_columns_and_index(pg_engine):
    from alembic import command

    command.downgrade(_alembic_cfg(), _PRIOR_REVISION)
    cols = _columns(pg_engine)
    idx = _indexes(pg_engine)
    assert not (_NEW_COLUMNS & cols), f"downgrade left columns {_NEW_COLUMNS & cols}"
    assert _UNIQUE_INDEX not in idx
    # Re-upgrade restores them (idempotent, reversible).
    command.upgrade(_alembic_cfg(), _HEAD)
    assert _NEW_COLUMNS <= _columns(pg_engine)
