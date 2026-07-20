"""PostgreSQL round-trip proof for the PR5F durable rollback write fence.

Skipped unless the repository's dedicated ``SECP_TEST_POSTGRES_URL`` test database is configured.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from secp_api.config import get_settings
from secp_api.discovery_activation_rollback_fence import (
    engage_rollback_fence,
    observe_rollback_fence,
    release_rollback_fence,
)
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

_PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")
_HEAD = "d8f1a2b3c4e5"
_BASELINE = "c4e2f9a1b7d3"
_FENCE = "ck_worker_identity_pr5f_ed25519_rollback_fence"

pytestmark = pytest.mark.skipif(
    not _PG_URL,
    reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL PR5F rollback migration tests",
)


def _config() -> Config:
    api_dir = Path(__file__).resolve().parents[1]
    config = Config(str(api_dir / "alembic.ini"))
    config.set_main_option("script_location", str(api_dir / "migrations"))
    config.set_main_option("sqlalchemy.url", str(_PG_URL))
    return config


def _identity_values(
    *, organization_id: uuid.UUID, mechanism: str, label: str
) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "id": uuid.uuid4(),
        "organization_id": organization_id,
        "mechanism": mechanism,
        "identity_label": label,
        "deployment_binding": "production-worker",
        "verification_anchor_fingerprint": "sha256:" + "a" * 64,
        "identity_version": 1,
        "expiry": now + timedelta(hours=1),
        "evidence_fingerprint": "",
        "status": "draft",
        "revision": 0,
        "created_by": None,
        "approved_by": None,
        "approved_at": None,
        "revoked_by": None,
        "revoked_at": None,
        "revocation_reason_code": "",
        "created_at": now,
    }


def _insert_identity(connection, values: dict[str, object]) -> None:
    connection.execute(
        text(
            """
            INSERT INTO worker_identity_registration (
                id, organization_id, mechanism, identity_label, deployment_binding,
                verification_anchor_fingerprint, identity_version, expiry,
                evidence_fingerprint, status, revision, created_by, approved_by, approved_at,
                revoked_by, revoked_at, revocation_reason_code, created_at
            ) VALUES (
                :id, :organization_id, :mechanism, :identity_label, :deployment_binding,
                :verification_anchor_fingerprint, :identity_version, :expiry,
                :evidence_fingerprint, :status, :revision, :created_by, :approved_by, :approved_at,
                :revoked_by, :revoked_at, :revocation_reason_code, :created_at
            )
            """
        ),
        values,
    )


def _constraint_names(engine) -> set[str | None]:
    return {
        constraint["name"]
        for constraint in inspect(engine).get_check_constraints("worker_identity_registration")
    }


def test_fence_persists_across_downgrade_and_reupgrade_until_explicit_release() -> None:
    assert _PG_URL
    engine = create_engine(_PG_URL, future=True)
    previous_url = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = _PG_URL
    get_settings.cache_clear()
    try:
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        command.upgrade(_config(), _HEAD)
        assert _FENCE in _constraint_names(engine)
        with Session(engine) as session:
            assert observe_rollback_fence(session) == "engaged"
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT convalidated FROM pg_constraint WHERE conname = :name"),
                    {"name": _FENCE},
                ).scalar_one()
                is True
            )

        # Release is transactional: a process/database abort before commit leaves the durable
        # named constraint engaged.  Observation inside the transaction sees only its local drop.
        with Session(engine) as session:
            release_rollback_fence(session)
            assert observe_rollback_fence(session) == "released"
            session.rollback()
        with Session(engine) as session:
            assert observe_rollback_fence(session) == "engaged"

        # A same-name but weaker constraint is never mistaken for the repository-owned fence.
        with engine.begin() as connection:
            connection.execute(
                text(f"ALTER TABLE worker_identity_registration DROP CONSTRAINT {_FENCE}")
            )
            connection.execute(
                text(
                    f"ALTER TABLE worker_identity_registration ADD CONSTRAINT {_FENCE} "
                    "CHECK (mechanism IS NOT NULL)"
                )
            )
        with Session(engine) as session:
            assert observe_rollback_fence(session) == "unverified"
            engage_rollback_fence(session)
            assert observe_rollback_fence(session) == "engaged"
            session.commit()

        organization_id = uuid.uuid4()
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO organization (id, name, slug, created_at) "
                    "VALUES (:id, 'PR5F Test', :slug, :created_at)"
                ),
                {
                    "id": organization_id,
                    "slug": f"pr5f-{organization_id.hex[:12]}",
                    "created_at": datetime.now(UTC),
                },
            )

        # The first controller install leaves identity adoption fenced while the signed worker
        # handoff is pending, even though the new API code and migration are already live.
        with pytest.raises(IntegrityError), engine.begin() as connection:
            _insert_identity(
                connection,
                _identity_values(
                    organization_id=organization_id,
                    mechanism="ed25519_signed_nonce",
                    label="pending-worker",
                ),
            )

        command.downgrade(_config(), _BASELINE)
        assert _FENCE in _constraint_names(engine)
        with engine.begin() as connection:
            _insert_identity(
                connection,
                _identity_values(
                    organization_id=organization_id,
                    mechanism="mtls_workload_identity",
                    label="baseline-worker",
                ),
            )

        with pytest.raises(IntegrityError), engine.begin() as connection:
            _insert_identity(
                connection,
                _identity_values(
                    organization_id=organization_id,
                    mechanism="ed25519_signed_nonce",
                    label="fenced-worker",
                ),
            )

        command.upgrade(_config(), _HEAD)
        assert _FENCE in _constraint_names(engine)
        with Session(engine) as session:
            release_rollback_fence(session)
            assert observe_rollback_fence(session) == "released"
            session.commit()
        constraint_names = _constraint_names(engine)
        assert _FENCE not in constraint_names
        with Session(engine) as session:
            assert observe_rollback_fence(session) == "released"
        with engine.begin() as connection:
            _insert_identity(
                connection,
                _identity_values(
                    organization_id=organization_id,
                    mechanism="ed25519_signed_nonce",
                    label="activated-worker",
                ),
            )
    finally:
        engine.dispose()
        if previous_url is None:
            os.environ.pop("SECP_DATABASE_URL", None)
        else:
            os.environ["SECP_DATABASE_URL"] = previous_url
        get_settings.cache_clear()
