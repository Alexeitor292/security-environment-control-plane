"""SECP-B7 — PostgreSQL schema-consistency tests for the discovery ``updated_at`` fix.

Proves the canary bug is fixed on a REAL PostgreSQL (migrations, not SQLite ``create_all``): a
discovery enrollment — and the other discovery tables + the new bootstrap session — can be inserted
through the ORM without any manual ``updated_at`` DB patch, with ``created_at``/``updated_at`` both
populated and ``updated_at`` bumping on UPDATE. Skipped unless ``SECP_TEST_POSTGRES_URL`` is set.
"""

from __future__ import annotations

import copy
import os
import time
import uuid

import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import Session

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL discovery-schema tests"
)

_DISCOVERY_TABLES = (
    "target_discovery_enrollment",
    "discovery_job",
    "discovery_snapshot",
    "discovery_candidate_plan",
    "discovery_candidate_plan_approval",
    "worker_discovery_admission",
    "proxmox_readonly_bootstrap_session",
)


@pytest.fixture(scope="module")
def pg_engine():
    assert PG_URL
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import text

    engine = create_engine(PG_URL, future=True)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    api_dir = __import__("pathlib").Path(__file__).resolve().parents[1]
    previous = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = PG_URL
    from secp_api.config import get_settings

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


def test_all_discovery_tables_have_updated_at_not_null(pg_engine):
    insp = inspect(pg_engine)
    tables = set(insp.get_table_names())
    for table in _DISCOVERY_TABLES:
        assert table in tables, f"missing table {table}"
        cols = {c["name"]: c for c in insp.get_columns(table)}
        assert "created_at" in cols and "updated_at" in cols, f"{table} missing timestamp columns"
        assert cols["updated_at"]["nullable"] is False, f"{table}.updated_at should be NOT NULL"


def _proxmox_target(session, principal):
    from conftest import VALID_PROVISIONING_SCOPE, onboard_and_activate
    from secp_api.services import staging_labs, targets

    target = targets.register_target(
        session,
        principal,
        display_name="PG Lab",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        secret_ref="env:SECP_PROVIDER_SECRET__LAB",
        scope_policy={"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
        address_spaces=[{"cidr_block": "10.60.0.0/16", "subnet_prefix": 24}],
    )
    onboard_and_activate(session, principal, target)
    staging_labs.grant_substrate_eligibility(session, principal, execution_target_id=target.id)
    return target


def test_enrollment_insert_succeeds_on_postgres_without_manual_patch(pg_engine):
    # The exact canary: creating a discovery enrollment through the ORM/service on PostgreSQL.
    import secp_api.immutability  # noqa: F401
    from secp_api.seed import bootstrap_dev
    from secp_api.services import target_discovery as td

    with Session(pg_engine) as s:
        p = bootstrap_dev(s)
        s.flush()
        target = _proxmox_target(s, p)
        s.flush()
        enrollment = td.request_discovery(s, p, execution_target_id=target.id)
        s.flush()
        assert enrollment.created_at is not None
        assert enrollment.updated_at is not None
        first = enrollment.updated_at
        time.sleep(0.01)
        enrollment.revision = enrollment.revision + 1  # a real mutation
        s.flush()
        assert enrollment.updated_at > first  # onupdate bumped it
        s.rollback()


def test_bootstrap_session_insert_succeeds_on_postgres(pg_engine):
    import secp_api.immutability  # noqa: F401
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from secp_api.seed import bootstrap_dev
    from secp_api.services import bootstrap_discovery as bs

    pub = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    with Session(pg_engine) as s:
        p = bootstrap_dev(s)
        s.flush()
        target = _proxmox_target(s, p)
        s.flush()
        sess = bs.create_bootstrap_session(
            s, p, execution_target_id=target.id, worker_ssh_public_key=pub
        )
        s.flush()
        assert sess.created_at is not None and sess.updated_at is not None
        s.rollback()


def test_pr5f_legacy_worker_columns_keep_server_defaults(pg_engine):
    """The pinned pre-PR5F images omit both new columns, so their defaults are permanent API."""

    insp = inspect(pg_engine)
    node_columns = {column["name"]: column for column in insp.get_columns("worker_discovery_node")}
    snapshot_columns = {column["name"]: column for column in insp.get_columns("discovery_snapshot")}
    assert node_columns["revision"]["default"] is not None
    assert snapshot_columns["contact_state"]["default"] is not None


def test_pr5f_postgres_advances_legacy_worker_key_revision(pg_engine):
    """A write shaped like the pinned B8 worker advances revision and unlinks the old anchor."""

    from secp_api.seed import bootstrap_dev

    with Session(pg_engine) as session:
        principal = bootstrap_dev(session)
        session.flush()
        node_id = uuid.uuid4()
        linked_registration = uuid.uuid4()
        session.execute(
            text(
                """
                INSERT INTO worker_discovery_node
                    (id, organization_id, node_label, ssh_public_key,
                     ssh_public_key_fingerprint, admission_anchor_hex,
                     admission_anchor_fingerprint, worker_identity_registration_id,
                     created_by, created_at, updated_at)
                VALUES
                    (:id, :organization_id, 'legacy-worker', 'ssh-ed25519 AAAA-old',
                     'SHA256:old', :old_anchor, 'sha256:old', :registration_id,
                     NULL, now(), now())
                """
            ),
            {
                "id": node_id,
                "organization_id": principal.organization_id,
                "old_anchor": "a" * 64,
                "registration_id": linked_registration,
            },
        )
        assert (
            session.execute(
                text("SELECT revision FROM worker_discovery_node WHERE id = :id"), {"id": node_id}
            ).scalar_one()
            == 1
        )

        # The old image does not know about revision and therefore omits it from this UPDATE.
        session.execute(
            text(
                """
                UPDATE worker_discovery_node
                SET ssh_public_key = 'ssh-ed25519 AAAA-new',
                    ssh_public_key_fingerprint = 'SHA256:new',
                    admission_anchor_hex = :new_anchor,
                    admission_anchor_fingerprint = 'sha256:new',
                    updated_at = now()
                WHERE id = :id
                """
            ),
            {"id": node_id, "new_anchor": "b" * 64},
        )
        row = session.execute(
            text(
                """
                SELECT revision, worker_identity_registration_id
                FROM worker_discovery_node WHERE id = :id
                """
            ),
            {"id": node_id},
        ).one()
        assert row.revision == 2
        assert row.worker_identity_registration_id is None
        session.rollback()


def test_pr5f_postgres_derives_contact_state_for_legacy_snapshot_writes(pg_engine):
    """The pinned B8 worker's existing facts map to durable, closed contact evidence."""

    import secp_api.immutability  # noqa: F401
    from secp_api.discovery_models import DiscoveryJob
    from secp_api.seed import bootstrap_dev
    from secp_api.services import target_discovery as td

    cases = (
        (None, True, "unverifiable"),
        ("probe_source_sealed", False, "sealed"),
        ("enrollment_changed", False, "drift"),
        ("bootstrap_unavailable", False, "bundle_unavailable"),
        ("host_key_binding_unverified", True, "host_key_refused"),
        ("probe_refused", True, "unverifiable"),
        (None, False, "unverifiable"),
    )
    with Session(pg_engine) as session:
        principal = bootstrap_dev(session)
        session.flush()
        target = _proxmox_target(session, principal)
        enrollment = td.request_discovery(session, principal, execution_target_id=target.id)
        session.flush()
        job = session.execute(
            select(DiscoveryJob).where(DiscoveryJob.enrollment_id == enrollment.id)
        ).scalar_one()

        for index, (reason_code, bundle_available, expected) in enumerate(cases):
            snapshot_id = uuid.uuid4()
            session.execute(
                text(
                    """
                    INSERT INTO discovery_snapshot
                        (id, enrollment_id, organization_id, job_id, enrollment_version,
                         evidence, evidence_hash, capacity_snapshot_hash, eligibility,
                         reason_code, worker_identity_version, bundle_available, created_by,
                         created_at, updated_at)
                    VALUES
                        (:id, :enrollment_id, :organization_id, :job_id, :enrollment_version,
                         '{}'::json, :evidence_hash, :capacity_hash, 'unverifiable',
                         :reason_code, 1, :bundle_available, NULL, now(), now())
                    """
                ),
                {
                    "id": snapshot_id,
                    "enrollment_id": enrollment.id,
                    "organization_id": enrollment.organization_id,
                    "job_id": job.id,
                    "enrollment_version": enrollment.enrollment_version,
                    "evidence_hash": f"sha256:legacy-{index}",
                    "capacity_hash": f"sha256:capacity-{index}",
                    "reason_code": reason_code,
                    "bundle_available": bundle_available,
                },
            )
            actual = session.execute(
                text("SELECT contact_state FROM discovery_snapshot WHERE id = :id"),
                {"id": snapshot_id},
            ).scalar_one()
            assert actual == expected
        session.rollback()


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
