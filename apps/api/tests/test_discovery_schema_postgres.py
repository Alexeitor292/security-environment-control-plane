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

import pytest
from sqlalchemy import create_engine, inspect
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


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
