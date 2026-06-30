"""PostgreSQL-specific reservation concurrency proof.

The default suite covers the service on SQLite. This module runs only when
``SECP_TEST_POSTGRES_URL`` is set and proves the per-target allocation lock works
with independent PostgreSQL transactions.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from secp_api.auth import Principal
from secp_api.enums import Permission
from secp_api.models import Base
from secp_api.seed import bootstrap_dev
from secp_api.services import reservations, targets
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL reservation tests"
)


@pytest.fixture
def pg_factory_and_principal():
    assert PG_URL
    engine = create_engine(PG_URL, future=True)
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        conn.exec_driver_sql("CREATE SCHEMA public")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, future=True)
    with factory() as session:
        principal = bootstrap_dev(session)
        session.commit()
        actor = Principal(
            user_id=principal.user_id,
            organization_id=principal.organization_id,
            email=principal.email,
            permissions=frozenset(Permission),
        )
    try:
        yield factory, actor
    finally:
        engine.dispose()


def test_postgres_concurrent_same_prefix_allocations_are_distinct(
    pg_factory_and_principal,
):
    factory, actor = pg_factory_and_principal
    with factory() as session:
        target = targets.register_target(
            session,
            actor,
            display_name="PG Lab",
            plugin_name="proxmox",
            config={"base_url": "https://proxmox.example.test:8006", "verify_tls": True},
            secret_ref="env:SECP_PROVIDER_SECRET__PG",
            address_spaces=[{"cidr_block": "10.81.0.0/16", "subnet_prefix": 24}],
        )
        target_id = target.id
        session.commit()

    barrier = Barrier(2)

    def allocate(team_ref: str) -> str:
        with factory() as session:
            barrier.wait(timeout=10)
            reservation = reservations.reserve_network(
                session,
                actor,
                target_id=target_id,
                team_ref=team_ref,
            )
            cidr = reservation.cidr
            session.commit()
            return cidr

    with ThreadPoolExecutor(max_workers=2) as pool:
        cidrs = sorted(pool.map(allocate, ["team-a", "team-b"]))

    assert cidrs == ["10.81.0.0/24", "10.81.1.0/24"]
