"""B1B-PR5B — PostgreSQL CAS proof for the plan-only execution lease (ADR-022 §8).

SQLite cannot prove genuinely concurrent transactions. These run only when
``SECP_TEST_POSTGRES_URL``
is set (CI) and prove, on a real PostgreSQL at the current head, that the partial-unique
``operation_fingerprint WHERE status='active'`` index is the CAS guard: at most one ACTIVE lease per
operation fingerprint survives even under two genuinely concurrent inserts, while terminal
(``consumed``/``expired``/``recovery_required``) leases and distinct fingerprints never collide (so
a
fresh epoch can be acquired after a terminal lease without ever permitting two live leases at once).

The FK referential-integrity triggers are disabled for these probe inserts
(``session_replication_role
= 'replica'``) so the CAS index can be exercised without reconstructing the whole ~15-record
readiness chain; a UNIQUE INDEX is NOT a trigger, so it still fires — which is precisely the CAS
guarantee under test. The application-level acquire/budget/recovery semantics are proven on SQLite
in
``test_plan_execution_lease.py``.
"""

from __future__ import annotations

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from secp_api.enums import PlanExecutionLeaseStatus
from secp_api.models import Base
from secp_api.plan_activation_models import (
    PLAN_EXECUTION_ATTEMPT_BUDGET,
    PlanGenerationExecutionLease,
)
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL execution-lease CAS tests"
)

NOW = datetime(2026, 7, 15, tzinfo=UTC)
_FP = "sha256:" + "c" * 60


@pytest.fixture
def pg_factory():
    assert PG_URL
    engine = create_engine(PG_URL, future=True)
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        conn.exec_driver_sql("CREATE SCHEMA public")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, future=True)
    try:
        yield factory
    finally:
        engine.dispose()


def _lease(
    fingerprint: str,
    *,
    status: PlanExecutionLeaseStatus = PlanExecutionLeaseStatus.active,
    epoch: int = 1,
    attempts_used: int = 0,
) -> PlanGenerationExecutionLease:
    """A complete lease row (every non-null column filled) — no FK parents (replica-mode probe)."""

    def h(c: str) -> str:
        return "sha256:" + c * 16

    return PlanGenerationExecutionLease(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        authorization_id=uuid.uuid4(),
        authorization_version=1,
        authorization_expiry=NOW + timedelta(hours=2),
        provisioning_manifest_id=uuid.uuid4(),
        provisioning_manifest_content_hash=h("m"),
        deployment_plan_id=uuid.uuid4(),
        environment_version_id=uuid.uuid4(),
        execution_target_id=uuid.uuid4(),
        target_config_hash=h("t"),
        target_onboarding_id=uuid.uuid4(),
        onboarding_boundary_hash=h("o"),
        activation_dossier_id=uuid.uuid4(),
        activation_dossier_hash=h("d"),
        activation_dossier_revision=1,
        eligibility_preflight_id=uuid.uuid4(),
        eligibility_evidence_hash=h("e"),
        toolchain_profile_id=uuid.uuid4(),
        toolchain_profile_hash=h("p"),
        toolchain_attestation_id=uuid.uuid4(),
        toolchain_attestation_hash=h("a"),
        worker_identity_registration_id=uuid.uuid4(),
        worker_identity_version=1,
        provider_credential_binding_id=uuid.uuid4(),
        provider_credential_binding_version=1,
        state_credential_binding_id=uuid.uuid4(),
        state_credential_binding_version=1,
        remote_state_readiness_id=uuid.uuid4(),
        remote_state_evidence_hash=h("r"),
        plan_secret_readiness_id=uuid.uuid4(),
        plan_secret_evidence_hash=h("s"),
        operation_fingerprint=fingerprint,
        lease_epoch=epoch,
        lease_owner="w",
        lease_expires_at=NOW + timedelta(minutes=10),
        attempt_budget=PLAN_EXECUTION_ATTEMPT_BUDGET,
        attempts_used=attempts_used,
        status=status,
        acquired_at=NOW,
    )


def _insert(factory, lease: PlanGenerationExecutionLease) -> None:
    with factory() as session:
        session.execute(text("SET LOCAL session_replication_role = 'replica'"))
        session.add(lease)
        session.commit()


def _active_count(factory, fingerprint: str) -> int:
    with factory() as session:
        return int(
            session.execute(
                select(func.count())
                .select_from(PlanGenerationExecutionLease)
                .where(
                    PlanGenerationExecutionLease.operation_fingerprint == fingerprint,
                    PlanGenerationExecutionLease.status == PlanExecutionLeaseStatus.active,
                )
            ).scalar_one()
        )


def test_a_second_active_lease_for_the_same_fingerprint_is_refused(pg_factory):
    """The partial-unique index refuses a second ACTIVE lease for the exact operation
    fingerprint."""
    _insert(pg_factory, _lease(_FP))
    with pytest.raises(IntegrityError):
        _insert(pg_factory, _lease(_FP, epoch=2))
    assert _active_count(pg_factory, _FP) == 1


def test_only_one_active_lease_survives_two_concurrent_inserts(pg_factory):
    """Under two GENUINELY concurrent replica-mode transactions, exactly one active lease
    survives."""
    barrier = Barrier(2)

    def worker() -> bool:
        barrier.wait(timeout=15)
        try:
            _insert(pg_factory, _lease(_FP))
        except IntegrityError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [f.result(timeout=30) for f in [pool.submit(worker) for _ in range(2)]]

    assert sorted(results) == [False, True]  # exactly one winner
    assert _active_count(pg_factory, _FP) == 1


def test_terminal_leases_never_block_a_fresh_active_epoch(pg_factory):
    """A ``consumed``/``expired``/``recovery_required`` lease frees the partial-active index, so a
    new
    epoch can be acquired for the same fingerprint — without ever permitting two live leases."""
    for i, terminal in enumerate(
        (
            PlanExecutionLeaseStatus.consumed,
            PlanExecutionLeaseStatus.expired,
            PlanExecutionLeaseStatus.recovery_required,
        ),
        start=1,
    ):
        _insert(pg_factory, _lease(_FP, status=terminal, epoch=i))
    # A fresh ACTIVE epoch is accepted; the terminal rows do not collide with it.
    _insert(pg_factory, _lease(_FP, epoch=9))
    assert _active_count(pg_factory, _FP) == 1


def test_distinct_fingerprints_do_not_collide(pg_factory):
    """The CAS guard is per operation fingerprint: distinct operations lease independently."""
    _insert(pg_factory, _lease("sha256:" + "a" * 60))
    _insert(pg_factory, _lease("sha256:" + "b" * 60))
    assert _active_count(pg_factory, "sha256:" + "a" * 60) == 1
    assert _active_count(pg_factory, "sha256:" + "b" * 60) == 1
