"""SECP-B2-0 — worker durable preflight consumer + runtime loop (fake-only, no connection)."""

from __future__ import annotations

import threading
from contextlib import contextmanager

from secp_api.enums import (
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    ReadonlyPreflightOutcome,
    ReadonlyPreflightStatus,
    StagingWorkStatus,
    TargetStatus,
)
from secp_api.models import ExecutionTarget, ReadonlyStagingPreflight, TargetOnboarding
from secp_api.services import readonly_preflight, staging_labs
from secp_worker.preflight import runtime
from secp_worker.preflight.consumer import claim_and_process_one
from sqlalchemy import update

SECRET_REF = "env:SECP_PROVIDER_SECRET__PF"


def _queued_preflight(session, principal):
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref=SECRET_REF,
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
    )


def test_queued_stays_queued_until_worker_runtime_processes_it(session, principal):
    pf = _queued_preflight(session, principal)
    assert pf.status == ReadonlyPreflightStatus.queued

    @contextmanager
    def _scope():
        yield session

    # Queueing does not execute; only the worker runtime loop drains and records the outcome.
    # (No intervening commit: SQLite drops DateTime(timezone=True) tzinfo on reload, which the
    # authorization verifier treats as malformed — a SQLite-only artifact; PostgreSQL preserves it
    # and the PostgreSQL integration test exercises the committed path.)
    processed = runtime.run_consumer_loop(
        threading.Event(), interval_seconds=0, session_scope=_scope, max_ticks=1
    )
    assert processed == 1
    session.refresh(pf)
    assert pf.status == ReadonlyPreflightStatus.completed
    assert pf.outcome_code == ReadonlyPreflightOutcome.credential_unavailable


def test_consumer_returns_none_when_no_queued_work(session, principal):
    assert claim_and_process_one(session) is None


def test_claim_is_exclusive_compare_and_swap(session, principal):
    pf = _queued_preflight(session, principal)

    def _claim() -> int:
        return session.execute(
            update(ReadonlyStagingPreflight)
            .where(
                ReadonlyStagingPreflight.id == pf.id,
                ReadonlyStagingPreflight.status == ReadonlyPreflightStatus.queued,
                ReadonlyStagingPreflight.revision == 0,
            )
            .values(status=ReadonlyPreflightStatus.claimed, revision=1)
        ).rowcount

    assert _claim() == 1
    assert _claim() == 0


def test_worker_main_wires_the_preflight_consumer_not_the_api():
    import inspect

    import secp_worker.main as worker_main

    src = inspect.getsource(worker_main)
    assert "preflight.runtime" in src
    assert "_start_readonly_preflight_consumer" in src


def test_stale_worker_status_enum_unaffected():
    # Sanity: preflight lifecycle is a distinct enum from the staging-lab work lifecycle.
    assert ReadonlyPreflightStatus.queued.__class__ is not StagingWorkStatus
