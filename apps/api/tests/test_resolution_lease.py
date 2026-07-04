"""SECP-B2-3 — durable resolution-lease state machine (worker-only, fake-only, no contact).

Proves the B2-2 durable lease + retry contract: the global operation uniqueness key excludes worker
identity; the fixed N=3 budget is durable across leases/identities; a fresh lease never resets it;
consumption is globally single-use (replay refused); expiry preserves the attempt budget; and a new
authorization version is an independent operation key with a fresh budget. Nothing here resolves a
secret or contacts anything.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.enums import (
    AuditAction,
    IsolationModel,
    LiveReadAuthorizationStatus,
    OnboardingMode,
    OnboardingStatus,
    ResolutionLeaseReason,
    ResolutionLeaseStatus,
    TargetStatus,
)
from secp_api.live_read_contract import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    LIVE_READ_EVIDENCE_SOURCE,
    LIVE_VERIFIED_LEVEL,
    PROXMOX_READONLY_POLICY_VERSION,
)
from secp_api.models import (
    AuditEvent,
    ExecutionTarget,
    LiveReadAuthorization,
    Organization,
    ResolutionLease,
    TargetOnboarding,
)
from secp_worker.preflight.lease import (
    RETRY_BUDGET,
    LeaseRefused,
    OperationKey,
    acquire_lease,
    begin_attempt,
    mark_consumed,
)

WORKER_A = "worker-a"
WORKER_B = "worker-b"


def _now() -> datetime:
    return datetime(2026, 7, 4, 12, 0, 0, tzinfo=UTC)


def _org(session) -> uuid.UUID:
    org = Organization(name="Org", slug=f"org-{uuid.uuid4().hex[:8]}")
    session.add(org)
    session.flush()
    return org.id


def _authorization_id(session, org: uuid.UUID) -> uuid.UUID:
    """Seed a minimal authoritative authorization chain and return the authorization id.

    The lease FK requires the authorization row to exist; the lease uniqueness key's version is
    independent data (so one authorization row backs both version 1 and version 2 keys in tests).
    """
    target = ExecutionTarget(
        organization_id=org,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref="env:SECP_PROVIDER_SECRET__PF",
        status=TargetStatus.active,
        scope_policy={},
    )
    session.add(target)
    session.flush()
    onboarding = TargetOnboarding(
        organization_id=org,
        execution_target_id=target.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=IsolationModel.logical,
        status=OnboardingStatus.active,
        declared_boundary={},
        boundary_hash="sha256:" + "cd" * 32,
    )
    session.add(onboarding)
    session.flush()
    auth = LiveReadAuthorization(
        organization_id=org,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        connection_hash="sha256:" + "ab" * 32,
        boundary_hash="sha256:" + "cd" * 32,
        authorization_version=1,
        authorization_expiry=_now() + timedelta(hours=1),
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        evidence_source=LIVE_READ_EVIDENCE_SOURCE,
        verification_level=LIVE_VERIFIED_LEVEL,
        status=LiveReadAuthorizationStatus.approved,
    )
    session.add(auth)
    session.flush()
    return auth.id


def _key(session, org, *, version: int = 1, fingerprint: str | None = None) -> OperationKey:
    return OperationKey(
        live_read_authorization_id=_authorization_id(session, org),
        authorization_version=version,
        operation_fingerprint=fingerprint or ("sha256:" + "ab" * 32),
    )


def _expiry(now: datetime, *, hours: int = 1) -> datetime:
    return now + timedelta(hours=hours)


def test_retry_budget_is_fixed_at_three():
    assert RETRY_BUDGET == 3


def test_acquire_creates_single_active_lease_with_zero_attempts(session):
    org = _org(session)
    now = _now()
    key = _key(session, org)
    lease = acquire_lease(
        session,
        organization_id=org,
        key=key,
        worker_identity_id=WORKER_A,
        authorization_expiry=_expiry(now),
        now=now,
    )
    assert lease.status == ResolutionLeaseStatus.active
    assert lease.attempt_count == 0
    assert lease.worker_identity_id == WORKER_A
    # Exactly one row for the operation key.
    assert session.query(ResolutionLease).count() == 1


def test_second_worker_cannot_hold_a_concurrent_lease_for_the_same_operation(session):
    org = _org(session)
    now = _now()
    key = _key(session, org)
    acquire_lease(
        session,
        organization_id=org,
        key=key,
        worker_identity_id=WORKER_A,
        authorization_expiry=_expiry(now),
        now=now,
    )
    # A different worker identity for the SAME operation key is refused (single valid lease).
    with pytest.raises(LeaseRefused) as exc:
        acquire_lease(
            session,
            organization_id=org,
            key=key,
            worker_identity_id=WORKER_B,
            authorization_expiry=_expiry(now),
            now=now,
        )
    assert exc.value.reason == ResolutionLeaseReason.lease_held
    assert session.query(ResolutionLease).count() == 1


def test_begin_attempt_increments_durable_budget_and_exhausts_at_three(session):
    org = _org(session)
    now = _now()
    key = _key(session, org)
    exp = _expiry(now)
    lease = acquire_lease(
        session,
        organization_id=org,
        key=key,
        worker_identity_id=WORKER_A,
        authorization_expiry=exp,
        now=now,
    )
    # Three attempts allowed.
    for expected in (1, 2, 3):
        begin_attempt(session, lease, now=now)
        assert lease.attempt_count == expected
    # The fourth begin-attempt is refused and the operation is durably exhausted.
    with pytest.raises(LeaseRefused) as exc:
        begin_attempt(session, lease, now=now)
    assert exc.value.reason == ResolutionLeaseReason.retry_bound_exceeded
    session.refresh(lease)
    assert lease.status == ResolutionLeaseStatus.exhausted
    assert lease.reason_code == ResolutionLeaseReason.retry_bound_exceeded.value


def test_exhausted_operation_refuses_new_acquire_until_new_version(session):
    org = _org(session)
    now = _now()
    key = _key(session, org, version=1)
    exp = _expiry(now)
    lease = acquire_lease(
        session,
        organization_id=org,
        key=key,
        worker_identity_id=WORKER_A,
        authorization_expiry=exp,
        now=now,
    )
    for _ in range(RETRY_BUDGET):
        begin_attempt(session, lease, now=now)
    with pytest.raises(LeaseRefused):
        begin_attempt(session, lease, now=now)  # exhausts
    # A fresh acquire for the SAME key is refused (budget is durable; a fresh lease can't reset it).
    with pytest.raises(LeaseRefused) as exc:
        acquire_lease(
            session,
            organization_id=org,
            key=key,
            worker_identity_id=WORKER_B,
            authorization_expiry=exp,
            now=now + timedelta(minutes=5),
        )
    assert exc.value.reason == ResolutionLeaseReason.retry_bound_exceeded

    # A NEW authorization version is a distinct operation key with a fresh budget.
    key_v2 = OperationKey(
        live_read_authorization_id=key.live_read_authorization_id,
        authorization_version=2,
        operation_fingerprint=key.operation_fingerprint,
    )
    fresh = acquire_lease(
        session,
        organization_id=org,
        key=key_v2,
        worker_identity_id=WORKER_A,
        authorization_expiry=exp,
        now=now,
    )
    assert fresh.attempt_count == 0
    assert fresh.status == ResolutionLeaseStatus.active


def test_lease_expiry_preserves_attempt_count_and_reacquires_fresh_lease(session):
    org = _org(session)
    now = _now()
    key = _key(session, org)
    exp = _expiry(now, hours=6)
    lease = acquire_lease(
        session,
        organization_id=org,
        key=key,
        worker_identity_id=WORKER_A,
        authorization_expiry=exp,
        now=now,
        lease_ttl_seconds=60,
    )
    begin_attempt(session, lease, now=now)
    begin_attempt(session, lease, now=now)
    assert lease.attempt_count == 2
    original_lease_id = lease.lease_id
    # After the lease instance TTL passes (but authorization still valid), a re-acquire issues a
    # FRESH lease id, PRESERVING the durable attempt budget.
    later = now + timedelta(seconds=120)
    reacquired = acquire_lease(
        session,
        organization_id=org,
        key=key,
        worker_identity_id=WORKER_B,
        authorization_expiry=exp,
        now=later,
        lease_ttl_seconds=60,
    )
    assert reacquired.id == lease.id  # same operation row
    assert reacquired.lease_id != original_lease_id  # new lease instance
    assert reacquired.attempt_count == 2  # budget preserved across the fresh lease
    assert reacquired.worker_identity_id == WORKER_B
    # Only one attempt remains before exhaustion.
    begin_attempt(session, reacquired, now=later)
    assert reacquired.attempt_count == 3
    with pytest.raises(LeaseRefused) as exc:
        begin_attempt(session, reacquired, now=later)
    assert exc.value.reason == ResolutionLeaseReason.retry_bound_exceeded


def test_consumed_operation_is_globally_replay_refused(session):
    org = _org(session)
    now = _now()
    key = _key(session, org)
    exp = _expiry(now)
    lease = acquire_lease(
        session,
        organization_id=org,
        key=key,
        worker_identity_id=WORKER_A,
        authorization_expiry=exp,
        now=now,
    )
    begin_attempt(session, lease, now=now)
    mark_consumed(session, lease, now=now)
    assert lease.status == ResolutionLeaseStatus.consumed
    # A different worker attempting to acquire the same operation is replay-refused.
    with pytest.raises(LeaseRefused) as exc:
        acquire_lease(
            session,
            organization_id=org,
            key=key,
            worker_identity_id=WORKER_B,
            authorization_expiry=exp,
            now=now + timedelta(minutes=1),
        )
    assert exc.value.reason == ResolutionLeaseReason.replay_refused
    # begin-attempt on a consumed operation is also replay-refused.
    with pytest.raises(LeaseRefused) as exc2:
        begin_attempt(session, lease, now=now)
    assert exc2.value.reason == ResolutionLeaseReason.replay_refused


def test_acquire_refuses_when_authorization_already_expired(session):
    org = _org(session)
    now = _now()
    key = _key(session, org)
    with pytest.raises(LeaseRefused) as exc:
        acquire_lease(
            session,
            organization_id=org,
            key=key,
            worker_identity_id=WORKER_A,
            authorization_expiry=now - timedelta(seconds=1),
            now=now,
        )
    assert exc.value.reason == ResolutionLeaseReason.authorization_expired
    assert session.query(ResolutionLease).count() == 0


def test_lease_expiry_never_exceeds_authorization_expiry(session):
    org = _org(session)
    now = _now()
    key = _key(session, org)
    # Authorization expires in 30s but the default lease TTL is longer: lease is clamped.
    auth_exp = now + timedelta(seconds=30)
    lease = acquire_lease(
        session,
        organization_id=org,
        key=key,
        worker_identity_id=WORKER_A,
        authorization_expiry=auth_exp,
        now=now,
        lease_ttl_seconds=120,
    )
    stored = lease.lease_expires_at
    stored = stored if stored.tzinfo else stored.replace(tzinfo=UTC)
    assert stored == auth_exp


def test_stale_cas_transition_fails_closed_without_state_change_or_audit(session):
    """A losing concurrent begin-attempt (stale revision) must not change state or emit audit."""
    from sqlalchemy import update

    org = _org(session)
    now = _now()
    key = _key(session, org)
    exp = _expiry(now)
    lease = acquire_lease(
        session,
        organization_id=org,
        key=key,
        worker_identity_id=WORKER_A,
        authorization_expiry=exp,
        now=now,
    )
    # Simulate a competing worker advancing the revision underneath us.
    session.execute(
        update(ResolutionLease)
        .where(ResolutionLease.id == lease.id)
        .values(revision=ResolutionLease.revision + 5)
        .execution_options(synchronize_session=False)
    )
    session.flush()
    # Our in-memory `lease` now has a stale revision; begin-attempt must fail closed.
    with pytest.raises(LeaseRefused) as exc:
        begin_attempt(session, lease, now=now)
    assert exc.value.reason == ResolutionLeaseReason.lease_held
    session.refresh(lease)
    assert lease.attempt_count == 0  # unchanged
    # No attempt_started audit was emitted for the losing transition.
    session.flush()  # session is autoflush=False; surface any (regression) pending audit rows
    started = [
        e
        for e in session.query(AuditEvent).all()
        if e.action == AuditAction.resolution_lease_attempt_started.value
    ]
    assert started == []


def test_lease_row_and_audit_store_no_secret_or_reference(session):
    org = _org(session)
    now = _now()
    key = _key(session, org)
    exp = _expiry(now)
    lease = acquire_lease(
        session,
        organization_id=org,
        key=key,
        worker_identity_id=WORKER_A,
        authorization_expiry=exp,
        now=now,
    )
    begin_attempt(session, lease, now=now)
    # The row exposes only safe columns — there is no secret/reference/endpoint column at all.
    cols = set(ResolutionLease.__table__.columns.keys())
    for forbidden in ("secret_ref", "credential_ref", "secret", "endpoint", "base_url", "token"):
        assert forbidden not in cols
    # Audit payloads carry only safe identifiers + closed codes.
    session.flush()  # session is autoflush=False; make pending audit rows queryable
    events = session.query(AuditEvent).all()
    assert any(e.action.startswith("resolution_lease.") for e in events)  # audits exist to inspect
    blob = " ".join(str(e.data) for e in events).lower()
    for forbidden in ("secret", "credential", "token", "endpoint", "base_url", "://", "@pam"):
        assert forbidden not in blob
