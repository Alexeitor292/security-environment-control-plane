"""Control-plane worker discovery-admission verifier (SECP-B6 MB-1).

A worker may perform live read-only discovery ONLY after it proves possession of its registered
deployment-local identity key to THIS control-plane service. The service issues a single-use nonce
bound to the full job context, verifies the worker's Ed25519 signature against the PUBLIC anchor
whose fingerprint is pinned in the durable ``WorkerIdentityRegistration`` (never one the worker
asserts), and only then marks a durable, one-time ``WorkerDiscoveryAdmission`` ``admitted``. The
discovery engine independently binds that admission to the exact claimed job and consumes it once
before a plan can be produced.

Secret-free: this module persists/audits ONLY closed reason codes + safe control-plane IDs. It never
stores or logs a certificate, private key, public anchor, signature, challenge bytes, endpoint,
host, port, or credential. It contacts nothing and imports no SSH/Proxmox/transport/worker code.
"""

from __future__ import annotations

import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.enums import (
    AuditAction,
    LiveReadAuthorizationStatus,
    OnboardingStatus,
    TargetStatus,
    WorkerDiscoveryAdmissionStatus,
    WorkerIdentityStatus,
)
from secp_api.live_read_contract import connection_identity_hash
from secp_api.models import (
    DiscoveryJob,
    ExecutionTarget,
    LiveReadAuthorization,
    TargetDiscoveryEnrollment,
    TargetOnboarding,
    WorkerDiscoveryAdmission,
    WorkerIdentityRegistration,
)
from secp_api.worker_admission_contract import (
    WORKER_ADMISSION_PURPOSE,
    WORKER_ADMISSION_TTL_SECONDS,
    admission_signing_message,
    compute_verification_anchor_fingerprint,
    ed25519_verify,
)


class WorkerAdmissionRefused(Exception):
    """Fail-closed admission refusal carrying ONLY a closed, secret-free reason code."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"worker discovery admission refused: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class AdmissionResult:
    """The authoritative registration id + version an admission proves (never a claim value)."""

    registration_id: uuid.UUID
    identity_version: int


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _approved_registrations(
    session: Session, org_id: uuid.UUID
) -> list[WorkerIdentityRegistration]:
    return list(
        session.execute(
            select(WorkerIdentityRegistration).where(
                WorkerIdentityRegistration.organization_id == org_id,
                WorkerIdentityRegistration.status == WorkerIdentityStatus.approved,
            )
        )
        .scalars()
        .all()
    )


def _verify_registration(
    session: Session, registration_id: uuid.UUID, expected_version: int, now: datetime
) -> WorkerIdentityRegistration:
    """The worker registration must exist, be approved, UNEXPIRED (even if status still says
    approved), and at the expected identity version. Raises ``WorkerAdmissionRefused`` otherwise."""
    reg = session.get(WorkerIdentityRegistration, registration_id)
    if reg is None or reg.status != WorkerIdentityStatus.approved:
        raise WorkerAdmissionRefused("worker_identity_unapproved")
    if _aware(reg.expiry) <= now:
        raise WorkerAdmissionRefused("worker_identity_expired")
    if reg.identity_version != expected_version:
        raise WorkerAdmissionRefused("worker_identity_version_drift")
    return reg


def _verify_authorization(session: Session, auth: LiveReadAuthorization, now: datetime) -> None:
    """Re-run the authoritative live-read authorization checks (SECP-B6 MB-1 §3): approved,
    unexpired, target active, onboarding active, connection-hash and boundary-hash not drifted.
    Raises ``WorkerAdmissionRefused`` on any failure. Called at issue, complete, assert, AND consume
    so a revocation/drift at any phase fails closed."""
    if auth.status == LiveReadAuthorizationStatus.revoked:
        raise WorkerAdmissionRefused("authorization_revoked")
    if auth.status != LiveReadAuthorizationStatus.approved:
        raise WorkerAdmissionRefused("authorization_not_approved")
    if _aware(auth.authorization_expiry) <= now:
        raise WorkerAdmissionRefused("authorization_expired")
    target = session.get(ExecutionTarget, auth.execution_target_id)
    onboarding = session.get(TargetOnboarding, auth.onboarding_id)
    if target is None or onboarding is None:
        raise WorkerAdmissionRefused("authorization_records_missing")
    if target.status != TargetStatus.active:
        raise WorkerAdmissionRefused("target_not_active")
    if onboarding.status != OnboardingStatus.active:
        raise WorkerAdmissionRefused("onboarding_not_active")
    if auth.connection_hash != connection_identity_hash(target.config or {}):
        raise WorkerAdmissionRefused("connection_hash_drift")
    if auth.boundary_hash != onboarding.boundary_hash:
        raise WorkerAdmissionRefused("boundary_hash_drift")


def _load_admission_authorization(
    session: Session, admission: WorkerDiscoveryAdmission
) -> LiveReadAuthorization:
    """Load the live-read authorization the admission was issued against and confirm it still names
    the same version + endpoint digest, else fail closed."""
    auth = session.get(LiveReadAuthorization, admission.live_read_authorization_id)
    if auth is None:
        raise WorkerAdmissionRefused("authorization_missing")
    if auth.authorization_version != admission.authorization_version:
        raise WorkerAdmissionRefused("authorization_version_drift")
    if auth.endpoint_binding_hash != admission.endpoint_binding_hash:
        raise WorkerAdmissionRefused("endpoint_binding_mismatch")
    return auth


def _audit(
    session: Session,
    admission: WorkerDiscoveryAdmission,
    *,
    action: AuditAction,
    reason_code: str,
    outcome: str,
) -> None:
    audit.record(
        session,
        action=action,
        resource_type="worker_discovery_admission",
        resource_id=admission.id,
        organization_id=admission.organization_id,
        actor="worker",
        outcome=outcome,
        data={
            "reason_code": reason_code,
            "discovery_job_id": str(admission.discovery_job_id),
            "worker_registration_id": str(admission.worker_registration_id),
            "identity_version": admission.identity_version,
            "purpose": admission.purpose,
            "status": admission.status.value,
        },
    )


def issue_discovery_admission_challenge(
    session: Session,
    *,
    discovery_job_id: uuid.UUID,
    authorization_id: uuid.UUID,
    authorization_version: int,
    endpoint_binding_hash: str,
    now: datetime | None = None,
) -> WorkerDiscoveryAdmission:
    """Issue a single-use signing challenge for a discovery job, bound to the authoritative worker
    registration + a valid endpoint-bound live-read authorization. Fails closed on any mismatch."""
    now = now or datetime.now(UTC)

    def refuse(reason: str) -> WorkerDiscoveryAdmission:
        raise WorkerAdmissionRefused(reason)

    job = session.get(DiscoveryJob, discovery_job_id)
    if job is None:
        refuse("job_not_found")
    assert job is not None
    enrollment = session.get(TargetDiscoveryEnrollment, job.enrollment_id)
    if enrollment is None:
        refuse("enrollment_not_found")
    assert enrollment is not None

    regs = _approved_registrations(session, enrollment.organization_id)
    if not regs:
        refuse("worker_identity_unapproved")
    if len(regs) > 1:
        refuse("worker_identity_ambiguous")
    reg = regs[0]
    if _aware(reg.expiry) <= now:
        refuse("worker_identity_expired")

    auth = session.get(LiveReadAuthorization, authorization_id)
    if auth is None:
        refuse("authorization_missing")
    assert auth is not None
    if (
        auth.organization_id != enrollment.organization_id
        or auth.execution_target_id != enrollment.execution_target_id
        or auth.onboarding_id != enrollment.onboarding_id
    ):
        refuse("authorization_target_mismatch")
    if auth.authorization_version != authorization_version:
        refuse("authorization_version_drift")
    if not (auth.endpoint_binding_hash and isinstance(endpoint_binding_hash, str)):
        refuse("endpoint_binding_unset")
    if auth.endpoint_binding_hash != endpoint_binding_hash:
        refuse("endpoint_binding_mismatch")
    # Full authoritative re-verification (status/expiry/target/onboarding/connection/boundary).
    _verify_authorization(session, auth, now)

    admission = WorkerDiscoveryAdmission(
        organization_id=enrollment.organization_id,
        worker_registration_id=reg.id,
        identity_version=reg.identity_version,
        discovery_job_id=job.id,
        enrollment_id=enrollment.id,
        execution_target_id=enrollment.execution_target_id,
        onboarding_id=enrollment.onboarding_id,
        live_read_authorization_id=auth.id,
        authorization_version=auth.authorization_version,
        endpoint_binding_hash=endpoint_binding_hash,
        purpose=WORKER_ADMISSION_PURPOSE,
        nonce=secrets.token_hex(32),
        status=WorkerDiscoveryAdmissionStatus.challenged,
        issued_at=now,
        expires_at=now + timedelta(seconds=WORKER_ADMISSION_TTL_SECONDS),
    )
    session.add(admission)
    session.flush()
    _audit(
        session,
        admission,
        action=AuditAction.worker_discovery_admission_issued,
        reason_code="challenge_issued",
        outcome="success",
    )
    return admission


def complete_discovery_admission(
    session: Session,
    *,
    admission_id: uuid.UUID,
    presented_anchor: str,
    signature: str,
    now: datetime | None = None,
) -> WorkerDiscoveryAdmission:
    """Verify the worker's Ed25519 signature over the issued challenge and mark the admission
    ``admitted``. The public anchor is pinned to the registration's fingerprint — a self-asserted or
    wrong-worker key, an expired challenge, or a bad signature all fail closed."""
    now = now or datetime.now(UTC)
    admission = session.get(WorkerDiscoveryAdmission, admission_id)
    if admission is None:
        raise WorkerAdmissionRefused("admission_not_found")
    if admission.status != WorkerDiscoveryAdmissionStatus.challenged:
        raise WorkerAdmissionRefused("admission_not_pending")

    def refuse(reason: str) -> None:
        admission.status = WorkerDiscoveryAdmissionStatus.refused
        session.flush()
        _audit(
            session,
            admission,
            action=AuditAction.worker_discovery_admission_refused,
            reason_code=reason,
            outcome="refused",
        )
        raise WorkerAdmissionRefused(reason)

    if _aware(admission.expires_at) <= now:
        refuse("admission_expired")
    # Re-verify the worker registration (approved + UNEXPIRED + version) and the live-read
    # authorization (status/expiry/target/onboarding/connection/boundary) at completion too.
    try:
        reg = _verify_registration(
            session, admission.worker_registration_id, admission.identity_version, now
        )
        _verify_authorization(
            session,
            _load_admission_authorization(session, admission),
            now,
        )
    except WorkerAdmissionRefused as exc:
        refuse(exc.reason_code)
        raise  # unreachable (refuse raises)
    # Pin the presented public anchor to the AUTHORITATIVE registered fingerprint (never asserted).
    if not (isinstance(presented_anchor, str) and presented_anchor):
        refuse("anchor_missing")
    if not hmac.compare_digest(
        compute_verification_anchor_fingerprint(presented_anchor),
        str(reg.verification_anchor_fingerprint),
    ):
        refuse("anchor_pin_mismatch")
    message = admission_signing_message(
        nonce=admission.nonce,
        organization_id=str(admission.organization_id),
        discovery_job_id=str(admission.discovery_job_id),
        worker_registration_id=str(reg.id),
        identity_version=reg.identity_version,
        endpoint_binding_hash=admission.endpoint_binding_hash,
        expires_at=_aware(admission.expires_at),
    )
    if not ed25519_verify(public_anchor=presented_anchor, message=message, signature=signature):
        refuse("proof_of_possession_failed")

    admission.status = WorkerDiscoveryAdmissionStatus.admitted
    admission.admitted_at = now
    session.flush()
    _audit(
        session,
        admission,
        action=AuditAction.worker_discovery_admission_issued,
        reason_code="admitted",
        outcome="success",
    )
    return admission


def assert_discovery_admission_valid(
    session: Session,
    *,
    admission_id: uuid.UUID,
    enrollment: TargetDiscoveryEnrollment,
    discovery_job_id: uuid.UUID,
    endpoint_binding_hash: str,
    now: datetime,
) -> AdmissionResult:
    """Engine-side pre-SSH check: the admission must be ``admitted``, unexpired, bound to THIS exact
    claimed job/target/org/enrollment + endpoint, and its registration still approved at the same
    version. Does NOT consume. Raises ``WorkerAdmissionRefused`` on any mismatch."""
    admission = session.get(WorkerDiscoveryAdmission, admission_id)
    if admission is None:
        raise WorkerAdmissionRefused("admission_not_found")
    if admission.status != WorkerDiscoveryAdmissionStatus.admitted:
        raise WorkerAdmissionRefused("admission_not_admitted")
    if _aware(admission.expires_at) <= now:
        raise WorkerAdmissionRefused("admission_expired")
    if (
        admission.organization_id != enrollment.organization_id
        or admission.enrollment_id != enrollment.id
        or admission.discovery_job_id != discovery_job_id
        or admission.execution_target_id != enrollment.execution_target_id
        or admission.onboarding_id != enrollment.onboarding_id
    ):
        raise WorkerAdmissionRefused("admission_job_mismatch")
    if admission.endpoint_binding_hash != endpoint_binding_hash:
        raise WorkerAdmissionRefused("admission_endpoint_mismatch")
    # Re-verify the worker registration (approved + UNEXPIRED + version) AND rerun the authoritative
    # live-read authorization verifier — so a revocation / expiry / target-onboarding / config /
    # boundary drift between admission and this check fails closed (SECP-B6 MB-1 §3).
    reg = _verify_registration(
        session, admission.worker_registration_id, admission.identity_version, now
    )
    _verify_authorization(session, _load_admission_authorization(session, admission), now)
    return AdmissionResult(registration_id=reg.id, identity_version=reg.identity_version)


def consume_discovery_admission(
    session: Session,
    *,
    admission_id: uuid.UUID,
    enrollment: TargetDiscoveryEnrollment,
    discovery_job_id: uuid.UUID,
    endpoint_binding_hash: str,
    now: datetime,
) -> AdmissionResult:
    """Engine-side post-probe one-time consume: re-assert validity, then atomically transition
    ``admitted`` → ``consumed`` (a replay/second consume fails closed). Returns the authoritative
    registration id + version bound into the persisted candidate plan."""
    result = assert_discovery_admission_valid(
        session,
        admission_id=admission_id,
        enrollment=enrollment,
        discovery_job_id=discovery_job_id,
        endpoint_binding_hash=endpoint_binding_hash,
        now=now,
    )
    rowcount = session.execute(
        update(WorkerDiscoveryAdmission)
        .where(
            WorkerDiscoveryAdmission.id == admission_id,
            WorkerDiscoveryAdmission.status == WorkerDiscoveryAdmissionStatus.admitted,
        )
        .values(status=WorkerDiscoveryAdmissionStatus.consumed, consumed_at=now)
    ).rowcount  # type: ignore[attr-defined]
    if rowcount != 1:
        raise WorkerAdmissionRefused("admission_replayed")
    session.expire_all()
    admission = session.get(WorkerDiscoveryAdmission, admission_id)
    if admission is not None:
        _audit(
            session,
            admission,
            action=AuditAction.worker_discovery_admission_consumed,
            reason_code="consumed",
            outcome="success",
        )
    return result
