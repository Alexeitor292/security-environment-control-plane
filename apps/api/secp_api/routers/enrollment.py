"""Supported worker-enrollment controller API (SECP-PR5H-B1).

The customer-visible controller surface over the durable PR5H-A enrollment foundation. This first
vertical slice covers the controller invitation lifecycle:

* ``POST /api/v1/enrollment/invitations`` — create a single-use invitation and open its enrollment
  at revision 0, returning the **non-secret** invitation the operator hands to the worker.
* ``GET  /api/v1/enrollment/{enrollment_id}`` — the bounded, secret-free status projection.

Authentication is required (``current_principal``); authorization is the organization boundary,
enforced by the service against the authoritative persisted row (Charter invariant: organization is
the only authorization boundary). The endpoint performs NO privileged infrastructure action, opens
no outbound connection, and transports no private key or raw handoff record — it only persists the
pure transition through the PR5H-A CAS service. Bounded ``WorkerEnrollmentError`` codes map to HTTP
via the domain-error handler; no rejected input, endpoint, path or secret is ever echoed.

The worker-progression steps — worker bind, controller offer, worker result, release verified,
healthy — exist as thin adapters over the PR5H-A CAS service, but they are **claim-only**: RBAC
authorizes an actor to *request* an operation; it is not proof that a worker owns a key, that a
handoff was signed, that the release is running, or that the worker is healthy. They are therefore
**NOT a supported trusted exchange** and are **SEALED by default** — sealed closed in production
(``SECP_ENABLE_ENROLLMENT_PROGRESSION`` is refused there) and returning ``enrollment_progression_
sealed`` unless a deployment-local development/test profile explicitly enables them to exercise the
durable primitives. The supported, evidence-driven surface is the authenticated worker-initiated
EnrollmentTransport (delivered separately): worker proof-of-possession, an internally-signed
controller offer, a verified signed worker result, and controller-side verified/healthy decisions.
The claim-only handlers take ONLY the caller's last-observed ``expected_revision``; the durable CAS
coordinates are derived server-side and never cross the public boundary.
"""

from __future__ import annotations

import datetime as _dt

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.config import Settings
from secp_api.deps import current_principal, db_session, settings_dep
from secp_api.enums import WorkerEnrollmentErrorCode as EC
from secp_api.errors import WorkerEnrollmentError
from secp_api.schemas_enrollment import (
    BindWorkerRequest,
    CreateEnrollmentInvitation,
    EnrollmentInvitationOut,
    EnrollmentStatusOut,
    MarkHealthyRequest,
    RecordHandoffRequest,
    RevokeEnrollment,
    VerifyReleaseRequest,
)
from secp_api.services import worker_enrollment as svc
from secp_api.worker_enrollment_contract import HandoffFacts

router = APIRouter(prefix="/api/v1/enrollment", tags=["enrollment"])


def _require_progression_enabled(settings: Settings) -> None:
    """The claim-only progression steps are a sealed, non-supported surface. They fail closed unless
    a deployment-local development/test profile explicitly enables them; production refuses the flag
    entirely (see config). A sealed request is a bounded, redacted ``enrollment_progression_sealed``
    — the trusted exchange is the authenticated EnrollmentTransport, not these routes."""
    if not settings.enable_enrollment_progression:
        raise WorkerEnrollmentError(EC.progression_sealed)


def _utc_now() -> _dt.datetime:
    # impure clock read lives in the router, never in the pure contract
    return _dt.datetime.now(_dt.UTC)


def _iso(moment: _dt.datetime) -> str:
    # canonical UTC string the pure contract accepts (explicit +00:00 offset, <= 40 chars)
    return moment.astimezone(_dt.UTC).isoformat(timespec="seconds")


@router.post("/invitations", response_model=EnrollmentInvitationOut, status_code=201)
def create_enrollment_invitation(
    body: CreateEnrollmentInvitation,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> EnrollmentInvitationOut:
    # one clock sample: created_at and expires_at derive from the SAME instant, so the effective TTL
    # is exactly ttl_seconds and a requested 86400 can never truncate to 86401 across a boundary.
    now_dt = _utc_now()
    result = svc.create_supported_invitation(
        session,
        principal,
        idempotency_key=body.idempotency_key,
        deployment_site_label=body.deployment_site_label,
        ttl_seconds=body.ttl_seconds,
        created_at=_iso(now_dt),
        expires_at=_iso(now_dt + _dt.timedelta(seconds=body.ttl_seconds)),
    )
    return EnrollmentInvitationOut(
        enrollment_id=result.enrollment_id,
        invitation_id=result.invitation_id,
        controller_installation_id=result.controller_installation_id,
        controller_key_id=result.controller_key_id,
        controller_trust_anchor_hex=result.controller_trust_anchor_hex,
        controller_origin=result.controller_origin,
        release_digest=result.release_digest,
        transaction_id=result.transaction_id,
        deployment_site_label=result.deployment_site_label,
        created_at=result.created_at,
        expires_at=result.expires_at,
        state=result.state,
        revision=result.revision,
    )


@router.get("/{enrollment_id}", response_model=EnrollmentStatusOut)
def get_enrollment_status(
    enrollment_id: str,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> EnrollmentStatusOut:
    view = svc.load_public_view(session, principal, enrollment_id=enrollment_id)
    return EnrollmentStatusOut.model_validate(view)


@router.post("/{enrollment_id}/revoke", response_model=EnrollmentStatusOut)
def revoke_enrollment(
    enrollment_id: str,
    body: RevokeEnrollment,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> EnrollmentStatusOut:
    outcome = svc.revoke_enrollment(
        session, principal, enrollment_id=enrollment_id, expected_revision=body.expected_revision
    )
    return EnrollmentStatusOut.model_validate(outcome.state.public_view())


# --- SEALED claim-only progression steps (not a supported trusted exchange; see module docstring) -
# Each carries ONLY the caller's ``expected_revision``; the service derives the durable CAS
# coordinates from the authoritative loaded state. Gated closed by default via
# ``_require_progression_enabled`` — the supported path is the authenticated EnrollmentTransport.


@router.post("/{enrollment_id}/bind", response_model=EnrollmentStatusOut)
def bind_worker(
    enrollment_id: str,
    body: BindWorkerRequest,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
    settings: Settings = Depends(settings_dep),
) -> EnrollmentStatusOut:
    _require_progression_enabled(settings)
    outcome = svc.bind_worker(
        session,
        principal,
        enrollment_id=enrollment_id,
        worker_installation_id=body.worker_installation_id,
        worker_key_id=body.worker_key_id,
        transaction_id=body.transaction_id,
        now=_iso(_utc_now()),
        expected_revision=body.expected_revision,
    )
    return EnrollmentStatusOut.model_validate(outcome.state.public_view())


@router.post("/{enrollment_id}/offer", response_model=EnrollmentStatusOut)
def record_controller_offer(
    enrollment_id: str,
    body: RecordHandoffRequest,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
    settings: Settings = Depends(settings_dep),
) -> EnrollmentStatusOut:
    _require_progression_enabled(settings)
    outcome = svc.record_offer(
        session,
        principal,
        enrollment_id=enrollment_id,
        facts=HandoffFacts(
            kind="controller-offer",
            digest=body.digest,
            transaction_id=body.transaction_id,
            signer_key_id=body.signer_key_id,
        ),
        now=_iso(_utc_now()),
        expected_revision=body.expected_revision,
    )
    return EnrollmentStatusOut.model_validate(outcome.state.public_view())


@router.post("/{enrollment_id}/result", response_model=EnrollmentStatusOut)
def record_worker_result(
    enrollment_id: str,
    body: RecordHandoffRequest,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
    settings: Settings = Depends(settings_dep),
) -> EnrollmentStatusOut:
    _require_progression_enabled(settings)
    outcome = svc.record_result(
        session,
        principal,
        enrollment_id=enrollment_id,
        facts=HandoffFacts(
            kind="worker-result",
            digest=body.digest,
            transaction_id=body.transaction_id,
            signer_key_id=body.signer_key_id,
        ),
        now=_iso(_utc_now()),
        expected_revision=body.expected_revision,
    )
    return EnrollmentStatusOut.model_validate(outcome.state.public_view())


@router.post("/{enrollment_id}/verify", response_model=EnrollmentStatusOut)
def verify_release(
    enrollment_id: str,
    body: VerifyReleaseRequest,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
    settings: Settings = Depends(settings_dep),
) -> EnrollmentStatusOut:
    _require_progression_enabled(settings)
    outcome = svc.verify_release(
        session,
        principal,
        enrollment_id=enrollment_id,
        release_digest=body.release_digest,
        now=_iso(_utc_now()),
        expected_revision=body.expected_revision,
    )
    return EnrollmentStatusOut.model_validate(outcome.state.public_view())


@router.post("/{enrollment_id}/healthy", response_model=EnrollmentStatusOut)
def mark_enrollment_healthy(
    enrollment_id: str,
    body: MarkHealthyRequest,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
    settings: Settings = Depends(settings_dep),
) -> EnrollmentStatusOut:
    _require_progression_enabled(settings)
    outcome = svc.mark_enrollment_healthy(
        session,
        principal,
        enrollment_id=enrollment_id,
        now=_iso(_utc_now()),
        expected_revision=body.expected_revision,
    )
    return EnrollmentStatusOut.model_validate(outcome.state.public_view())
