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

Beyond create/status/revoke this slice also exposes the durable worker-progression steps —
worker bind, controller offer, worker result, release verified, healthy — each a thin adapter over
the PR5H-A CAS service (service-layer ``enrollment:progress`` authorization, organization/site
enforcement, exact-retry through the existing receipts). The endpoints consume ONLY already-bound
facts (a digest + transaction + signer key id); no raw private key, handoff-record bytes, provider
action or operator action crosses this surface, and no outbound EnrollmentTransport is opened yet.
"""

from __future__ import annotations

import datetime as _dt

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.schemas_enrollment import (
    BindWorkerRequest,
    CreateEnrollmentInvitation,
    EnrollmentInvitationOut,
    EnrollmentStatusOut,
    ExpectedToken,
    MarkHealthyRequest,
    RecordHandoffRequest,
    RevokeEnrollment,
    VerifyReleaseRequest,
)
from secp_api.services import worker_enrollment as svc
from secp_api.worker_enrollment_contract import HandoffFacts

router = APIRouter(prefix="/api/v1/enrollment", tags=["enrollment"])


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


def _expected(token: ExpectedToken) -> svc.ExpectedRevision:
    # the caller's observed CAS coordinates, passed through verbatim to the durable service
    return svc.ExpectedRevision(
        revision=token.revision,
        state_digest=token.state_digest,
        sequence=token.sequence,
        predecessor_digest=token.predecessor_digest,
    )


@router.post("/{enrollment_id}/bind", response_model=EnrollmentStatusOut)
def bind_worker(
    enrollment_id: str,
    body: BindWorkerRequest,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> EnrollmentStatusOut:
    outcome = svc.bind_worker(
        session,
        principal,
        enrollment_id=enrollment_id,
        worker_installation_id=body.worker_installation_id,
        worker_key_id=body.worker_key_id,
        transaction_id=body.transaction_id,
        now=_iso(_utc_now()),
        expected=_expected(body.expected),
    )
    return EnrollmentStatusOut.model_validate(outcome.state.public_view())


@router.post("/{enrollment_id}/offer", response_model=EnrollmentStatusOut)
def record_controller_offer(
    enrollment_id: str,
    body: RecordHandoffRequest,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> EnrollmentStatusOut:
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
        expected=_expected(body.expected),
    )
    return EnrollmentStatusOut.model_validate(outcome.state.public_view())


@router.post("/{enrollment_id}/result", response_model=EnrollmentStatusOut)
def record_worker_result(
    enrollment_id: str,
    body: RecordHandoffRequest,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> EnrollmentStatusOut:
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
        expected=_expected(body.expected),
    )
    return EnrollmentStatusOut.model_validate(outcome.state.public_view())


@router.post("/{enrollment_id}/verify", response_model=EnrollmentStatusOut)
def verify_release(
    enrollment_id: str,
    body: VerifyReleaseRequest,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> EnrollmentStatusOut:
    outcome = svc.verify_release(
        session,
        principal,
        enrollment_id=enrollment_id,
        release_digest=body.release_digest,
        now=_iso(_utc_now()),
        expected=_expected(body.expected),
    )
    return EnrollmentStatusOut.model_validate(outcome.state.public_view())


@router.post("/{enrollment_id}/healthy", response_model=EnrollmentStatusOut)
def mark_enrollment_healthy(
    enrollment_id: str,
    body: MarkHealthyRequest,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> EnrollmentStatusOut:
    outcome = svc.mark_enrollment_healthy(
        session,
        principal,
        enrollment_id=enrollment_id,
        now=_iso(_utc_now()),
        expected=_expected(body.expected),
    )
    return EnrollmentStatusOut.model_validate(outcome.state.public_view())
