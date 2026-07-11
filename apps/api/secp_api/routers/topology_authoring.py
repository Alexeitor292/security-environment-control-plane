"""Durable topology draft authoring routes (SECP-B9, control plane only).

The API creates a topology-authoring aggregate, records immutable revisions,
runs infrastructure-free validation, and drives submit/approve/reject. It never
imports worker/provider/runner/transport/secret code, contacts no infrastructure,
and generates no deployment. Approval records a decision only — live apply and
plan generation remain out of this contract.

Refusals that record a durable audit event are committed before the closed-code
error propagates (mirroring resolver-activation), so refused mutations are
audited even though the request fails closed.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.errors import TopologyAuthoringError
from secp_api.schemas_topology_authoring import (
    TopologyDecision,
    TopologyDocumentDetailOut,
    TopologyDocumentOut,
    TopologyDraftCreate,
    TopologyHashPin,
    TopologyRevisionCreate,
    TopologyRevisionDetailOut,
    TopologyRevisionOut,
    TopologyValidationOut,
)
from secp_api.services import topology_authoring as svc

router = APIRouter(prefix="/api/v1", tags=["topology-authoring"])

# Nothing in this router executes, applies, or contacts infrastructure.
CONTROL_PLANE_ONLY_NOTICE = (
    "Control plane only — authoring a topology never deploys or contacts infrastructure."
)


def _durable(session: Session, fn):
    """Run a service mutation; if it fails closed after recording a durable
    refusal audit, commit that audit before re-raising the closed code."""
    try:
        return fn()
    except TopologyAuthoringError as exc:
        if getattr(exc, "durable_transition", False):
            session.commit()
        raise


def _detail(session: Session, principal: Principal, doc) -> TopologyDocumentDetailOut:
    current = svc.get_current_revision(session, principal, doc.id)
    return TopologyDocumentDetailOut(
        **TopologyDocumentOut.model_validate(doc).model_dump(),
        current_revision=(TopologyRevisionDetailOut.model_validate(current) if current else None),
        current_validation_status=svc.validation_status_for_current(session, doc),
    )


@router.post(
    "/topology-authoring/documents",
    response_model=TopologyDocumentDetailOut,
    status_code=201,
)
def create_draft(
    body: TopologyDraftCreate,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> TopologyDocumentDetailOut:
    doc = _durable(
        session,
        lambda: svc.create_draft(
            session,
            principal,
            display_name=body.display_name,
            source_environment_version_id=body.source_environment_version_id,
            exercise_id=body.exercise_id,
            document=body.document,
        ),
    )
    return _detail(session, principal, doc)


@router.get(
    "/topology-authoring/documents/{document_id}",
    response_model=TopologyDocumentDetailOut,
)
def get_document(
    document_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> TopologyDocumentDetailOut:
    doc = svc.get_document(session, principal, document_id)
    return _detail(session, principal, doc)


@router.get(
    "/topology-authoring/documents/{document_id}/revisions",
    response_model=list[TopologyRevisionOut],
)
def list_revisions(
    document_id: uuid.UUID,
    limit: int = Query(default=svc.MAX_HISTORY_PAGE, ge=1, le=svc.MAX_HISTORY_PAGE),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[TopologyRevisionOut]:
    revisions = svc.list_revisions(session, principal, document_id, limit=limit, offset=offset)
    return [TopologyRevisionOut.model_validate(r) for r in revisions]


@router.get(
    "/topology-authoring/documents/{document_id}/revisions/{revision_id}",
    response_model=TopologyRevisionDetailOut,
)
def get_revision(
    document_id: uuid.UUID,
    revision_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> TopologyRevisionDetailOut:
    revision = svc.get_revision(session, principal, document_id, revision_id)
    return TopologyRevisionDetailOut.model_validate(revision)


@router.post(
    "/topology-authoring/documents/{document_id}/revisions",
    response_model=TopologyRevisionDetailOut,
    status_code=201,
)
def create_revision(
    document_id: uuid.UUID,
    body: TopologyRevisionCreate,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> TopologyRevisionDetailOut:
    revision = _durable(
        session,
        lambda: svc.create_revision(
            session,
            principal,
            document_id,
            base_revision_number=body.base_revision_number,
            base_content_hash=body.base_content_hash,
            document=body.document,
            change_note=body.change_note,
        ),
    )
    return TopologyRevisionDetailOut.model_validate(revision)


@router.post(
    "/topology-authoring/documents/{document_id}/revisions/{revision_id}/validate",
    response_model=TopologyValidationOut,
)
def validate_revision(
    document_id: uuid.UUID,
    revision_id: uuid.UUID,
    body: TopologyHashPin,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> TopologyValidationOut:
    result = _durable(
        session,
        lambda: svc.validate_revision(
            session,
            principal,
            document_id,
            revision_id,
            expected_content_hash=body.content_hash,
        ),
    )
    return TopologyValidationOut.model_validate(result)


@router.get(
    "/topology-authoring/documents/{document_id}/revisions/{revision_id}/validation",
    response_model=TopologyValidationOut | None,
)
def get_validation(
    document_id: uuid.UUID,
    revision_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> TopologyValidationOut | None:
    result = svc.get_latest_validation(session, principal, document_id, revision_id)
    return TopologyValidationOut.model_validate(result) if result else None


@router.post(
    "/topology-authoring/documents/{document_id}/revisions/{revision_id}/submit",
    response_model=TopologyRevisionOut,
)
def submit_revision(
    document_id: uuid.UUID,
    revision_id: uuid.UUID,
    body: TopologyHashPin,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> TopologyRevisionOut:
    revision = _durable(
        session,
        lambda: svc.submit_revision(
            session,
            principal,
            document_id,
            revision_id,
            expected_content_hash=body.content_hash,
        ),
    )
    return TopologyRevisionOut.model_validate(revision)


@router.post(
    "/topology-authoring/documents/{document_id}/revisions/{revision_id}/approve",
    response_model=TopologyRevisionOut,
)
def approve_revision(
    document_id: uuid.UUID,
    revision_id: uuid.UUID,
    body: TopologyDecision,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> TopologyRevisionOut:
    revision = _durable(
        session,
        lambda: svc.approve_revision(
            session,
            principal,
            document_id,
            revision_id,
            expected_content_hash=body.content_hash,
            reason=body.reason,
        ),
    )
    return TopologyRevisionOut.model_validate(revision)


@router.post(
    "/topology-authoring/documents/{document_id}/revisions/{revision_id}/reject",
    response_model=TopologyRevisionOut,
)
def reject_revision(
    document_id: uuid.UUID,
    revision_id: uuid.UUID,
    body: TopologyDecision,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> TopologyRevisionOut:
    revision = _durable(
        session,
        lambda: svc.reject_revision(
            session,
            principal,
            document_id,
            revision_id,
            expected_content_hash=body.content_hash,
            reason=body.reason,
        ),
    )
    return TopologyRevisionOut.model_validate(revision)
