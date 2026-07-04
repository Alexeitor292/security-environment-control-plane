"""Resolver-activation authorization admin lifecycle API (SECP-B2-4.1).

App-owned administrative lifecycle only: create a draft, record closed evidence, view the safe
state/evidence summary, approve (separate permission), and revoke. There is NO secret entry, backend
endpoint entry, backend configuration form, credential form, worker-identity material, or
activation-toggle route. Approving this authorization does NOT arm any resolver — the worker
independently re-verifies it and the shipped defaults keep resolution sealed.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.schemas_resolver_activation import (
    CreateResolverActivation,
    RecordResolverActivationEvidence,
    ResolverActivationOut,
)
from secp_api.services import resolver_activation

router = APIRouter(prefix="/api/v1/resolver-activation", tags=["resolver-activation"])


@router.post("/authorizations", response_model=ResolverActivationOut, status_code=201)
def create_authorization(
    body: CreateResolverActivation,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ResolverActivationOut:
    return ResolverActivationOut.model_validate(
        resolver_activation.create_activation_authorization(
            session, principal, preflight_id=body.preflight_id, ttl_seconds=body.ttl_seconds
        )
    )


@router.get("/authorizations", response_model=list[ResolverActivationOut])
def list_authorizations(
    execution_target_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[ResolverActivationOut]:
    return [
        ResolverActivationOut.model_validate(a)
        for a in resolver_activation.list_activation_authorizations(
            session, principal, execution_target_id=execution_target_id
        )
    ]


@router.get("/authorizations/{authorization_id}", response_model=ResolverActivationOut)
def get_authorization(
    authorization_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ResolverActivationOut:
    return ResolverActivationOut.model_validate(
        resolver_activation.get_activation_authorization(session, principal, authorization_id)
    )


@router.post("/authorizations/{authorization_id}/evidence", response_model=ResolverActivationOut)
def record_evidence(
    authorization_id: uuid.UUID,
    body: RecordResolverActivationEvidence,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ResolverActivationOut:
    resolver_activation.record_evidence(
        session,
        principal,
        authorization_id,
        kind=body.kind,
        status=body.status,
        proof_id=body.proof_id,
        issuer=body.issuer,
    )
    return ResolverActivationOut.model_validate(
        resolver_activation.get_activation_authorization(session, principal, authorization_id)
    )


@router.post("/authorizations/{authorization_id}/approve", response_model=ResolverActivationOut)
def approve_authorization(
    authorization_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ResolverActivationOut:
    return ResolverActivationOut.model_validate(
        resolver_activation.approve_activation_authorization(session, principal, authorization_id)
    )


@router.post("/authorizations/{authorization_id}/revoke", response_model=ResolverActivationOut)
def revoke_authorization(
    authorization_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ResolverActivationOut:
    return ResolverActivationOut.model_validate(
        resolver_activation.revoke_activation_authorization(session, principal, authorization_id)
    )
