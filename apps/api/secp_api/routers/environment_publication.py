"""Audited EnvironmentVersion publication route (ADR-016 PR C, control plane only).

One explicit control-plane mutation: an already-approved topology revision + its passing
validation + a non-topology v1alpha2 definition -> one new immutable EnvironmentVersion. Nothing
runs afterwards: no exercise, plan, workflow, worker, provider, or infrastructure contact. The
transactional publication service (SECP-B10) remains the authoritative permission and
precondition boundary; this route only transports request fields, sets a truthful 201-vs-200
status, and records success + durable refusal audits. It imports no worker/provider/transport/
subprocess/socket/HTTP-client/secret-resolver code and constructs no downstream object.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.db import session_scope
from secp_api.deps import current_principal, db_session
from secp_api.enums import AuditAction
from secp_api.enums import EnvironmentPublicationErrorCode as EC
from secp_api.errors import EnvironmentPublicationError
from secp_api.schemas import VersionOut
from secp_api.schemas_environment_publication import EnvironmentPublicationRequest
from secp_api.services import environment_publication as svc

if TYPE_CHECKING:
    from secp_api.models import EnvironmentVersion

logger = logging.getLogger("secp.api")

router = APIRouter(prefix="/api/v1", tags=["environment-publication"])


def _refusal_audit_data(body: EnvironmentPublicationRequest, code: str) -> dict:
    """Allowlisted, bounded refusal-audit payload — ids/hashes/closed code only, never the
    definition, topology, provenance, rejected values, or exception text."""
    return {
        "refusal_code": code,
        "template_id": str(body.template_id),
        "topology_document_id": str(body.topology_document_id),
        "topology_revision_id": str(body.topology_revision_id),
        "expected_topology_content_hash": body.expected_topology_content_hash,
        "validation_result_id": str(body.validation_result_id),
        "base_environment_version_id": (
            str(body.base_environment_version_id) if body.base_environment_version_id else None
        ),
    }


def _success_audit_data(version: EnvironmentVersion) -> dict:
    """Allowlisted success-audit payload — safe ids, hashes, version number, and closed contract
    values only (from the immutable row); no definition/spec/topology/findings/free text."""
    base = version.base_environment_version_id
    return {
        "template_id": str(version.template_id),
        "environment_version_id": str(version.id),
        "version_number": version.version_number,
        "environment_content_hash": version.content_hash,
        "publication_fingerprint": version.publication_fingerprint,
        "topology_document_id": str(version.source_topology_document_id),
        "topology_revision_id": str(version.source_topology_revision_id),
        "topology_content_hash": version.topology_content_hash,
        "topology_validation_result_id": str(version.topology_validation_result_id),
        "topology_validation_result_hash": version.topology_validation_result_hash,
        "base_environment_version_id": (str(base) if base is not None else None),
        "publication_contract_version": version.publication_contract_version,
    }


def _record_refusal(principal: Principal, body: EnvironmentPublicationRequest, code: str) -> None:
    """Durably audit a service refusal in a SEPARATE transaction so it survives the failed
    request's rollback and never commits a partial version. If the refusal audit itself fails,
    log server-side without rejected content and raise the closed audit-failure code (HTTP 500)."""
    try:
        with session_scope() as audit_session:
            audit.record(
                audit_session,
                action=AuditAction.version_publish_refused,
                resource_type="environment_version_publication",
                resource_id=str(body.template_id),
                actor=str(principal.user_id),
                organization_id=principal.organization_id,
                outcome="denied",
                data=_refusal_audit_data(body, code),
            )
    except Exception:
        logger.exception("durable publication refusal audit failed")
        raise EnvironmentPublicationError(EC.version_publish_audit_failure) from None


@router.post(
    "/environment-versions/publish",
    response_model=VersionOut,
    responses={201: {"model": VersionOut}, 200: {"model": VersionOut}},
    summary="Publish an approved topology revision into a new immutable EnvironmentVersion",
)
def publish_environment_version(
    body: EnvironmentPublicationRequest,
    response: Response,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> VersionOut:
    """Publish -> new immutable v1alpha2 EnvironmentVersion. 201 on creation (with one atomic
    ``version.published`` audit), 200 on an exact idempotent replay (same version id, no new row,
    no version-number increment, no duplicate mutation audit). Service refusals are durably
    audited and mapped to closed per-code HTTP statuses."""
    try:
        result = svc.publish_version_with_result(
            session,
            principal,
            template_id=body.template_id,
            definition=body.definition,
            topology_document_id=body.topology_document_id,
            topology_revision_id=body.topology_revision_id,
            expected_topology_content_hash=body.expected_topology_content_hash,
            validation_result_id=body.validation_result_id,
            base_environment_version_id=body.base_environment_version_id,
        )
    except EnvironmentPublicationError as exc:
        # Roll back the (possibly savepoint-touched) request transaction, durably record the
        # refusal in a separate transaction, then re-raise the ORIGINAL closed refusal code.
        session.rollback()
        _record_refusal(principal, body, exc.code)  # may raise version_publish_audit_failure
        raise

    if result.created:
        # The success audit is atomic with the new version (same request transaction): if it
        # fails, roll back so NO version persists and return only the closed audit-failure code.
        try:
            audit.record(
                session,
                action=AuditAction.version_published,
                resource_type="environment_version",
                resource_id=str(result.version.id),
                actor=str(principal.user_id),
                organization_id=principal.organization_id,
                outcome="success",
                data=_success_audit_data(result.version),
            )
            session.commit()
        except Exception:
            session.rollback()
            logger.exception("publication success audit failed")
            raise EnvironmentPublicationError(EC.version_publish_audit_failure) from None
        response.status_code = 201
    else:
        # Exact idempotent replay — no second version, no increment, no duplicate mutation audit.
        response.status_code = 200

    return VersionOut.from_version(result.version)
