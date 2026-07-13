"""Template and immutable-version routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.registry import get_registry
from secp_api.schemas import (
    TemplateCreate,
    TemplateOut,
    ValidationOut,
    VersionCreate,
    VersionOut,
)
from secp_api.services import catalog

router = APIRouter(prefix="/api/v1", tags=["catalog"])


@router.get("/templates", response_model=list[TemplateOut])
def list_templates(
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[TemplateOut]:
    return [TemplateOut.model_validate(t) for t in catalog.list_templates(session, principal)]


@router.post("/templates", response_model=TemplateOut, status_code=201)
def create_template(
    body: TemplateCreate,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> TemplateOut:
    template = catalog.create_template(
        session,
        principal,
        name=body.name,
        slug=body.slug,
        display_name=body.display_name,
        description=body.description,
    )
    return TemplateOut.model_validate(template)


@router.get("/templates/{template_id}/versions", response_model=list[VersionOut])
def list_versions(
    template_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[VersionOut]:
    return [
        VersionOut.from_version(v) for v in catalog.list_versions(session, principal, template_id)
    ]


@router.post("/templates/{template_id}/versions", response_model=VersionOut, status_code=201)
def create_version(
    template_id: uuid.UUID,
    body: VersionCreate,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> VersionOut:
    version = catalog.create_version(
        session, principal, template_id=template_id, definition=body.definition
    )
    return VersionOut.from_version(version)


@router.get("/environment-versions/{version_id}", response_model=VersionOut)
def get_environment_version(
    version_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> VersionOut:
    """Exact, organization-scoped, read-only EnvironmentVersion read (ADR-016 PR E).

    Resolves the one version by id through ``catalog.get_version`` (Principal org boundary). Legacy
    v1alpha1 returns ``publication_provenance=null``; published v1alpha2 returns the typed immutable
    provenance. No mutation or audit event, no topology-authoring lookup, no caller template id, no
    list-all/latest fallback.
    """
    return VersionOut.from_version(catalog.get_version(session, principal, version_id))


@router.post("/definitions/validate", response_model=ValidationOut)
def validate_definition_endpoint(
    body: VersionCreate,
    _: Principal = Depends(current_principal),
) -> ValidationOut:
    """Validate a raw definition without persisting it (editor live-validation)."""
    result = get_registry().get("simulator").validate(body.definition)
    return ValidationOut(ok=result.ok, errors=result.errors, warnings=result.warnings)
