"""Catalog services: organizations, teams, templates, immutable versions."""

from __future__ import annotations

import uuid

from secp_scenario_schema import content_hash, validate_definition
from secp_scenario_schema.validator import SchemaValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import AuditAction, Permission
from secp_api.errors import NotFoundError, ValidationFailedError
from secp_api.models import (
    EnvironmentTemplate,
    EnvironmentVersion,
    Organization,
    Team,
)


def create_organization(session: Session, name: str, slug: str) -> Organization:
    org = Organization(name=name, slug=slug)
    session.add(org)
    session.flush()
    audit.record(
        session,
        action=AuditAction.organization_created,
        resource_type="organization",
        resource_id=org.id,
        organization_id=org.id,
        actor="system",
        data={"slug": slug},
    )
    return org


def ensure_teams(session: Session, organization_id: uuid.UUID, count: int) -> list[Team]:
    """Idempotently ensure team1..teamN exist for an org. Returns ordered teams."""
    teams: list[Team] = []
    for idx in range(count):
        slug = f"team{idx + 1}"
        existing = session.execute(
            select(Team).where(Team.organization_id == organization_id, Team.slug == slug)
        ).scalar_one_or_none()
        if existing is None:
            existing = Team(organization_id=organization_id, name=f"Team {idx + 1}", slug=slug)
            session.add(existing)
            session.flush()
            audit.record(
                session,
                action=AuditAction.team_created,
                resource_type="team",
                resource_id=existing.id,
                organization_id=organization_id,
                actor="system",
                data={"slug": slug},
            )
        teams.append(existing)
    return teams


def create_template(
    session: Session,
    actor: Principal,
    *,
    name: str,
    slug: str,
    display_name: str = "",
    description: str = "",
) -> EnvironmentTemplate:
    actor.require(Permission.template_author)
    template = EnvironmentTemplate(
        organization_id=actor.organization_id,
        name=name,
        slug=slug,
        display_name=display_name or name,
        description=description,
        created_by=actor.user_id,
    )
    session.add(template)
    session.flush()
    audit.record(
        session,
        action=AuditAction.template_created,
        resource_type="environment_template",
        resource_id=template.id,
        organization_id=actor.organization_id,
        actor=str(actor.user_id),
        data={"slug": slug},
    )
    return template


def get_template(session: Session, actor: Principal, template_id: uuid.UUID) -> EnvironmentTemplate:
    template = session.get(EnvironmentTemplate, template_id)
    if template is None:
        raise NotFoundError(f"template {template_id} not found")
    actor.require_org(template.organization_id)
    return template


def create_version(
    session: Session,
    actor: Principal,
    *,
    template_id: uuid.UUID,
    definition: dict,
) -> EnvironmentVersion:
    """Create an immutable environment version from a declarative definition.

    Validates against the versioned schema, computes a content hash, and assigns
    the next per-template version number (ADR-002). The row is immutable once
    created (enforced in :mod:`secp_api.immutability`).
    """
    actor.require(Permission.version_create)
    template = get_template(session, actor, template_id)

    try:
        validated = validate_definition(definition)
    except SchemaValidationError as exc:
        raise ValidationFailedError(
            "environment definition failed schema validation", errors=exc.errors
        ) from exc

    next_number = (
        session.execute(
            select(func.coalesce(func.max(EnvironmentVersion.version_number), 0)).where(
                EnvironmentVersion.template_id == template_id
            )
        ).scalar_one()
        + 1
    )

    version = EnvironmentVersion(
        organization_id=template.organization_id,
        template_id=template_id,
        version_number=next_number,
        api_version=validated.apiVersion,
        spec=definition,
        content_hash=content_hash(definition),
        created_by=actor.user_id,
    )
    session.add(version)
    session.flush()
    audit.record(
        session,
        action=AuditAction.version_created,
        resource_type="environment_version",
        resource_id=version.id,
        organization_id=template.organization_id,
        actor=str(actor.user_id),
        data={
            "version_number": next_number,
            "content_hash": version.content_hash,
        },
    )
    return version


def get_version(session: Session, actor: Principal, version_id: uuid.UUID) -> EnvironmentVersion:
    version = session.get(EnvironmentVersion, version_id)
    if version is None:
        raise NotFoundError(f"version {version_id} not found")
    actor.require_org(version.organization_id)
    return version


def list_templates(session: Session, actor: Principal) -> list[EnvironmentTemplate]:
    return list(
        session.execute(
            select(EnvironmentTemplate)
            .where(EnvironmentTemplate.organization_id == actor.organization_id)
            .order_by(EnvironmentTemplate.created_at)
        )
        .scalars()
        .all()
    )


def list_versions(
    session: Session, actor: Principal, template_id: uuid.UUID
) -> list[EnvironmentVersion]:
    get_template(session, actor, template_id)
    return list(
        session.execute(
            select(EnvironmentVersion)
            .where(EnvironmentVersion.template_id == template_id)
            .order_by(EnvironmentVersion.version_number)
        )
        .scalars()
        .all()
    )
