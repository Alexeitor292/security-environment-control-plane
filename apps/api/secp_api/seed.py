"""Development bootstrap seed.

Provisions a development organization, an all-permissions platform-admin role, and
the development admin principal used by the dev auth fallback. All of this is
DEVELOPMENT-ONLY and clearly labelled; production uses real OIDC and proper RBAC
assignment (see ADR / security model). No secrets are created.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.auth import (
    DEV_PRINCIPAL_SUBJECT,
    LEGACY_DEV_PRINCIPAL_SUBJECT,
    Principal,
    principal_from_user,
)
from secp_api.enums import Permission
from secp_api.models import Organization, Role, User, UserRoleAssignment
from secp_api.services import catalog

DEV_ORG_SLUG = "dev-org"
DEV_ADMIN_EMAIL = "dev-admin@local.test"
PLATFORM_ADMIN_ROLE = "platform-admin"


def bootstrap_dev(session: Session) -> Principal:
    """Idempotently provision the dev org/role/admin. Returns the admin principal."""
    org = session.execute(
        select(Organization).where(Organization.slug == DEV_ORG_SLUG)
    ).scalar_one_or_none()
    if org is None:
        org = catalog.create_organization(
            session, name="Development Organization", slug=DEV_ORG_SLUG
        )

    role = session.execute(
        select(Role).where(Role.name == PLATFORM_ADMIN_ROLE)
    ).scalar_one_or_none()
    all_permissions = [p.value for p in Permission]
    if role is None:
        role = Role(
            name=PLATFORM_ADMIN_ROLE,
            description="DEV ONLY: all permissions.",
            permissions=all_permissions,
        )
        session.add(role)
        session.flush()
    elif set(role.permissions or []) != set(all_permissions):
        # Keep the dev admin in sync with new permissions across milestones so a
        # persisted dev database does not retain a stale permission set.
        role.permissions = all_permissions
        session.flush()

    # ADR-017 idempotent adoption: an existing dev database seeded before OIDC-A carries the legacy
    # dev subject; adopt the deterministic UUID subject in place so the same row resolves on the
    # dev-fallback and the real Keycloak bearer path (dev/test only — production never seeds).
    user = session.execute(
        select(User).where(User.subject == DEV_PRINCIPAL_SUBJECT)
    ).scalar_one_or_none()
    if user is None:
        legacy = session.execute(
            select(User).where(User.subject == LEGACY_DEV_PRINCIPAL_SUBJECT)
        ).scalar_one_or_none()
        if legacy is not None:
            legacy.subject = DEV_PRINCIPAL_SUBJECT
            session.flush()
            user = legacy
    if user is None:
        user = User(
            organization_id=org.id,
            email=DEV_ADMIN_EMAIL,
            display_name="Development Admin",
            subject=DEV_PRINCIPAL_SUBJECT,
        )
        session.add(user)
        session.flush()

    assignment = session.execute(
        select(UserRoleAssignment).where(
            UserRoleAssignment.user_id == user.id,
            UserRoleAssignment.role_id == role.id,
        )
    ).scalar_one_or_none()
    if assignment is None:
        session.add(UserRoleAssignment(organization_id=org.id, user_id=user.id, role_id=role.id))
        session.flush()

    return principal_from_user(session, user)


def load_sample_definition() -> dict:
    """Load the bundled web-breach-101 environment definition."""
    candidates = [
        Path(__file__).resolve().parents[3] / "docs" / "scenarios" / "web-breach-101.yaml",
        Path.cwd() / "docs" / "scenarios" / "web-breach-101.yaml",
    ]
    for path in candidates:
        if path.exists():
            return yaml.safe_load(path.read_text(encoding="utf-8"))
    raise FileNotFoundError("web-breach-101.yaml not found")


def seed_sample_environment(session: Session, actor: Principal) -> None:
    """Seed the Web Breach 101 template + immutable version for the demo."""
    existing = catalog.list_templates(session, actor)
    if any(t.slug == "web-breach-101" for t in existing):
        return
    definition = load_sample_definition()
    template = catalog.create_template(
        session,
        actor,
        name="Web Breach 101",
        slug="web-breach-101",
        display_name="Web Breach 101",
        description="Two-team web exploitation scenario (Kali vs. vulnerable Ubuntu).",
    )
    catalog.create_version(session, actor, template_id=template.id, definition=definition)
