"""Authentication principal and organization-scoped RBAC.

SECP-001 authentication is intentionally minimal: a clearly-gated **development
fallback principal** keeps the local stack runnable without a configured realm,
and OIDC bearer-token validation is a documented placeholder for SECP-002+.

The fallback is refused in production (see :class:`Settings.dev_auth_enabled`).
Authorization is organization-scoped: every access is checked against the
principal's ``organization_id`` and required permissions (Charter §13; Phase 2 rule 7).

SECP-001 placeholder — bearer-token authentication
----------------------------------------------------
Keycloak is wired and reachable in the dev stack (the OIDC discovery endpoint
returns 200), but the API does **not** validate bearer tokens in this milestone.
Any token sent is explicitly rejected with a clear error (see
:func:`secp_api.deps.current_principal`).  Real OIDC validation will be
implemented in SECP-002+ when the full token-verification seam is wired.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.enums import Permission
from secp_api.errors import AuthenticationError, AuthorizationError
from secp_api.models import Role, User, UserRoleAssignment

DEV_PRINCIPAL_SUBJECT = "dev-admin"


@dataclass
class Principal:
    """An authenticated identity with resolved org scope and permissions."""

    user_id: uuid.UUID
    organization_id: uuid.UUID
    email: str
    permissions: frozenset[Permission] = field(default_factory=frozenset)
    is_dev_fallback: bool = False

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions

    def require(self, permission: Permission) -> None:
        if not self.has(permission):
            raise AuthorizationError(f"missing required permission '{permission.value}'")

    def require_org(self, organization_id: uuid.UUID) -> None:
        """Reject cross-organization access (Charter §13, Invariant: org isolation)."""
        if self.organization_id != organization_id:
            raise AuthorizationError("cross-organization access is not permitted")


def resolve_permissions(session: Session, user: User) -> frozenset[Permission]:
    rows = session.execute(
        select(Role.permissions)
        .join(UserRoleAssignment, UserRoleAssignment.role_id == Role.id)
        .where(
            UserRoleAssignment.user_id == user.id,
            UserRoleAssignment.organization_id == user.organization_id,
        )
    ).all()
    perms: set[Permission] = set()
    for (permission_list,) in rows:
        for p in permission_list or []:
            try:
                perms.add(Permission(p))
            except ValueError:
                continue
    return frozenset(perms)


def principal_from_user(session: Session, user: User) -> Principal:
    return Principal(
        user_id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        permissions=resolve_permissions(session, user),
    )


def dev_principal(session: Session) -> Principal:
    """Return the bootstrapped development admin principal.

    Only used when the dev fallback is enabled (never in production).
    """
    user = session.execute(
        select(User).where(User.subject == DEV_PRINCIPAL_SUBJECT)
    ).scalar_one_or_none()
    if user is None:
        raise AuthenticationError("development principal not provisioned; run the bootstrap seed")
    principal = principal_from_user(session, user)
    principal.is_dev_fallback = True
    return principal
