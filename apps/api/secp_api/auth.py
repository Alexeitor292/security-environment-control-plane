"""Authentication principal and organization-scoped RBAC.

Two authentication paths resolve a :class:`Principal` (see :func:`secp_api.deps.current_principal`):

* **OIDC bearer token (ADR-017 / OIDC-A).** A presented ``Authorization: Bearer`` token is
  cryptographically verified against the configured issuer's JWKS (:mod:`secp_api.oidc`), and its
  exact ``sub`` claim is mapped to exactly one pre-provisioned internal user
  (:func:`principal_from_oidc_claims`). Organization, roles, and permissions come EXCLUSIVELY from
  SECP database records — the token never supplies or elevates organization membership, internal
  roles, SECP permissions, or administrator status.
* **Development fallback.** A clearly-gated dev fallback principal keeps the local stack runnable
  without a real IdP, ONLY on a no-Authorization-header request and ONLY when the dev fallback is
  enabled (never in production; see :attr:`Settings.dev_auth_enabled`). A presented bearer token is
  always evaluated first and never falls back.

Authorization is organization-scoped: every access is checked against the principal's
``organization_id`` and required permissions (Charter §13; Phase 2 rule 7). Valid authentication is
NOT authorization — the per-route, per-permission, and org checks remain authoritative.

Interactive browser login (Authorization Code + PKCE) is deliberately NOT implemented here; it is
the future OIDC-B slice. This module establishes only the trusted backend boundary.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.enums import Permission
from secp_api.errors import AuthenticationError, AuthorizationError
from secp_api.models import Role, User, UserRoleAssignment
from secp_api.oidc import (
    CATEGORY_CLAIMS_INVALID,
    CATEGORY_SUBJECT_UNKNOWN,
    OidcVerificationError,
)

# Deterministic development identity (ADR-017). The dev fallback subject AND the dev Keycloak user's
# id (which becomes the access token ``sub``) are this exact UUID, so the SAME seeded user row
# resolves on BOTH the no-token dev-fallback path and the real bearer path against the dev realm.
# It is a clearly-fake, well-formed UUID; production never seeds this identity.
DEV_PRINCIPAL_SUBJECT = "5ec9ad00-0000-4000-8000-000000000001"
# The pre-ADR-017 dev subject; an existing dev database is migrated to the UUID idempotently by the
# bootstrap seed (never in production, which does not seed).
LEGACY_DEV_PRINCIPAL_SUBJECT = "dev-admin"


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


def principal_from_oidc_claims(
    session: Session,
    *,
    issuer: str,
    claims: Mapping[str, Any],
) -> Principal:
    """Map cryptographically-verified OIDC claims to an internal :class:`Principal` (ADR-017).

    The verifier (:mod:`secp_api.oidc`) has verified signature, issuer, audience, and time claims.
    This function performs ONLY the exact subject → internal user resolution:

    * the claims' ``iss`` must equal the configured trusted ``issuer`` (defense in depth);
    * the exact ``sub`` (no lowercase/trim/normalize/slugify) maps to exactly one pre-provisioned
      user via ``app_user.subject``;
    * organization, roles, and permissions come from that user's DB row (``principal_from_user`` /
      ``resolve_permissions``) — a user with zero role assignments yields an authenticated principal
      with NO permissions.

    It NEVER creates or modifies a user, never links by email/username, never trusts token
    roles/groups or an organization claim, never updates the display name/email from claims, and
    never grants a default role. An unknown subject is unauthenticated, NOT a new user; a duplicate
    subject (despite the DB partial-unique index) fails closed.
    """
    if claims.get("iss") != issuer:
        raise OidcVerificationError(CATEGORY_CLAIMS_INVALID)
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise OidcVerificationError(CATEGORY_CLAIMS_INVALID)
    users = session.execute(select(User).where(User.subject == sub)).scalars().all()
    if len(users) != 1:
        # 0 -> the subject is not provisioned (unauthenticated, never a new user);
        # >1 -> ambiguous identity (impossible under the DB guard) -> fail closed.
        raise OidcVerificationError(CATEGORY_SUBJECT_UNKNOWN)
    principal = principal_from_user(session, users[0])
    principal.is_dev_fallback = False
    return principal


def dev_principal(session: Session) -> Principal:
    """Return the bootstrapped development admin principal.

    Only used on a no-Authorization-header request when the dev fallback is enabled
    (never in production; a presented bearer token is verified instead).
    """
    user = session.execute(
        select(User).where(User.subject == DEV_PRINCIPAL_SUBJECT)
    ).scalar_one_or_none()
    if user is None:
        raise AuthenticationError("development principal not provisioned; run the bootstrap seed")
    principal = principal_from_user(session, user)
    principal.is_dev_fallback = True
    return principal
