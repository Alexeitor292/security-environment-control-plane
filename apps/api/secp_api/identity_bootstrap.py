"""Provisioning the FIRST production administrator, and nothing more.

``SI-001`` is the invariant this closes: **in production no authenticated API call is possible
through any supported path.** ``verify_oidc_claims`` maps an exact ``sub`` to an already-provisioned
``app_user`` row and refuses an unknown subject (`auth.py`), there is no just-in-time provisioning
by design, and until now the only way to create that first row was a direct database write — which
is outside the SECP mutation path and produces no ``AuditEvent``. Every "an operator can do X
through /api/v1" claim therefore failed at the identity layer before reaching any feature gate.

This module is the supported way in. It is deliberately the *smallest* thing that closes SI-001:
one local, operator-invoked, audited, one-shot operation.

WHAT IS PRESERVED, EXACTLY
---------------------------
Nothing about OIDC verification is weakened, and the model that an OIDC subject grants nothing on
its own is the correct one. This module does not touch verification at all — it creates the row
that verification requires. Specifically it does NOT:

* match on email, name, or any human-readable attribute;
* normalize, case-fold or otherwise massage the subject;
* read application roles or groups from a token;
* accept an issuer other than the one the deployment is configured to trust;
* create anything in response to a login attempt.

WHY IT IS ONE-SHOT, AND WHAT "ONE-SHOT" MEANS HERE
---------------------------------------------------
A bootstrap that stays available is a permanent unauthenticated path to administrator. So this
refuses once ANY subject-bound user exists in the deployment — not "any user in this organization",
because an attacker who can create an organization could otherwise bootstrap into it beside a
legitimate one.

The check is on subject-bound users specifically. Rows with a NULL subject are not IdP-linked and
cannot authenticate, so they neither satisfy nor block the bootstrap; a deployment seeded with
placeholder rows is still bootstrappable, and a deployment with a real administrator is not.

Re-running it with the SAME issuer and subject is idempotent and returns the existing user, so a
retried install does not fail an operator who cannot tell whether the first attempt committed.
Re-running it with a DIFFERENT subject is refused: that is not a retry, it is a second
administrator, and it must go through the authenticated management path.

WHAT IT IS NOT
--------------
It is not the identity management surface. Creating further users, assigning organizations,
binding subjects, granting and revoking roles, disabling and removing mappings are authenticated,
permission-checked operations that belong on the API — this exists only so that there is somebody
authorized to perform them.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.enums import AuditAction, Permission
from secp_api.models import Organization, Role, User, UserRoleAssignment

#: Recorded in the audit event so an operator can tell which bootstrap contract produced a row.
IDENTITY_BOOTSTRAP_VERSION = "secp.identity-bootstrap/v1"

#: The role the initial administrator is granted. A dedicated name rather than reusing the dev
#: seeder's: the dev role is rewritten to the full permission set on every seed, and an operation
#: that silently re-grants everything on each run is not something a production row should inherit.
INITIAL_ADMINISTRATOR_ROLE = "platform-administrator"

#: Every way the bootstrap refuses, closed. Each names what an operator must change.
BOOTSTRAP_REFUSAL_REASONS: tuple[str, ...] = (
    "identity_bootstrap_not_confirmed",
    "identity_bootstrap_issuer_mismatch",
    "identity_bootstrap_issuer_not_configured",
    "identity_bootstrap_subject_invalid",
    "identity_bootstrap_email_invalid",
    "identity_bootstrap_organization_invalid",
    "identity_bootstrap_already_completed",
)


class IdentityBootstrapRefused(Exception):
    """Refused. Carries ONE closed reason code and never a subject, email or issuer."""

    def __init__(self, reason: str) -> None:
        if reason not in BOOTSTRAP_REFUSAL_REASONS:
            raise ValueError(f"unknown identity bootstrap refusal reason: {reason!r}")
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class BootstrappedAdministrator:
    """What was provisioned. Carries no secret and no token — there is neither."""

    user_id: uuid.UUID
    organization_id: uuid.UUID
    role_name: str
    subject: str
    already_existed: bool


def bootstrap_initial_administrator(
    session: Session,
    *,
    issuer: str,
    subject: str,
    email: str,
    organization_name: str,
    organization_slug: str,
    trusted_issuer: str,
    confirmed: bool,
    actor: str = "operator",
) -> BootstrappedAdministrator:
    """Provision the first administrator, or refuse with a closed reason.

    ``trusted_issuer`` is passed in rather than read from settings so that the caller — the local
    operator command — is the one place that decides which configuration is authoritative, and so
    that this function can be exercised without a process-wide settings mutation. It is compared
    against ``issuer`` for exact equality after both are normalized identically; a mismatch is a
    refusal, never a warning.
    """
    if not confirmed:
        # Explicit confirmation is a separate act from supplying the arguments. An operator who
        # pasted a command from a runbook has supplied arguments; they have not yet decided.
        raise IdentityBootstrapRefused("identity_bootstrap_not_confirmed")

    expected = _normalized_issuer(trusted_issuer)
    if not expected:
        raise IdentityBootstrapRefused("identity_bootstrap_issuer_not_configured")
    if _normalized_issuer(issuer) != expected:
        raise IdentityBootstrapRefused("identity_bootstrap_issuer_mismatch")

    checked_subject = (subject or "").strip()
    if not checked_subject or len(checked_subject) > 255 or checked_subject != subject.strip():
        raise IdentityBootstrapRefused("identity_bootstrap_subject_invalid")

    checked_email = (email or "").strip()
    if not checked_email or "@" not in checked_email or len(checked_email) > 320:
        # The email is stored for operator legibility and for the per-organization uniqueness the
        # schema already requires. It is NEVER an identity input: nothing authenticates by it.
        raise IdentityBootstrapRefused("identity_bootstrap_email_invalid")

    checked_slug = (organization_slug or "").strip()
    checked_org_name = (organization_name or "").strip()
    if not checked_slug or not checked_org_name:
        raise IdentityBootstrapRefused("identity_bootstrap_organization_invalid")

    existing = (
        session.execute(select(User).where(User.subject.is_not(None)).order_by(User.created_at))
        .scalars()
        .all()
    )
    if existing:
        # Idempotent retry: the SAME subject returns what is already there. Anything else is a
        # second administrator, and that is the authenticated management path's job.
        for user in existing:
            if user.subject == checked_subject:
                return BootstrappedAdministrator(
                    user_id=user.id,
                    organization_id=user.organization_id,
                    role_name=INITIAL_ADMINISTRATOR_ROLE,
                    subject=checked_subject,
                    already_existed=True,
                )
        raise IdentityBootstrapRefused("identity_bootstrap_already_completed")

    organization = session.execute(
        select(Organization).where(Organization.slug == checked_slug)
    ).scalar_one_or_none()
    if organization is None:
        organization = Organization(name=checked_org_name, slug=checked_slug)
        session.add(organization)
        session.flush()

    role = session.execute(
        select(Role).where(Role.name == INITIAL_ADMINISTRATOR_ROLE)
    ).scalar_one_or_none()
    if role is None:
        role = Role(
            name=INITIAL_ADMINISTRATOR_ROLE,
            description="Initial production administrator provisioned by the identity bootstrap.",
            permissions=[p.value for p in Permission],
        )
        session.add(role)
        session.flush()

    user = User(
        organization_id=organization.id,
        email=checked_email,
        subject=checked_subject,
        display_name=checked_email,
    )
    session.add(user)
    session.flush()

    session.add(
        UserRoleAssignment(organization_id=organization.id, user_id=user.id, role_id=role.id)
    )
    session.flush()

    audit.record(
        session,
        action=AuditAction.user_created,
        resource_type="app_user",
        resource_id=user.id,
        actor=str(actor),
        organization_id=organization.id,
        outcome="success",
        data={
            "contract": IDENTITY_BOOTSTRAP_VERSION,
            "reason": "initial_administrator_bootstrap",
            "role": INITIAL_ADMINISTRATOR_ROLE,
            # The issuer and subject are the two facts an auditor needs to attribute the row, and
            # neither is a secret: the subject is an opaque IdP identifier and the issuer is public
            # deployment configuration. The email is deliberately NOT recorded — it plays no part in
            # authentication and putting a person's address in an append-only ledger is a choice
            # that should be made deliberately rather than inherited from a debug field.
            "issuer": expected,
            "subject": checked_subject,
        },
    )

    return BootstrappedAdministrator(
        user_id=user.id,
        organization_id=organization.id,
        role_name=INITIAL_ADMINISTRATOR_ROLE,
        subject=checked_subject,
        already_existed=False,
    )


def bootstrap_is_available(session: Session) -> bool:
    """Whether the one-shot bootstrap can still run. Read-only, and safe to expose to an operator.

    Deliberately not exposed as an unauthenticated HTTP route: "is this deployment still
    bootstrappable" is exactly the reconnaissance question an attacker asks first, and answering it
    to an unauthenticated caller converts a race into a schedule.
    """
    return (
        session.execute(select(User).where(User.subject.is_not(None)).limit(1)).scalar_one_or_none()
        is None
    )


def _normalized_issuer(value: str) -> str:
    """Exact-match normalization, and nothing more.

    Only a trailing slash is removed — that difference is a formatting artifact of how an issuer is
    written down, not a different issuer. Case is NOT folded and the host is NOT resolved: an
    issuer that differs in any other way is a different trust root, and treating it as the same one
    is precisely the confusion this comparison exists to prevent.
    """
    text = (value or "").strip()
    if not text:
        return ""
    parsed = urlsplit(text)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return text.rstrip("/")
