"""The first production administrator, and the seven ways provisioning one is refused.

``SI-001`` said: in production no authenticated API call is possible through any supported path,
because the only way to create the first subject-bound user was a direct database write. These
tests are what makes the supported path real — and, more importantly, what stops it becoming a
permanent unauthenticated route to administrator.
"""

from __future__ import annotations

import pytest
from secp_api.enums import AuditAction, Permission
from secp_api.identity_bootstrap import (
    BOOTSTRAP_REFUSAL_REASONS,
    INITIAL_ADMINISTRATOR_ROLE,
    BootstrappedAdministrator,
    IdentityBootstrapRefused,
    bootstrap_initial_administrator,
    bootstrap_is_available,
)
from secp_api.models import AuditEvent, Organization, Role, User, UserRoleAssignment
from sqlalchemy import select

ISSUER = "https://idp.example.test/realms/secp"
SUBJECT = "a3f1c9d2-0000-4000-8000-1234567890ab"
EMAIL = "operator@example.test"


def _bootstrap(session, **overrides):
    kwargs = dict(
        issuer=ISSUER,
        subject=SUBJECT,
        email=EMAIL,
        organization_name="Production",
        organization_slug="production",
        trusted_issuer=ISSUER,
        confirmed=True,
    )
    kwargs.update(overrides)
    return bootstrap_initial_administrator(session, **kwargs)


@pytest.fixture
def empty(session):
    """A database with no subject-bound user. The conftest seeds a dev admin, so remove it —
    otherwise every test here would exercise the already-completed path."""
    for assignment in session.execute(select(UserRoleAssignment)).scalars().all():
        session.delete(assignment)
    for user in session.execute(select(User)).scalars().all():
        session.delete(user)
    session.flush()
    return session


# === it provisions exactly one administrator =====================================================


def test_it_provisions_an_administrator_who_can_actually_authenticate(empty):
    result = _bootstrap(empty)
    assert isinstance(result, BootstrappedAdministrator)
    assert result.already_existed is False

    user = empty.get(User, result.user_id)
    # The subject is what `verify_oidc_claims` looks up, EXACTLY as supplied.
    assert user.subject == SUBJECT
    assert user.email == EMAIL

    role = empty.execute(select(Role).where(Role.name == INITIAL_ADMINISTRATOR_ROLE)).scalar_one()
    assignment = empty.execute(
        select(UserRoleAssignment).where(UserRoleAssignment.user_id == user.id)
    ).scalar_one()
    assert assignment.role_id == role.id
    assert set(role.permissions) == {p.value for p in Permission}


def test_the_organization_is_created_or_reused_by_slug(empty):
    existing = Organization(name="Already Here", slug="production")
    empty.add(existing)
    empty.flush()
    result = _bootstrap(empty)
    assert result.organization_id == existing.id
    assert (
        len(
            empty.execute(select(Organization).where(Organization.slug == "production"))
            .scalars()
            .all()
        )
        == 1
    )


def test_the_bootstrap_is_audited_and_records_no_email(empty):
    result = _bootstrap(empty)
    # The sessionmaker is autoflush=False (db.py:81), so an event the service `add`ed is not
    # visible to a query until something flushes. The service is right not to flush it — the audit
    # row belongs to the caller's transaction — but a test that forgot this would silently find
    # nothing and read as "no audit event was recorded".
    empty.flush()
    event = (
        empty.execute(select(AuditEvent).where(AuditEvent.resource_id == str(result.user_id)))
        .scalars()
        .one()
    )
    assert event.action == AuditAction.user_created
    assert event.data["reason"] == "initial_administrator_bootstrap"
    assert event.data["issuer"] == ISSUER
    assert event.data["subject"] == SUBJECT
    # The email plays no part in authentication; putting a person's address into an append-only
    # ledger should be a deliberate decision, not an inherited debug field.
    assert EMAIL not in str(event.data)


# === it is one-shot ==============================================================================


def test_availability_flips_after_the_first_administrator(empty):
    assert bootstrap_is_available(empty) is True
    _bootstrap(empty)
    assert bootstrap_is_available(empty) is False


def test_a_second_DIFFERENT_subject_is_refused(empty):
    """A bootstrap that stays open is a permanent unauthenticated path to administrator."""
    _bootstrap(empty)
    with pytest.raises(IdentityBootstrapRefused) as exc:
        _bootstrap(empty, subject="b7c2e4f6-1111-4000-8000-0987654321ba")
    assert exc.value.reason == "identity_bootstrap_already_completed"


def test_the_SAME_subject_is_idempotent(empty):
    """A retried install must not fail an operator who cannot tell whether the first attempt
    committed."""
    first = _bootstrap(empty)
    second = _bootstrap(empty)
    assert second.user_id == first.user_id
    assert second.already_existed is True
    assert len(empty.execute(select(User).where(User.subject.is_not(None))).scalars().all()) == 1


def test_an_administrator_in_ANOTHER_organization_still_closes_the_bootstrap(empty):
    """Deliberately not scoped per-organization: an attacker able to create an organization could
    otherwise bootstrap into it beside a legitimate administrator."""
    _bootstrap(empty)
    with pytest.raises(IdentityBootstrapRefused, match="already_completed"):
        _bootstrap(
            empty,
            subject="c9d1e2f3-2222-4000-8000-abcdefabcdef",
            organization_slug="another",
            organization_name="Another",
            email="other@example.test",
        )


def test_a_user_with_no_subject_neither_satisfies_nor_blocks_the_bootstrap(empty):
    """NULL-subject rows cannot authenticate, so a deployment carrying placeholder rows is still
    bootstrappable."""
    org = Organization(name="Placeholder", slug="placeholder")
    empty.add(org)
    empty.flush()
    empty.add(
        User(organization_id=org.id, email="nobody@example.test", display_name="n", subject=None)
    )
    empty.flush()

    assert bootstrap_is_available(empty) is True
    assert _bootstrap(empty).already_existed is False


# === it refuses, seven ways ======================================================================


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"confirmed": False}, "identity_bootstrap_not_confirmed"),
        (
            {"issuer": "https://attacker.example.test/realms/secp"},
            "identity_bootstrap_issuer_mismatch",
        ),
        ({"issuer": "https://idp.example.test/realms/OTHER"}, "identity_bootstrap_issuer_mismatch"),
        # Case is NOT folded: a differently-cased issuer is a different trust root.
        ({"issuer": "https://IDP.example.test/realms/secp"}, "identity_bootstrap_issuer_mismatch"),
        ({"trusted_issuer": ""}, "identity_bootstrap_issuer_not_configured"),
        ({"trusted_issuer": "not-a-url"}, "identity_bootstrap_issuer_not_configured"),
        ({"subject": ""}, "identity_bootstrap_subject_invalid"),
        ({"subject": "   "}, "identity_bootstrap_subject_invalid"),
        ({"subject": "x" * 256}, "identity_bootstrap_subject_invalid"),
        ({"email": ""}, "identity_bootstrap_email_invalid"),
        ({"email": "not-an-email"}, "identity_bootstrap_email_invalid"),
        ({"organization_slug": ""}, "identity_bootstrap_organization_invalid"),
        ({"organization_name": "  "}, "identity_bootstrap_organization_invalid"),
    ],
)
def test_each_bad_input_refuses_with_its_own_reason(empty, overrides, reason):
    with pytest.raises(IdentityBootstrapRefused) as exc:
        _bootstrap(empty, **overrides)
    assert exc.value.reason == reason
    # And nothing was created.
    assert empty.execute(select(User).where(User.subject.is_not(None))).scalars().all() == []


def test_a_trailing_slash_is_the_only_issuer_difference_tolerated(empty):
    """That difference is a formatting artifact of how an issuer is written down. Anything else is
    a different trust root."""
    result = _bootstrap(empty, issuer=ISSUER + "/", trusted_issuer=ISSUER)
    assert result.already_existed is False


def test_confirmation_is_a_separate_act_from_supplying_arguments(empty):
    """An operator who pasted a command from a runbook has supplied arguments; they have not yet
    decided."""
    with pytest.raises(IdentityBootstrapRefused, match="not_confirmed"):
        _bootstrap(empty, confirmed=False)
    assert bootstrap_is_available(empty) is True


def test_every_refusal_reason_is_in_the_closed_set():
    with pytest.raises(ValueError, match="unknown identity bootstrap refusal reason"):
        IdentityBootstrapRefused("something_new")
    assert len(BOOTSTRAP_REFUSAL_REASONS) == len(set(BOOTSTRAP_REFUSAL_REASONS))
    for reason in BOOTSTRAP_REFUSAL_REASONS:
        assert reason.startswith("identity_bootstrap_"), reason


def test_a_refusal_carries_no_subject_issuer_or_email(empty):
    with pytest.raises(IdentityBootstrapRefused) as exc:
        _bootstrap(empty, issuer="https://attacker.example.test/realms/secp")
    text = str(exc.value)
    assert text == "identity_bootstrap_issuer_mismatch"
    for leaked in (SUBJECT, EMAIL, "attacker.example.test"):
        assert leaked not in text


# === it changes nothing about how authentication works ===========================================


def test_it_takes_no_token_no_claims_and_no_role_input():
    """The module creates the row verification requires. It must not participate in verification,
    and it must not let a caller choose the granted role."""
    import inspect

    params = set(inspect.signature(bootstrap_initial_administrator).parameters)
    assert params == {
        "session",
        "issuer",
        "subject",
        "email",
        "organization_name",
        "organization_slug",
        "trusted_issuer",
        "confirmed",
        "actor",
    }
    for banned in ("token", "claims", "id_token", "access_token", "role", "roles", "permissions"):
        assert banned not in params, banned


def test_the_module_cannot_reach_the_oidc_verifier_or_a_network():
    """Structural: a bootstrap that could verify a token would be a second authentication path."""
    import ast
    import pathlib

    source = (
        pathlib.Path(__file__).resolve().parents[1] / "secp_api" / "identity_bootstrap.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    for banned in (
        "httpx",
        "requests",
        "jwt",
        "secp_api.oidc",
        "secp_api.auth",
        "os",
        "subprocess",
    ):
        assert banned not in imported, banned


def test_availability_is_not_an_unauthenticated_route():
    """ "Is this deployment still bootstrappable" is the first reconnaissance question an attacker
    asks; answering it to an unauthenticated caller turns a race into a schedule."""
    import pathlib

    routers = pathlib.Path(__file__).resolve().parents[1] / "secp_api" / "routers"
    for path in routers.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "bootstrap_is_available" not in text, path.name
        assert "bootstrap_initial_administrator" not in text, path.name
