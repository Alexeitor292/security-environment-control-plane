"""Hardening §2 — development authentication safety.

Production cannot enable the dev auth fallback or silently bootstrap an admin, and
the fallback principal requires both a non-production env and explicit dev-auth.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from secp_api.auth import Principal
from secp_api.config import Settings
from secp_api.enums import Permission
from secp_api.errors import AuthenticationError, AuthorizationError


def test_production_with_dev_auth_mode_is_rejected():
    with pytest.raises(ValidationError):
        # default auth_dev_mode=True is unsafe in production
        Settings(app_env="production", workflow_dispatch_mode="temporal")


def test_production_with_inline_dispatch_is_rejected():
    with pytest.raises(ValidationError):
        Settings(app_env="production", auth_dev_mode=False, workflow_dispatch_mode="inline")


def test_valid_production_config_disables_dev_auth():
    settings = Settings(
        app_env="production", auth_dev_mode=False, workflow_dispatch_mode="temporal"
    )
    assert settings.dev_auth_enabled is False
    assert settings.is_production is True


def test_dev_auth_requires_both_dev_env_and_explicit_mode():
    # dev env but dev-auth explicitly off -> fallback unavailable
    assert Settings(app_env="dev", auth_dev_mode=False).dev_auth_enabled is False
    # dev env + dev-auth on -> available
    assert Settings(app_env="dev", auth_dev_mode=True).dev_auth_enabled is True
    # test env behaves like dev for the fallback
    assert Settings(app_env="test", auth_dev_mode=True).dev_auth_enabled is True


def test_current_principal_refused_when_dev_auth_disabled(session, principal):
    from secp_api.deps import current_principal

    settings = Settings(app_env="dev", auth_dev_mode=False)  # fallback disabled
    with pytest.raises(AuthenticationError):
        current_principal(session=session, settings=settings, authorization=None)


def test_bearer_token_explicitly_rejected_with_oidc_not_implemented_error(session):
    """Any bearer token is explicitly refused with a clear SECP-001 placeholder message.

    OIDC token verification is not implemented in SECP-001; a caller sending a
    token must receive an unambiguous error — not a silent fallback and not a
    generic authentication failure that might imply the token was inspected.
    """
    from secp_api.deps import current_principal

    settings = Settings(app_env="dev", auth_dev_mode=False)
    with pytest.raises(AuthenticationError) as exc_info:
        current_principal(
            session=session,
            settings=settings,
            authorization="Bearer eyJhbGciOiJSUzI1NiJ9.fake.token",
        )
    message = str(exc_info.value)
    assert "not implemented" in message.lower()
    assert "SECP-001" in message


def test_bearer_token_rejected_even_when_dev_auth_enabled(session):
    """A bearer token is rejected EVEN when dev_auth_mode=True.

    The Authorization header check runs BEFORE the dev fallback, so a token is
    never silently dropped in favour of the dev admin principal.  This prevents
    callers from being misled into thinking their token was validated.
    """
    from secp_api.deps import current_principal

    # dev mode enabled — would normally return the dev principal for unauthenticated
    # requests, but a presented token must still be refused explicitly.
    settings = Settings(app_env="dev", auth_dev_mode=True, workflow_dispatch_mode="inline")
    with pytest.raises(AuthenticationError) as exc_info:
        current_principal(
            session=session,
            settings=settings,
            authorization="Bearer eyJhbGciOiJSUzI1NiJ9.fake.token",
        )
    message = str(exc_info.value)
    assert "not implemented" in message.lower()
    assert "SECP-001" in message


def test_bearer_token_rejected_even_when_dev_auth_disabled_no_production_fallback(session):
    """Production-like settings (dev_auth disabled) also reject bearer tokens."""
    from secp_api.deps import current_principal

    settings = Settings(app_env="dev", auth_dev_mode=False)
    with pytest.raises(AuthenticationError) as exc_info:
        current_principal(
            session=session,
            settings=settings,
            authorization="Bearer some.opaque.token",
        )
    assert "SECP-001" in str(exc_info.value)


def test_no_credential_defaults_in_settings_source():
    # No Settings field is a password/secret with a non-empty default, and the
    # default database URL embeds no credentials.
    for field_name, field in Settings.model_fields.items():
        lowered = field_name.lower()
        if "password" in lowered or "secret" in lowered:
            assert not field.default, f"settings field {field_name} has a default secret"
    # Check the SOURCE-declared default (not a runtime instance, which may read a
    # developer's local .env): the default database URL embeds no credentials.
    assert str(Settings.model_fields["database_url"].default).startswith("sqlite")


# --- authorization coverage: cross-org + role-gated destroy -------------------


def test_role_gated_destroy_denied_without_permission(session, principal, running_exercise):
    from secp_api.services import exercises

    exercise = running_exercise()
    weak = Principal(
        user_id=principal.user_id,
        organization_id=principal.organization_id,
        email=principal.email,
        permissions=frozenset({Permission.exercise_operate}),  # no exercise:destroy
    )
    with pytest.raises(AuthorizationError):
        exercises.destroy_exercise(session, weak, exercise.id)


def test_role_gated_reset_denied_without_permission(session, principal, running_exercise):
    from secp_api.models import EnvironmentInstance
    from secp_api.services import exercises

    exercise = running_exercise()
    instance = (
        session.query(EnvironmentInstance)
        .filter(EnvironmentInstance.exercise_id == exercise.id)
        .first()
    )
    weak = Principal(
        user_id=principal.user_id,
        organization_id=principal.organization_id,
        email=principal.email,
        permissions=frozenset({Permission.exercise_operate}),  # no exercise:reset
    )
    with pytest.raises(AuthorizationError):
        exercises.reset_instance(session, weak, exercise.id, instance.id)


def test_cross_org_exercise_access_denied(
    session, principal, other_org_principal, running_exercise
):
    from secp_api.services import exercises

    exercise = running_exercise()
    with pytest.raises(AuthorizationError):
        exercises.get_exercise(session, other_org_principal, exercise.id)
