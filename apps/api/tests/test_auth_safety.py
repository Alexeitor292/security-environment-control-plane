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
        app_env="production",
        auth_dev_mode=False,
        workflow_dispatch_mode="temporal",
        # Production also requires a safe OIDC issuer/audience (ADR-017).
        oidc_issuer="https://idp.example.test/realms/secp",
        oidc_audience="secp-api",
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


def _verifier():
    # A seam-injected verifier (no network); the tokens below fail before any discovery/JWKS fetch.
    from tests.oidc_helpers import FakeIdp, build_verifier  # type: ignore

    return build_verifier(FakeIdp())


def test_current_principal_refused_when_dev_auth_disabled(session, principal):
    from secp_api.deps import resolve_principal

    settings = Settings(app_env="dev", auth_dev_mode=False)  # fallback disabled
    with pytest.raises(AuthenticationError):
        resolve_principal(
            session=session, settings=settings, verifier=_verifier(), authorization=None
        )


def test_invalid_bearer_is_verified_and_refused_not_placeholder(session):
    """A bearer token is now cryptographically verified (ADR-017): a malformed/unverifiable token is
    refused with a closed AuthenticationError — NOT the old 'not implemented' SECP-001 placeholder,
    and never a silent fallback."""
    from secp_api.deps import resolve_principal

    settings = Settings(app_env="dev", auth_dev_mode=False)
    with pytest.raises(AuthenticationError) as exc_info:
        resolve_principal(
            session=session,
            settings=settings,
            verifier=_verifier(),
            authorization="Bearer not.a.valid.jwt",
        )
    message = str(exc_info.value).lower()
    assert "not implemented" not in message
    assert "secp-001" not in message


def test_invalid_bearer_never_falls_back_even_when_dev_auth_enabled(session):
    """The Authorization header is evaluated BEFORE the dev fallback: an invalid token never yields
    the dev principal, even with dev auth enabled."""
    from secp_api.deps import resolve_principal

    settings = Settings(app_env="dev", auth_dev_mode=True, workflow_dispatch_mode="inline")
    with pytest.raises(AuthenticationError):
        resolve_principal(
            session=session,
            settings=settings,
            verifier=_verifier(),
            authorization="Bearer eyJhbGciOiJSUzI1NiJ9.fake.token",
        )


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


# --- ADR-017: OIDC production validation + bounded verifier settings ----------

_VALID_PROD = dict(
    app_env="production",
    auth_dev_mode=False,
    workflow_dispatch_mode="temporal",
    oidc_issuer="https://idp.example.test/realms/secp",
    oidc_audience="secp-api",
)


def test_valid_production_oidc_config_is_accepted():
    settings = Settings(**_VALID_PROD)
    assert settings.is_production is True
    assert settings.dev_auth_enabled is False


@pytest.mark.parametrize(
    "override",
    [
        {"oidc_issuer": ""},  # empty issuer
        {"oidc_issuer": "http://idp.example.test/realms/secp"},  # non-HTTPS
        {"oidc_issuer": "https://user:pass@idp.example.test/realms/secp"},  # credentials
        {"oidc_issuer": "https://idp.example.test/realms/secp?x=1"},  # query
        {"oidc_issuer": "https://idp.example.test/realms/secp#frag"},  # fragment
        {"oidc_audience": ""},  # empty audience
    ],
)
def test_production_rejects_unsafe_issuer_or_audience(override):
    with pytest.raises(ValidationError):
        Settings(**{**_VALID_PROD, **override})


def test_non_production_allows_http_issuer():
    # The dev Keycloak service is HTTP; non-production may use it.
    settings = Settings(app_env="dev", oidc_issuer="http://keycloak:8080/realms/secp")
    assert settings.oidc_issuer.startswith("http://")


@pytest.mark.parametrize(
    "override",
    [
        {"oidc_http_timeout_seconds": 0},  # not > 0
        {"oidc_http_timeout_seconds": 999},  # excessive
        {"oidc_clock_skew_seconds": -1},  # negative
        {"oidc_clock_skew_seconds": 100000},  # excessive
        {"oidc_discovery_cache_seconds": -5},  # negative
        {"oidc_jwks_cache_seconds": 10**9},  # excessive
        {"oidc_max_token_bytes": 10},  # below floor
        {"oidc_max_token_bytes": 10**9},  # above ceiling
        {"oidc_max_document_bytes": 100},  # below floor
        {"oidc_max_document_bytes": 10**9},  # above ceiling
    ],
)
def test_bounded_oidc_numeric_settings_are_validated_in_every_env(override):
    with pytest.raises(ValidationError):
        Settings(app_env="dev", **override)


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
