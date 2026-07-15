"""B1B-PR5A amendment §1 + §4 — the strict real-plan credential gate and closed revocation codes.

Amendment §1 draws a hard line between the two authoritative real-plan credential selections and the
dev/simulated ``secret_ref`` fallback:

* the provider plan-read and state-backend plan credentials are TWO distinct, DEDICATED selections,
  each with its own opaque versioned binding that rotates independently;
* the strict gate (:func:`real_plan_credential_bindings`) admits ONLY ``dedicated_operation``
  bindings sourced from distinct dedicated references — never the generic ``secret_ref`` fallback,
  and never one reference shared across both purposes; and
* a generic ``secret_ref`` change can never refresh a dedicated provider binding (a legacy
  reference cannot silently re-key a real-plan credential), while it DOES rotate a legacy binding.

Amendment §4 closes the ``revocation_reason_code`` domain: only a bounded set of codes may reach the
durable column, and any unrecognized value is coerced to the neutral ``operator`` default.
"""

from __future__ import annotations

import pytest
from secp_api.credential_binding import (
    RealPlanCredentialError,
    active_credential_binding,
    real_plan_credential_bindings,
)
from secp_api.enums import (
    CredentialBindingSource,
    CredentialPurposeClass,
    ReadinessErrorCode,
)
from secp_api.errors import ReadinessError
from secp_api.services import targets
from secp_api.services.plan_activation import (
    create_activation_dossier,
    get_plan_generation_readiness,
    revoke_activation_dossier,
)
from tests._readiness_fixtures import NOW, build_readiness_env  # type: ignore[import-not-found]

GOOD_CONFIG = {"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True}
PROVIDER_REF = "env:SECP_PROVIDER_SECRET__PROV"
STATE_REF = "env:SECP_PROVIDER_SECRET__STATE"

_PROVIDER = CredentialPurposeClass.provider_plan_read
_STATE = CredentialPurposeClass.state_backend_plan
_DEDICATED = CredentialBindingSource.dedicated_operation
_LEGACY = CredentialBindingSource.legacy_generic


def _register(session, actor, **overrides):
    """Register a target with BOTH dedicated operation references by default."""
    kwargs = dict(
        display_name="Lab Proxmox",
        plugin_name="proxmox",
        config=GOOD_CONFIG,
        secret_ref="env:SECP_PROVIDER_SECRET__GEN",
        provider_plan_secret_ref=PROVIDER_REF,
        state_backend_secret_ref=STATE_REF,
        address_spaces=[{"cidr_block": "10.50.0.0/16", "subnet_prefix": 24}],
    )
    kwargs.update(overrides)
    return targets.register_target(session, actor, **kwargs)


def _active(session, target_id, purpose):
    return active_credential_binding(session, target_id, purpose)


def _rotate(session, actor, target, purpose, ref):
    targets.rotate_target_operation_credential(
        session, actor, target.id, purpose_class=purpose, secret_ref=ref
    )


def _dedicated_env(session, principal, tmp_path):
    """The full authoritative chain plus BOTH dedicated, distinct operation credentials."""
    env = build_readiness_env(session, principal, toolchain_root=str(tmp_path))
    _rotate(session, principal, env.target, _PROVIDER, PROVIDER_REF)
    _rotate(session, principal, env.target, _STATE, STATE_REF)
    session.flush()
    return env


def _new_dossier(session, principal, manifest_id):
    return create_activation_dossier(
        session,
        principal,
        manifest_id=manifest_id,
        recovery_owner_proof="proof-recovery",
        emergency_stop_owner_proof="proof-estop",
    )


# --- amendment §1: registration binding source ---------------------------------------------------


def test_registration_binding_source_reflects_the_reference(session, principal):
    dedicated = _register(session, principal)
    session.flush()
    provider = _active(session, dedicated.id, _PROVIDER)
    state = _active(session, dedicated.id, _STATE)
    assert provider.binding_source == _DEDICATED
    assert state.binding_source == _DEDICATED

    legacy = _register(
        session,
        principal,
        display_name="Legacy Proxmox",
        provider_plan_secret_ref=None,
        state_backend_secret_ref=None,
    )
    session.flush()
    legacy_provider = _active(session, legacy.id, _PROVIDER)
    assert legacy_provider.binding_source == _LEGACY
    # No dedicated state reference => no state binding at all (never a generic fallback).
    assert _active(session, legacy.id, _STATE) is None


# --- amendment §1: the strict gate ---------------------------------------------------------------


def test_real_plan_credential_bindings_happy_path(session, principal):
    target = _register(session, principal)
    session.flush()
    provider, state = real_plan_credential_bindings(session, target)
    assert provider.purpose_class == _PROVIDER
    assert state.purpose_class == _STATE
    assert provider.binding_source == _DEDICATED
    assert state.binding_source == _DEDICATED
    assert provider.id != state.id


def test_generic_secret_ref_cannot_satisfy_the_real_plan_gate(session, principal, tmp_path):
    # The env registers with only a generic secret_ref: the provider binding is a legacy fallback
    # and there is no state binding, so both the strict resolver AND the dossier gate must refuse.
    env = build_readiness_env(session, principal, toolchain_root=str(tmp_path))
    with pytest.raises(RealPlanCredentialError):
        real_plan_credential_bindings(session, env.target)
    with pytest.raises(ReadinessError) as exc:
        _new_dossier(session, principal, env.manifest.id)
    assert exc.value.code == ReadinessErrorCode.binding_invalid.value


def test_provider_dedicated_but_state_absent_raises(session, principal):
    target = _register(session, principal, state_backend_secret_ref=None)
    session.flush()
    with pytest.raises(RealPlanCredentialError) as exc:
        real_plan_credential_bindings(session, target)
    assert "state" in exc.value.reason_code


def test_state_dedicated_but_provider_absent_raises(session, principal):
    target = _register(session, principal, provider_plan_secret_ref=None)
    session.flush()
    with pytest.raises(RealPlanCredentialError) as exc:
        real_plan_credential_bindings(session, target)
    assert "provider" in exc.value.reason_code


def test_a_reference_shared_across_purposes_is_refused(session, principal):
    shared = "env:SECP_PROVIDER_SECRET__SHARED"
    target = _register(
        session, principal, provider_plan_secret_ref=shared, state_backend_secret_ref=shared
    )
    session.flush()
    with pytest.raises(RealPlanCredentialError) as exc:
        real_plan_credential_bindings(session, target)
    assert "shared" in exc.value.reason_code


def test_a_legacy_sourced_binding_cannot_satisfy_the_gate(session, principal):
    # A target with only the generic secret_ref has a legacy_generic provider binding and no state
    # binding, so the strict gate refuses it (a legacy fallback is never a real-plan credential).
    target = _register(
        session, principal, provider_plan_secret_ref=None, state_backend_secret_ref=None
    )
    session.flush()
    provider = _active(session, target.id, _PROVIDER)
    assert provider.binding_source == _LEGACY
    with pytest.raises(RealPlanCredentialError):
        real_plan_credential_bindings(session, target)


# --- amendment §1: independent rotation ----------------------------------------------------------


def test_rotation_advances_only_the_rotated_purpose(session, principal):
    target = _register(session, principal)
    session.flush()
    provider_v1 = _active(session, target.id, _PROVIDER)
    state_v1 = _active(session, target.id, _STATE)

    _rotate(session, principal, target, _PROVIDER, "env:SECP_PROVIDER_SECRET__PROV_R2")
    session.flush()
    provider_v2 = _active(session, target.id, _PROVIDER)
    state_after = _active(session, target.id, _STATE)
    assert provider_v2.id != provider_v1.id
    assert provider_v2.binding_version == provider_v1.binding_version + 1
    # The state binding is UNTOUCHED by a provider rotation.
    assert state_after.id == state_v1.id
    assert state_after.binding_version == state_v1.binding_version

    _rotate(session, principal, target, _STATE, "env:SECP_PROVIDER_SECRET__STATE_R2")
    session.flush()
    state_v2 = _active(session, target.id, _STATE)
    provider_after = _active(session, target.id, _PROVIDER)
    assert state_v2.id != state_v1.id
    assert state_v2.binding_version == state_v1.binding_version + 1
    # The provider binding is UNTOUCHED by a state rotation.
    assert provider_after.id == provider_v2.id
    assert provider_after.binding_version == provider_v2.binding_version


def test_legacy_secret_ref_change_does_not_refresh_a_dedicated_provider_binding(session, principal):
    target = _register(session, principal)
    session.flush()
    provider_v1 = _active(session, target.id, _PROVIDER)
    assert provider_v1.binding_source == _DEDICATED

    # A change to the generic secret_ref while a dedicated provider reference is present cannot
    # re-key the real-plan (dedicated) binding: it is left exactly as it was.
    target.secret_ref = "env:SECP_PROVIDER_SECRET__OTHER"
    session.flush()
    provider_v2 = _active(session, target.id, _PROVIDER)
    assert provider_v2.id == provider_v1.id
    assert provider_v2.binding_version == provider_v1.binding_version
    assert provider_v2.binding_source == _DEDICATED


def test_secret_ref_change_rotates_a_purely_legacy_provider_binding(session, principal):
    target = _register(
        session, principal, provider_plan_secret_ref=None, state_backend_secret_ref=None
    )
    session.flush()
    provider_v1 = _active(session, target.id, _PROVIDER)
    assert provider_v1.binding_source == _LEGACY

    # With no dedicated provider reference, the generic secret_ref IS the source, so changing it
    # rotates the binding to the next version (still a legacy_generic source).
    target.secret_ref = "env:SECP_PROVIDER_SECRET__NEW"
    session.flush()
    provider_v2 = _active(session, target.id, _PROVIDER)
    assert provider_v2.id != provider_v1.id
    assert provider_v2.binding_version == provider_v1.binding_version + 1
    assert provider_v2.binding_source == _LEGACY


# --- readiness read-model ------------------------------------------------------------------------


def test_readiness_read_model_reports_not_ready_without_dedicated_credentials(
    session, principal, tmp_path
):
    # The env registers with only a generic secret_ref, so its target has no dedicated real-plan
    # credentials. The combined plan-generation read model can therefore never be ``ready``; it
    # resolves + executes nothing and returns a bounded, non-empty set of closed reason codes.
    #
    # NOTE: the strict-credential reason ``real_plan_credentials_not_dedicated`` lives behind the
    # dossier + full-readiness-world gates of the read model (it is evaluated only after an active
    # dossier and a re-derived readiness binding both resolve), so for a target with no dedicated
    # credentials the read model short-circuits earlier (``activation_dossier_missing``). The
    # dedicated-credential enforcement itself is proven directly against the strict resolver above.
    env = build_readiness_env(session, principal, toolchain_root=str(tmp_path))
    status = get_plan_generation_readiness(session, principal, env.manifest.id, now=NOW)
    assert status["ready"] is False
    assert status["reasons"]  # a bounded, non-empty set of closed reason codes


# --- amendment §4: closed revocation reason codes ------------------------------------------------


def test_revocation_reason_codes_are_closed(session, principal, tmp_path):
    env = _dedicated_env(session, principal, tmp_path)

    unknown = _new_dossier(session, principal, env.manifest.id)
    revoked = revoke_activation_dossier(
        session, principal, unknown.id, reason_code="not_a_real_code"
    )
    # An unrecognized code never reaches the durable column: it is coerced to the neutral default.
    assert revoked.revocation_reason_code == "operator"

    # A recognized closed code is persisted verbatim (the prior dossier is revoked, so the
    # manifest's active slot is free for a fresh draft).
    recognized = _new_dossier(session, principal, env.manifest.id)
    revoked_2 = revoke_activation_dossier(
        session, principal, recognized.id, reason_code="security_review"
    )
    assert revoked_2.revocation_reason_code == "security_review"
