"""B1B-PR5A §4 — operation-specific credential separation (ADR-022).

The provider plan-read credential and the state-backend plan credential are TWO independent opaque
bindings. Changing one rotates ONLY its matching binding; the other is untouched. There is no single
binding shared across the two purposes, and the state credential has no generic fallback.
"""

from __future__ import annotations

from secp_api.credential_binding import active_credential_binding
from secp_api.enums import AuditAction, CredentialBindingStatus, CredentialPurposeClass
from secp_api.models import AuditEvent
from secp_api.services import targets

GOOD_CONFIG = {"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True}
PROVIDER_REF = "env:SECP_PROVIDER_SECRET__PROV_T1"
STATE_REF = "env:SECP_PROVIDER_SECRET__STATE_T1"


def _register(session, actor, **overrides):
    kwargs = dict(
        display_name="Lab Proxmox",
        plugin_name="proxmox",
        config=GOOD_CONFIG,
        secret_ref="env:SECP_PROVIDER_SECRET__GEN_T1",
        provider_plan_secret_ref=PROVIDER_REF,
        state_backend_secret_ref=STATE_REF,
        address_spaces=[{"cidr_block": "10.50.0.0/16", "subnet_prefix": 24}],
    )
    kwargs.update(overrides)
    return targets.register_target(session, actor, **kwargs)


def _active(session, target_id, purpose):
    return active_credential_binding(session, target_id, purpose)


def test_registration_creates_two_independent_active_bindings(session, principal):
    target = _register(session, principal)
    session.flush()
    provider = _active(session, target.id, CredentialPurposeClass.provider_plan_read)
    state = _active(session, target.id, CredentialPurposeClass.state_backend_plan)
    assert provider is not None and state is not None
    assert provider.id != state.id
    assert provider.purpose_class == CredentialPurposeClass.provider_plan_read
    assert state.purpose_class == CredentialPurposeClass.state_backend_plan
    assert provider.binding_version == 1 and state.binding_version == 1


def test_rotating_the_provider_ref_rotates_only_the_provider_binding(session, principal):
    target = _register(session, principal)
    session.flush()
    provider_v1 = _active(session, target.id, CredentialPurposeClass.provider_plan_read)
    state_v1 = _active(session, target.id, CredentialPurposeClass.state_backend_plan)

    targets.rotate_target_operation_credential(
        session,
        principal,
        target.id,
        purpose_class=CredentialPurposeClass.provider_plan_read,
        secret_ref="env:SECP_PROVIDER_SECRET__PROV_T1_ROTATED",
    )
    session.flush()

    provider_v2 = _active(session, target.id, CredentialPurposeClass.provider_plan_read)
    state_after = _active(session, target.id, CredentialPurposeClass.state_backend_plan)
    # Provider binding advanced; the old one is rotated (not active); state binding is UNTOUCHED.
    assert provider_v2.id != provider_v1.id
    assert provider_v2.binding_version == 2
    session.refresh(provider_v1)
    assert provider_v1.status == CredentialBindingStatus.rotated
    assert state_after.id == state_v1.id
    assert state_after.binding_version == 1
    assert state_after.status == CredentialBindingStatus.active

    ev = (
        session.query(AuditEvent)
        .filter(AuditEvent.action == AuditAction.target_credential_rotated.value)
        .first()
    )
    assert ev is not None
    assert "env:SECP_PROVIDER_SECRET__PROV_T1_ROTATED" not in str(ev.data)  # ref never echoed


def test_rotating_the_state_ref_rotates_only_the_state_binding(session, principal):
    target = _register(session, principal)
    session.flush()
    provider_v1 = _active(session, target.id, CredentialPurposeClass.provider_plan_read)

    targets.rotate_target_operation_credential(
        session,
        principal,
        target.id,
        purpose_class=CredentialPurposeClass.state_backend_plan,
        secret_ref="env:SECP_PROVIDER_SECRET__STATE_T1_ROTATED",
    )
    session.flush()

    state_v2 = _active(session, target.id, CredentialPurposeClass.state_backend_plan)
    provider_after = _active(session, target.id, CredentialPurposeClass.provider_plan_read)
    assert state_v2.binding_version == 2
    assert provider_after.id == provider_v1.id  # provider untouched
    assert provider_after.binding_version == 1


def test_state_credential_has_no_generic_fallback(session, principal):
    # A target with NO state_backend_secret_ref has NO state binding, even though it has a generic
    # secret_ref (which only feeds the provider purpose as a dev fallback).
    target = _register(session, principal, state_backend_secret_ref=None)
    session.flush()
    provider = _active(session, target.id, CredentialPurposeClass.provider_plan_read)
    state = _active(session, target.id, CredentialPurposeClass.state_backend_plan)
    assert provider is not None
    assert state is None


def test_provider_binding_falls_back_to_the_generic_secret_ref(session, principal):
    # With no dedicated provider ref, the provider binding is still created from the generic
    # secret_ref (dev-compat). The real-plan gate refuses this fallback separately.
    target = _register(session, principal, provider_plan_secret_ref=None)
    session.flush()
    provider = _active(session, target.id, CredentialPurposeClass.provider_plan_read)
    assert provider is not None and provider.binding_version == 1
