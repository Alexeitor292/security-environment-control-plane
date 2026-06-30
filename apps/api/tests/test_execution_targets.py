"""Slice 2 + proofs #1, #9 — execution targets: no plaintext secrets, immutable
config, org scope."""

from __future__ import annotations

import pytest
from secp_api.enums import AuditAction, TargetStatus
from secp_api.errors import AuthorizationError, ImmutableResourceError, ValidationFailedError
from secp_api.models import AuditEvent, ExecutionTarget

GOOD_CONFIG = {"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": False}
GOOD_SECRET_REF = "env:SECP_PROVIDER_SECRET__TARGET_ONE"


def _register(session, actor, **overrides):
    from secp_api.services import targets

    kwargs = dict(
        display_name="Lab Proxmox (dev placeholder)",
        plugin_name="proxmox",
        config=GOOD_CONFIG,
        secret_ref=GOOD_SECRET_REF,
        address_spaces=[{"cidr_block": "10.50.0.0/16", "subnet_prefix": 24}],
    )
    kwargs.update(overrides)
    return targets.register_target(session, actor, **kwargs)


def test_register_target_ok(session, principal):
    target = _register(session, principal)
    session.commit()
    assert target.config_hash.startswith("sha256:")
    assert target.secret_ref == GOOD_SECRET_REF  # a reference, not a secret
    assert target.status == TargetStatus.active
    # audit recorded without secret material
    ev = (
        session.query(AuditEvent)
        .filter(AuditEvent.action == AuditAction.target_created.value)
        .first()
    )
    assert ev is not None
    assert "secret" not in str(ev.data).lower() or ev.data.get("has_secret_ref") is True
    assert GOOD_SECRET_REF not in str(ev.data)  # the ref is not echoed as a value


def test_register_rejects_plaintext_secret_key(session, principal):
    bad = dict(GOOD_CONFIG, password="hunter2")
    with pytest.raises(ValidationFailedError):
        _register(session, principal, config=bad)


def test_register_rejects_nested_plaintext_secret(session, principal):
    bad = dict(GOOD_CONFIG, auth={"api_token": "PVEAPIToken=root@pam!x=abc"})
    with pytest.raises(ValidationFailedError):
        _register(session, principal, config=bad)


def test_register_rejects_plaintext_secret_ref(session, principal):
    with pytest.raises(ValidationFailedError):
        _register(session, principal, secret_ref="PVEAPIToken=root@pam!x=raw-secret")


def test_register_rejects_unsafe_env_ref(session, principal):
    with pytest.raises(ValidationFailedError):
        _register(session, principal, secret_ref="env:HOME")  # not namespaced


def test_target_config_is_immutable(session, principal):
    target = _register(session, principal)
    session.commit()
    target.config = {**target.config, "tampered": True}
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_no_plaintext_secret_persisted_in_db(session, principal):
    _register(session, principal)
    session.commit()
    # Scan every execution_target row's stored config for secret-like content.
    for t in session.query(ExecutionTarget).all():
        blob = str(t.config).lower()
        for needle in ("password", "token", "secret", "private_key"):
            assert needle not in blob


def test_cross_org_target_access_denied(session, principal, other_org_principal):
    from secp_api.services import targets

    target = _register(session, principal)
    session.commit()
    with pytest.raises(AuthorizationError):
        targets.get_target(session, other_org_principal, target.id)


def test_disable_target(session, principal):
    from secp_api.services import targets

    target = _register(session, principal)
    targets.disable_target(session, principal, target.id)
    session.commit()
    assert target.status == TargetStatus.disabled
