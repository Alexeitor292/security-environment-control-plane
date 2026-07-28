"""Closed controller-enrollment finalization plan + sealed adapter (SECP-PR5H-B2, commit 2b-3a).

Proves the shipped default fails closed on every op (no false success), an empty receipt proves no
effect, the typed value objects are frozen + carry no secret, and the engine's default EngineDeps
wires the SEALED finalization adapter (so a bare engine refuses finalization).
"""

from __future__ import annotations

import dataclasses

import pytest
from secp_management import ManagementError
from secp_management.adapters import CompensationResult, ReviewedUnit
from secp_management.engine import EngineDeps
from secp_management.finalization import (
    ControllerEnrollmentFinalizationPlan,
    ControllerFinalizationReceipt,
    ControllerIdentityActivation,
    EnrollmentKeyIdentity,
    ReviewedApiSigner,
    ReviewedSignerRole,
    SealedControllerEnrollmentFinalizationAdapter,
)

_SEALED = "controller_finalization_adapter_not_provisioned"
_ROLE = ReviewedSignerRole(role_name="secp_enrollment_signer", credential_source_path="/etc/secp/x")
_API = ReviewedApiSigner(enablement_path="/etc/secp/controller/enrollment-signer.enabled")
_UNIT = ReviewedUnit(identity="sha256:" + "0" * 64, content=b"[Unit]\n")
_ACTIVATION = ControllerIdentityActivation(
    controller_installation_id="controller-abc12345",
    controller_key_id="sha256:" + "1" * 64,
    controller_trust_anchor_hex="1" * 64,
    controller_origin="https://c.example",
    release_digest="sha256:" + "2" * 64,
    management_identity_digest="sha256:" + "3" * 64,
    bootstrap_evidence_digest="sha256:" + "4" * 64,
    enrollment_key_proof_id="enrkp:" + "5" * 64,
)


def test_every_sealed_op_fails_closed():
    a = SealedControllerEnrollmentFinalizationAdapter()
    calls = [
        lambda: a.install_tls_material(
            policy=None, canonical_origin="https://c.example", tls_mode="generated_local_ca"
        ),
        lambda: a.record_locator(canonical_origin="https://c.example"),
        lambda: a.provision_signer_role(_ROLE),
        lambda: a.prepare_enrollment_key(),
        lambda: a.install_broker_unit(_UNIT),
        lambda: a.enable_api_signer(_API),
        lambda: a.activate_controller_identity(_ACTIVATION),
    ]
    for call in calls:
        with pytest.raises(ManagementError) as e:
            call()
        assert e.value.reason_code == _SEALED


def test_empty_receipt_proves_no_effect_and_compensation_is_proven():
    a = SealedControllerEnrollmentFinalizationAdapter()
    receipt = a.receipt()
    assert receipt == ControllerFinalizationReceipt()
    assert all(
        getattr(receipt, f.name) == () for f in dataclasses.fields(ControllerFinalizationReceipt)
    )
    result = a.compensate(receipt)
    assert result == CompensationResult(proven=True)


def test_typed_objects_are_frozen():
    key = EnrollmentKeyIdentity(
        controller_key_id="sha256:" + "1" * 64,
        controller_trust_anchor_hex="1" * 64,
        enrollment_key_proof_id="enrkp:" + "5" * 64,
    )
    for obj in (key, _ROLE, _API, _ACTIVATION):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(obj, "controller_key_id", "x")  # noqa: B010 - frozen-check needs setattr


def test_plan_carries_no_secret_field():
    # every plan field name is a non-secret descriptor (policy/origin/mode/paths/digests) — a plan
    # must never carry a private key, password, or verifier.
    names = {f.name for f in dataclasses.fields(ControllerEnrollmentFinalizationPlan)}
    for forbidden in ("password", "secret", "verifier", "private", "key_pem", "plaintext"):
        assert not any(forbidden in n for n in names), forbidden


def test_default_engine_deps_wires_the_sealed_finalization_adapter():
    deps = EngineDeps()
    assert isinstance(deps.finalization_adapter, SealedControllerEnrollmentFinalizationAdapter)
    with pytest.raises(ManagementError) as e:
        deps.finalization_adapter.prepare_enrollment_key()
    assert e.value.reason_code == _SEALED
