"""The bound, versioned, immutable runtime-provisioning attestation (SECP-PR5D Round 4, blocker #3).

A bare ``provisioned=True`` is not constructible; a caller-fabricated, cross-deployment, stale, or
non-reviewed attestation cannot contribute to readiness; and validation calls no runtime method.
"""

from __future__ import annotations

import dataclasses
import uuid

import pytest
from _deploy_support import (
    SOURCE_SHA,
    SOURCE_TREE_SHA,
    runtime_attestation,
    valid_expected,
    valid_profile,
)
from secp_operator_deployment.runtime_seams import (
    RuntimeProvisioningAttestation,
    attest_runtime,
    deployment_profile_digest,
    expected_identities_digest,
    issue_runtime_attestation,
    validate_runtime_attestation,
)

_TEST_PROVIDER = "secp-test/reviewed-runtime-provider/v1"


def _review(monkeypatch):
    import secp_operator_deployment.runtime_seams as rs

    monkeypatch.setattr(rs, "REVIEWED_RUNTIME_PROVIDERS", frozenset({_TEST_PROVIDER}))


def _valid_attestation(*, profile=None, expected=None, provider_id=_TEST_PROVIDER, **over):
    profile = profile if profile is not None else valid_profile()
    expected = expected if expected is not None else valid_expected()
    kwargs = dict(
        runtime_provider_implementation_id=provider_id,
        deployment_profile_digest=deployment_profile_digest(profile),
        expected_identities_digest=expected_identities_digest(expected),
        release_source_sha=SOURCE_SHA,
        source_tree_sha=SOURCE_TREE_SHA,
        deployment_activation_dossier_hash="sha256:" + "a" * 64,
        worker_identity_registration_id=str(uuid.UUID(int=1)),
        toolchain_layout_identity="secp/toolchain-layout/v1",
        provisioned=True,
    )
    kwargs.update(over)
    return issue_runtime_attestation(**kwargs)


def test_bool_only_self_attestation_is_impossible():
    # The bound attestation has many required fields; the bool-only form cannot be constructed.
    with pytest.raises(TypeError):
        RuntimeProvisioningAttestation(provisioned=True)  # type: ignore[call-arg]


def test_unprovisioned_default_is_not_ready():
    att = runtime_attestation()  # sealed stub → UNPROVISIONED bound attestation
    ok, reason = validate_runtime_attestation(
        att, profile=valid_profile(), expected=valid_expected()
    )
    assert ok is False and reason == "attestation_not_provisioned"


def test_valid_reviewed_attestation_validates(monkeypatch):
    _review(monkeypatch)
    att = _valid_attestation()
    ok, reason = validate_runtime_attestation(
        att, profile=valid_profile(), expected=valid_expected()
    )
    assert ok is True and reason is None


def test_provider_not_reviewed_refuses():
    # Even a perfectly-formed provisioned attestation refuses in PR5D: the reviewed set is empty.
    att = _valid_attestation()
    ok, reason = validate_runtime_attestation(
        att, profile=valid_profile(), expected=valid_expected()
    )
    assert ok is False and reason == "attestation_provider_not_reviewed"


def test_attestation_from_another_profile_refuses(monkeypatch):
    _review(monkeypatch)
    att = _valid_attestation(profile=valid_profile())
    other = valid_profile(operator_image_digest="sha256:" + "9" * 64)
    ok, reason = validate_runtime_attestation(att, profile=other, expected=valid_expected())
    assert ok is False and reason == "attestation_profile_binding_invalid"


def test_attestation_from_another_expected_refuses(monkeypatch):
    _review(monkeypatch)
    att = _valid_attestation(expected=valid_expected())
    other = valid_expected(operator_image_digest="sha256:" + "9" * 64)
    ok, reason = validate_runtime_attestation(att, profile=valid_profile(), expected=other)
    assert ok is False and reason == "attestation_expected_binding_invalid"


def test_stale_provider_digest_refuses(monkeypatch):
    _review(monkeypatch)
    att = _valid_attestation()
    tampered = dataclasses.replace(att, runtime_provider_implementation_digest="sha256:" + "0" * 64)
    ok, reason = validate_runtime_attestation(
        tampered, profile=valid_profile(), expected=valid_expected()
    )
    assert ok is False and reason == "attestation_provider_digest_invalid"


def test_wrong_dossier_binding_refuses(monkeypatch):
    _review(monkeypatch)
    att = _valid_attestation()
    tampered = dataclasses.replace(att, deployment_activation_dossier_hash="sha256:" + "0" * 64)
    ok, reason = validate_runtime_attestation(
        tampered, profile=valid_profile(), expected=valid_expected()
    )
    assert ok is False and reason == "attestation_hash_invalid"


def test_wrong_worker_binding_refuses(monkeypatch):
    _review(monkeypatch)
    att = _valid_attestation()
    tampered = dataclasses.replace(att, worker_identity_registration_id="other")
    ok, reason = validate_runtime_attestation(
        tampered, profile=valid_profile(), expected=valid_expected()
    )
    assert ok is False and reason == "attestation_hash_invalid"


def test_wrong_contract_version_refuses(monkeypatch):
    _review(monkeypatch)
    att = _valid_attestation()
    tampered = dataclasses.replace(att, attestation_contract_version="other/v9")
    ok, reason = validate_runtime_attestation(
        tampered, profile=valid_profile(), expected=valid_expected()
    )
    assert ok is False and reason == "attestation_contract_version_invalid"


def test_foreign_subclass_attestation_refuses(monkeypatch):
    _review(monkeypatch)
    att = _valid_attestation()

    class _Sub(RuntimeProvisioningAttestation):
        pass

    sub = _Sub(**dataclasses.asdict(att))
    ok, reason = validate_runtime_attestation(
        sub, profile=valid_profile(), expected=valid_expected()
    )
    assert ok is False and reason == "attestation_type_invalid"


def test_duck_typed_attestation_refuses():
    class _Duck:
        provisioned = True
        attestation_contract_version = "secp-pr5d/runtime-provisioning-attestation/v1"

    ok, reason = validate_runtime_attestation(
        _Duck(), profile=valid_profile(), expected=valid_expected()
    )
    assert ok is False and reason == "attestation_type_invalid"


def test_attest_runtime_calls_no_seams_and_yields_unprovisioned():
    # attest_runtime is the issuance step; a hostile runtime whose
    # provisioned()/plan_execution_seams() explode proves attest_runtime touches NEITHER — it only
    # asks for provisioning_attestation, which here fails closed, yielding an UNPROVISIONED bound
    # attestation.
    from secp_operator_deployment import DeploymentPackageError

    class _Hostile:
        def provisioned(self):  # noqa: ANN202
            raise AssertionError("attest_runtime must not call provisioned()")

        def plan_execution_seams(self):  # noqa: ANN202
            raise AssertionError("attest_runtime must not call plan_execution_seams()")

        def provisioning_attestation(
            self, *, deployment_profile_digest, expected_identities_digest
        ):  # noqa: ANN001, ANN202
            raise DeploymentPackageError("controlled_live_runtime_not_provisioned")

    att = attest_runtime(_Hostile(), profile=valid_profile(), expected=valid_expected())
    ok, reason = validate_runtime_attestation(
        att, profile=valid_profile(), expected=valid_expected()
    )
    assert ok is False and reason == "attestation_not_provisioned"
