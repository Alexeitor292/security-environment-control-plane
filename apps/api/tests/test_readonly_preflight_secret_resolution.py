"""SECP-B2-1 — worker-only sealed secret-resolution contract (unit-level, fake-only, no backend).

Proves: the closed resolution-purpose catalog; immutable, redacted, non-serializable request /
credential-reference / secret-material types; the per-field contract gate; that a trusted request
can only be built after the verifier succeeds (never hand-crafted); and that the shipped sealed
resolver runs the contract gate then fails closed BEFORE any secret material could exist. Nothing
here contacts a real backend or resolves a real secret.
"""

from __future__ import annotations

import pickle
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.live_read_contract import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    LIVE_READ_EVIDENCE_SOURCE,
    LIVE_VERIFIED_LEVEL,
    PROXMOX_READONLY_POLICY_VERSION,
)
from secp_api.models import ExecutionTarget, LiveReadAuthorization, TargetOnboarding
from secp_worker.onboarding.live_authorization import VerifiedLiveReadAuthorization
from secp_worker.onboarding.live_readonly import LiveReadCollectionBinding
from secp_worker.preflight.sealed_secret_resolver import SealedSecretResolver
from secp_worker.preflight.secret_resolution import (
    SUPPORTED_PURPOSES,
    ResolutionContract,
    ResolutionContractViolation,
    ResolutionPurpose,
    SecretMaterial,
    SecretResolutionUnavailable,
    TrustedCredentialReference,
    TrustedResolutionRequest,
    assert_resolution_authorized,
    build_resolution_contract,
    build_trusted_resolution_request,
)

_FUTURE = "2999-01-01T00:00:00Z"
_REF = "env:SECP_PROVIDER_SECRET__PREFLIGHT"
_PREFLIGHT_ID = uuid.UUID(int=5)


def _contract(**over) -> ResolutionContract:
    base = dict(
        purpose=ResolutionPurpose.readonly_staging_preflight,
        organization_id=uuid.UUID(int=1),
        execution_target_id=uuid.UUID(int=2),
        onboarding_id=uuid.UUID(int=3),
        authorization_id=uuid.UUID(int=4),
        authorization_version=2,
        authorization_expiry=_FUTURE,
        preflight_id=uuid.UUID(int=5),
        operation_fingerprint="sha256:" + "ab" * 32,
        contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_policy_version=PROXMOX_READONLY_POLICY_VERSION,
        credential_reference=TrustedCredentialReference(_REF),
    )
    ref = over.pop("credential_reference", None)
    base.update(over)
    if ref is not None:
        base["credential_reference"] = ref
    return ResolutionContract(**base)  # type: ignore[arg-type]


def _verified(*, secret_ref: str = _REF, version: int = 2, expiry: str = _FUTURE):
    org = uuid.uuid4()
    tid = uuid.uuid4()
    oid = uuid.uuid4()
    aid = uuid.uuid4()
    target = ExecutionTarget(organization_id=org, secret_ref=secret_ref)
    target.id = tid
    binding = LiveReadCollectionBinding(
        execution_target_id=str(tid),
        target_config_hash="sha256:" + "ab" * 32,
        onboarding_id=str(oid),
        boundary_hash="sha256:" + "cd" * 32,
        authorization_id=str(aid),
        authorization_version=version,
        authorization_expiry=expiry,
        credential_ref=secret_ref,
        evidence_source=LIVE_READ_EVIDENCE_SOURCE,
        verification_level=LIVE_VERIFIED_LEVEL,
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
    )
    return VerifiedLiveReadAuthorization(
        execution_target=target,
        onboarding=TargetOnboarding(),
        authorization=LiveReadAuthorization(),
        binding=binding,
    )


def _now() -> datetime:
    return datetime(2026, 7, 4, tzinfo=UTC)


# --- Closed purpose catalog ---------------------------------------------------------------------


def test_resolution_purpose_catalog_is_closed_and_readonly_only():
    assert [p.value for p in ResolutionPurpose] == ["readonly_staging_preflight"]
    assert SUPPORTED_PURPOSES == frozenset({ResolutionPurpose.readonly_staging_preflight})


# --- Contract gate: accepts a match, rejects every field mismatch --------------------------------


def test_gate_accepts_matching_contract():
    assert_resolution_authorized(_contract(), _contract(), now=_now())


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"organization_id": uuid.UUID(int=99)}, "wrong_organization"),
        ({"execution_target_id": uuid.UUID(int=99)}, "wrong_execution_target"),
        ({"onboarding_id": uuid.UUID(int=99)}, "wrong_onboarding"),
        ({"authorization_id": uuid.UUID(int=99)}, "wrong_authorization"),
        ({"authorization_version": 7}, "authorization_version_mismatch"),
        ({"operation_fingerprint": "sha256:" + "ff" * 32}, "operation_fingerprint_mismatch"),
        ({"authorization_expiry": "2999-06-01T00:00:00Z"}, "authorization_expiry_mismatch"),
        (
            {"credential_reference": TrustedCredentialReference("env:OTHER")},
            "credential_reference_mismatch",
        ),
    ],
)
def test_gate_rejects_each_binding_field_mismatch(override, reason):
    candidate = _contract(**override)
    with pytest.raises(ResolutionContractViolation) as exc:
        assert_resolution_authorized(candidate, _contract(), now=_now())
    assert exc.value.reason_code == reason


def test_gate_rejects_blank_credential_reference():
    candidate = _contract(credential_reference=TrustedCredentialReference("   "))
    authoritative = _contract(credential_reference=TrustedCredentialReference("   "))
    with pytest.raises(ResolutionContractViolation) as exc:
        assert_resolution_authorized(candidate, authoritative, now=_now())
    assert exc.value.reason_code == "credential_reference_missing"


def test_gate_rejects_expired_authorization():
    past = "2000-01-01T00:00:00Z"
    with pytest.raises(ResolutionContractViolation) as exc:
        assert_resolution_authorized(
            _contract(authorization_expiry=past), _contract(authorization_expiry=past), now=_now()
        )
    assert exc.value.reason_code == "authorization_expired"


def test_gate_rejects_unsupported_contract_or_policy_labels():
    # Both sides agree on a NON-pinned label; the pinned policy check still refuses it.
    bad_contract = _contract(contract_version="other/v9")
    with pytest.raises(ResolutionContractViolation) as exc:
        assert_resolution_authorized(bad_contract, bad_contract, now=_now())
    assert exc.value.reason_code == "unsupported_contract_version"

    bad_policy = _contract(endpoint_policy_version="other/policy/v9")
    with pytest.raises(ResolutionContractViolation) as exc2:
        assert_resolution_authorized(bad_policy, bad_policy, now=_now())
    assert exc2.value.reason_code == "unsupported_endpoint_policy_version"


def test_gate_rejects_unsupported_purpose():
    # A contract whose purpose is not in the closed supported set is refused. (Constructed via a
    # raw object to simulate a future/unknown purpose without widening the enum.)
    class _Fake(str):
        pass

    unknown = _contract()
    object.__setattr__(unknown, "purpose", _Fake("some_future_purpose"))
    with pytest.raises(ResolutionContractViolation) as exc:
        assert_resolution_authorized(unknown, _contract(), now=_now())
    assert exc.value.reason_code == "unsupported_purpose"


# --- Trusted request can only be built post-verification -----------------------------------------


def test_trusted_request_cannot_be_constructed_directly():
    with pytest.raises(TypeError):
        TrustedResolutionRequest(_contract(), token=object())


def test_build_request_requires_verified_binding_and_matches_independent_expectation():
    verified = _verified()
    fp = "sha256:" + "12" * 32
    request = build_trusted_resolution_request(
        verified=verified,
        purpose=ResolutionPurpose.readonly_staging_preflight,
        operation_fingerprint=fp,
        preflight_id=_PREFLIGHT_ID,
        now=_now(),
    )
    assert isinstance(request, TrustedResolutionRequest)
    expectation = build_resolution_contract(
        verified=verified,
        purpose=ResolutionPurpose.readonly_staging_preflight,
        operation_fingerprint=fp,
        preflight_id=_PREFLIGHT_ID,
        now=_now(),
    )
    # A request built from a verified binding matches an independently derived authoritative
    # contract, so the resolver gate passes.
    assert_resolution_authorized(request.contract, expectation, now=_now())
    assert request.contract == expectation


def test_build_contract_runs_pinned_policy_check_and_rejects_bad_labels():
    # LiveReadCollectionBinding is a frozen dataclass; bypass frozen to inject a bad pinned label.
    bad = _verified()
    object.__setattr__(bad.binding, "collector_contract_version", "other/v9")
    with pytest.raises(ResolutionContractViolation) as exc:
        build_resolution_contract(
            verified=bad,
            purpose=ResolutionPurpose.readonly_staging_preflight,
            operation_fingerprint="sha256:" + "12" * 32,
            preflight_id=_PREFLIGHT_ID,
            now=_now(),
        )
    assert exc.value.reason_code == "unsupported_contract_version"


def test_build_contract_rejects_expired_binding():
    expired = _verified(expiry="2000-01-01T00:00:00Z")
    with pytest.raises(ResolutionContractViolation) as exc:
        build_resolution_contract(
            verified=expired,
            purpose=ResolutionPurpose.readonly_staging_preflight,
            operation_fingerprint="sha256:" + "12" * 32,
            preflight_id=_PREFLIGHT_ID,
            now=_now(),
        )
    assert exc.value.reason_code == "authorization_expired"


# --- Redaction / non-serializability -------------------------------------------------------------


def test_secret_material_is_opaque_redacted_and_non_serializable():
    m = SecretMaterial("s3cr3t-value")
    assert m.reveal_secret() == "s3cr3t-value"
    # No value leaks through any string/repr/format form.
    for rendered in (repr(m), str(m), f"{m}", format(m, ""), f"{m}"):
        assert "s3cr3t-value" not in rendered
        assert rendered == "SecretMaterial(<redacted>)"
    # No __dict__, and it cannot be pickled/serialized.
    assert not hasattr(m, "__dict__")
    with pytest.raises(TypeError):
        pickle.dumps(m)
    with pytest.raises(TypeError):
        m.__reduce__()


def test_trusted_credential_reference_is_redacted_and_non_serializable():
    ref = TrustedCredentialReference(_REF)
    assert ref.reveal_reference() == _REF
    assert _REF not in repr(ref) and _REF not in str(ref)
    assert repr(ref) == "TrustedCredentialReference(<redacted>)"
    assert ref == TrustedCredentialReference(_REF)
    assert ref != TrustedCredentialReference("env:OTHER")
    assert TrustedCredentialReference("   ").is_blank is True
    assert ref.is_blank is False
    with pytest.raises(TypeError):
        pickle.dumps(ref)


def test_trusted_resolution_request_is_redacted_and_non_serializable():
    request = build_trusted_resolution_request(
        verified=_verified(),
        purpose=ResolutionPurpose.readonly_staging_preflight,
        operation_fingerprint="sha256:" + "12" * 32,
        preflight_id=_PREFLIGHT_ID,
        now=_now(),
    )
    assert repr(request) == "TrustedResolutionRequest(<redacted>)"
    assert _REF not in repr(request)
    with pytest.raises(TypeError):
        pickle.dumps(request)


def test_resolution_contract_repr_redacts_reference():
    text = repr(_contract())
    assert "credential_reference=<redacted>" in text
    assert _REF not in text


# --- Sealed default: gate runs, then fail closed BEFORE any secret material ----------------------


def test_sealed_resolver_runs_gate_then_fails_closed_for_valid_request():
    verified = _verified()
    fp = "sha256:" + "12" * 32
    request = build_trusted_resolution_request(
        verified=verified,
        purpose=ResolutionPurpose.readonly_staging_preflight,
        operation_fingerprint=fp,
        preflight_id=_PREFLIGHT_ID,
        now=_now(),
    )
    expectation = build_resolution_contract(
        verified=verified,
        purpose=ResolutionPurpose.readonly_staging_preflight,
        operation_fingerprint=fp,
        preflight_id=_PREFLIGHT_ID,
        now=_now(),
    )
    # Even for a perfectly valid request the sealed resolver returns NO SecretMaterial — it fails
    # closed. This is the shipped default that keeps every preflight at credential_unavailable.
    with pytest.raises(SecretResolutionUnavailable):
        SealedSecretResolver().resolve(request, expectation=expectation, now=_now())


def test_sealed_resolver_refuses_mismatched_request_before_failing_open():
    # A request that does NOT match the authoritative contract is refused by the gate (a contract
    # violation), proving the gate runs before the fail-closed boundary. Either way, no material.
    verified = _verified()
    request = build_trusted_resolution_request(
        verified=verified,
        purpose=ResolutionPurpose.readonly_staging_preflight,
        operation_fingerprint="sha256:" + "12" * 32,
        preflight_id=_PREFLIGHT_ID,
        now=_now(),
    )
    mismatched = build_resolution_contract(
        verified=_verified(),  # a DIFFERENT binding (different ids)
        purpose=ResolutionPurpose.readonly_staging_preflight,
        operation_fingerprint="sha256:" + "34" * 32,
        preflight_id=_PREFLIGHT_ID,
        now=_now(),
    )
    with pytest.raises(ResolutionContractViolation):
        SealedSecretResolver().resolve(request, expectation=mismatched, now=_now())


def test_sealed_resolver_never_returns_secret_material_under_any_input():
    # Exhaustive-ish: neither a valid nor an expired binding yields SecretMaterial.
    for expiry in (_FUTURE, "2000-01-01T00:00:00Z"):
        verified = _verified(expiry=expiry)
        fp = "sha256:" + "12" * 32
        try:
            request = build_trusted_resolution_request(
                verified=verified,
                purpose=ResolutionPurpose.readonly_staging_preflight,
                operation_fingerprint=fp,
                preflight_id=_PREFLIGHT_ID,
                now=_now(),
            )
        except ResolutionContractViolation:
            continue  # expired binding never even builds a request
        with pytest.raises(SecretResolutionUnavailable):
            SealedSecretResolver().resolve(
                request,
                expectation=build_resolution_contract(
                    verified=verified,
                    purpose=ResolutionPurpose.readonly_staging_preflight,
                    operation_fingerprint=fp,
                    preflight_id=_PREFLIGHT_ID,
                    now=_now(),
                ),
                now=_now(),
            )


def test_expiry_used_by_gate_is_the_binding_now(_ignore=None):
    # A binding valid now but expired at a later `now` is refused by the gate at that later time.
    verified = _verified(expiry="2026-07-05T00:00:00Z")
    fp = "sha256:" + "12" * 32
    request = build_trusted_resolution_request(
        verified=verified,
        purpose=ResolutionPurpose.readonly_staging_preflight,
        operation_fingerprint=fp,
        preflight_id=_PREFLIGHT_ID,
        now=_now(),
    )
    expectation = build_resolution_contract(
        verified=verified,
        purpose=ResolutionPurpose.readonly_staging_preflight,
        operation_fingerprint=fp,
        preflight_id=_PREFLIGHT_ID,
        now=_now(),
    )
    later = _now() + timedelta(days=2)
    with pytest.raises(ResolutionContractViolation) as exc:
        assert_resolution_authorized(request.contract, expectation, now=later)
    assert exc.value.reason_code == "authorization_expired"
