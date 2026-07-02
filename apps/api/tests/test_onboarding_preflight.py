"""SECP-002B-1B-0 onboarding preflight — request/result contract, trusted provenance,
redaction, and the complete hash-bound evidence package. Fakes only; nothing real."""

from __future__ import annotations

import copy

import pytest
from secp_api.enums import (
    CollectorKind,
    IsolationModel,
    OnboardingMode,
    PreflightCheckStatus,
    VerificationLevel,
)
from secp_api.errors import (
    ImmutableResourceError,
    LiveEvidenceSealedError,
    ProvisioningRefusedError,
    ValidationFailedError,
)
from secp_api.onboarding import (
    BASE_REQUIRED_CHECKS,
    CHECK_NO_ROUTE_TO_PROTECTED,
    build_evidence_package,
    evidence_package_hash,
    required_checks_passed,
    simulate_boundary_checks,
    validate_collector_and_level,
    validate_preflight_evidence,
)
from secp_api.services import onboarding as onb
from tests.conftest import VALID_ONBOARDING_BOUNDARY, VALID_PROVISIONING_SCOPE  # type: ignore


def _target(session, principal, slug):
    from secp_api.services import targets

    t = targets.register_target(
        session,
        principal,
        display_name="Preflight Target",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        secret_ref=f"env:SECP_PROVIDER_SECRET__{slug.upper()}",
        scope_policy={"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
    )
    session.commit()
    return t


def _onboarding(session, principal, slug, isolation=IsolationModel.logical):
    t = _target(session, principal, slug)
    return onb.create_onboarding(
        session,
        principal,
        target_id=t.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=isolation,
        declared_boundary=copy.deepcopy(VALID_ONBOARDING_BOUNDARY),
    )


# --- simulated preflight (API path, no arbitrary caller input) ---------------


def test_simulated_preflight_is_labeled_simulated(session, principal):
    ob = _onboarding(session, principal, "sim")
    pf = onb.record_simulated_preflight(session, principal, ob.id)
    assert pf.verification_level == VerificationLevel.simulated.value
    assert pf.collector_kind == CollectorKind.fake_declared_boundary.value
    assert pf.collector_identity == "control-plane-simulator"
    assert pf.passed is True


def test_simulated_preflight_evidence_is_redacted(session, principal):
    ob = _onboarding(session, principal, "redact")
    pf = onb.record_simulated_preflight(session, principal, ob.id)
    blob = str(pf.checks).lower()
    for needle in ("token", "password", "secret", "proxmox.example.test", "10.60.", "vmbr0"):
        assert needle not in blob


def test_fake_collector_covers_base_checks_for_physical():
    checks = simulate_boundary_checks(VALID_ONBOARDING_BOUNDARY, IsolationModel.physical)
    names = {c["check"] for c in checks}
    assert BASE_REQUIRED_CHECKS <= names
    no_route = next(c for c in checks if c["check"] == CHECK_NO_ROUTE_TO_PROTECTED)
    assert no_route["status"] == PreflightCheckStatus.skipped.value


# --- required-check semantics ------------------------------------------------


def test_required_checks_logical_needs_no_route():
    passing = validate_preflight_evidence(
        simulate_boundary_checks(VALID_ONBOARDING_BOUNDARY, IsolationModel.logical)
    )
    ok, missing = required_checks_passed(passing, isolation_model=IsolationModel.logical)
    assert ok and not missing

    without = validate_preflight_evidence(
        simulate_boundary_checks(
            VALID_ONBOARDING_BOUNDARY, IsolationModel.logical, omit={CHECK_NO_ROUTE_TO_PROTECTED}
        )
    )
    ok2, missing2 = required_checks_passed(without, isolation_model=IsolationModel.logical)
    assert not ok2 and CHECK_NO_ROUTE_TO_PROTECTED in missing2


# --- trusted-provenance contract (simulated vs live) -------------------------


def test_collector_level_contract_rejects_fake_live():
    with pytest.raises(ValidationFailedError):
        validate_collector_and_level(
            CollectorKind.fake_declared_boundary.value, VerificationLevel.live_verified.value
        )


def test_collector_level_contract_rejects_unknown():
    with pytest.raises(ValidationFailedError):
        validate_collector_and_level("attacker_supplied", VerificationLevel.simulated.value)
    with pytest.raises(ValidationFailedError):
        validate_collector_and_level(CollectorKind.provider_worker.value, "trust_me")


def test_worker_result_recorder_cannot_produce_live_verified(session, principal):
    """B1-B-0 seal: even the worker seam cannot create live_verified evidence in this release."""
    ob = _onboarding(session, principal, "live")
    checks = simulate_boundary_checks(ob.declared_boundary, ob.isolation_model)
    with pytest.raises(LiveEvidenceSealedError):
        onb.record_preflight_result(
            session,
            ob.id,
            evidence_record=None,
            checks=checks,
            verification_level=VerificationLevel.live_verified.value,
            collector_kind=CollectorKind.provider_worker.value,
            collector_identity="fake-provider-worker",
        )


def test_worker_recorder_rejects_provider_worker_even_when_simulated(session, principal):
    """The sealed provider_worker collector is inert: it cannot record ANY evidence in B1-B-0."""
    ob = _onboarding(session, principal, "pw")
    checks = simulate_boundary_checks(ob.declared_boundary, ob.isolation_model)
    with pytest.raises(LiveEvidenceSealedError):
        onb.record_preflight_result(
            session,
            ob.id,
            evidence_record=None,
            checks=checks,
            verification_level=VerificationLevel.simulated.value,
            collector_kind=CollectorKind.provider_worker.value,
            collector_identity="fake-provider-worker",
        )


def test_sealed_provider_worker_collector_is_inert():
    """The provider_worker collector seam exists but its implementation is unavailable."""
    from secp_worker.onboarding.preflight import SealedProviderWorkerCollector

    collector = SealedProviderWorkerCollector()
    assert collector.collector_kind == CollectorKind.provider_worker.value
    with pytest.raises(LiveEvidenceSealedError):
        collector.collect(declared_boundary=VALID_ONBOARDING_BOUNDARY, isolation_model="logical")


def test_api_simulated_path_cannot_forge_live(session, principal):
    """No API-reachable path can produce live_verified evidence."""
    ob = _onboarding(session, principal, "forge")
    pf = onb.record_simulated_preflight(session, principal, ob.id)
    assert pf.verification_level == VerificationLevel.simulated.value  # always simulated


def test_simulated_onboarding_supports_contract_but_never_live(session, principal):
    """A simulated onboarding is valid for the fake/contract path but never live-eligible."""
    from secp_worker.provisioning.execution import assert_evidence_sufficient_for_execution

    ob = _onboarding(session, principal, "contract")
    onb.record_simulated_preflight(session, principal, ob.id)
    onb.submit_for_review(session, principal, ob.id)
    onb.approve_onboarding(session, principal, ob.id, "ok")
    onb.activate_onboarding(session, principal, ob.id)
    assert ob.approved_verification_level == VerificationLevel.simulated.value
    assert_evidence_sufficient_for_execution(ob, require_live=False)  # contract path: fine
    with pytest.raises(ProvisioningRefusedError, match="live_verified"):
        assert_evidence_sufficient_for_execution(ob, require_live=True)


# --- robust redaction of detail text (correction pass) -----------------------


@pytest.mark.parametrize(
    "detail",
    [
        "auth token ABCDEF0123456789ABCDEF",  # token-like (high-entropy)
        "password: hunter2trustme",  # password-like
        "password=hunter2trustme",  # password-like (assignment)
        "credential=abc123def456ghi",  # credential-like (assignment)
        "https://proxmox.example.test:8006/api2/json",  # endpoint-like (URL)
        "reachable at 10.60.0.5:8006",  # endpoint-like (IPv4)
        "node pve-node-1 storage local-lvm bridge vmbr0",  # raw-inventory-like
        "reserved 10.60.0.0/16",  # raw-inventory-like (CIDR)
        "-----BEGIN RSA PRIVATE KEY-----",  # private key
    ],
)
def test_secret_bearing_detail_is_refused_before_persistence(detail):
    with pytest.raises(ValidationFailedError):
        validate_preflight_evidence(
            [{"check": "nodes_in_allowlist", "status": "passed", "detail": detail}]
        )


def test_generic_simulated_details_all_pass_redaction():
    from secp_api.onboarding import _SIMULATED_DETAILS, detail_is_secret_bearing

    for detail in _SIMULATED_DETAILS.values():
        assert not detail_is_secret_bearing(detail), detail
    # And they validate structurally.
    checks = simulate_boundary_checks(VALID_ONBOARDING_BOUNDARY, IsolationModel.logical)
    assert validate_preflight_evidence(checks)


# --- complete evidence-package hash ------------------------------------------


def test_evidence_hash_covers_provenance(session, principal):
    ob = _onboarding(session, principal, "prov")
    pf = onb.record_simulated_preflight(session, principal, ob.id)
    # Recompute matches the stored hash.
    assert onb.recompute_evidence_hash(pf) == pf.evidence_hash
    # A package that differs in a provenance field yields a different hash.
    base = build_evidence_package(
        onboarding_id=str(ob.id),
        boundary_hash=pf.boundary_hash,
        target_config_hash=pf.target_config_hash,
        scope_policy_hash=pf.scope_policy_hash,
        toolchain_profile_id=None,
        toolchain_profile_hash=None,
        verification_level=pf.verification_level,
        collector_kind=pf.collector_kind,
        collector_identity=pf.collector_identity,
        evidence_version=pf.evidence_version,
        checks=pf.checks,
    )
    drifted = {**base, "target_config_hash": "sha256:different"}
    assert evidence_package_hash(base) != evidence_package_hash(drifted)


def test_recorded_preflight_evidence_is_immutable(session, principal):
    ob = _onboarding(session, principal, "immut")
    pf = onb.record_simulated_preflight(session, principal, ob.id)
    session.commit()
    pf.checks = [{"check": "tampered", "status": "passed", "detail": "x"}]
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()
    pf2 = session.get(type(pf), pf.id)
    pf2.verification_level = "live_verified"
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()
