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
from secp_api.errors import ImmutableResourceError, ValidationFailedError
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


def test_worker_result_recorder_can_produce_live_verified(session, principal):
    """The trusted worker collector seam can produce live_verified evidence (fake fixture)."""
    ob = _onboarding(session, principal, "live")
    checks = simulate_boundary_checks(ob.declared_boundary, ob.isolation_model)
    pf = onb.record_preflight_result(
        session,
        ob.id,
        checks=checks,
        verification_level=VerificationLevel.live_verified.value,
        collector_kind=CollectorKind.provider_worker.value,
        collector_identity="fake-provider-worker",
    )
    assert pf.verification_level == VerificationLevel.live_verified.value


def test_api_simulated_path_cannot_forge_live(session, principal):
    """No API-reachable path can produce live_verified evidence."""
    ob = _onboarding(session, principal, "forge")
    pf = onb.record_simulated_preflight(session, principal, ob.id)
    assert pf.verification_level == VerificationLevel.simulated.value  # always simulated


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
