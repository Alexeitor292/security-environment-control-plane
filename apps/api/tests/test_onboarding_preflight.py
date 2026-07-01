"""SECP-002B-1B-0 onboarding preflight — fake collector, redaction, and required-check
semantics. The collector inspects NO real target; evidence is redacted and hash-bound."""

from __future__ import annotations

import copy

import pytest
from secp_api.enums import IsolationModel, OnboardingMode, PreflightCheckStatus
from secp_api.errors import ImmutableResourceError, ValidationFailedError
from secp_api.onboarding import (
    BASE_REQUIRED_CHECKS,
    CHECK_NO_ROUTE_TO_PROTECTED,
    preflight_evidence_hash,
    required_checks_passed,
    validate_preflight_evidence,
)
from secp_api.services import onboarding as onb
from secp_worker.onboarding import FakePreflightCollector
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


def _onboarding(session, principal, slug, isolation):
    t = _target(session, principal, slug)
    return onb.create_onboarding(
        session,
        principal,
        target_id=t.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=isolation,
        declared_boundary=copy.deepcopy(VALID_ONBOARDING_BOUNDARY),
    )


# --- fake collector inspects nothing real ------------------------------------


def test_fake_collector_covers_base_checks_for_physical():
    checks = FakePreflightCollector().collect(
        declared_boundary=VALID_ONBOARDING_BOUNDARY, isolation_model="physical"
    )
    names = {c["check"] for c in checks}
    assert BASE_REQUIRED_CHECKS <= names
    # no_route is reported but skipped for physical isolation.
    no_route = next(c for c in checks if c["check"] == CHECK_NO_ROUTE_TO_PROTECTED)
    assert no_route["status"] == PreflightCheckStatus.skipped.value


def test_fake_collector_passes_no_route_for_logical():
    checks = FakePreflightCollector().collect(
        declared_boundary=VALID_ONBOARDING_BOUNDARY, isolation_model="logical"
    )
    no_route = next(c for c in checks if c["check"] == CHECK_NO_ROUTE_TO_PROTECTED)
    assert no_route["status"] == PreflightCheckStatus.passed.value


def test_fake_collector_evidence_is_redacted():
    checks = FakePreflightCollector().collect(
        declared_boundary=VALID_ONBOARDING_BOUNDARY, isolation_model="logical"
    )
    blob = str(checks).lower()
    for needle in ("token", "password", "secret", "proxmox.example.test", "10.60."):
        assert needle not in blob


# --- required-check semantics ------------------------------------------------


def test_required_checks_logical_needs_no_route():
    passing = validate_preflight_evidence(
        FakePreflightCollector().collect(
            declared_boundary=VALID_ONBOARDING_BOUNDARY, isolation_model="logical"
        )
    )
    ok, missing = required_checks_passed(passing, isolation_model=IsolationModel.logical)
    assert ok and not missing

    without_no_route = validate_preflight_evidence(
        FakePreflightCollector(omit={CHECK_NO_ROUTE_TO_PROTECTED}).collect(
            declared_boundary=VALID_ONBOARDING_BOUNDARY, isolation_model="logical"
        )
    )
    ok2, missing2 = required_checks_passed(without_no_route, isolation_model=IsolationModel.logical)
    assert not ok2 and CHECK_NO_ROUTE_TO_PROTECTED in missing2


def test_physical_does_not_require_no_route():
    physical = validate_preflight_evidence(
        FakePreflightCollector(omit={CHECK_NO_ROUTE_TO_PROTECTED}).collect(
            declared_boundary=VALID_ONBOARDING_BOUNDARY, isolation_model="physical"
        )
    )
    ok, missing = required_checks_passed(physical, isolation_model=IsolationModel.physical)
    assert ok and not missing


# --- redaction + structure validation ----------------------------------------


def test_preflight_evidence_rejects_secret_in_detail():
    with pytest.raises(ValidationFailedError):
        validate_preflight_evidence(
            [{"check": "tls_posture_acceptable", "status": "passed", "detail": "api_token=abc123"}]
        )


def test_preflight_evidence_rejects_duplicates_and_empty():
    with pytest.raises(ValidationFailedError):
        validate_preflight_evidence([])
    with pytest.raises(ValidationFailedError):
        validate_preflight_evidence(
            [
                {"check": "tls_posture_acceptable", "status": "passed", "detail": "ok"},
                {"check": "tls_posture_acceptable", "status": "passed", "detail": "ok"},
            ]
        )


def test_evidence_hash_is_order_independent():
    a = [
        {"check": "nodes_in_allowlist", "status": "passed"},
        {"check": "storage_in_allowlist", "status": "passed"},
    ]
    b = list(reversed(a))
    assert preflight_evidence_hash(a) == preflight_evidence_hash(b)


def test_recorded_preflight_evidence_is_immutable(session, principal):
    ob = _onboarding(session, principal, "immut", IsolationModel.logical)
    checks = FakePreflightCollector().collect(
        declared_boundary=ob.declared_boundary, isolation_model="logical"
    )
    pf = onb.record_preflight(session, principal, ob.id, checks=checks)
    session.commit()
    pf.checks = [{"check": "tampered", "status": "passed"}]
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()
