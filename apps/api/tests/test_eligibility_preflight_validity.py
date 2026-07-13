"""Expiry / drift / approval-consumption validity for live eligibility evidence (B1B-PR3 amendment).

Proves a previously-passing evidence row cannot be USED once its bindings drift or it expires, that
the historical row is never mutated (current validity is DERIVED, and a new preflight — a new
operation fingerprint — is required), and that the fingerprint pins every security-relevant
binding so any change yields a new operation.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from secp_api.eligibility_policy import (
    ELIGIBILITY_POLICY_VERSION,
    eligibility_operation_fingerprint,
)
from secp_api.enums import EligibilityOutcome, LiveReadAuthorizationStatus
from secp_api.models import LiveReadAuthorization, TargetPreflight
from secp_api.services import eligibility as elig
from secp_worker.onboarding.eligibility_preflight import run_real_eligibility_preflight
from sqlalchemy import select
from tests._eligibility_fixtures import (  # type: ignore
    NOW,
    _build_chain,
    _full_composition,
)


def _make_eligible(session, chain):
    result = run_real_eligibility_preflight(
        session, request=chain.request(), composition=_full_composition(), now=NOW
    )
    assert result.outcome == EligibilityOutcome.eligible.value
    return result


def _view(session, principal, onboarding_id, *, now):
    return elig.get_live_eligibility_evidence(session, principal, onboarding_id, now=now)


def test_fresh_eligible_evidence_is_valid(session, principal):
    chain = _build_chain(session)
    _make_eligible(session, chain)
    v = _view(session, principal, chain.onboarding.id, now=NOW)
    assert v["eligibility_outcome"] == "eligible"
    assert v["valid"] is True and v["expired"] is False and v["drifted"] is False


def test_ttl_expiry_invalidates_without_mutating_the_row(session, principal):
    chain = _build_chain(session)
    _make_eligible(session, chain)
    later = NOW + timedelta(hours=7)  # past the 6h TTL (auth still valid at +1day)
    v = _view(session, principal, chain.onboarding.id, now=later)
    assert v["expired"] is True and v["valid"] is False
    # The historical row is NOT mutated: its stored outcome stays 'eligible' (validity is derived).
    pf = session.execute(
        select(TargetPreflight).where(TargetPreflight.onboarding_id == chain.onboarding.id)
    ).scalar_one()
    assert pf.eligibility_outcome == "eligible" and pf.passed is True


def test_authorization_expiry_drift_invalidates(session, principal):
    # Short authorization expiry (valid at collection NOW, expired shortly after) — vs TTL.
    chain = _build_chain(session, over={"auth_expiry": NOW + timedelta(hours=1)})
    _make_eligible(session, chain)
    later = NOW + timedelta(hours=2)  # TTL (6h) not yet expired; the AUTHORIZATION has expired
    v = _view(session, principal, chain.onboarding.id, now=later)
    assert v["expired"] is False
    assert v["drifted"] is True and v["valid"] is False


def test_authorization_revocation_invalidates(session, principal):
    chain = _build_chain(session)
    _make_eligible(session, chain)
    auth = session.get(LiveReadAuthorization, chain.authorization.id)
    auth.approved_by = principal.user_id  # set-once (was None) — required to record revocation
    auth.status = LiveReadAuthorizationStatus.revoked
    auth.revoked_by = principal.user_id
    auth.revoked_at = NOW
    auth.revocation_reason_code = "operator_revoked"
    session.flush()
    v = _view(session, principal, chain.onboarding.id, now=NOW)
    assert v["drifted"] is True and v["valid"] is False


def test_worker_identity_expiry_drift_invalidates(session, principal):
    chain = _build_chain(session, over={"worker_expiry": NOW + timedelta(hours=1)})
    _make_eligible(session, chain)
    later = NOW + timedelta(hours=2)
    v = _view(session, principal, chain.onboarding.id, now=later)
    assert v["drifted"] is True and v["valid"] is False


def test_policy_version_bump_invalidates(session, principal, monkeypatch):
    chain = _build_chain(session)
    _make_eligible(session, chain)
    # A future policy version means the stored (old-version) evidence is no longer current.
    monkeypatch.setattr(elig, "ELIGIBILITY_POLICY_VERSION", ELIGIBILITY_POLICY_VERSION + "-next")
    v = _view(session, principal, chain.onboarding.id, now=NOW)
    assert v["drifted"] is True and v["valid"] is False


def test_changed_authorization_version_forces_a_new_attempt(session, principal):
    """A changed binding yields a DIFFERENT fingerprint → not an idempotent reuse → a new attempt.
    The stale row is untouched; a new preflight row is created for the new operation."""
    chain = _build_chain(session)
    first = _make_eligible(session, chain)

    # A new, higher-version approved authorization supersedes the prior one (a changed binding).

    session.add(
        LiveReadAuthorization(
            organization_id=chain.org_id,
            execution_target_id=chain.target.id,
            onboarding_id=chain.onboarding.id,
            connection_hash=chain.authorization.connection_hash,
            boundary_hash=chain.authorization.boundary_hash,
            authorization_version=2,
            authorization_expiry=NOW + timedelta(days=1),
            collector_contract_version=chain.authorization.collector_contract_version,
            endpoint_allowlist_version=chain.authorization.endpoint_allowlist_version,
            evidence_source="live_readonly_proxmox",
            verification_level="live_verified",
            status=LiveReadAuthorizationStatus.approved,
            approved_at=NOW,
        )
    )
    session.flush()

    # Resolution now picks version 2 → a different fingerprint → a NEW (not reused) attempt.
    from secp_worker.onboarding.eligibility_preflight import resolve_eligibility_preflight_request

    request, reason = resolve_eligibility_preflight_request(session, chain.onboarding.id, NOW)
    assert reason is None and request.authorization_version == 2
    second = run_real_eligibility_preflight(
        session, request=request, composition=_full_composition(), now=NOW
    )
    assert second.reused is False
    assert second.preflight_id != first.preflight_id
    rows = (
        session.execute(
            select(TargetPreflight).where(TargetPreflight.onboarding_id == chain.onboarding.id)
        )
        .scalars()
        .all()
    )
    assert len(rows) == 2  # the stale row was preserved, a new one was appended


def test_operation_fingerprint_binds_every_security_field():
    base = dict(
        organization_id="o",
        execution_target_id="t",
        target_config_hash="c",
        onboarding_id="ob",
        boundary_hash="b",
        authorization_id="a",
        authorization_version=1,
        authorization_expiry="2026-01-01T00:00:00Z",
        worker_identity_registration_id="w",
        worker_identity_version=1,
        evidence_source="live_readonly_proxmox",
        verification_level="live_verified",
        collector_contract_version="cc",
        endpoint_allowlist_version="ea",
        policy_version="pv",
        toolchain_profile_hash=None,
    )
    baseline = eligibility_operation_fingerprint(**base)
    # Changing ANY security-relevant field changes the fingerprint (a new operation).
    for field, changed in (
        ("organization_id", "o2"),
        ("execution_target_id", "t2"),
        ("target_config_hash", "c2"),
        ("onboarding_id", "ob2"),
        ("boundary_hash", "b2"),
        ("authorization_id", "a2"),
        ("authorization_version", 2),
        ("authorization_expiry", "2027-01-01T00:00:00Z"),
        ("worker_identity_registration_id", "w2"),
        ("worker_identity_version", 2),
        ("collector_contract_version", "cc2"),
        ("endpoint_allowlist_version", "ea2"),
        ("policy_version", "pv2"),
        ("toolchain_profile_hash", "th"),
    ):
        assert eligibility_operation_fingerprint(**{**base, field: changed}) != baseline, field


def test_eligible_row_carries_stable_id_and_full_hash_for_approval_binding(session, principal):
    """A future real-lab approval binds the exact evidence row id + complete evidence hash; the row
    is immutable, so the binding is stable. A non-eligible row is not passed (unapprovable)."""
    chain = _build_chain(session)
    result = _make_eligible(session, chain)
    pf = session.get(TargetPreflight, result.preflight_id)
    assert pf.passed is True
    assert pf.evidence_hash.startswith("sha256:") and pf.target_evidence_hash.startswith("sha256:")
    from secp_api.errors import ImmutableResourceError

    pf.eligibility_outcome = "ineligible"
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()
