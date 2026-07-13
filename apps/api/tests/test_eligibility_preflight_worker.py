"""Controlled worker-owned read-only eligibility preflight (SECP-002B-1B, B1B-PR3).

Exercises the sealed-by-default worker seam ``run_real_eligibility_preflight`` end to end over a
fully-consistent DB chain and INJECTED fake Path B seams. Nothing real is contacted: no network, no
Proxmox, no SSH, no subprocess, no OpenTofu. Proves: sealed default refuses and contacts nothing; a
complete gate chain + injected collection produces immutable, redacted, expiry-bound live_verified
evidence; the shipped collector (no dedicated observations) yields ``unverifiable``, never a false
``eligible``; each gate refusal fails closed with a closed reason category and persists no evidence;
persistence is exact-once; privileged seams are never touched before their gate; and a simulated/
fake payload can never be recorded as live eligibility evidence.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from secp_api.enums import (
    AuditAction,
    CollectorKind,
    EligibilityOutcome,
    LiveReadAuthorizationStatus,
    OnboardingStatus,
    VerificationLevel,
    WorkerIdentityStatus,
)
from secp_api.live_read_contract import connection_identity_hash
from secp_api.models import (
    TargetEvidenceRecord,
    TargetPreflight,
)
from secp_scenario_schema import content_hash
from secp_worker.onboarding.eligibility_preflight import (
    EligibilityPreflightComposition,
    EligibilityPreflightGate,
    run_real_eligibility_preflight,
    sealed_eligibility_composition,
)
from secp_worker.onboarding.live_readonly import LiveReadCollectionGate
from sqlalchemy import select
from tests._eligibility_fixtures import (  # type: ignore
    ELIGIBLE_OBSERVED,
    NOW,
    _AllowVerifier,
    _audit_actions,
    _build_chain,
    _EligibleCollector,
    _full_composition,
    _preflight_rows,
    _RaisingSeam,
    _Resolver,
    _transport_factory,
)

# --- Sealed default ------------------------------------------------------------------------------


def test_sealed_default_refuses_and_persists_no_evidence(session, principal):
    chain = _build_chain(session)
    result = run_real_eligibility_preflight(
        session, request=chain.request(), composition=sealed_eligibility_composition(), now=NOW
    )
    assert result.outcome == EligibilityOutcome.refused.value
    assert result.reason_category == "sealed"
    assert result.preflight_id is None
    assert _preflight_rows(session) == []
    assert session.execute(select(TargetEvidenceRecord)).scalars().all() == []
    actions = _audit_actions(session, chain.org_id)
    assert AuditAction.eligibility_preflight_refused in actions
    assert AuditAction.eligibility_preflight_started not in actions


def test_default_composition_is_sealed(session, principal):
    chain = _build_chain(session)
    # No composition passed at all → sealed default → refused.
    result = run_real_eligibility_preflight(session, request=chain.request(), now=NOW)
    assert result.outcome == EligibilityOutcome.refused.value
    assert result.reason_category == "sealed"


def test_privileged_seams_not_touched_when_sealed(session, principal):
    chain = _build_chain(session)
    spy = _RaisingSeam()
    composition = EligibilityPreflightComposition(
        gate=EligibilityPreflightGate(enabled=False),  # sealed
        live_read_gate=LiveReadCollectionGate(enabled=True),
        secret_resolver=spy,
        transport_factory=spy,
        collector=spy,
        authorization_verifier=spy,
    )
    result = run_real_eligibility_preflight(
        session, request=chain.request(), composition=composition, now=NOW
    )
    assert result.outcome == EligibilityOutcome.refused.value  # spies never raised


def test_transport_and_collector_not_touched_before_authorization_gate(session, principal):
    """Ordering (§14): even with the gate ENABLED, a failing authorization gate refuses BEFORE any
    resolver/transport/collector is reached — the raising spies must never fire, and no target is
    contacted and no evidence is persisted."""
    spy = _RaisingSeam()
    chain = _build_chain(session, over={"auth_boundary_hash": content_hash({"drifted": True})})
    composition = EligibilityPreflightComposition(
        gate=EligibilityPreflightGate(enabled=True),
        live_read_gate=LiveReadCollectionGate(enabled=True),
        secret_resolver=spy,
        transport_factory=spy,
        collector=spy,
        authorization_verifier=spy,
    )
    result = run_real_eligibility_preflight(
        session, request=chain.request(), composition=composition, now=NOW
    )
    assert result.outcome == EligibilityOutcome.refused.value
    assert result.reason_category == "boundary_drift"  # refused at the authorization gate
    assert _preflight_rows(session) == []  # spies never fired; nothing persisted


# --- Full eligible path --------------------------------------------------------------------------


def test_full_eligible_path_persists_immutable_live_evidence(session, principal):
    chain = _build_chain(session)
    result = run_real_eligibility_preflight(
        session, request=chain.request(), composition=_full_composition(), now=NOW
    )
    assert result.outcome == EligibilityOutcome.eligible.value
    assert result.preflight_id is not None

    pf = session.get(TargetPreflight, result.preflight_id)
    assert pf.verification_level == VerificationLevel.live_verified.value
    assert pf.collector_kind == CollectorKind.provider_worker.value
    assert pf.passed is True
    assert pf.eligibility_outcome == EligibilityOutcome.eligible.value
    assert pf.operation_fingerprint and pf.operation_fingerprint.startswith("sha256:")
    assert pf.evidence_expires_at is not None
    assert pf.live_read_authorization_id == chain.authorization.id

    record = session.get(TargetEvidenceRecord, pf.target_evidence_id)
    assert record.evidence_source == "live_readonly_proxmox"
    assert record.verification_level == VerificationLevel.live_verified.value

    actions = _audit_actions(session, chain.org_id)
    assert AuditAction.eligibility_preflight_started in actions
    assert AuditAction.eligibility_preflight_completed in actions

    # Immutable: the recorded preflight cannot be mutated.
    from secp_api.errors import ImmutableResourceError

    pf.passed = False
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()


def test_shipped_collector_without_dedicated_obs_is_unverifiable_not_eligible(session, principal):
    """The real collector supplies no isolation/vmid/quota/disposability observation, so those
    dimensions are unverifiable and the outcome is ``unverifiable`` — never a false ``eligible``."""
    from secp_plugin_proxmox.live_collector import LiveReadOnlyProxmoxCollector

    class _NodesOnlyTransport:
        _DATA = {
            "/nodes": [{"node": "labnode"}],
            "/cluster/sdn/vnets": [{"vnet": "labseg", "cidr": "10.9.0.0/24"}],
            "/nodes/labnode/storage": [{"storage": "labstore"}],
        }

        def get(self, path):
            return self._DATA.get(path, [])

    chain = _build_chain(session)
    composition = _full_composition(collector=LiveReadOnlyProxmoxCollector())
    composition = EligibilityPreflightComposition(
        gate=composition.gate,
        live_read_gate=composition.live_read_gate,
        secret_resolver=composition.secret_resolver,
        transport_factory=lambda vc, tok: _NodesOnlyTransport(),
        collector=LiveReadOnlyProxmoxCollector(),
        authorization_verifier=composition.authorization_verifier,
    )
    result = run_real_eligibility_preflight(
        session, request=chain.request(), composition=composition, now=NOW
    )
    assert result.outcome == EligibilityOutcome.unverifiable.value
    pf = session.get(TargetPreflight, result.preflight_id)
    assert pf.passed is False


# --- Idempotency ---------------------------------------------------------------------------------


def test_exact_retry_is_idempotent(session, principal):
    chain = _build_chain(session)
    first = run_real_eligibility_preflight(
        session, request=chain.request(), composition=_full_composition(), now=NOW
    )
    second = run_real_eligibility_preflight(
        session,
        request=chain.request(),
        composition=_full_composition(),
        now=NOW + timedelta(minutes=1),
    )
    assert second.reused is True
    assert second.preflight_id == first.preflight_id
    assert len(_preflight_rows(session)) == 1
    completed = [
        a
        for a in _audit_actions(session, chain.org_id)
        if a == AuditAction.eligibility_preflight_completed
    ]
    assert len(completed) == 1  # no duplicate success audit


# --- Refusals (each fails closed, persists no evidence) ------------------------------------------


def _refusal_cases():
    from secp_api.enums import TargetStatus

    other_conn = connection_identity_hash(
        {"base_url": "https://x.test:8006/api2/json", "verify_tls": True}
    )
    return {
        "boundary_drift": (
            dict(boundary_hash=content_hash({"changed": True})),
            {},
            "boundary_drift",
        ),
        "auth_boundary_drift": (
            dict(auth_boundary_hash=content_hash({"changed": True})),
            {},
            "boundary_drift",
        ),
        "config_drift": (dict(connection_hash=other_conn), {}, "config_drift"),
        "expired_auth": (dict(auth_expiry=NOW - timedelta(hours=1)), {}, "authorization_invalid"),
        "revoked_auth": (
            dict(auth_status=LiveReadAuthorizationStatus.revoked),
            {},
            "authorization_invalid",
        ),
        "draft_auth": (
            dict(auth_status=LiveReadAuthorizationStatus.draft),
            {},
            "authorization_invalid",
        ),
        "onboarding_not_active": (
            dict(onboarding_status=OnboardingStatus.approved),
            {},
            "onboarding_not_active",
        ),
        "target_not_active": (
            dict(target_status=TargetStatus.disabled),
            {},
            "onboarding_not_active",
        ),
        "auth_version_drift": ({}, dict(authorization_version=99), "authorization_invalid"),
        "contract_version": (
            dict(collector_contract_version="wrong/contract/v9"),
            {},
            "contract_version_mismatch",
        ),
        "allowlist_version": (
            dict(endpoint_allowlist_version="wrong/allowlist/v9"),
            {},
            "policy_version_mismatch",
        ),
        "evidence_source_drift": (dict(evidence_source="not_live"), {}, "authorization_invalid"),
        "worker_not_approved": (
            dict(worker_status=WorkerIdentityStatus.draft),
            {},
            "worker_identity_untrusted",
        ),
        "worker_expired": (
            dict(worker_expiry=NOW - timedelta(hours=1)),
            {},
            "worker_identity_untrusted",
        ),
        "worker_missing": (
            {},
            dict(worker_identity_registration_id=uuid.uuid4()),
            "worker_identity_untrusted",
        ),
        "wrong_org": ({}, dict(organization_id=uuid.uuid4()), "authorization_invalid"),
    }


@pytest.mark.parametrize("case", list(_refusal_cases()))
def test_gate_refusals_fail_closed(session, principal, case):
    over, req_over, expected_reason = _refusal_cases()[case]
    chain = _build_chain(session, over=over)
    result = run_real_eligibility_preflight(
        session, request=chain.request(**req_over), composition=_full_composition(), now=NOW
    )
    assert result.outcome == EligibilityOutcome.refused.value
    assert result.reason_category == expected_reason
    assert _preflight_rows(session) == []
    assert session.execute(select(TargetEvidenceRecord)).scalars().all() == []


def test_gate_incomplete_when_seam_missing(session, principal):
    chain = _build_chain(session)
    composition = EligibilityPreflightComposition(
        gate=EligibilityPreflightGate(enabled=True),
        live_read_gate=LiveReadCollectionGate(enabled=True),
        secret_resolver=None,  # missing seam
        transport_factory=_transport_factory,
        collector=_EligibleCollector(),
        authorization_verifier=_AllowVerifier(),
    )
    result = run_real_eligibility_preflight(
        session, request=chain.request(), composition=composition, now=NOW
    )
    assert result.outcome == EligibilityOutcome.refused.value
    assert result.reason_category == "gate_incomplete"
    assert _preflight_rows(session) == []


def test_disabled_inner_live_gate_refuses(session, principal):
    chain = _build_chain(session)
    composition = EligibilityPreflightComposition(
        gate=EligibilityPreflightGate(enabled=True),
        live_read_gate=LiveReadCollectionGate(enabled=False),  # Path B stays dormant
        secret_resolver=_Resolver(),
        transport_factory=_transport_factory,
        collector=_EligibleCollector(),
        authorization_verifier=_AllowVerifier(),
    )
    result = run_real_eligibility_preflight(
        session, request=chain.request(), composition=composition, now=NOW
    )
    assert result.outcome == EligibilityOutcome.refused.value
    assert result.reason_category == "gate_incomplete"


# --- Fake evidence can never satisfy live eligibility --------------------------------------------


def test_simulated_payload_rejected_by_live_recorder(session, principal):
    """A relabelled/simulated payload carried on a typed evaluation is refused by the worker-only
    recorder — the (source, level) allowlist is an additional check on top of worker-origination."""
    from secp_api.eligibility_policy import EligibilityEvaluation
    from secp_api.target_evidence import SIMULATED_EVIDENCE_SOURCE, TARGET_EVIDENCE_SCHEMA_VERSION
    from secp_worker.onboarding.eligibility_recorder import (
        LiveEligibilityRecordingRefused,
        record_live_eligibility_evidence,
    )

    chain = _build_chain(session)
    simulated_payload = {
        "schema_version": TARGET_EVIDENCE_SCHEMA_VERSION,
        "evidence_source": SIMULATED_EVIDENCE_SOURCE,
        "verification_level": VerificationLevel.simulated.value,
        "observed": dict(ELIGIBLE_OBSERVED),
    }
    # The recorder takes the payload ONLY from the typed evaluation — never a separate dict.
    evaluation = EligibilityEvaluation(
        outcome=EligibilityOutcome.eligible.value,
        policy_version="x",
        dimensions=(),
        evidence_payload=simulated_payload,
        findings=(),
    )
    with pytest.raises(LiveEligibilityRecordingRefused):
        record_live_eligibility_evidence(
            session,
            onboarding=chain.onboarding,
            target=chain.target,
            evaluation=evaluation,
            operation_fingerprint="sha256:" + "0" * 64,
            collector_identity="worker:x",
            live_read_authorization_id=chain.authorization.id,
            live_read_authorization_version=1,
            worker_identity_registration_id=chain.worker_reg.id,
            now=NOW,
        )
