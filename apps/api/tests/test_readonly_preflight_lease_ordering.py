"""SECP-B2-3 — worker ordering + default fail-closed stop point (fake-only, no contact).

Proves the required order (re-verify -> pinned policy -> three-way binding -> identity -> gate ->
lease -> begin-attempt -> sealed secret boundary) and that the SHIPPED default (deny-by-default
identity, disabled activation gate) stops BEFORE any durable lease is acquired or attempt begun,
still terminating as ``credential_unavailable``. Also proves the three-way credential-reference
binding fails closed on a mismatch.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from secp_api.enums import (
    AuditAction,
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    ReadonlyPreflightOutcome,
    ResolverActivationEvidenceKind,
    ResolverActivationEvidenceStatus,
    TargetStatus,
)
from secp_api.live_read_contract import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    LIVE_READ_EVIDENCE_SOURCE,
    LIVE_VERIFIED_LEVEL,
    PROXMOX_READONLY_POLICY_VERSION,
)
from secp_api.models import (
    AuditEvent,
    ExecutionTarget,
    LiveReadAuthorization,
    ResolutionLease,
    TargetOnboarding,
)
from secp_api.services import readonly_preflight, resolver_activation, staging_labs
from secp_worker.preflight.orchestration import (
    _three_way_reference_match,
    run_readonly_preflight,
)
from secp_worker.preflight.secret_resolution import (
    ResolutionPurpose,
    SecretMaterial,
    TrustedCredentialReference,
    TrustedResolutionRequest,
    build_trusted_resolution_request,
)

OPAQUE_REF = "env:SECP_PROVIDER_SECRET__PREFLIGHT"


class _ApprovedGate:
    def check(self) -> None:
        return None


class _CapturingResolver:
    invoked = False

    def resolve(self, request, *, expectation, now) -> SecretMaterial:
        type(self).invoked = True
        raise AssertionError("resolver must not be reached when identity/gate fail closed")


def _substrate(session, principal):
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref=OPAQUE_REF,
        status=TargetStatus.active,
        scope_policy={},
        created_by=principal.user_id,
    )
    session.add(target)
    session.flush()
    session.add(
        TargetOnboarding(
            organization_id=principal.organization_id,
            execution_target_id=target.id,
            onboarding_mode=OnboardingMode.existing_environment,
            isolation_model=IsolationModel.logical,
            status=OnboardingStatus.active,
            declared_boundary={},
            boundary_hash="sha256:" + "cd" * 32,
            created_by=principal.user_id,
        )
    )
    session.flush()
    staging_labs.grant_substrate_eligibility(session, principal, execution_target_id=target.id)
    return target


def _queued(session, principal):
    target = _substrate(session, principal)
    auth = readonly_preflight.create_preflight_authorization(
        session, principal, execution_target_id=target.id
    )
    readonly_preflight.approve_preflight_authorization(session, principal, auth.id)
    return readonly_preflight.queue_preflight(
        session, principal, live_read_authorization_id=auth.id
    )


def _approve_activation(session, principal, pf) -> None:
    """Create + fully-evidence + approve the durable resolver-activation authorization for a queued
    preflight so the SECP-B2-4.2 mandatory pre-lease activation check passes (authoritative durable
    records — never an injected capability)."""
    row = resolver_activation.create_activation_authorization(
        session, principal, preflight_id=pf.id
    )
    for kind in ResolverActivationEvidenceKind:
        resolver_activation.record_evidence(
            session,
            principal,
            row.id,
            kind=kind,
            status=ResolverActivationEvidenceStatus.verified,
            proof_id="TKT-1",
            issuer="reviewer",
        )
    resolver_activation.approve_activation_authorization(session, principal, row.id)


def _lease_audit_actions() -> set[str]:
    return {
        AuditAction.resolution_lease_acquired.value,
        AuditAction.resolution_lease_attempt_started.value,
        AuditAction.resolution_lease_refused.value,
        AuditAction.resolution_lease_consumed.value,
    }


def test_shipped_default_stops_before_lease_and_begin_attempt(session, principal):
    """Default deny-by-default identity: no lease row, no begin-attempt, credential_unavailable."""
    pf = _queued(session, principal)
    resolver = _CapturingResolver()
    result = run_readonly_preflight(session, pf.id, secret_resolver=resolver)
    assert result.outcome == ReadonlyPreflightOutcome.credential_unavailable
    assert _CapturingResolver.invoked is False  # never reached the secret boundary
    # No durable lease row and no lease audit under default runtime wiring.
    session.flush()  # session is autoflush=False; surface any (regression) pending audit rows
    assert session.query(ResolutionLease).count() == 0
    lease_events = [
        e for e in session.query(AuditEvent).all() if e.action in _lease_audit_actions()
    ]
    assert lease_events == []


def test_disabled_gate_with_approved_identity_still_stops_before_lease(
    session, principal, worker_identity_verifier
):
    pf = _queued(session, principal)
    from secp_worker.preflight.activation_gate import SealedActivationGate

    resolver = _CapturingResolver()
    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=resolver,
        identity_verifier=worker_identity_verifier(),
        activation_gate=SealedActivationGate(),
    )
    assert result.outcome == ReadonlyPreflightOutcome.credential_unavailable
    assert _CapturingResolver.invoked is False
    assert session.query(ResolutionLease).count() == 0


def test_approved_identity_and_gate_reach_lease_begin_attempt_then_sealed_resolver(
    session, principal, worker_identity_verifier
):
    """With approved identity + gate (test-only), the durable lease + begin-attempt run, then the
    SEALED resolver still fails closed -> credential_unavailable. One attempt is consumed."""
    from secp_worker.preflight.sealed_secret_resolver import SealedSecretResolver

    pf = _queued(session, principal)
    _approve_activation(session, principal, pf)  # SECP-B2-4.2 mandatory pre-lease activation gate
    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=SealedSecretResolver(),
        identity_verifier=worker_identity_verifier(),
        activation_gate=_ApprovedGate(),
    )
    assert result.outcome == ReadonlyPreflightOutcome.credential_unavailable
    lease = session.query(ResolutionLease).one()
    assert lease.live_read_authorization_id == pf.live_read_authorization_id
    assert lease.authorization_version == pf.authorization_version
    assert lease.attempt_count == 1  # begin-attempt ran exactly once before the sealed boundary
    assert lease.worker_identity_id == "staging-worker-a"  # durable registration label
    # Both an acquire and an attempt_started audit were emitted (secret-free).
    session.flush()  # session is autoflush=False; make pending audit rows queryable
    actions = {e.action for e in session.query(AuditEvent).all()}
    assert AuditAction.resolution_lease_acquired.value in actions
    assert AuditAction.resolution_lease_attempt_started.value in actions


# --- Three-way credential-reference binding ------------------------------------------------------


def _verified(*, target_ref: str, binding_ref: str):
    from secp_worker.onboarding.live_authorization import VerifiedLiveReadAuthorization
    from secp_worker.onboarding.live_readonly import LiveReadCollectionBinding

    tid, oid, aid = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    target = ExecutionTarget(organization_id=uuid.uuid4(), secret_ref=target_ref)
    target.id = tid
    binding = LiveReadCollectionBinding(
        execution_target_id=str(tid),
        target_config_hash="sha256:" + "ab" * 32,
        onboarding_id=str(oid),
        boundary_hash="sha256:" + "cd" * 32,
        authorization_id=str(aid),
        authorization_version=1,
        authorization_expiry="2999-01-01T00:00:00Z",
        credential_ref=binding_ref,
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


def _request_for(verified) -> TrustedResolutionRequest:
    return build_trusted_resolution_request(
        verified=verified,
        purpose=ResolutionPurpose.readonly_staging_preflight,
        operation_fingerprint="sha256:" + "12" * 32,
        preflight_id=uuid.uuid4(),
        now=datetime(2026, 7, 4, tzinfo=UTC),
    )


def test_three_way_reference_match_accepts_equal_references():
    verified = _verified(target_ref=OPAQUE_REF, binding_ref=OPAQUE_REF)
    assert _three_way_reference_match(verified, _request_for(verified)) is True


def test_three_way_reference_match_rejects_a_binding_mismatch():
    # Target + request references agree, but the verified binding reference differs -> fail closed.
    verified = _verified(target_ref=OPAQUE_REF, binding_ref="env:OTHER_REF")
    # The request derives its reference from the target record, so it equals target_ref.
    request = _request_for(_verified(target_ref=OPAQUE_REF, binding_ref=OPAQUE_REF))
    assert _three_way_reference_match(verified, request) is False


def test_three_way_reference_match_rejects_blank_reference():
    verified = _verified(target_ref="", binding_ref="")

    class _Req:
        class contract:
            credential_reference = TrustedCredentialReference("   ")

    assert _three_way_reference_match(verified, _Req()) is False
