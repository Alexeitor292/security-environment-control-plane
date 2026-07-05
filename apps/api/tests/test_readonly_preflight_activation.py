"""SECP-B2-4.2 — mandatory, load-bearing resolver activation in the sealed preflight chain.

Proves: the durable resolver-activation authorization is independently re-verified BEFORE any
durable lease is acquired; every invalid activation state (missing / draft / revoked / expired)
fails closed with the SAME safe outcome as the sealed chain (``credential_unavailable``) and creates
no lease/attempt/secret/transport/contact; an EXACT valid test-only setup reaches the sealed
resolver boundary yet still produces no credential/transport/contact; the shipped defaults still
stop before the activation check and the lease; a capability cannot be forged by a caller; and the
offline wiring self-test reports the sealed chain. Fake-only: nothing here contacts a backend,
resolves a real secret, or constructs a transport.
"""

from __future__ import annotations

import uuid
from datetime import UTC, timedelta

import pytest
from secp_api.enums import (
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    ReadonlyPreflightOutcome,
    ResolverActivationEvidenceKind,
    ResolverActivationEvidenceStatus,
    TargetStatus,
)
from secp_api.models import ExecutionTarget, ResolutionLease, TargetOnboarding
from secp_api.services import readonly_preflight, resolver_activation, staging_labs
from secp_worker.preflight.activation_authorization import ResolverActivationCapability
from secp_worker.preflight.orchestration import run_readonly_preflight
from secp_worker.preflight.sealed_secret_resolver import SealedSecretResolver
from secp_worker.preflight.self_test import (
    SELF_TEST_SEALED_OK,
    PreflightSelfTestResult,
    run_preflight_wiring_self_test,
)

OPAQUE_REF = "env:SECP_PROVIDER_SECRET__PREFLIGHT"


class _ApprovedIdentity:
    """Test-only approved worker identity (never selectable by production runtime)."""

    def verify(self):
        from secp_worker.preflight.identity import WorkerIdentity

        return WorkerIdentity(worker_identity_id="test-worker")


class _ApprovedGate:
    """Test-only approved activation gate (never selectable by production runtime)."""

    def check(self) -> None:
        return None


class _CredentialReturningResolver:
    """Test-only resolver that would return material — used to prove the collection handoff is
    reached ONLY with a verified capability. Never contacts a backend."""

    def resolve(self, request, *, expectation, now):
        from secp_worker.preflight.secret_resolution import (
            SecretMaterial,
            assert_resolution_authorized,
        )

        assert_resolution_authorized(request.contract, expectation, now=now)
        return SecretMaterial("opaque-test-material")


def _substrate(session, principal) -> ExecutionTarget:
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="staging substrate",
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


def _record_all_evidence(session, principal, activation_id) -> None:
    for kind in ResolverActivationEvidenceKind:
        resolver_activation.record_evidence(
            session,
            principal,
            activation_id,
            kind=kind,
            status=ResolverActivationEvidenceStatus.verified,
            proof_id="TKT-1",
            issuer="reviewer",
        )


def _approved_activation(session, principal, pf, *, ttl_seconds: int = 3600):
    row = resolver_activation.create_activation_authorization(
        session, principal, preflight_id=pf.id, ttl_seconds=ttl_seconds
    )
    _record_all_evidence(session, principal, row.id)
    return resolver_activation.approve_activation_authorization(session, principal, row.id)


def _no_lease(session) -> bool:
    session.flush()  # session is autoflush=False; surface any pending lease row
    return session.query(ResolutionLease).count() == 0


# --- 1. Activation verification is MANDATORY before lease acquisition -----------------------------


def test_missing_activation_authorization_fails_closed_before_lease(session, principal):
    # Approved identity + gate (test-only), but NO durable activation authorization exists: the
    # mandatory pre-lease activation check fails closed with the safe outcome and no lease appears.
    pf = _queued(session, principal)
    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=SealedSecretResolver(),
        identity_verifier=_ApprovedIdentity(),
        activation_gate=_ApprovedGate(),
    )
    assert result.outcome == ReadonlyPreflightOutcome.credential_unavailable
    assert result.readiness_facts is None
    assert _no_lease(session)


def test_valid_activation_reaches_sealed_resolver_but_no_credential_or_contact(session, principal):
    # The EXACT valid setup (approved+evidenced activation + approved identity + gate) passes the
    # activation gate and acquires the durable lease, then the SEALED resolver still fails closed:
    # no SecretMaterial, no transport, no contact. Reaching the lease proves the activation gate
    # was satisfied; the sealed resolver proves nothing is produced.
    from secp_api.enums import AuditAction
    from secp_api.models import AuditEvent

    pf = _queued(session, principal)
    _approved_activation(session, principal, pf)
    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=SealedSecretResolver(),
        identity_verifier=_ApprovedIdentity(),
        activation_gate=_ApprovedGate(),
    )
    assert result.outcome == ReadonlyPreflightOutcome.credential_unavailable
    assert result.readiness_facts is None
    lease = session.query(ResolutionLease).one()  # reached the lease (activation passed)
    assert lease.attempt_count == 1
    assert lease.worker_identity_id == "test-worker"
    session.flush()
    actions = {e.action for e in session.query(AuditEvent).all()}
    assert AuditAction.resolution_lease_acquired.value in actions


def test_valid_activation_gates_the_collection_handoff(session, principal):
    # With a test resolver that returns material, the collection runner IS reached — and it receives
    # the verified, redacted, non-serializable capability (the governed handoff is bound to it).
    pf = _queued(session, principal)
    _approved_activation(session, principal, pf)

    seen: dict[str, object] = {}

    class _CapturingRunner:
        def run(self, *, verified, credential, capability, now):
            seen["capability"] = capability
            return {"api_reachable": True, "node_count": 1}

    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=_CredentialReturningResolver(),
        collection_runner=_CapturingRunner(),
        identity_verifier=_ApprovedIdentity(),
        activation_gate=_ApprovedGate(),
    )
    assert result.outcome == ReadonlyPreflightOutcome.ready
    assert isinstance(seen["capability"], ResolverActivationCapability)
    # The capability is redacted + non-serializable even where the collector receives it.
    assert repr(seen["capability"]) == "ResolverActivationCapability(<redacted>)"


# --- 2. Each invalid activation state fails closed (safe outcome, no lease) -----------------------


def test_draft_activation_fails_closed_before_lease(session, principal):
    pf = _queued(session, principal)
    row = resolver_activation.create_activation_authorization(
        session, principal, preflight_id=pf.id
    )
    _record_all_evidence(session, principal, row.id)  # complete evidence but NOT approved
    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=SealedSecretResolver(),
        identity_verifier=_ApprovedIdentity(),
        activation_gate=_ApprovedGate(),
    )
    assert result.outcome == ReadonlyPreflightOutcome.credential_unavailable
    assert _no_lease(session)


def test_revoked_activation_fails_closed_before_lease(session, principal):
    pf = _queued(session, principal)
    row = _approved_activation(session, principal, pf)
    resolver_activation.revoke_activation_authorization(session, principal, row.id, "operator")
    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=SealedSecretResolver(),
        identity_verifier=_ApprovedIdentity(),
        activation_gate=_ApprovedGate(),
    )
    assert result.outcome == ReadonlyPreflightOutcome.credential_unavailable
    assert _no_lease(session)


def test_expired_activation_fails_closed_before_lease(session, principal):
    # A SHORT-lived (60s) activation is expired at a later `now` chosen to sit strictly BETWEEN the
    # activation expiry and the (longer-lived) live-read authorization expiry, so verification gets
    # past the live-read step and fails specifically at the activation check, before any lease.
    from secp_api.models import LiveReadAuthorization

    def _as_utc(value):  # SQLite drops tzinfo on reload; normalize to UTC-aware for arithmetic
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)

    pf = _queued(session, principal)
    activation = _approved_activation(session, principal, pf, ttl_seconds=60)
    live_read = session.get(LiveReadAuthorization, pf.live_read_authorization_id)
    later = _as_utc(activation.authorization_expiry) + timedelta(seconds=5)
    assert later < _as_utc(live_read.authorization_expiry)  # live-read still valid at `later`
    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=SealedSecretResolver(),
        identity_verifier=_ApprovedIdentity(),
        activation_gate=_ApprovedGate(),
        now=later,
    )
    assert result.outcome == ReadonlyPreflightOutcome.credential_unavailable
    assert _no_lease(session)


def test_activation_for_a_different_preflight_does_not_authorize_this_one(session, principal):
    # A valid activation bound to operation A never authorizes operation B: the verifier finds no
    # approved activation for B's preflight id and fails closed.
    pf_a = _queued(session, principal)
    _approved_activation(session, principal, pf_a)
    pf_b = _queued(session, principal)  # distinct target/onboarding/authorization/preflight
    result = run_readonly_preflight(
        session,
        pf_b.id,
        secret_resolver=SealedSecretResolver(),
        identity_verifier=_ApprovedIdentity(),
        activation_gate=_ApprovedGate(),
    )
    assert result.outcome == ReadonlyPreflightOutcome.credential_unavailable
    # Only operation A ever reached a lease (none for B).
    leases = session.query(ResolutionLease).all()
    assert all(
        lease.live_read_authorization_id == pf_a.live_read_authorization_id for lease in leases
    )


# --- 3. Shipped defaults still stop BEFORE the activation check and the lease ---------------------


def test_shipped_defaults_stop_before_activation_and_lease(session, principal):
    # Even with a fully valid, approved activation authorization present, the SHIPPED default deny
    # identity stops the run before the activation check and before any lease is created.
    pf = _queued(session, principal)
    _approved_activation(session, principal, pf)
    result = run_readonly_preflight(session, pf.id, secret_resolver=SealedSecretResolver())
    assert result.outcome == ReadonlyPreflightOutcome.credential_unavailable
    assert result.readiness_facts is None
    assert _no_lease(session)


# --- 4. A capability cannot be forged / injected by a caller --------------------------------------


def test_capability_cannot_be_constructed_by_a_caller():
    with pytest.raises(TypeError):
        ResolverActivationCapability(
            authorization_id=uuid.uuid4(),
            operation_fingerprint="sha256:" + "00" * 32,
            token=object(),
        )


# --- 5. Offline, secret-free wiring self-test -----------------------------------------------------


def test_self_test_reports_sealed_wiring_offline_and_creates_no_lease(session, principal):
    result = run_preflight_wiring_self_test()
    assert isinstance(result, PreflightSelfTestResult)
    assert result.status == SELF_TEST_SEALED_OK
    # Only safe booleans; the sealed chain + mandatory activation verifier are all confirmed.
    assert set(result.facts.values()) == {True}
    assert result.facts["activation_capability_required"] is True
    assert result.facts["identity_denies_by_default"] is True
    # It resolved nothing and touched no durable state.
    assert _no_lease(session)
