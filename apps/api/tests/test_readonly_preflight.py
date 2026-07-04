"""SECP-B2-0 — app-owned read-only staging preflight (service + durable worker consumer).

Fake-only, no real target connection. Covers substrate-scoped authorization create/approve/revoke,
queue-only API, worker durable lifecycle, authorization expiry/revocation mapping,
credential_unavailable (sealed resolver), policy-refusal + ready via injected fakes, idempotency,
immutability, org scoping, and secret/endpoint-free serialization.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.enums import (
    IsolationModel,
    LiveReadAuthorizationStatus,
    OnboardingMode,
    OnboardingStatus,
    ReadonlyPreflightOutcome,
    ReadonlyPreflightStatus,
    TargetStatus,
)
from secp_api.errors import (
    DomainError,
    ImmutableResourceError,
    ReadonlyPreflightError,
)
from secp_api.live_read_contract import connection_identity_hash
from secp_api.models import (
    AuditEvent,
    ExecutionTarget,
    LiveReadAuthorization,
    ReadonlyStagingPreflight,
    TargetOnboarding,
)
from secp_api.services import readonly_preflight, staging_labs
from secp_worker.preflight.consumer import claim_and_process_one
from secp_worker.preflight.orchestration import (
    _PolicyOrTlsRefusal,
    run_readonly_preflight,
)
from secp_worker.preflight.secret_resolution import (
    ResolutionContract,
    SecretMaterial,
    TrustedResolutionRequest,
    assert_resolution_authorized,
)

OPAQUE_SECRET_REF = "env:SECP_PROVIDER_SECRET__PREFLIGHT"


class _FakeWorkerResolver:
    """Test-only worker resolver: enforces the contract, then returns opaque SecretMaterial.

    Injected in tests ONLY (there is no production resolver). It proves the ready/refused paths
    downstream of a valid secret-resolution boundary without touching any real backend.
    """

    def resolve(
        self,
        request: TrustedResolutionRequest,
        *,
        expectation: ResolutionContract,
        now: datetime,
    ) -> SecretMaterial:
        assert_resolution_authorized(request.contract, expectation, now=now)
        return SecretMaterial("opaque-test-material")


class _ApprovedIdentity:
    """Test-only approved worker identity (never selectable by production runtime)."""

    def verify(self):
        from secp_worker.preflight.identity import WorkerIdentity

        return WorkerIdentity(worker_identity_id="test-worker")


class _ApprovedGate:
    """Test-only approved activation gate (never selectable by production runtime)."""

    def check(self) -> None:
        return None


def _substrate(session, principal, *, secret_ref=OPAQUE_SECRET_REF):
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="staging substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref=secret_ref,
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


def _approved_authorization(session, principal, target) -> LiveReadAuthorization:
    auth = readonly_preflight.create_preflight_authorization(
        session, principal, execution_target_id=target.id
    )
    return readonly_preflight.approve_preflight_authorization(session, principal, auth.id)


def _queue(session, principal, auth) -> ReadonlyStagingPreflight:
    return readonly_preflight.queue_preflight(
        session, principal, live_read_authorization_id=auth.id
    )


def test_authorization_hashes_are_server_derived(session, principal):
    target = _substrate(session, principal)
    auth = readonly_preflight.create_preflight_authorization(
        session, principal, execution_target_id=target.id
    )
    assert auth.status == LiveReadAuthorizationStatus.draft
    assert auth.connection_hash == connection_identity_hash(target.config)
    assert auth.boundary_hash == "sha256:" + "cd" * 32  # onboarding boundary hash
    # Short-lived by construction.
    assert auth.authorization_expiry <= datetime.now(UTC) + timedelta(seconds=3601)


def test_queue_only_then_worker_fails_closed_credential_unavailable(session, principal):
    target = _substrate(session, principal)
    auth = _approved_authorization(session, principal, target)
    pf = _queue(session, principal, auth)
    assert pf.status == ReadonlyPreflightStatus.queued
    assert pf.outcome_code is None
    assert pf.readiness_facts is None

    # The WORKER (sealed resolver by default) claims + processes it, failing closed.
    assert claim_and_process_one(session) == pf.id
    session.refresh(pf)
    assert pf.status == ReadonlyPreflightStatus.completed
    assert pf.outcome_code == ReadonlyPreflightOutcome.credential_unavailable
    assert pf.readiness_facts is None


def test_authorization_version_is_monotonic_and_supports_renewal(session, principal):
    target = _substrate(session, principal)
    first = readonly_preflight.create_preflight_authorization(
        session, principal, execution_target_id=target.id
    )
    assert first.authorization_version == 1
    readonly_preflight.approve_preflight_authorization(session, principal, first.id)
    readonly_preflight.revoke_preflight_authorization(session, principal, first.id, "operator")
    # Renewal after the prior authorization is no longer usable: a NEW authorization for the same
    # target+onboarding gets a monotonically higher version (not blocked by the version unique key).
    second = readonly_preflight.create_preflight_authorization(
        session, principal, execution_target_id=target.id
    )
    assert second.authorization_version == 2
    assert second.execution_target_id == first.execution_target_id
    assert second.onboarding_id == first.onboarding_id
    # A preflight binds to the exact authorization + version it was created for.
    readonly_preflight.approve_preflight_authorization(session, principal, second.id)
    pf = readonly_preflight.queue_preflight(
        session, principal, live_read_authorization_id=second.id
    )
    assert pf.live_read_authorization_id == second.id
    assert pf.authorization_version == 2


def test_stale_worker_terminal_cas_writes_no_facts_or_terminal_audit(session, principal):
    from secp_api.models import ReadonlyStagingPreflight
    from sqlalchemy import update

    target = _substrate(session, principal)
    auth = _approved_authorization(session, principal, target)
    pf = _queue(session, principal, auth)

    class _DriftingRunner:
        """Simulates another operation advancing the preflight's revision mid-run."""

        def run(self, *, verified, credential, now):
            session.execute(
                update(ReadonlyStagingPreflight)
                .where(ReadonlyStagingPreflight.id == pf.id)
                .values(revision=ReadonlyStagingPreflight.revision + 5)
                .execution_options(synchronize_session=False)
            )
            session.flush()
            return {"api_reachable": True, "node_count": 1}

    claim_and_process_one(
        session,
        secret_resolver=_FakeWorkerResolver(),
        collection_runner=_DriftingRunner(),
        identity_verifier=_ApprovedIdentity(),
        activation_gate=_ApprovedGate(),
    )
    session.refresh(pf)
    # The terminal CAS expected the pre-run revision; it drifted -> CAS fails -> fail closed:
    # no readiness facts, no outcome code, and the state is NOT overwritten to a terminal.
    assert pf.readiness_facts is None
    assert pf.outcome_code is None
    assert pf.status == ReadonlyPreflightStatus.running
    # And no terminal (completed/refused/failed) audit was emitted after the failed CAS.
    terminal_actions = {
        "readonly_preflight.completed",
        "readonly_preflight.refused",
        "readonly_preflight.failed",
    }
    events = session.query(AuditEvent).all()
    assert [e for e in events if e.action in terminal_actions] == []


def test_expired_authorization_maps_to_expired_outcome(session, principal):
    target = _substrate(session, principal)
    auth = _approved_authorization(session, principal, target)
    pf = _queue(session, principal, auth)
    # Force expiry in the past (bypasses immutability guard via a raw UPDATE-like assignment on a
    # committed row would be blocked; instead expire the authorization's expiry directly here is a
    # protected field — so use the verifier path with now in the far future).
    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=_FakeWorkerResolver(),
        now=auth.authorization_expiry + timedelta(seconds=1),
    )
    assert result.outcome == ReadonlyPreflightOutcome.authorization_expired


def test_revoked_authorization_maps_to_revoked_outcome(session, principal):
    target = _substrate(session, principal)
    auth = _approved_authorization(session, principal, target)
    pf = _queue(session, principal, auth)
    readonly_preflight.revoke_preflight_authorization(session, principal, auth.id, "operator")
    result = run_readonly_preflight(session, pf.id, secret_resolver=_FakeWorkerResolver())
    assert result.outcome == ReadonlyPreflightOutcome.authorization_revoked


def test_ready_and_policy_refusal_via_injected_collection_runner(session, principal):
    target = _substrate(session, principal)
    auth = _approved_authorization(session, principal, target)
    pf = _queue(session, principal, auth)

    class _ReadyRunner:
        def run(self, *, verified, credential, now):
            return {"api_reachable": True, "node_count": 3, "endpoint": "SHOULD_BE_DROPPED"}

    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=_FakeWorkerResolver(),
        collection_runner=_ReadyRunner(),
        identity_verifier=_ApprovedIdentity(),
        activation_gate=_ApprovedGate(),
    )
    assert result.outcome == ReadonlyPreflightOutcome.ready
    # Only safe facts survive; the stray 'endpoint' key is dropped.
    assert result.readiness_facts == {"api_reachable": True, "node_count": 3}

    class _RefusingRunner:
        def run(self, *, verified, credential, now):
            raise _PolicyOrTlsRefusal("tls refusal")

    # A distinct operation (fresh substrate/auth/preflight): the prior operation already holds a
    # single-use lease, so the refusal path must run against its own operation key.
    target2 = _substrate(session, principal)
    auth2 = _approved_authorization(session, principal, target2)
    pf2 = _queue(session, principal, auth2)
    result2 = run_readonly_preflight(
        session,
        pf2.id,
        secret_resolver=_FakeWorkerResolver(),
        collection_runner=_RefusingRunner(),
        identity_verifier=_ApprovedIdentity(),
        activation_gate=_ApprovedGate(),
    )
    assert result2.outcome == ReadonlyPreflightOutcome.tls_or_policy_refused


def test_sealed_resolver_fails_closed_before_transport_or_collector(session, principal):
    """SECP-B2-1 ordering: with the shipped sealed resolver, the secret-resolution boundary fails
    closed and the (would-be transport) collection runner is NEVER reached."""
    from secp_worker.preflight.sealed_secret_resolver import SealedSecretResolver

    target = _substrate(session, principal)
    auth = _approved_authorization(session, principal, target)
    pf = _queue(session, principal, auth)

    class _TripwireRunner:
        called = False

        def run(self, *, verified, credential, now):  # pragma: no cover - must never run
            _TripwireRunner.called = True
            raise AssertionError("collection runner must not be reached under the sealed resolver")

    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=SealedSecretResolver(),
        collection_runner=_TripwireRunner(),
    )
    assert result.outcome == ReadonlyPreflightOutcome.credential_unavailable
    assert result.readiness_facts is None
    assert _TripwireRunner.called is False


def test_request_is_not_built_until_verification_succeeds(session, principal):
    """A failed verification (expired authorization) short-circuits BEFORE the secret-resolution
    boundary — no trusted resolution request is constructed and the resolver is never invoked."""

    target = _substrate(session, principal)
    auth = _approved_authorization(session, principal, target)
    pf = _queue(session, principal, auth)

    class _SpyResolver:
        invoked = False

        def resolve(
            self,
            request: TrustedResolutionRequest,
            *,
            expectation: ResolutionContract,
            now,
        ) -> SecretMaterial:  # pragma: no cover - must never run
            _SpyResolver.invoked = True
            return SecretMaterial("x")

    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=_SpyResolver(),
        now=auth.authorization_expiry + timedelta(seconds=1),
    )
    assert result.outcome == ReadonlyPreflightOutcome.authorization_expired
    assert _SpyResolver.invoked is False


def test_queue_is_idempotent_by_fingerprint(session, principal):
    target = _substrate(session, principal)
    auth = _approved_authorization(session, principal, target)
    first = _queue(session, principal, auth)
    second = _queue(session, principal, auth)
    assert first.id == second.id
    assert session.query(ReadonlyStagingPreflight).count() == 1


def test_queue_requires_approved_authorization(session, principal):
    target = _substrate(session, principal)
    auth = readonly_preflight.create_preflight_authorization(
        session, principal, execution_target_id=target.id
    )  # draft, not approved
    with pytest.raises(DomainError):
        _queue(session, principal, auth)


def test_uneligible_substrate_is_refused(session, principal):
    # Active proxmox target with onboarding but NO staging eligibility.
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="t",
        plugin_name="proxmox",
        config={"base_url": "x"},
        config_hash="sha256:" + "ab" * 32,
        secret_ref=OPAQUE_SECRET_REF,
        status=TargetStatus.active,
        scope_policy={},
        created_by=principal.user_id,
    )
    session.add(target)
    session.flush()
    with pytest.raises(DomainError):
        readonly_preflight.create_preflight_authorization(
            session, principal, execution_target_id=target.id
        )


def test_binding_is_immutable(session, principal):
    target = _substrate(session, principal)
    auth = _approved_authorization(session, principal, target)
    pf = _queue(session, principal, auth)
    session.commit()
    pf.execution_target_id = uuid.uuid4()
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()
    pf = session.get(ReadonlyStagingPreflight, pf.id)
    with pytest.raises(ImmutableResourceError):
        session.delete(pf)
        session.flush()


def test_cross_org_access_refused(session, principal, other_org_principal):
    target = _substrate(session, principal)
    auth = _approved_authorization(session, principal, target)
    pf = _queue(session, principal, auth)
    with pytest.raises(ReadonlyPreflightError) as exc:
        readonly_preflight.get_preflight(session, other_org_principal, pf.id)
    assert exc.value.code == "readonly_preflight_forbidden"


def test_manage_permission_required_to_queue(session, principal):
    from dataclasses import replace

    from secp_api.enums import Permission

    target = _substrate(session, principal)
    auth = _approved_authorization(session, principal, target)
    # onboarding_approve alone can create/approve authorizations but NOT queue a preflight.
    auth_only = replace(principal, permissions=frozenset({Permission.onboarding_approve}))
    with pytest.raises(ReadonlyPreflightError) as exc:
        readonly_preflight.queue_preflight(session, auth_only, live_read_authorization_id=auth.id)
    assert exc.value.code == "readonly_preflight_forbidden"


def test_serialization_and_audit_are_secret_and_endpoint_free(session, principal):
    target = _substrate(session, principal)
    auth = _approved_authorization(session, principal, target)
    pf = _queue(session, principal, auth)
    claim_and_process_one(session)
    session.commit()
    from secp_api.schemas_readonly_preflight import (
        PreflightAuthorizationOut,
        ReadonlyPreflightOut,
    )

    pf = session.get(ReadonlyStagingPreflight, pf.id)
    auth = session.get(LiveReadAuthorization, auth.id)
    # (1) The user-facing API response schemas expose no hashes, secrets, endpoints, or config.
    api_blob = (
        ReadonlyPreflightOut.model_validate(pf).model_dump_json()
        + PreflightAuthorizationOut.model_validate(auth).model_dump_json()
    ).lower()
    for forbidden in ("connection_hash", "boundary_hash", "hash", "base_url", "placeholder", "://"):
        assert forbidden not in api_blob, f"API response leaks {forbidden!r}"

    # (2) Across ALL B2-0 surfaces (responses + audit), no concrete endpoint or secret VALUE leaks.
    events = session.query(AuditEvent).all()
    combined = api_blob + " " + json.dumps([e.data for e in events]).lower()
    for forbidden in (OPAQUE_SECRET_REF.lower(), "env:secp_", "base_url", "placeholder", "://"):
        assert forbidden not in combined, f"leaked {forbidden!r}"
