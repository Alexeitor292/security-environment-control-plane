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
from secp_api.errors import AuthorizationError, DomainError, ImmutableResourceError
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
from secp_worker.secrets import FakeSecretResolver

OPAQUE_SECRET_REF = "env:SECP_PROVIDER_SECRET__PREFLIGHT"


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
        secret_resolver=FakeSecretResolver({OPAQUE_SECRET_REF: "x"}),
        now=auth.authorization_expiry + timedelta(seconds=1),
    )
    assert result.outcome == ReadonlyPreflightOutcome.authorization_expired


def test_revoked_authorization_maps_to_revoked_outcome(session, principal):
    target = _substrate(session, principal)
    auth = _approved_authorization(session, principal, target)
    pf = _queue(session, principal, auth)
    readonly_preflight.revoke_preflight_authorization(session, principal, auth.id, "operator")
    result = run_readonly_preflight(
        session, pf.id, secret_resolver=FakeSecretResolver({OPAQUE_SECRET_REF: "x"})
    )
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
        secret_resolver=FakeSecretResolver({OPAQUE_SECRET_REF: "x"}),
        collection_runner=_ReadyRunner(),
    )
    assert result.outcome == ReadonlyPreflightOutcome.ready
    # Only safe facts survive; the stray 'endpoint' key is dropped.
    assert result.readiness_facts == {"api_reachable": True, "node_count": 3}

    class _RefusingRunner:
        def run(self, *, verified, credential, now):
            raise _PolicyOrTlsRefusal("tls refusal")

    result2 = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=FakeSecretResolver({OPAQUE_SECRET_REF: "x"}),
        collection_runner=_RefusingRunner(),
    )
    assert result2.outcome == ReadonlyPreflightOutcome.tls_or_policy_refused


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
    with pytest.raises(AuthorizationError):
        readonly_preflight.get_preflight(session, other_org_principal, pf.id)


def test_manage_permission_required_to_queue(session, principal):
    from dataclasses import replace

    from secp_api.enums import Permission

    target = _substrate(session, principal)
    auth = _approved_authorization(session, principal, target)
    # onboarding_approve alone can create/approve authorizations but NOT queue a preflight.
    auth_only = replace(principal, permissions=frozenset({Permission.onboarding_approve}))
    with pytest.raises(AuthorizationError):
        readonly_preflight.queue_preflight(session, auth_only, live_read_authorization_id=auth.id)


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
