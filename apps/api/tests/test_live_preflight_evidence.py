"""SECP-B2-4.5 — durable, immutable, secret-free live-preflight evidence boundary (fake-only).

Proves: the strict schema rejects every prohibited (unknown/secret/target/network/free-text/
unbounded) value and canonicalizes deterministically; the sealed writer refuses and persists no
evidence (and records a secret-free refusal audit); the durable writer persists exactly once
(idempotent) with a deterministic hash + secret-free audit; the record is immutable (no update/
delete) via the ORM guard; and the simulated evidence path is untouched. Nothing here contacts a
backend, target, or infrastructure.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from secp_api.enums import (
    IsolationModel,
    LivePreflightEvidenceStatus,
    OnboardingMode,
    OnboardingStatus,
    ResolutionLeaseStatus,
    ResolverActivationEvidenceKind,
    ResolverActivationEvidenceStatus,
    TargetStatus,
    WorkerIdentityEvidenceKind,
    WorkerIdentityEvidenceStatus,
    WorkerIdentityMechanism,
)
from secp_api.errors import ImmutableResourceError
from secp_api.live_preflight_evidence_schema import (
    LIVE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
    LiveEvidencePayloadError,
    build_live_evidence_payload,
    compute_live_evidence_hash,
)
from secp_api.live_read_contract import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    PROXMOX_READONLY_POLICY_VERSION,
)
from secp_api.models import (
    AuditEvent,
    ExecutionTarget,
    LivePreflightEvidence,
    ResolutionLease,
    TargetOnboarding,
)
from secp_api.resolver_activation_contract import RESOLVER_ADAPTER_CONTRACT_VERSION
from secp_api.services import readonly_preflight, resolver_activation, staging_labs
from secp_api.services import worker_identity as wi
from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint
from secp_worker.preflight.live_evidence_writer import (
    DurableLivePreflightEvidenceWriter,
    LivePreflightEvidenceContext,
    LivePreflightEvidenceRefused,
    SealedLivePreflightEvidenceWriter,
)

STATUS = LivePreflightEvidenceStatus
_FACTS = {"api_reachable": True, "readonly_policy_enforced": True, "node_count": 2}
_CHECKS = [
    {"code": "tls_verified", "status": "passed"},
    {"code": "get_only_enforced", "status": "passed"},
    {"code": "fully_segregated_isolation", "status": "unverifiable"},
]


def _now() -> datetime:
    return datetime.now(UTC)


def _substrate(session, principal):
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref="vault:secp/x",
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


def _full_context(session, principal) -> LivePreflightEvidenceContext:
    target = _substrate(session, principal)
    auth = readonly_preflight.create_preflight_authorization(
        session, principal, execution_target_id=target.id
    )
    readonly_preflight.approve_preflight_authorization(session, principal, auth.id)
    pf = readonly_preflight.queue_preflight(session, principal, live_read_authorization_id=auth.id)

    act = resolver_activation.create_activation_authorization(
        session, principal, preflight_id=pf.id
    )
    for kind in ResolverActivationEvidenceKind:
        resolver_activation.record_evidence(
            session,
            principal,
            act.id,
            kind=kind,
            status=ResolverActivationEvidenceStatus.verified,
            proof_id="TKT-1",
            issuer="rev",
        )
    resolver_activation.approve_activation_authorization(session, principal, act.id)

    reg = wi.register_worker_identity(
        session,
        principal,
        mechanism=WorkerIdentityMechanism.mtls_workload_identity,
        identity_label="staging-worker-a",
        deployment_binding="deploy-01",
        verification_anchor_fingerprint=compute_verification_anchor_fingerprint("anchor-v1"),
    )
    for kind in WorkerIdentityEvidenceKind:
        wi.record_evidence(
            session,
            principal,
            reg.id,
            kind=kind,
            status=WorkerIdentityEvidenceStatus.verified,
            proof_id="TKT-1",
            issuer="rev",
        )
    wi.approve_worker_identity(session, principal, reg.id)

    lease = ResolutionLease(
        organization_id=pf.organization_id,
        live_read_authorization_id=pf.live_read_authorization_id,
        authorization_version=pf.authorization_version,
        operation_fingerprint=pf.operation_fingerprint,
        status=ResolutionLeaseStatus.active,
        attempt_count=1,
        lease_expires_at=_now() + timedelta(minutes=5),
        worker_identity_id="staging-worker-a",
        reason_code="",
    )
    session.add(lease)
    session.flush()

    return LivePreflightEvidenceContext(
        organization_id=pf.organization_id,
        preflight_id=pf.id,
        execution_target_id=pf.execution_target_id,
        onboarding_id=pf.onboarding_id,
        live_read_authorization_id=pf.live_read_authorization_id,
        live_read_authorization_version=pf.authorization_version,
        resolver_activation_authorization_id=act.id,
        resolver_activation_authorization_version=act.authorization_version,
        worker_identity_registration_id=reg.id,
        worker_identity_version=reg.identity_version,
        resolution_lease_id=lease.id,
        operation_fingerprint=pf.operation_fingerprint,
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        resolver_contract_version=RESOLVER_ADAPTER_CONTRACT_VERSION,
    )


# --- strict schema ------------------------------------------------------------------------------


def test_schema_canonicalizes_and_hashes_deterministically():
    a = build_live_evidence_payload(status=STATUS.passed, facts=_FACTS, checks=_CHECKS)
    # Same content in a different order canonicalizes identically -> identical hash.
    b = build_live_evidence_payload(
        status=STATUS.passed,
        facts={"node_count": 2, "readonly_policy_enforced": True, "api_reachable": True},
        checks=list(reversed(_CHECKS)),
    )
    assert a == b
    assert compute_live_evidence_hash(a) == compute_live_evidence_hash(b)
    assert a["schema_version"] == LIVE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION


@pytest.mark.parametrize(
    "bad",
    [
        {"status": "bogus", "facts": {}, "checks": []},  # non-closed status
        {"status": STATUS.passed, "facts": {"endpoint": "h"}, "checks": []},  # unknown/secret key
        {"status": STATUS.passed, "facts": {"base_url": "x"}, "checks": []},  # target/network value
        {"status": STATUS.passed, "facts": {"node_count": -1}, "checks": []},  # out-of-range count
        {"status": STATUS.passed, "facts": {"node_count": 10**9}, "checks": []},  # unbounded count
        {"status": STATUS.passed, "facts": {"api_reachable": 1}, "checks": []},  # int not bool
        {"status": STATUS.passed, "facts": {"node_count": "3"}, "checks": []},  # string not int
        {
            "status": STATUS.passed,
            "facts": {},
            "checks": [{"code": "x", "status": "passed"}],
        },  # code
        {
            "status": STATUS.passed,
            "facts": {},
            "checks": [{"code": "tls_verified", "status": "ok"}],
        },
        {"status": STATUS.passed, "facts": {}, "checks": [{"code": "tls_verified"}]},  # missing key
        {
            "status": STATUS.passed,
            "facts": {},
            "checks": [{"code": "tls_verified", "status": "passed", "x": 1}],
        },
        {"status": STATUS.passed, "facts": {}, "checks": "notalist"},
    ],
)
def test_schema_rejects_prohibited_or_malformed_payloads(bad):
    with pytest.raises(LiveEvidencePayloadError):
        build_live_evidence_payload(**bad)


# --- writers ------------------------------------------------------------------------------------


def test_sealed_writer_refuses_and_persists_nothing(session, principal):
    ctx = _full_context(session, principal)
    with pytest.raises(LivePreflightEvidenceRefused) as exc:
        SealedLivePreflightEvidenceWriter().write(
            session, context=ctx, status=STATUS.passed, facts=_FACTS, checks=_CHECKS, now=_now()
        )
    assert exc.value.reason_code == "live_preflight_evidence_writer_sealed"
    session.flush()
    assert session.query(LivePreflightEvidence).count() == 0
    refused = [
        e
        for e in session.query(AuditEvent).all()
        if e.action == "live_preflight_evidence.write_refused"
    ]
    assert len(refused) == 1
    # secret-free refusal audit: only closed reason + schema version + safe ids
    blob = str(refused[0].data).lower()
    for banned in ("secret", "token", "endpoint", "://", "vault"):
        assert banned not in blob


def test_durable_writer_persists_once_with_hash_and_audit(session, principal):
    ctx = _full_context(session, principal)
    writer = DurableLivePreflightEvidenceWriter()
    row = writer.write(
        session, context=ctx, status=STATUS.passed, facts=_FACTS, checks=_CHECKS, now=_now()
    )
    assert row.status == STATUS.passed
    assert row.evidence_hash.startswith("sha256:")
    assert row.evidence_schema_version == LIVE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    assert row.payload["schema_version"] == LIVE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    # Binds the complete authoritative context.
    assert row.preflight_id == ctx.preflight_id
    assert row.worker_identity_registration_id == ctx.worker_identity_registration_id
    assert row.resolver_activation_authorization_id == ctx.resolver_activation_authorization_id
    assert row.resolution_lease_id == ctx.resolution_lease_id
    session.flush()
    written = [
        e for e in session.query(AuditEvent).all() if e.action == "live_preflight_evidence.written"
    ]
    assert len(written) == 1
    # Idempotent / exact-once: a second write returns the SAME row and emits no second audit.
    row2 = writer.write(
        session, context=ctx, status=STATUS.passed, facts=_FACTS, checks=_CHECKS, now=_now()
    )
    assert row2.id == row.id
    session.flush()
    assert session.query(LivePreflightEvidence).count() == 1
    written2 = [
        e for e in session.query(AuditEvent).all() if e.action == "live_preflight_evidence.written"
    ]
    assert len(written2) == 1


def test_durable_writer_rejects_a_prohibited_payload_before_persisting(session, principal):
    ctx = _full_context(session, principal)
    with pytest.raises(LiveEvidencePayloadError):
        DurableLivePreflightEvidenceWriter().write(
            session,
            context=ctx,
            status=STATUS.passed,
            facts={"endpoint": "leaked-host"},  # prohibited key/value
            checks=[],
            now=_now(),
        )
    session.flush()
    assert session.query(LivePreflightEvidence).count() == 0


def test_persisted_payload_contains_no_prohibited_value(session, principal):
    ctx = _full_context(session, principal)
    row = DurableLivePreflightEvidenceWriter().write(
        session, context=ctx, status=STATUS.passed, facts=_FACTS, checks=_CHECKS, now=_now()
    )
    blob = str(row.payload).lower()
    for banned in ("secret", "token", "endpoint", "://", "vault", "base_url", "host", "cert"):
        assert banned not in blob


# --- immutability (ORM) --------------------------------------------------------------------------


def test_live_evidence_is_immutable_via_orm(session, principal):
    ctx = _full_context(session, principal)
    row = DurableLivePreflightEvidenceWriter().write(
        session, context=ctx, status=STATUS.passed, facts=_FACTS, checks=_CHECKS, now=_now()
    )
    session.commit()
    # No field may change.
    row.status = STATUS.failed
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()
    # No deletion.
    row = session.get(LivePreflightEvidence, row.id)
    session.delete(row)
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()


def test_simulated_target_evidence_path_is_untouched():
    # The live schema is SEPARATE from the simulated target-evidence schema/source; importing the
    # live schema does not alter the simulated evidence source constant.
    from secp_api.target_evidence import SIMULATED_EVIDENCE_SOURCE

    assert SIMULATED_EVIDENCE_SOURCE != LIVE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    assert "live" not in SIMULATED_EVIDENCE_SOURCE.lower()
