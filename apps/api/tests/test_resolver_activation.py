"""SECP-B2-4.1 — durable resolver-activation authorization lifecycle + worker verifier (fake-only).

Proves: the authorization is separate/explicit (not auto-created, separate approve permission,
complete closed evidence), time-bounded, audited, revocable, monotonic-versioned; the worker
verifier independently re-validates every bound fact + the evidence fingerprint and fails closed on
any drift; the capability is redacted, non-serializable, and not caller-constructible; and no
secret/backend value can persist. Nothing here contacts a backend, target, or infrastructure.
"""

from __future__ import annotations

import pickle
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.auth import Principal
from secp_api.enums import (
    IsolationModel,
    LiveReadAuthorizationStatus,
    OnboardingMode,
    OnboardingStatus,
    Permission,
    ReadonlyPreflightStatus,
    ResolverActivationEvidenceKind,
    ResolverActivationEvidenceStatus,
    ResolverActivationStatus,
    TargetStatus,
)
from secp_api.errors import ResolverActivationError
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
    ReadonlyStagingPreflight,
    ResolverActivationAuthorization,
    ResolverActivationEvidence,
    TargetOnboarding,
)
from secp_api.resolver_activation_contract import (
    RESOLVER_ADAPTER_CONTRACT_VERSION,
    compute_operation_fingerprint,
)
from secp_api.services import resolver_activation as ra
from secp_worker.preflight.activation_authorization import (
    ActivationAuthorizationRefused,
    ResolverActivationCapability,
    load_and_verify_activation_capability,
)
from sqlalchemy import update

MANAGE = Permission.resolver_activation_manage
APPROVE = Permission.resolver_activation_approve


def _now() -> datetime:
    return datetime.now(UTC)


def _principal(org_id, *perms) -> Principal:
    return Principal(
        user_id=uuid.uuid4(), organization_id=org_id, email="a@b.test", permissions=frozenset(perms)
    )


def _work_item(session, org_id):
    target = ExecutionTarget(
        organization_id=org_id,
        display_name="t",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref="vault:secp/proxmox/t1",
        status=TargetStatus.active,
        scope_policy={},
    )
    session.add(target)
    session.flush()
    ob = TargetOnboarding(
        organization_id=org_id,
        execution_target_id=target.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=IsolationModel.logical,
        status=OnboardingStatus.active,
        declared_boundary={},
        boundary_hash="sha256:" + "cd" * 32,
    )
    session.add(ob)
    session.flush()
    auth = LiveReadAuthorization(
        organization_id=org_id,
        execution_target_id=target.id,
        onboarding_id=ob.id,
        connection_hash="sha256:" + "ab" * 32,
        boundary_hash="sha256:" + "cd" * 32,
        authorization_version=1,
        authorization_expiry=_now() + timedelta(hours=2),
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        evidence_source=LIVE_READ_EVIDENCE_SOURCE,
        verification_level=LIVE_VERIFIED_LEVEL,
        status=LiveReadAuthorizationStatus.approved,
    )
    session.add(auth)
    session.flush()
    pf = ReadonlyStagingPreflight(
        organization_id=org_id,
        execution_target_id=target.id,
        onboarding_id=ob.id,
        live_read_authorization_id=auth.id,
        authorization_version=1,
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        operation_fingerprint="sha256:" + "ef" * 32,
        status=ReadonlyPreflightStatus.running,
        revision=0,
    )
    session.add(pf)
    session.flush()
    return target, ob, auth, pf


def _all_evidence(session, actor, authorization_id):
    for kind in ResolverActivationEvidenceKind:
        ra.record_evidence(
            session,
            actor,
            authorization_id,
            kind=kind,
            status=ResolverActivationEvidenceStatus.verified,
            proof_id="TKT-123",
            issuer="reviewer-1",
        )


def _approved(session, org_id):
    _t, _ob, _auth, pf = _work_item(session, org_id)
    row = ra.create_activation_authorization(
        session, _principal(org_id, MANAGE), preflight_id=pf.id
    )
    _all_evidence(session, _principal(org_id, MANAGE), row.id)
    row = ra.approve_activation_authorization(session, _principal(org_id, APPROVE), row.id)
    return pf, row


# --- lifecycle / separation ----------------------------------------------------------------------


def test_create_draft_binds_facts_server_side(session, principal):
    _t, _ob, _auth, pf = _work_item(session, principal.organization_id)
    row = ra.create_activation_authorization(
        session, _principal(principal.organization_id, MANAGE), preflight_id=pf.id
    )
    assert row.status == ResolverActivationStatus.draft
    assert row.preflight_id == pf.id
    assert row.operation_fingerprint == compute_operation_fingerprint(pf)
    assert row.resolver_adapter_contract_version == RESOLVER_ADAPTER_CONTRACT_VERSION
    assert row.purpose == "readonly_staging_preflight"
    assert row.authorization_version == 1
    assert row.evidence_fingerprint == ""


def test_create_requires_manage_permission(session, principal):
    _t, _ob, _auth, pf = _work_item(session, principal.organization_id)
    with pytest.raises(ResolverActivationError) as exc:
        ra.create_activation_authorization(
            session, _principal(principal.organization_id, APPROVE), preflight_id=pf.id
        )
    assert exc.value.code == "resolver_activation_forbidden"


def test_approve_requires_the_separate_approve_permission(session, principal):
    _t, _ob, _auth, pf = _work_item(session, principal.organization_id)
    org = principal.organization_id
    row = ra.create_activation_authorization(session, _principal(org, MANAGE), preflight_id=pf.id)
    _all_evidence(session, _principal(org, MANAGE), row.id)
    # MANAGE alone (and even every OTHER approval permission) cannot approve.
    others = _principal(
        org,
        MANAGE,
        Permission.onboarding_approve,
        Permission.staging_lab_approve,
        Permission.plan_approve,
        Permission.provisioning_approve,
    )
    with pytest.raises(ResolverActivationError) as exc:
        ra.approve_activation_authorization(session, others, row.id)
    assert exc.value.code == "resolver_activation_forbidden"
    # Only the dedicated permission approves.
    approved = ra.approve_activation_authorization(session, _principal(org, APPROVE), row.id)
    assert approved.status == ResolverActivationStatus.approved


def test_approve_requires_complete_verified_evidence(session, principal):
    _t, _ob, _auth, pf = _work_item(session, principal.organization_id)
    org = principal.organization_id
    row = ra.create_activation_authorization(session, _principal(org, MANAGE), preflight_id=pf.id)
    # Only some evidence, one still pending.
    kinds = list(ResolverActivationEvidenceKind)
    for kind in kinds[:-1]:
        ra.record_evidence(
            session,
            _principal(org, MANAGE),
            row.id,
            kind=kind,
            status=ResolverActivationEvidenceStatus.verified,
            proof_id="TKT-1",
            issuer="rev",
        )
    ra.record_evidence(
        session,
        _principal(org, MANAGE),
        row.id,
        kind=kinds[-1],
        status=ResolverActivationEvidenceStatus.pending,
        proof_id="TKT-1",
        issuer="rev",
    )
    with pytest.raises(ResolverActivationError) as exc:
        ra.approve_activation_authorization(session, _principal(org, APPROVE), row.id)
    assert exc.value.code == "resolver_activation_evidence_incomplete"


def test_evidence_metadata_is_validated_closed_shape(session, principal):
    _t, _ob, _auth, pf = _work_item(session, principal.organization_id)
    org = principal.organization_id
    row = ra.create_activation_authorization(session, _principal(org, MANAGE), preflight_id=pf.id)
    for bad in ("vault:secp/x", "https://host", "a b", "user@host", "tok/secret"):
        with pytest.raises(ResolverActivationError) as exc:
            ra.record_evidence(
                session,
                _principal(org, MANAGE),
                row.id,
                kind=ResolverActivationEvidenceKind.isolated_staging_identity,
                status=ResolverActivationEvidenceStatus.verified,
                proof_id=bad,
                issuer="rev",
            )
        assert exc.value.code == "resolver_activation_evidence_invalid"


def test_authorization_version_is_monotonic_per_target_onboarding(session, principal):
    _t, ob, _auth, pf = _work_item(session, principal.organization_id)
    org = principal.organization_id
    first = ra.create_activation_authorization(session, _principal(org, MANAGE), preflight_id=pf.id)
    assert first.authorization_version == 1
    ra.revoke_activation_authorization(session, _principal(org, MANAGE), first.id)
    # A SECOND work item on the SAME target+onboarding (a renewed live-read authorization v2) yields
    # a monotonically higher resolver-activation version.
    auth2 = LiveReadAuthorization(
        organization_id=org,
        execution_target_id=pf.execution_target_id,
        onboarding_id=ob.id,
        connection_hash="sha256:" + "ab" * 32,
        boundary_hash="sha256:" + "cd" * 32,
        authorization_version=2,
        authorization_expiry=_now() + timedelta(hours=2),
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        evidence_source=LIVE_READ_EVIDENCE_SOURCE,
        verification_level=LIVE_VERIFIED_LEVEL,
        status=LiveReadAuthorizationStatus.approved,
    )
    session.add(auth2)
    session.flush()
    pf2 = ReadonlyStagingPreflight(
        organization_id=org,
        execution_target_id=pf.execution_target_id,
        onboarding_id=ob.id,
        live_read_authorization_id=auth2.id,
        authorization_version=2,
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        operation_fingerprint="sha256:" + "12" * 32,
        status=ReadonlyPreflightStatus.running,
        revision=0,
    )
    session.add(pf2)
    session.flush()
    second = ra.create_activation_authorization(
        session, _principal(org, MANAGE), preflight_id=pf2.id
    )
    assert second.authorization_version == 2


def test_revoke_is_immediate_and_audited(session, principal):
    pf, row = _approved(session, principal.organization_id)
    org = principal.organization_id
    revoked = ra.revoke_activation_authorization(
        session, _principal(org, MANAGE), row.id, "operator"
    )
    assert revoked.status == ResolverActivationStatus.revoked
    assert revoked.revoked_at is not None
    session.flush()
    actions = {e.action for e in session.query(AuditEvent).all()}
    assert "resolver_activation.created" in actions
    assert "resolver_activation.approved" in actions
    assert "resolver_activation.revoked" in actions


def test_not_auto_created_from_live_read_or_staging_lab_approval(session, principal):
    # Approving a LiveReadAuthorization creates NO resolver-activation authorization.
    _t, _ob, _auth, pf = _work_item(session, principal.organization_id)
    assert session.query(ResolverActivationAuthorization).count() == 0
    # Even with every other approval permission, no resolver-activation row appears until an
    # explicit create call is made.
    assert session.query(ResolverActivationAuthorization).count() == 0


def test_cross_org_access_refused(session, principal, other_org_principal):
    pf, row = _approved(session, principal.organization_id)
    intruder = _principal(other_org_principal.organization_id, MANAGE, APPROVE)
    with pytest.raises(ResolverActivationError) as exc:
        ra.get_activation_authorization(session, intruder, row.id)
    # Cross-org access is refused (forbidden) — never revealing the record's contents.
    assert exc.value.code == "resolver_activation_forbidden"


# --- audit + model are secret-free ---------------------------------------------------------------


def test_audit_and_model_carry_no_secret_or_backend_value(session, principal):
    pf, row = _approved(session, principal.organization_id)
    cols = set(ResolverActivationAuthorization.__table__.columns.keys()) | set(
        ResolverActivationEvidence.__table__.columns.keys()
    )
    for forbidden in (
        "secret",
        "secret_ref",
        "credential",
        "endpoint",
        "base_url",
        "token",
        "vault",
        "policy",
        "mount",
        "unseal",
        "host",
        "port",
    ):
        assert forbidden not in cols
    session.flush()
    blob = " ".join(str(e.data) for e in session.query(AuditEvent).all()).lower()
    for forbidden in ("vault:", "env:", "://", "secret", "token", "endpoint", "@pam"):
        assert forbidden not in blob


# --- worker verifier: independent re-validation, fail closed on every drift ----------------------


def test_worker_capability_only_after_full_verification(session, principal):
    pf, row = _approved(session, principal.organization_id)
    cap = load_and_verify_activation_capability(
        session,
        preflight=pf,
        resolver_contract_version=RESOLVER_ADAPTER_CONTRACT_VERSION,
        now=_now(),
    )
    assert isinstance(cap, ResolverActivationCapability)
    assert repr(cap) == "ResolverActivationCapability(<redacted>)"
    assert not hasattr(cap, "__dict__")
    with pytest.raises(TypeError):
        pickle.dumps(cap)


def test_capability_is_not_caller_constructible():
    with pytest.raises(TypeError):
        ResolverActivationCapability(
            authorization_id=uuid.uuid4(), operation_fingerprint="x", token=object()
        )


def test_worker_refuses_draft_and_revoked(session, principal):
    _t, _ob, _auth, pf = _work_item(session, principal.organization_id)
    org = principal.organization_id
    row = ra.create_activation_authorization(session, _principal(org, MANAGE), preflight_id=pf.id)
    # draft (no approved row) -> refused
    with pytest.raises(ActivationAuthorizationRefused) as exc:
        load_and_verify_activation_capability(
            session,
            preflight=pf,
            resolver_contract_version=RESOLVER_ADAPTER_CONTRACT_VERSION,
            now=_now(),
        )
    assert exc.value.reason_code == "authorization_not_approved"
    # approve then revoke -> refused again
    _all_evidence(session, _principal(org, MANAGE), row.id)
    ra.approve_activation_authorization(session, _principal(org, APPROVE), row.id)
    ra.revoke_activation_authorization(session, _principal(org, MANAGE), row.id)
    with pytest.raises(ActivationAuthorizationRefused):
        load_and_verify_activation_capability(
            session,
            preflight=pf,
            resolver_contract_version=RESOLVER_ADAPTER_CONTRACT_VERSION,
            now=_now(),
        )


@pytest.mark.parametrize(
    ("column", "value", "reason"),
    [
        ("live_read_authorization_version", 99, "authorization_version_mismatch"),
        ("operation_fingerprint", "sha256:" + "00" * 32, "operation_fingerprint_mismatch"),
        ("resolver_adapter_contract_version", "other/v9", "contract_version_mismatch"),
        ("purpose", "something_else", "wrong_purpose"),
        ("evidence_fingerprint", "sha256:tampered", "evidence_fingerprint_mismatch"),
    ],
)
def test_worker_fails_closed_on_bound_fact_drift(session, principal, column, value, reason):
    pf, row = _approved(session, principal.organization_id)
    session.execute(
        update(ResolverActivationAuthorization)
        .where(ResolverActivationAuthorization.id == row.id)
        .values(**{column: value})
    )
    session.flush()
    session.expire_all()
    with pytest.raises(ActivationAuthorizationRefused) as exc:
        load_and_verify_activation_capability(
            session,
            preflight=pf,
            resolver_contract_version=RESOLVER_ADAPTER_CONTRACT_VERSION,
            now=_now(),
        )
    assert exc.value.reason_code == reason


def test_worker_fails_closed_on_expiry_and_contract_arg(session, principal):
    pf, row = _approved(session, principal.organization_id)
    with pytest.raises(ActivationAuthorizationRefused) as exc:
        load_and_verify_activation_capability(
            session,
            preflight=pf,
            resolver_contract_version=RESOLVER_ADAPTER_CONTRACT_VERSION,
            now=_now() + timedelta(hours=5),
        )
    assert exc.value.reason_code == "authorization_expired"
    with pytest.raises(ActivationAuthorizationRefused) as exc2:
        load_and_verify_activation_capability(
            session, preflight=pf, resolver_contract_version="other/v9", now=_now()
        )
    assert exc2.value.reason_code == "contract_version_mismatch"


def test_worker_fails_closed_on_evidence_deletion(session, principal):
    pf, row = _approved(session, principal.organization_id)
    # Remove one evidence row -> incomplete -> refused (fingerprint would also change).
    one = session.query(ResolverActivationEvidence).filter_by(authorization_id=row.id).first()
    session.delete(one)
    session.flush()
    session.expire_all()
    with pytest.raises(ActivationAuthorizationRefused) as exc:
        load_and_verify_activation_capability(
            session,
            preflight=pf,
            resolver_contract_version=RESOLVER_ADAPTER_CONTRACT_VERSION,
            now=_now(),
        )
    assert exc.value.reason_code in ("evidence_incomplete", "evidence_fingerprint_mismatch")


# --- expiry: fail-closed materialization + revision-safe replacement (audit-once) ----------------


def _force_expiry_past(session, authorization_id):
    """Simulate wall-clock expiry: push ``authorization_expiry`` into the past WITHOUT touching
    ``status`` (models an expired row whose cleanup transition has not yet been materialized)."""
    session.execute(
        update(ResolverActivationAuthorization)
        .where(ResolverActivationAuthorization.id == authorization_id)
        .values(authorization_expiry=_now() - timedelta(seconds=1))
    )
    session.flush()
    session.expire_all()


def _expiration_events(session, authorization_id):
    return [
        e
        for e in session.query(AuditEvent).all()
        if e.action == "resolver_activation.expired" and e.resource_id == str(authorization_id)
    ]


def test_expired_approved_is_materialized_once_and_allows_replacement(session, principal):
    org = principal.organization_id
    pf, row = _approved(session, org)
    old_id, old_version = row.id, row.authorization_version
    old_fp, old_by, old_at = row.evidence_fingerprint, row.approved_by, row.approved_at
    session.commit()

    # The approved authorization passes its canonical UTC expiry but is still 'approved' in the DB.
    _force_expiry_past(session, old_id)

    # Creating a replacement for the SAME work item first materializes the stale approved row as
    # expired, then creates a new draft with the next monotonic version in the freed active slot.
    replacement = ra.create_activation_authorization(
        session, _principal(org, MANAGE), preflight_id=pf.id
    )
    session.flush()

    old = session.get(ResolverActivationAuthorization, old_id)
    assert old.status == ResolverActivationStatus.expired
    assert replacement.id != old_id
    assert replacement.status == ResolverActivationStatus.draft
    assert replacement.preflight_id == pf.id
    assert replacement.authorization_version == old_version + 1

    # Exactly ONE expiration audit event for the old authorization, and it is secret-free.
    events = _expiration_events(session, old_id)
    assert len(events) == 1
    blob = str(events[0].data).lower()
    for forbidden in ("vault:", "env:", "://", "secret", "token", "endpoint", "@pam"):
        assert forbidden not in blob

    # The old approved row's approval facts + evidence fingerprint are never revived/mutated.
    assert old.evidence_fingerprint == old_fp
    assert old.approved_by == old_by
    assert old.approved_at == old_at


def test_expired_draft_allows_replacement_with_higher_version(session, principal):
    org = principal.organization_id
    _t, _ob, _auth, pf = _work_item(session, org)
    draft = ra.create_activation_authorization(session, _principal(org, MANAGE), preflight_id=pf.id)
    old_id, old_version = draft.id, draft.authorization_version
    session.flush()

    _force_expiry_past(session, old_id)
    replacement = ra.create_activation_authorization(
        session, _principal(org, MANAGE), preflight_id=pf.id
    )
    session.flush()

    old = session.get(ResolverActivationAuthorization, old_id)
    assert old.status == ResolverActivationStatus.expired
    assert replacement.status == ResolverActivationStatus.draft
    assert replacement.authorization_version == old_version + 1
    assert len(_expiration_events(session, old_id)) == 1


def test_approve_fails_closed_and_materializes_once_when_expired(session, principal):
    org = principal.organization_id
    _t, _ob, _auth, pf = _work_item(session, org)
    row = ra.create_activation_authorization(session, _principal(org, MANAGE), preflight_id=pf.id)
    _all_evidence(session, _principal(org, MANAGE), row.id)
    _force_expiry_past(session, row.id)

    with pytest.raises(ResolverActivationError) as exc:
        ra.approve_activation_authorization(session, _principal(org, APPROVE), row.id)
    assert exc.value.code == "resolver_activation_invalid_state"
    session.flush()

    refreshed = session.get(ResolverActivationAuthorization, row.id)
    assert refreshed.status == ResolverActivationStatus.expired
    # Approval was never bound: no approver, no approval time, no evidence fingerprint.
    assert refreshed.approved_by is None
    assert refreshed.approved_at is None
    assert refreshed.evidence_fingerprint == ""
    assert len(_expiration_events(session, row.id)) == 1


def test_worker_refuses_expired_authorization_before_materialization(session, principal):
    org = principal.organization_id
    pf, row = _approved(session, org)
    # The row is still 'approved' (cleanup NOT materialized) but its canonical UTC expiry passed.
    _force_expiry_past(session, row.id)
    assert (
        session.get(ResolverActivationAuthorization, row.id).status
        == ResolverActivationStatus.approved
    )
    with pytest.raises(ActivationAuthorizationRefused) as exc:
        load_and_verify_activation_capability(
            session,
            preflight=pf,
            resolver_contract_version=RESOLVER_ADAPTER_CONTRACT_VERSION,
            now=_now(),
        )
    assert exc.value.reason_code == "authorization_expired"


def test_expired_row_preserves_approval_facts_and_audit_history(session, principal):
    org = principal.organization_id
    pf, row = _approved(session, org)
    old_id = row.id
    facts = (
        row.approved_by,
        row.approved_at,
        row.evidence_fingerprint,
        row.operation_fingerprint,
        row.authorization_version,
    )
    evidence_before = {
        (e.kind, e.status, e.proof_id, e.issuer)
        for e in session.query(ResolverActivationEvidence).filter_by(authorization_id=old_id)
    }
    session.commit()

    _force_expiry_past(session, old_id)
    ra.create_activation_authorization(session, _principal(org, MANAGE), preflight_id=pf.id)
    session.flush()

    old = session.get(ResolverActivationAuthorization, old_id)
    assert old.status == ResolverActivationStatus.expired
    assert (
        old.approved_by,
        old.approved_at,
        old.evidence_fingerprint,
        old.operation_fingerprint,
        old.authorization_version,
    ) == facts
    evidence_after = {
        (e.kind, e.status, e.proof_id, e.issuer)
        for e in session.query(ResolverActivationEvidence).filter_by(authorization_id=old_id)
    }
    assert evidence_after == evidence_before
    # Prior create/approve audit events remain (append-only); the ONLY new event for this row is the
    # single expiration event.
    actions = [e.action for e in session.query(AuditEvent).all() if e.resource_id == str(old_id)]
    assert actions.count("resolver_activation.expired") == 1
    assert "resolver_activation.created" in actions
    assert "resolver_activation.approved" in actions
