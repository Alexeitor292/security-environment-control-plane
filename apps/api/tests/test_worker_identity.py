"""SECP-B2-4.3 — durable worker-identity trust anchor lifecycle + sealed verifier (fake-only).

Proves: the registration is separate/explicit (not auto-created, separate approve permission,
complete closed evidence), time-bounded, audited, revocable, monotonic-versioned, and secret-free;
the durable binding + approval/revocation facts are immutable; the sealed attestation source refuses
with no I/O; and the RegisteredWorkerIdentityVerifier independently re-validates every bound fact +
the recomputed anchor/evidence fingerprints and fails closed on any drift. Nothing here performs
mTLS, parses a certificate, accesses a key/CA, resolves a secret, or contacts anything.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.auth import Principal
from secp_api.enums import (
    Permission,
    WorkerIdentityEvidenceKind,
    WorkerIdentityEvidenceStatus,
    WorkerIdentityMechanism,
    WorkerIdentityStatus,
)
from secp_api.errors import ImmutableResourceError, WorkerIdentityError
from secp_api.models import AuditEvent, WorkerIdentityEvidence, WorkerIdentityRegistration
from secp_api.services import worker_identity as wi
from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint
from secp_worker.preflight.identity import WorkerIdentity
from secp_worker.preflight.worker_identity_attestation import (
    RegisteredWorkerIdentityVerifier,
    SealedWorkerIdentityAttestationSource,
    WorkerIdentityClaim,
    WorkerIdentityVerificationRefused,
)
from sqlalchemy import update

MANAGE = Permission.worker_identity_manage
APPROVE = Permission.worker_identity_approve
MTLS = WorkerIdentityMechanism.mtls_workload_identity
LABEL = "staging-worker-a"
ANCHOR = "public-anchor-material-v1"  # an opaque PUBLIC value (never a private key/secret)


def _now() -> datetime:
    return datetime.now(UTC)


def _principal(org_id, *perms) -> Principal:
    return Principal(
        user_id=uuid.uuid4(), organization_id=org_id, email="a@b.test", permissions=frozenset(perms)
    )


def _register(session, org_id, *, label=LABEL, anchor=ANCHOR, ttl_seconds=3600):
    return wi.register_worker_identity(
        session,
        _principal(org_id, MANAGE),
        mechanism=MTLS,
        identity_label=label,
        deployment_binding="deploy-01",
        verification_anchor_fingerprint=compute_verification_anchor_fingerprint(anchor),
        ttl_seconds=ttl_seconds,
    )


def _all_evidence(session, org_id, registration_id):
    for kind in WorkerIdentityEvidenceKind:
        wi.record_evidence(
            session,
            _principal(org_id, MANAGE),
            registration_id,
            kind=kind,
            status=WorkerIdentityEvidenceStatus.verified,
            proof_id="TKT-1",
            issuer="reviewer",
        )


def _approved(session, org_id, *, label=LABEL, anchor=ANCHOR):
    row = _register(session, org_id, label=label, anchor=anchor)
    _all_evidence(session, org_id, row.id)
    return wi.approve_worker_identity(session, _principal(org_id, APPROVE), row.id)


def _claim(
    org_id, *, label=LABEL, anchor=ANCHOR, mechanism=MTLS.value, binding="deploy-01", version=1
):
    return WorkerIdentityClaim(
        organization_id=org_id,
        mechanism=mechanism,
        identity_label=label,
        deployment_binding=binding,
        identity_version=version,
        public_anchor=anchor,
    )


class _FakeSource:
    def __init__(self, claim: WorkerIdentityClaim) -> None:
        self._claim = claim

    def attest(self, *, now):
        return self._claim


def _force_expiry(session, registration_id):
    # Raw Core update bypasses the ORM before_flush guard on SQLite (no PG trigger), standing in for
    # wall-clock expiry of the immutable ``expiry`` field.
    session.execute(
        update(WorkerIdentityRegistration)
        .where(WorkerIdentityRegistration.id == registration_id)
        .values(expiry=_now() - timedelta(hours=1))
    )
    session.flush()
    session.expire_all()


# --- lifecycle / separation ----------------------------------------------------------------------


def test_register_creates_secret_free_draft(session, principal):
    org = principal.organization_id
    row = _register(session, org)
    assert row.status == WorkerIdentityStatus.draft
    assert row.mechanism == MTLS
    assert row.identity_label == LABEL
    assert row.deployment_binding == "deploy-01"
    assert row.verification_anchor_fingerprint == compute_verification_anchor_fingerprint(ANCHOR)
    assert row.identity_version == 1
    assert row.evidence_fingerprint == ""


def test_register_requires_manage_permission(session, principal):
    with pytest.raises(WorkerIdentityError) as exc:
        wi.register_worker_identity(
            session,
            _principal(principal.organization_id, APPROVE),
            mechanism=MTLS,
            identity_label=LABEL,
            deployment_binding="deploy-01",
            verification_anchor_fingerprint=compute_verification_anchor_fingerprint(ANCHOR),
        )
    assert exc.value.code == "worker_identity_forbidden"


def test_approve_requires_the_separate_approve_permission(session, principal):
    org = principal.organization_id
    row = _register(session, org)
    _all_evidence(session, org, row.id)
    # MANAGE alone (and every OTHER approval permission) cannot approve.
    others = _principal(
        org,
        MANAGE,
        Permission.onboarding_approve,
        Permission.staging_lab_approve,
        Permission.resolver_activation_approve,
    )
    with pytest.raises(WorkerIdentityError) as exc:
        wi.approve_worker_identity(session, others, row.id)
    assert exc.value.code == "worker_identity_forbidden"
    approved = wi.approve_worker_identity(session, _principal(org, APPROVE), row.id)
    assert approved.status == WorkerIdentityStatus.approved
    assert approved.evidence_fingerprint != ""


def test_approve_requires_complete_verified_evidence(session, principal):
    org = principal.organization_id
    row = _register(session, org)
    kinds = list(WorkerIdentityEvidenceKind)
    for kind in kinds[:-1]:
        wi.record_evidence(
            session,
            _principal(org, MANAGE),
            row.id,
            kind=kind,
            status=WorkerIdentityEvidenceStatus.verified,
            proof_id="T",
            issuer="r",
        )
    wi.record_evidence(
        session,
        _principal(org, MANAGE),
        row.id,
        kind=kinds[-1],
        status=WorkerIdentityEvidenceStatus.pending,
        proof_id="T",
        issuer="r",
    )
    with pytest.raises(WorkerIdentityError) as exc:
        wi.approve_worker_identity(session, _principal(org, APPROVE), row.id)
    assert exc.value.code == "worker_identity_evidence_incomplete"


def test_evidence_metadata_is_validated_closed_shape(session, principal):
    org = principal.organization_id
    row = _register(session, org)
    for bad in ("vault:secp/x", "https://host", "a b", "user@host", "tok/secret"):
        with pytest.raises(WorkerIdentityError) as exc:
            wi.record_evidence(
                session,
                _principal(org, MANAGE),
                row.id,
                kind=WorkerIdentityEvidenceKind.deployment_binding_review,
                status=WorkerIdentityEvidenceStatus.verified,
                proof_id=bad,
                issuer="r",
            )
        assert exc.value.code == "worker_identity_invalid_metadata"


def test_register_rejects_non_opaque_label_or_binding_or_anchor(session, principal):
    org = principal.organization_id
    # Label/binding with a scheme/slash/space, and a non-sha256 anchor fingerprint, are all refused.
    for label, binding, fp in (
        ("bad label", "deploy-01", compute_verification_anchor_fingerprint(ANCHOR)),
        (LABEL, "vault:x", compute_verification_anchor_fingerprint(ANCHOR)),
        (LABEL, "deploy-01", "not-a-sha256"),
        (LABEL, "deploy-01", "sha256:tooshort"),
    ):
        with pytest.raises(WorkerIdentityError) as exc:
            wi.register_worker_identity(
                session,
                _principal(org, MANAGE),
                mechanism=MTLS,
                identity_label=label,
                deployment_binding=binding,
                verification_anchor_fingerprint=fp,
            )
        assert exc.value.code == "worker_identity_invalid_metadata"


def test_identity_version_is_monotonic_and_supports_rotation(session, principal):
    org = principal.organization_id
    first = _register(session, org)
    assert first.identity_version == 1
    wi.revoke_worker_identity(session, _principal(org, MANAGE), first.id)
    # Rotation: a NEW registration for the same (org, label) gets a monotonically higher version.
    second = _register(session, org)
    assert second.identity_version == 2
    assert second.identity_label == first.identity_label


def test_revoke_is_immediate_and_audited(session, principal):
    org = principal.organization_id
    row = _approved(session, org)
    revoked = wi.revoke_worker_identity(session, _principal(org, MANAGE), row.id, "operator")
    assert revoked.status == WorkerIdentityStatus.revoked
    assert revoked.revoked_at is not None
    session.flush()
    actions = {e.action for e in session.query(AuditEvent).all()}
    assert {
        "worker_identity.registered",
        "worker_identity.approved",
        "worker_identity.revoked",
    } <= actions


def test_not_auto_created(session, principal):
    assert session.query(WorkerIdentityRegistration).count() == 0


def test_cross_org_access_refused(session, principal, other_org_principal):
    org = principal.organization_id
    row = _approved(session, org)
    intruder = _principal(other_org_principal.organization_id, MANAGE, APPROVE)
    with pytest.raises(WorkerIdentityError) as exc:
        wi.get_worker_identity(session, intruder, row.id)
    assert exc.value.code == "worker_identity_forbidden"


def test_model_and_audit_carry_no_secret_or_backend_value(session, principal):
    org = principal.organization_id
    _approved(session, org)
    cols = set(WorkerIdentityRegistration.__table__.columns.keys()) | set(
        WorkerIdentityEvidence.__table__.columns.keys()
    )
    for forbidden in (
        "certificate",
        "cert",
        "private_key",
        "key",
        "csr",
        "ca",
        "secret",
        "secret_ref",
        "token",
        "endpoint",
        "host",
        "port",
        "url",
        "anchor_material",
        "public_key",
    ):
        assert forbidden not in cols
    session.flush()
    blob = " ".join(str(e.data) for e in session.query(AuditEvent).all()).lower()
    for forbidden in ("vault:", "env:", "://", "secret", "token", "endpoint", "begin ", "private"):
        assert forbidden not in blob


# --- immutability (ORM-path) ---------------------------------------------------------------------


def test_binding_facts_are_immutable_via_orm(session, principal):
    org = principal.organization_id
    row = _approved(session, org)
    session.commit()
    for field, value in (
        ("identity_label", "other-label"),
        ("deployment_binding", "other-deploy"),
        ("verification_anchor_fingerprint", compute_verification_anchor_fingerprint("other")),
        ("identity_version", 99),
        ("expiry", _now() + timedelta(days=365)),
        ("mechanism", MTLS),  # same value is fine; a change would raise (covered by other fields)
    ):
        if field == "mechanism":
            continue
        setattr(row, field, value)
        with pytest.raises(ImmutableResourceError):
            session.flush()
        session.rollback()


def test_setonce_and_terminal_and_delete_are_guarded_via_orm(session, principal):
    org = principal.organization_id
    row = _approved(session, org)
    session.commit()
    # set-once evidence fingerprint / approver
    for field, value in (
        ("evidence_fingerprint", "sha256:tampered"),
        ("approved_by", uuid.uuid4()),
    ):
        session.refresh(row)
        setattr(row, field, value)
        with pytest.raises(ImmutableResourceError):
            session.flush()
        session.rollback()
    # terminal revival refused
    wi.revoke_worker_identity(session, _principal(org, MANAGE), row.id)
    session.commit()
    for revived in (WorkerIdentityStatus.draft, WorkerIdentityStatus.approved):
        session.refresh(row)
        row.status = revived
        with pytest.raises(ImmutableResourceError):
            session.flush()
        session.rollback()
    # deletion refused
    session.refresh(row)
    session.delete(row)
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()


def test_evidence_is_immutable_after_approval_via_orm(session, principal):
    org = principal.organization_id
    row = _approved(session, org)
    session.commit()
    ev = session.query(WorkerIdentityEvidence).filter_by(registration_id=row.id).first()
    ev.proof_id = "CHANGED"
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()
    ev = session.query(WorkerIdentityEvidence).filter_by(registration_id=row.id).first()
    session.delete(ev)
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()
    session.add(
        WorkerIdentityEvidence(
            registration_id=row.id,
            kind=WorkerIdentityEvidenceKind.rotation_revocation_review,
            status=WorkerIdentityEvidenceStatus.verified,
            proof_id="NEW",
            issuer="r",
        )
    )
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()


def test_expired_registration_allows_higher_version_replacement(session, principal):
    org = principal.organization_id
    row = _approved(session, org)
    v1_id = row.id
    _force_expiry(session, v1_id)
    replacement = _register(session, org)
    session.flush()
    assert session.get(WorkerIdentityRegistration, v1_id).status == WorkerIdentityStatus.expired
    assert replacement.identity_version > 1
    expired = [e for e in session.query(AuditEvent).all() if e.action == "worker_identity.expired"]
    assert len(expired) == 1


# --- worker verifier: independent re-validation, fail closed on drift ----------------------------


def test_verifier_returns_identity_on_valid_claim(session, principal):
    org = principal.organization_id
    _approved(session, org)
    verifier = RegisteredWorkerIdentityVerifier(_FakeSource(_claim(org)))
    identity = verifier.verify(session, now=_now())
    assert isinstance(identity, WorkerIdentity)
    assert identity.worker_identity_id == LABEL


def test_verifier_refuses_sealed_source(session, principal):
    verifier = RegisteredWorkerIdentityVerifier(SealedWorkerIdentityAttestationSource())
    with pytest.raises(WorkerIdentityVerificationRefused) as exc:
        verifier.verify(session, now=_now())
    assert exc.value.reason_code == "no worker identity attestation is configured"


def test_verifier_refuses_when_only_a_draft_exists(session, principal):
    org = principal.organization_id
    _register(session, org)  # draft, not approved
    verifier = RegisteredWorkerIdentityVerifier(_FakeSource(_claim(org)))
    with pytest.raises(WorkerIdentityVerificationRefused) as exc:
        verifier.verify(session, now=_now())
    assert exc.value.reason_code == "identity_not_approved"


def test_verifier_refuses_revoked(session, principal):
    org = principal.organization_id
    row = _approved(session, org)
    wi.revoke_worker_identity(session, _principal(org, MANAGE), row.id)
    verifier = RegisteredWorkerIdentityVerifier(_FakeSource(_claim(org)))
    with pytest.raises(WorkerIdentityVerificationRefused) as exc:
        verifier.verify(session, now=_now())
    assert exc.value.reason_code == "identity_not_approved"


def test_verifier_refuses_expired(session, principal):
    org = principal.organization_id
    row = _approved(session, org)
    verifier = RegisteredWorkerIdentityVerifier(_FakeSource(_claim(org)))
    with pytest.raises(WorkerIdentityVerificationRefused) as exc:
        verifier.verify(session, now=_as_far_future(row))
    assert exc.value.reason_code == "identity_expired"


def _as_far_future(row):
    exp = row.expiry
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=UTC)
    return exp + timedelta(seconds=5)


@pytest.mark.parametrize(
    ("claim_over", "reason"),
    [
        ({"mechanism": "other_mechanism"}, "wrong_mechanism"),
        ({"binding": "other-deploy"}, "deployment_binding_mismatch"),
        ({"version": 99}, "identity_version_mismatch"),
        ({"anchor": "a-different-public-anchor"}, "verification_anchor_mismatch"),
    ],
)
def test_verifier_fails_closed_on_each_claim_drift(session, principal, claim_over, reason):
    org = principal.organization_id
    _approved(session, org)
    verifier = RegisteredWorkerIdentityVerifier(_FakeSource(_claim(org, **claim_over)))
    with pytest.raises(WorkerIdentityVerificationRefused) as exc:
        verifier.verify(session, now=_now())
    assert exc.value.reason_code == reason


def test_verifier_refuses_wrong_label_with_no_registration(session, principal):
    org = principal.organization_id
    _approved(session, org)
    verifier = RegisteredWorkerIdentityVerifier(_FakeSource(_claim(org, label="unknown-label")))
    with pytest.raises(WorkerIdentityVerificationRefused) as exc:
        verifier.verify(session, now=_now())
    assert exc.value.reason_code == "identity_not_approved"


def test_verifier_fails_closed_on_evidence_deletion(session, principal):
    from sqlalchemy import delete

    org = principal.organization_id
    row = _approved(session, org)
    one = session.query(WorkerIdentityEvidence).filter_by(registration_id=row.id).first()
    session.execute(delete(WorkerIdentityEvidence).where(WorkerIdentityEvidence.id == one.id))
    session.expire_all()
    verifier = RegisteredWorkerIdentityVerifier(_FakeSource(_claim(org)))
    with pytest.raises(WorkerIdentityVerificationRefused) as exc:
        verifier.verify(session, now=_now())
    assert exc.value.reason_code in ("evidence_incomplete", "evidence_fingerprint_mismatch")


def _refusal_events(session):
    session.flush()
    return [
        e
        for e in session.query(AuditEvent).all()
        if e.action == "worker_identity.verification_refused"
    ]


def _event_haystack(ev) -> str:
    # Everything that persists for one AuditEvent — the refusal must leak no claim value into any.
    return " ".join(
        str(x)
        for x in (
            ev.data,
            ev.resource_id,
            ev.resource_type,
            ev.actor,
            ev.outcome,
            ev.organization_id,
        )
    )


@pytest.mark.parametrize(
    ("claim_over", "reason", "poison"),
    [
        ({"mechanism": "POISON-MECH"}, "wrong_mechanism", "POISON-MECH"),
        ({"binding": "POISON-BIND"}, "deployment_binding_mismatch", "POISON-BIND"),
        ({"version": 987654}, "identity_version_mismatch", "987654"),
        ({"anchor": "POISON-ANCHOR"}, "verification_anchor_mismatch", "POISON-ANCHOR"),
    ],
)
def test_refusal_audit_never_persists_a_poisoned_claim_field(
    session, principal, claim_over, reason, poison
):
    # An approved identity exists (matching org + label); the claim carries a POISONED field. The
    # refusal must be attributed ONLY to the authoritative durable registration and must persist
    # NEITHER the poison value NOR any other claim field.
    org = principal.organization_id
    row = _approved(session, org)
    verifier = RegisteredWorkerIdentityVerifier(_FakeSource(_claim(org, **claim_over)))
    with pytest.raises(WorkerIdentityVerificationRefused) as exc:
        verifier.verify(session, now=_now())
    # The poison never appears in the raised refusal (exception text / args).
    assert poison not in str(exc.value)
    assert all(poison not in str(a) for a in exc.value.args)
    assert exc.value.reason_code == reason

    events = _refusal_events(session)
    assert len(events) == 1
    ev = events[0]
    # Attributed ONLY to the authoritative durable registration (server ids), never the claim.
    assert ev.resource_id == str(row.id)
    assert ev.organization_id == org
    # The persisted data is exactly the closed reason + pinned contract version — no claim field.
    assert set(ev.data.keys()) == {"reason_code", "worker_identity_contract_version"}
    assert ev.data["reason_code"] == reason
    # The poison (and the raw anchor / deployment binding) appear NOWHERE in the persisted event.
    haystack = _event_haystack(ev)
    for banned in (poison, "POISON", ANCHOR, "deploy-01"):
        assert banned not in haystack


def test_refusal_audit_is_context_free_when_no_authoritative_registration(session, principal):
    # A poisoned claim (poison org, label, mechanism, binding, anchor, version) that matches NO
    # registration yields ``identity_not_approved`` and a CONTEXT-FREE audit: no org, no resource
    # id, and only the closed reason + contract version — never any claim-supplied value.
    _approved(
        session, principal.organization_id
    )  # a real identity exists for a different (org,label)
    poison_org = uuid.uuid4()
    poisons = {
        "org": str(poison_org),
        "label": "POISON-LABEL",
        "mech": "POISON-MECH",
        "bind": "POISON-BIND",
        "anchor": "POISON-ANCHOR",
        "ver": "424242",
    }
    claim = WorkerIdentityClaim(
        organization_id=poison_org,
        mechanism="POISON-MECH",
        identity_label="POISON-LABEL",
        deployment_binding="POISON-BIND",
        identity_version=424242,
        public_anchor="POISON-ANCHOR",
    )
    verifier = RegisteredWorkerIdentityVerifier(_FakeSource(claim))
    with pytest.raises(WorkerIdentityVerificationRefused) as exc:
        verifier.verify(session, now=_now())
    assert exc.value.reason_code == "identity_not_approved"
    for value in poisons.values():
        assert value not in str(exc.value)

    events = _refusal_events(session)
    assert len(events) == 1
    ev = events[0]
    # No authoritative registration -> no org, no resource id; only the closed data.
    assert ev.resource_id is None
    assert ev.organization_id is None
    assert set(ev.data.keys()) == {"reason_code", "worker_identity_contract_version"}
    haystack = _event_haystack(ev)
    for value in poisons.values():
        assert value not in haystack
