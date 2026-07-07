"""SECP-B6 MB-1 — control-plane worker discovery admission verifier (crypto core, no host contact).

Proves the Ed25519 signed-nonce handshake: a challenge is issued bound to the job, the worker signs
it with its deployment-local key, the control plane verifies the signature against the REGISTERED
anchor (never a self-asserted key), and the one-time admission is consumed exactly once. Every
negative path (wrong key, wrong worker, expired, replay, endpoint/authorization mismatch) fails
closed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from secp_api.enums import (
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    TargetStatus,
    WorkerDiscoveryAdmissionStatus,
    WorkerIdentityEvidenceKind,
    WorkerIdentityEvidenceStatus,
    WorkerIdentityMechanism,
)
from secp_api.live_read_contract import normalize_target_host, ssh_endpoint_binding_hash
from secp_api.models import (
    DiscoveryJob,
    ExecutionTarget,
    TargetOnboarding,
    WorkerDiscoveryAdmission,
)
from secp_api.services import readonly_preflight, staging_labs
from secp_api.services import target_discovery as td_svc
from secp_api.services import worker_admission as adm
from secp_api.worker_admission_contract import (
    admission_signing_message,
    compute_verification_anchor_fingerprint,
    ed25519_sign,
    generate_ed25519_keypair,
)
from secp_api.worker_identity_contract import validate_verification_anchor_fingerprint

_BASE_URL = "https://pve-a.internal:8006"
_FP = "SHA256:" + "A" * 43


def _endpoint_hash(*, ssh_host="pve-a.internal", ssh_port=22, fingerprint=_FP) -> str:
    return ssh_endpoint_binding_hash(
        normalized_target_host=normalize_target_host({"base_url": _BASE_URL}),
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        host_key_fingerprint=fingerprint,
    )


def _register_worker(session, principal, *, pub_hex: str, label="staging-worker-a"):
    from secp_api.services import worker_identity as wi

    fp = compute_verification_anchor_fingerprint(pub_hex)
    validate_verification_anchor_fingerprint(fp)
    row = wi.register_worker_identity(
        session,
        principal,
        mechanism=WorkerIdentityMechanism.mtls_workload_identity,
        identity_label=label,
        deployment_binding=f"deploy-{label}",
        verification_anchor_fingerprint=fp,
    )
    for kind in WorkerIdentityEvidenceKind:
        wi.record_evidence(
            session,
            principal,
            row.id,
            kind=kind,
            status=WorkerIdentityEvidenceStatus.verified,
            proof_id="TKT-1",
            issuer="rev",
        )
    return wi.approve_worker_identity(session, principal, row.id)


def _target_auth(session, principal, *, endpoint_binding_hash):
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": _BASE_URL, "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref="vault:x",
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
    auth = readonly_preflight.create_preflight_authorization(
        session,
        principal,
        execution_target_id=target.id,
        endpoint_binding_hash=endpoint_binding_hash,
    )
    auth = readonly_preflight.approve_preflight_authorization(session, principal, auth.id)
    return target, auth


def _enroll(session, principal, target):
    enrollment = td_svc.request_discovery(session, principal, execution_target_id=target.id)
    job = session.query(DiscoveryJob).filter(DiscoveryJob.enrollment_id == enrollment.id).one()
    return enrollment, job


def _full_setup(session, principal, *, endpoint_binding_hash=None):
    priv, pub = generate_ed25519_keypair()
    ebh = endpoint_binding_hash or _endpoint_hash()
    _register_worker(session, principal, pub_hex=pub)
    target, auth = _target_auth(session, principal, endpoint_binding_hash=ebh)
    enrollment, job = _enroll(session, principal, target)
    return priv, pub, ebh, auth, enrollment, job


def _sign_and_complete(session, admission, priv, pub, *, now):
    message = admission_signing_message(
        nonce=admission.nonce,
        organization_id=str(admission.organization_id),
        discovery_job_id=str(admission.discovery_job_id),
        worker_registration_id=str(admission.worker_registration_id),
        identity_version=admission.identity_version,
        endpoint_binding_hash=admission.endpoint_binding_hash,
        expires_at=admission.expires_at.replace(tzinfo=UTC)
        if admission.expires_at.tzinfo is None
        else admission.expires_at,
    )
    sig = ed25519_sign(private_key_hex=priv, message=message)
    return adm.complete_discovery_admission(
        session, admission_id=admission.id, presented_anchor=pub, signature=sig, now=now
    )


def test_admission_bound_to_exact_job(session, principal):
    # An admission issued for one job cannot be asserted/consumed for a different job id.
    import uuid

    now = datetime.now(UTC)
    priv, pub, ebh, auth, enrollment, job = _full_setup(session, principal)
    admission = adm.issue_discovery_admission_challenge(
        session,
        discovery_job_id=job.id,
        authorization_id=auth.id,
        authorization_version=auth.authorization_version,
        endpoint_binding_hash=ebh,
        now=now,
    )
    _sign_and_complete(session, admission, priv, pub, now=now)
    with pytest.raises(adm.WorkerAdmissionRefused) as exc:
        adm.assert_discovery_admission_valid(
            session,
            admission_id=admission.id,
            enrollment=enrollment,
            discovery_job_id=uuid.uuid4(),  # a different job
            endpoint_binding_hash=ebh,
            now=now,
        )
    assert exc.value.reason_code == "admission_job_mismatch"


def test_admission_happy_path_issue_sign_complete_consume(session, principal):
    now = datetime.now(UTC)
    priv, pub, ebh, auth, enrollment, job = _full_setup(session, principal)
    admission = adm.issue_discovery_admission_challenge(
        session,
        discovery_job_id=job.id,
        authorization_id=auth.id,
        authorization_version=auth.authorization_version,
        endpoint_binding_hash=ebh,
        now=now,
    )
    assert admission.status == WorkerDiscoveryAdmissionStatus.challenged
    completed = _sign_and_complete(session, admission, priv, pub, now=now)
    assert completed.status == WorkerDiscoveryAdmissionStatus.admitted
    result = adm.assert_discovery_admission_valid(
        session,
        admission_id=admission.id,
        enrollment=enrollment,
        discovery_job_id=job.id,
        endpoint_binding_hash=ebh,
        now=now,
    )
    assert result.identity_version == admission.identity_version
    adm.consume_discovery_admission(
        session,
        admission_id=admission.id,
        enrollment=enrollment,
        discovery_job_id=job.id,
        endpoint_binding_hash=ebh,
        now=now,
    )
    assert session.get(WorkerDiscoveryAdmission, admission.id).status == (
        WorkerDiscoveryAdmissionStatus.consumed
    )
    # Replay: a second consume fails closed.
    with pytest.raises(adm.WorkerAdmissionRefused):
        adm.consume_discovery_admission(
            session,
            admission_id=admission.id,
            enrollment=enrollment,
            discovery_job_id=job.id,
            endpoint_binding_hash=ebh,
            now=now,
        )


def test_admission_wrong_signature_refused(session, principal):
    now = datetime.now(UTC)
    priv, pub, ebh, auth, enrollment, job = _full_setup(session, principal)
    admission = adm.issue_discovery_admission_challenge(
        session,
        discovery_job_id=job.id,
        authorization_id=auth.id,
        authorization_version=auth.authorization_version,
        endpoint_binding_hash=ebh,
        now=now,
    )
    # Sign a DIFFERENT message than the issued challenge.
    bad_sig = ed25519_sign(private_key_hex=priv, message=b"not the challenge")
    with pytest.raises(adm.WorkerAdmissionRefused) as exc:
        adm.complete_discovery_admission(
            session, admission_id=admission.id, presented_anchor=pub, signature=bad_sig, now=now
        )
    assert exc.value.reason_code == "proof_of_possession_failed"


def test_admission_wrong_worker_key_refused(session, principal):
    now = datetime.now(UTC)
    priv, pub, ebh, auth, enrollment, job = _full_setup(session, principal)
    admission = adm.issue_discovery_admission_challenge(
        session,
        discovery_job_id=job.id,
        authorization_id=auth.id,
        authorization_version=auth.authorization_version,
        endpoint_binding_hash=ebh,
        now=now,
    )
    # A different, unregistered keypair signs correctly — but its anchor is not the registered one.
    other_priv, other_pub = generate_ed25519_keypair()
    with pytest.raises(adm.WorkerAdmissionRefused) as exc:
        _sign_and_complete(session, admission, other_priv, other_pub, now=now)
    assert exc.value.reason_code == "anchor_pin_mismatch"


def test_admission_expired_challenge_refused(session, principal):
    now = datetime.now(UTC)
    priv, pub, ebh, auth, enrollment, job = _full_setup(session, principal)
    admission = adm.issue_discovery_admission_challenge(
        session,
        discovery_job_id=job.id,
        authorization_id=auth.id,
        authorization_version=auth.authorization_version,
        endpoint_binding_hash=ebh,
        now=now,
    )
    later = now + timedelta(seconds=1000)
    with pytest.raises(adm.WorkerAdmissionRefused) as exc:
        _sign_and_complete(session, admission, priv, pub, now=later)
    assert exc.value.reason_code == "admission_expired"


def test_admission_endpoint_binding_mismatch_refused(session, principal):
    now = datetime.now(UTC)
    priv, pub, ebh, auth, enrollment, job = _full_setup(session, principal)
    # Ask for a challenge with a DIFFERENT endpoint hash than the authorization stores.
    wrong = _endpoint_hash(ssh_port=2222)
    with pytest.raises(adm.WorkerAdmissionRefused) as exc:
        adm.issue_discovery_admission_challenge(
            session,
            discovery_job_id=job.id,
            authorization_id=auth.id,
            authorization_version=auth.authorization_version,
            endpoint_binding_hash=wrong,
            now=now,
        )
    assert exc.value.reason_code == "endpoint_binding_mismatch"


def test_admission_no_endpoint_hash_on_authorization_refused(session, principal):
    now = datetime.now(UTC)
    priv, pub = generate_ed25519_keypair()
    _register_worker(session, principal, pub_hex=pub)
    # An authorization created WITHOUT an endpoint binding hash (preflight-style) is unusable.
    target, auth = _target_auth(session, principal, endpoint_binding_hash=None)
    enrollment, job = _enroll(session, principal, target)
    with pytest.raises(adm.WorkerAdmissionRefused) as exc:
        adm.issue_discovery_admission_challenge(
            session,
            discovery_job_id=job.id,
            authorization_id=auth.id,
            authorization_version=auth.authorization_version,
            endpoint_binding_hash=_endpoint_hash(),
            now=now,
        )
    assert exc.value.reason_code == "endpoint_binding_unset"


def test_admission_revoked_worker_before_consume_refused(session, principal):
    from secp_api.services import worker_identity as wi

    now = datetime.now(UTC)
    priv, pub, ebh, auth, enrollment, job = _full_setup(session, principal)
    admission = adm.issue_discovery_admission_challenge(
        session,
        discovery_job_id=job.id,
        authorization_id=auth.id,
        authorization_version=auth.authorization_version,
        endpoint_binding_hash=ebh,
        now=now,
    )
    _sign_and_complete(session, admission, priv, pub, now=now)
    # Revoke the worker identity AFTER admission but BEFORE the engine consumes it.
    wi.revoke_worker_identity(session, principal, admission.worker_registration_id, reason_code="x")
    with pytest.raises(adm.WorkerAdmissionRefused) as exc:
        adm.assert_discovery_admission_valid(
            session,
            admission_id=admission.id,
            enrollment=enrollment,
            discovery_job_id=job.id,
            endpoint_binding_hash=ebh,
            now=now,
        )
    assert exc.value.reason_code == "worker_identity_unapproved"
