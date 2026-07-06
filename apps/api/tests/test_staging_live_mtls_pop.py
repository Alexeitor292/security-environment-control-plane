"""SECP-B3 — independent cryptographic proof-of-possession (closes B2-5-pre condition C).

Everything here is fake/deterministic: no CA, network, certificate, or private-key file is touched;
key material is generated in-memory. The tests prove the SIGNER and VERIFIER are different objects,
that verification is a genuine cryptographic check against the anchor pinned in the durable
registration, that proof binds a fresh operation challenge, and that a wrong key, wrong
identity / cross-org, stale challenge, replay across operations, and a tampered signature all fail
closed — with no key/anchor/challenge/signature value leaking through results or reprs.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.enums import (
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    TargetStatus,
)
from secp_api.models import ExecutionTarget, TargetOnboarding
from secp_api.services import readonly_preflight, staging_labs
from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint
from secp_worker.preflight.fingerprint import compute_operation_fingerprint
from secp_worker.preflight.worker_identity_attestation import WorkerIdentityAttestationUnavailable
from secp_worker.staging_live.mtls_pop import (
    DeploymentSignerUnavailable,
    IndependentPoPVerifier,
    LocalHashBasedPoPScheme,
    MtlsIdentityDescriptor,
    PoPVerifiedAttestationSource,
    RemoteAuthenticationIneligible,
    SealedDeploymentLocalSigner,
    assert_remote_authentication_eligible,
    issue_operation_challenge,
)

VAULT_REF = "vault:secp/proxmox/target-1"


# --- lightweight durable-identity stand-in for scheme/verifier tests -----------------------------


@dataclass(frozen=True)
class _PreflightStub:
    id: uuid.UUID
    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    onboarding_id: uuid.UUID
    live_read_authorization_id: uuid.UUID
    authorization_version: int = 1


def _stub(org: uuid.UUID | None = None) -> _PreflightStub:
    return _PreflightStub(
        id=uuid.uuid4(),
        organization_id=org or uuid.uuid4(),
        execution_target_id=uuid.uuid4(),
        onboarding_id=uuid.uuid4(),
        live_read_authorization_id=uuid.uuid4(),
    )


def _queued(session, principal, *, secret_ref: str = VAULT_REF):
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
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
    auth = readonly_preflight.create_preflight_authorization(
        session, principal, execution_target_id=target.id
    )
    readonly_preflight.approve_preflight_authorization(session, principal, auth.id)
    return readonly_preflight.queue_preflight(
        session, principal, live_read_authorization_id=auth.id
    )


# --- 1. The hash-based scheme is a genuine public-verifiable signature ----------------------------


def test_scheme_roundtrip_and_failure_modes():
    scheme = LocalHashBasedPoPScheme()
    signer = scheme.generate_signer()
    anchor, msg = signer.public_anchor(), b"operation-message"
    sig = signer.sign(msg)
    assert scheme.verify(public_anchor=anchor, message=msg, signature=sig) is True
    # Wrong message, wrong key, tampered signature, malformed hex all fail — verification uses only
    # public data (anchor + signature), never the private key.
    assert scheme.verify(public_anchor=anchor, message=b"other", signature=sig) is False
    other = scheme.generate_signer()
    assert scheme.verify(public_anchor=other.public_anchor(), message=msg, signature=sig) is False
    tampered = ("00" * 32) + sig[64:]
    assert scheme.verify(public_anchor=anchor, message=msg, signature=tampered) is False
    assert scheme.verify(public_anchor="zz", message=msg, signature=sig) is False


def test_signer_never_exposes_private_material():
    signer = LocalHashBasedPoPScheme().generate_signer()
    assert repr(signer) == "InMemoryHashBasedSigner(<redacted>)"
    # The public anchor is hex and carries no private leaf (private lives only on the signer).
    assert all(c in "0123456789abcdef" for c in signer.public_anchor())


# --- 2. Independent verifier: valid proof + every fail-closed path --------------------------------


def _verifier() -> IndependentPoPVerifier:
    return IndependentPoPVerifier(LocalHashBasedPoPScheme())


def _fingerprint(anchor: str) -> str:
    return compute_verification_anchor_fingerprint(anchor)


def test_valid_independent_proof_verifies():
    scheme = LocalHashBasedPoPScheme()
    signer = scheme.generate_signer()
    pf = _stub()
    now = datetime.now(UTC)
    challenge = issue_operation_challenge(preflight=pf, now=now)
    sig = signer.sign(challenge.signing_message())
    result = _verifier().verify(
        registered_anchor_fingerprint=_fingerprint(signer.public_anchor()),
        presented_anchor=signer.public_anchor(),
        challenge=challenge,
        signature=sig,
        now=now,
        expected_preflight_id=str(pf.id),
        expected_operation_fingerprint=compute_operation_fingerprint(pf),
    )
    assert result.ok is True
    assert result.reason_code == "verified"


def test_stale_challenge_fails_closed():
    scheme = LocalHashBasedPoPScheme()
    signer = scheme.generate_signer()
    pf = _stub()
    issued = datetime.now(UTC)
    challenge = issue_operation_challenge(preflight=pf, now=issued, ttl_seconds=60)
    sig = signer.sign(challenge.signing_message())
    later = issued + timedelta(seconds=61)
    result = _verifier().verify(
        registered_anchor_fingerprint=_fingerprint(signer.public_anchor()),
        presented_anchor=signer.public_anchor(),
        challenge=challenge,
        signature=sig,
        now=later,
        expected_preflight_id=str(pf.id),
        expected_operation_fingerprint=compute_operation_fingerprint(pf),
    )
    assert result == type(result)(ok=False, reason_code="stale_challenge")


def test_replay_across_operations_fails_closed():
    # A challenge issued for operation A cannot authorize operation B (replay across operations).
    scheme = LocalHashBasedPoPScheme()
    signer = scheme.generate_signer()
    pf_a, pf_b = _stub(), _stub()
    now = datetime.now(UTC)
    challenge_a = issue_operation_challenge(preflight=pf_a, now=now)
    sig = signer.sign(challenge_a.signing_message())
    result = _verifier().verify(
        registered_anchor_fingerprint=_fingerprint(signer.public_anchor()),
        presented_anchor=signer.public_anchor(),
        challenge=challenge_a,
        signature=sig,
        now=now,
        expected_preflight_id=str(pf_b.id),  # verifying against a DIFFERENT operation
        expected_operation_fingerprint=compute_operation_fingerprint(pf_b),
    )
    assert result.ok is False
    assert result.reason_code == "challenge_operation_mismatch"


def test_wrong_identity_or_cross_org_fails_the_anchor_pin():
    # The presented anchor is real and self-consistent, but it is NOT the one pinned in the durable
    # registration (a different identity / different org) — the pin check fails before any crypto.
    scheme = LocalHashBasedPoPScheme()
    signer = scheme.generate_signer()
    registered = scheme.generate_signer()  # the identity actually registered (different key)
    pf = _stub()
    now = datetime.now(UTC)
    challenge = issue_operation_challenge(preflight=pf, now=now)
    sig = signer.sign(challenge.signing_message())
    result = _verifier().verify(
        registered_anchor_fingerprint=_fingerprint(registered.public_anchor()),
        presented_anchor=signer.public_anchor(),
        challenge=challenge,
        signature=sig,
        now=now,
        expected_preflight_id=str(pf.id),
        expected_operation_fingerprint=compute_operation_fingerprint(pf),
    )
    assert result.ok is False
    assert result.reason_code == "anchor_pin_mismatch"


def test_wrong_key_signature_fails_proof_of_possession():
    # Presented anchor matches the pin, but the signature was made with a different key: the
    # cryptographic verification fails (the signer cannot prove possession of the registered key).
    scheme = LocalHashBasedPoPScheme()
    registered = scheme.generate_signer()
    impostor = scheme.generate_signer()
    pf = _stub()
    now = datetime.now(UTC)
    challenge = issue_operation_challenge(preflight=pf, now=now)
    forged_sig = impostor.sign(challenge.signing_message())
    result = _verifier().verify(
        registered_anchor_fingerprint=_fingerprint(registered.public_anchor()),
        presented_anchor=registered.public_anchor(),  # correct anchor...
        challenge=challenge,
        signature=forged_sig,  # ...but a signature by a key the impostor holds
        now=now,
        expected_preflight_id=str(pf.id),
        expected_operation_fingerprint=compute_operation_fingerprint(pf),
    )
    assert result.ok is False
    assert result.reason_code == "proof_of_possession_failed"


def test_replayed_signature_from_earlier_challenge_fails():
    # A signature captured for an earlier challenge does not verify against a NEW challenge for
    # the same operation (the message differs), so replay of the signature bytes fails closed.
    scheme = LocalHashBasedPoPScheme()
    signer = scheme.generate_signer()
    pf = _stub()
    now = datetime.now(UTC)
    first = issue_operation_challenge(preflight=pf, now=now)
    captured = signer.sign(first.signing_message())
    second = issue_operation_challenge(preflight=pf, now=now)  # fresh nonce → different message
    assert first.value != second.value
    result = _verifier().verify(
        registered_anchor_fingerprint=_fingerprint(signer.public_anchor()),
        presented_anchor=signer.public_anchor(),
        challenge=second,
        signature=captured,
        now=now,
        expected_preflight_id=str(pf.id),
        expected_operation_fingerprint=compute_operation_fingerprint(pf),
    )
    assert result.ok is False
    assert result.reason_code == "proof_of_possession_failed"


# --- 3. PoPVerifiedAttestationSource: independent by construction ---------------------------------


def _descriptor(org: uuid.UUID, *, version: int = 1) -> MtlsIdentityDescriptor:
    return MtlsIdentityDescriptor(
        organization_id=org,
        mechanism="mtls_workload_identity",
        identity_label="staging-worker-a",
        deployment_binding="deploy-01",
        identity_version=version,
    )


def test_attestation_source_emits_claim_only_after_independent_verification(session, principal):
    pf = _queued(session, principal)
    scheme = LocalHashBasedPoPScheme()
    signer = scheme.generate_signer()
    source = PoPVerifiedAttestationSource(
        signer=signer,
        verifier=IndependentPoPVerifier(scheme),
        descriptor=_descriptor(principal.organization_id),
        registered_anchor_fingerprint=compute_verification_anchor_fingerprint(
            signer.public_anchor()
        ),
    )
    claim = source.attest(preflight=pf, now=datetime.now(UTC))
    assert claim.organization_id == principal.organization_id
    assert claim.public_anchor == signer.public_anchor()
    # The signer object exposes no verification method — it cannot validate its own proof.
    assert not hasattr(signer, "verify_signature")


def test_attestation_source_fails_closed_on_sealed_signer(session, principal):
    pf = _queued(session, principal)
    scheme = LocalHashBasedPoPScheme()
    source = PoPVerifiedAttestationSource(
        signer=SealedDeploymentLocalSigner(),
        verifier=IndependentPoPVerifier(scheme),
        descriptor=_descriptor(principal.organization_id),
        registered_anchor_fingerprint="sha256:" + "00" * 32,
    )
    with pytest.raises(WorkerIdentityAttestationUnavailable):
        source.attest(preflight=pf, now=datetime.now(UTC))


def test_attestation_source_fails_closed_on_wrong_registered_anchor(session, principal):
    # If the durable registration pins a DIFFERENT anchor (wrong identity / cross-org), the source
    # fails closed even though the signer honestly signs its own (unregistered) anchor.
    pf = _queued(session, principal)
    scheme = LocalHashBasedPoPScheme()
    signer = scheme.generate_signer()
    other = scheme.generate_signer()
    source = PoPVerifiedAttestationSource(
        signer=signer,
        verifier=IndependentPoPVerifier(scheme),
        descriptor=_descriptor(principal.organization_id),
        registered_anchor_fingerprint=compute_verification_anchor_fingerprint(
            other.public_anchor()
        ),
    )
    with pytest.raises(WorkerIdentityAttestationUnavailable):
        source.attest(preflight=pf, now=datetime.now(UTC))


def test_sealed_deployment_signer_refuses_offline():
    sealed = SealedDeploymentLocalSigner()
    with pytest.raises(DeploymentSignerUnavailable):
        sealed.public_anchor()
    with pytest.raises(DeploymentSignerUnavailable):
        sealed.sign(b"challenge")


# --- 4. The local hash-based scheme is BLOCKED from remote authentication -------------------------


def test_local_hash_scheme_declares_itself_remote_ineligible():
    # The local placeholder must NEVER present itself as a remote-authentication primitive.
    assert LocalHashBasedPoPScheme().remote_authentication_eligible is False


def test_remote_eligibility_contract_refuses_the_local_scheme():
    # A future remote-authentication path calling this contract fails closed on the local scheme.
    with pytest.raises(RemoteAuthenticationIneligible):
        assert_remote_authentication_eligible(LocalHashBasedPoPScheme())


def test_remote_eligibility_contract_accepts_a_remote_eligible_scheme():
    # A genuine many-time asymmetric primitive (illustrated here by a fake declaring eligibility) is
    # the ONLY kind the contract admits; the local hash scheme can never satisfy it.
    class _FakeRemoteEligibleScheme:
        remote_authentication_eligible = True

        def verify(self, *, public_anchor, message, signature):  # pragma: no cover - not invoked
            return False

    assert_remote_authentication_eligible(_FakeRemoteEligibleScheme())  # does not raise
    # An object that merely omits the marker is treated as ineligible (default-deny).
    with pytest.raises(RemoteAuthenticationIneligible):
        assert_remote_authentication_eligible(object())  # type: ignore[arg-type]
