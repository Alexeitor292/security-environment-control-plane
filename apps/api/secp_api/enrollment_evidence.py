"""Controller-side verification of worker enrollment evidence (SECP-PR5H-B1, T2).

The pure, boundary-safe verification the controller applies to a worker attestation BEFORE it would
consume the single-use invitation (binding proof-of-possession) or record a signed worker result. It
reconstructs the canonical claim from the controller's OWN AUTHORITATIVE invitation fields — never
trusting the worker's echoed values — and verifies the worker's detached Ed25519 attestation under
the worker's PRESENTED public key, whose key id is DERIVED here (never taken on trust). Verification
needs only PUBLIC material, so no private key crosses the boundary.

It imports only the shared attestation primitive + the enrollment enums/errors — no ``httpx``, no
deployment/management behavior, no persistence. The production route that consumes a verified proof
(and, controller-side, the offer SIGNER) is the root-gated PR5H-B2 bootstrap; until then the public
progression surface stays sealed and this is the ready controller-side verification seam.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_commissioning.enrollment_attestation import (
    ENROLLMENT_ATTESTATION_DOMAIN,
    POP_KIND,
    RESULT_KIND,
    AttestationError,
    DetachedAttestation,
    claim_digest,
    key_id_for,
    verify_detached,
    worker_binding_claim,
    worker_result_claim,
)

from secp_api.enums import WorkerEnrollmentErrorCode as EC
from secp_api.errors import WorkerEnrollmentError


@dataclass(frozen=True)
class VerifiedWorkerBinding:
    """The result of a passing worker binding proof-of-possession: the worker key id the controller
    may now bind (proven possessed) and the worker installation id it agreed to."""

    worker_key_id: str
    worker_installation_id: str


def _key_id_for(public_key_hex: object) -> str:
    if not isinstance(public_key_hex, str):
        raise WorkerEnrollmentError(EC.pop_invalid)
    try:
        return key_id_for(public_key_hex)
    except (ValueError, TypeError):
        raise WorkerEnrollmentError(EC.pop_invalid) from None


def verify_worker_binding_pop(
    *,
    enrollment_id: str,
    invitation_id: str,
    controller_installation_id: str,
    controller_key_id: str,
    controller_transaction_id: str,
    release_digest: str,
    expires_at: str,
    worker_installation_id: str,
    worker_public_key_hex: str,
    attestation: DetachedAttestation,
) -> VerifiedWorkerBinding:
    """Verify a worker binding PoP. The binding claim is rebuilt from the AUTHORITATIVE invitation
    fields (the controller's own persisted invitation), so a valid signature proves the worker both
    possesses the presented key AND agreed to the exact enrollment / invitation / controller
    identity / transaction / release / expiry. Any failure — malformed key, unpinned signer, wrong
    signature, or a claim that disagrees with the invitation — raises ``enrollment_pop_invalid``."""
    worker_key_id = _key_id_for(worker_public_key_hex)
    claim = worker_binding_claim(
        enrollment_id=enrollment_id,
        invitation_id=invitation_id,
        controller_installation_id=controller_installation_id,
        controller_key_id=controller_key_id,
        controller_transaction_id=controller_transaction_id,
        worker_installation_id=worker_installation_id,
        worker_key_id=worker_key_id,
        release_digest=release_digest,
        expires_at=expires_at,
    )
    try:
        verify_detached(
            attestation,
            expected_key_id=worker_key_id,
            domain=ENROLLMENT_ATTESTATION_DOMAIN,
            kind=POP_KIND,
            digest=claim_digest(claim),
        )
    except AttestationError:
        raise WorkerEnrollmentError(EC.pop_invalid) from None
    return VerifiedWorkerBinding(
        worker_key_id=worker_key_id, worker_installation_id=worker_installation_id
    )


def verify_worker_result(
    *,
    enrollment_id: str,
    controller_transaction_id: str,
    predecessor_digest: str,
    release_digest: str,
    outcome: str,
    bound_worker_key_id: str,
    worker_public_key_hex: str,
    attestation: DetachedAttestation,
) -> None:
    """Verify a signed worker result against the ALREADY-BOUND worker key (the presented public key
    must derive the key the enrollment bound at PoP) and the exact enrollment / transaction /
    predecessor / release / outcome. Any failure raises a bounded ``enrollment_pop_invalid``."""
    worker_key_id = _key_id_for(worker_public_key_hex)
    if worker_key_id != bound_worker_key_id:
        raise WorkerEnrollmentError(EC.pop_invalid)
    claim = worker_result_claim(
        enrollment_id=enrollment_id,
        controller_transaction_id=controller_transaction_id,
        worker_key_id=worker_key_id,
        predecessor_digest=predecessor_digest,
        release_digest=release_digest,
        outcome=outcome,
    )
    try:
        verify_detached(
            attestation,
            expected_key_id=worker_key_id,
            domain=ENROLLMENT_ATTESTATION_DOMAIN,
            kind=RESULT_KIND,
            digest=claim_digest(claim),
        )
    except AttestationError:
        raise WorkerEnrollmentError(EC.pop_invalid) from None


__all__ = [
    "VerifiedWorkerBinding",
    "verify_worker_binding_pop",
    "verify_worker_result",
]
