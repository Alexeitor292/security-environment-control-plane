"""Shared pure Ed25519 detached-attestation primitive for the worker-enrollment exchange (PR5H-B1).

Both planes import this ONE pure primitive, so the signed bytes are byte-identical on both sides and
the protocol is never loosely duplicated:

* the WORKER (``secp_worker`` EnrollmentTransport) SIGNS its proof-of-possession binding and its
  worker-result with its own locally-generated Ed25519 key, and
* the CONTROLLER (``secp_api`` enrollment surface) VERIFIES those signatures using only the
  presented PUBLIC key + the pinned key id — no private key ever crosses the boundary.

Boundary-safe by construction: it imports only ``cryptography`` and the shared
``secp_commissioning.canonical`` primitive — never any API / worker / management / deployment
behavior — and the pure enrollment CONTRACT mirror (which forbids ``cryptography``) does not import
it.

The signed bytes are a DOMAIN-SEPARATED digest envelope (never the full record), byte-for-byte
compatible with the deployment cross-host-handoff attestation (proven by a byte-parity test)::

    canonical_json({"domain": D, "kind": K, "digest": <sha256>}).encode("ascii") + b"\\n"

The enrollment exchange uses its OWN domain, so an enrollment attestation can never be replayed as a
discovery-activation handoff (and vice versa), and the ``kind`` separates the binding-PoP from the
worker-result within the exchange.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from secp_commissioning.canonical import canonical_json, is_sha256_digest, sha256_digest

#: The enrollment exchange's own attestation domain (distinct from the discovery-activation one).
ENROLLMENT_ATTESTATION_DOMAIN = "secp.worker-enrollment.exchange/v1"
#: The ``kind`` labels within the exchange (domain-separated within the domain): the worker
#: binding proof-of-possession, the controller-signed offer, and the signed worker result.
POP_KIND = "worker-enrollment-binding-pop"
OFFER_KIND = "worker-enrollment-controller-offer"
RESULT_KIND = "worker-enrollment-result"
#: The OWNERSHIP claim's kind. A DISTINCT kind produces distinct signed bytes through
#: ``attestation_message``, so the ``/v1`` offer schema and every existing signature over it are
#: untouched — no signed canonical form changes meaning while keeping its identifier.
OWNERSHIP_KIND = "worker-enrollment-controller-ownership"
#: The canonical schema tags for the three structured claims.
BINDING_SCHEMA = "secp.worker-enrollment.binding/v1"
OFFER_SCHEMA = "secp.worker-enrollment.offer/v1"
RESULT_SCHEMA = "secp.worker-enrollment.result/v1"
OWNERSHIP_SCHEMA = "secp.worker-enrollment.ownership/v1"
#: Domain separator for the dedicated-enrollment-key proof-of-possession handle (see
#: ``enrollment_key_proof_id_for``) — distinct from any signed-message domain.
_ENROLLMENT_KEY_PROOF_DOMAIN = b"secp/controller-enrollment-key-proof/v1"

_RAW = serialization.Encoding.Raw
_PUBLIC = serialization.PublicFormat.Raw
_PRIVATE = serialization.PrivateFormat.Raw
_NO_ENCRYPTION = serialization.NoEncryption()
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")


class AttestationError(Exception):
    """A bounded, closed attestation refusal — carries ONLY a reason code, never key material, a
    signed message, a path, an endpoint or a raw exception."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class DetachedAttestation:
    """A detached Ed25519 attestation over a domain-separated digest message. PUBLIC material only —
    it carries no private key and no signed plaintext, only the public key, its key id and the
    signature."""

    algorithm: str  # always "Ed25519"
    key_id: str  # sha256 of the RAW public key bytes
    public_key_hex: str
    signature: str


def key_id_for(public_key_hex: str) -> str:
    """The key id pinned to a raw 32-byte Ed25519 public key: sha256 of the RAW key BYTES (not the
    ASCII hex), matching the controller identity's ``controller_key_id`` derivation."""
    return "sha256:" + hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


def attestation_message(*, domain: str, kind: str, digest: str) -> bytes:
    """The exact bytes signed/verified: a domain-separated digest envelope (not the full record)."""
    return (
        canonical_json({"domain": domain, "kind": kind, "digest": digest}).encode("ascii") + b"\n"
    )


def sign_detached(
    private_key_hex: str, *, domain: str, kind: str, digest: str
) -> DetachedAttestation:
    """Produce a detached attestation over ``(domain, kind, digest)``. Used by the worker (its own
    locally-generated key) and by tests; production controllers commit NO private key (that signer
    is the root-gated PR5H-B2 bootstrap)."""
    if not is_sha256_digest(digest):
        raise AttestationError("attestation_digest_invalid")
    try:
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    except (ValueError, TypeError):
        raise AttestationError("attestation_key_invalid") from None
    public_hex = key.public_key().public_bytes(_RAW, _PUBLIC).hex()
    signature = key.sign(attestation_message(domain=domain, kind=kind, digest=digest)).hex()
    return DetachedAttestation(
        algorithm="Ed25519",
        key_id=key_id_for(public_hex),
        public_key_hex=public_hex,
        signature=signature,
    )


def verify_detached(
    attestation: DetachedAttestation, *, expected_key_id: str, domain: str, kind: str, digest: str
) -> None:
    """Verify a detached attestation against the pinned ``expected_key_id`` and the exact
    ``(domain, kind, digest)``. Raises :class:`AttestationError` (bounded reason code) on ANY
    failure — a malformed field, an unpinned key id, a mismatched key-id/public-key, or an invalid
    signature — and never raises a raw exception or returns a partial result."""
    if attestation.algorithm != "Ed25519":
        raise AttestationError("attestation_algorithm_invalid")
    if not is_sha256_digest(expected_key_id) or not is_sha256_digest(attestation.key_id):
        raise AttestationError("attestation_signer_not_pinned")
    if attestation.key_id != expected_key_id:
        raise AttestationError("attestation_signer_not_pinned")
    if not _HEX64.fullmatch(attestation.public_key_hex) or not _HEX128.fullmatch(
        attestation.signature
    ):
        raise AttestationError("attestation_invalid")
    # the pinned key id MUST derive from the presented public key — no free-floating trust anchor
    if key_id_for(attestation.public_key_hex) != attestation.key_id:
        raise AttestationError("attestation_key_id_mismatch")
    if not is_sha256_digest(digest):
        raise AttestationError("attestation_digest_invalid")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(attestation.public_key_hex)).verify(
            bytes.fromhex(attestation.signature),
            attestation_message(domain=domain, kind=kind, digest=digest),
        )
    except Exception:
        raise AttestationError("attestation_signature_invalid") from None


def worker_binding_claim(
    *,
    enrollment_id: str,
    invitation_id: str,
    controller_installation_id: str,
    controller_key_id: str,
    controller_transaction_id: str,
    worker_installation_id: str,
    worker_key_id: str,
    release_digest: str,
    expires_at: str,
) -> dict[str, str]:
    """The canonical worker proof-of-possession binding claim. It binds the worker's presented key
    to the EXACT enrollment, invitation, controller identity, transaction, release and expiry, so a
    valid signature proves both key possession AND agreement to that exact context — a signature can
    never be replayed for a different enrollment, controller or release. Both the worker (which
    signs) and the controller (which reconstructs it from the authoritative invitation) build it
    HERE, so the two sides never drift."""
    return {
        "schema": BINDING_SCHEMA,
        "enrollment_id": enrollment_id,
        "invitation_id": invitation_id,
        "controller_installation_id": controller_installation_id,
        "controller_key_id": controller_key_id,
        "controller_transaction_id": controller_transaction_id,
        "worker_installation_id": worker_installation_id,
        "worker_key_id": worker_key_id,
        "release_digest": release_digest,
        "expires_at": expires_at,
    }


def worker_result_claim(
    *,
    enrollment_id: str,
    controller_transaction_id: str,
    worker_key_id: str,
    predecessor_digest: str,
    release_digest: str,
    outcome: str,
    health_evidence_digest: str,
    generation: str,
    challenge: str,
) -> dict[str, str]:
    """The canonical signed worker-result claim: binds the result to the enrollment, transaction,
    worker key, the predecessor state digest (chaining it to the exact prior state) and the exact
    release, plus a bounded outcome token. It ALSO binds the ``sha256:`` content address of the
    worker's bounded health-evidence structure (so the signed evidence cannot be swapped) and the
    exchange ``generation`` + ``challenge`` — the offer revision and the ``sha256:`` claim digest of
    the exact controller offer this result answers — so a signed result can never be replayed onto
    a different exchange/offer. No raw handoff bytes, host path or secret. Both the worker (which
    signs) and the controller (which rebuilds it from authoritative state + the received evidence)
    build it HERE, so the two sides never drift."""
    return {
        "schema": RESULT_SCHEMA,
        "enrollment_id": enrollment_id,
        "controller_transaction_id": controller_transaction_id,
        "worker_key_id": worker_key_id,
        "predecessor_digest": predecessor_digest,
        "release_digest": release_digest,
        "outcome": outcome,
        "health_evidence_digest": health_evidence_digest,
        "generation": generation,
        "challenge": challenge,
    }


def controller_offer_claim(
    *,
    enrollment_id: str,
    invitation_id: str,
    controller_installation_id: str,
    controller_key_id: str,
    controller_origin: str,
    controller_transaction_id: str,
    worker_installation_id: str,
    worker_key_id: str,
    release_digest: str,
    expires_at: str,
    predecessor_digest: str,
) -> dict[str, str]:
    """The canonical controller offer claim the controller's dedicated enrollment key signs. It
    commits the offer to the EXACT enrollment, invitation, active controller identity/origin,
    transaction, the exact worker key proven at bind, the release and expiry, and chains to the
    bind-PoP it answers via ``predecessor_digest`` (mirroring the worker-result chaining). Both the
    controller (which signs) and the worker (which verifies against the invitation's pinned
    controller key) build it HERE, so the two sides never drift."""
    return {
        "schema": OFFER_SCHEMA,
        "enrollment_id": enrollment_id,
        "invitation_id": invitation_id,
        "controller_installation_id": controller_installation_id,
        "controller_key_id": controller_key_id,
        "controller_origin": controller_origin,
        "controller_transaction_id": controller_transaction_id,
        "worker_installation_id": worker_installation_id,
        "worker_key_id": worker_key_id,
        "release_digest": release_digest,
        "expires_at": expires_at,
        "predecessor_digest": predecessor_digest,
    }


def controller_ownership_claim(
    *,
    organization_id: str,
    controller_installation_id: str,
    controller_key_id: str,
    controller_origin: str,
    controller_trust_anchor_id: str,
    worker_key_id: str,
    enrollment_id: str,
    invitation_id: str,
    controller_transaction_id: str,
    release_digest: str,
    predecessor_digest: str,
) -> dict[str, str]:
    """The canonical claim a worker PERMANENTLY pins as "who owns me".

    WHY A SEPARATE KIND RATHER THAN MORE FIELDS ON THE OFFER
    ---------------------------------------------------------
    The offer claim authenticates the enrollment EXCHANGE. Read its field list: it covers neither
    the organization nor the controller's TLS trust anchor. Those are exactly the facts an ownership
    binding must not take on trust, because a *proxying* attacker presents the real controller's
    signing key id, forwards the exchange so every signature verifies, and swaps only the CA. No
    existing signature says anything about the CA, so nothing catches it.

    Adding the fields to ``OFFER_SCHEMA`` was the alternative and is refused: changing which bytes a
    ``/v1`` identifier covers, while keeping the identifier, makes every existing statement about
    signed-byte compatibility false. A new ``kind`` changes the signed bytes through
    :func:`attestation_message` and leaves the offer untouched.

    ``controller_trust_anchor_id`` is the load-bearing field. The worker compares it against the
    anchor it ACTUALLY negotiated (:func:`secp_commissioning.trust_anchor.trust_anchor_id_for` over
    the bundle it built its TLS context from), so a signature obtained through a CA-swapping proxy
    fails the comparison rather than authorising the swap.
    """
    return {
        "schema": OWNERSHIP_SCHEMA,
        "organization_id": organization_id,
        "controller_installation_id": controller_installation_id,
        "controller_key_id": controller_key_id,
        "controller_origin": controller_origin,
        "controller_trust_anchor_id": controller_trust_anchor_id,
        "worker_key_id": worker_key_id,
        "enrollment_id": enrollment_id,
        "invitation_id": invitation_id,
        "controller_transaction_id": controller_transaction_id,
        "release_digest": release_digest,
        "predecessor_digest": predecessor_digest,
    }


def enrollment_key_proof_id_for(public_key_hex: str) -> str:
    """A deterministic, bounded, PUBLIC proof-of-possession handle for the dedicated controller
    enrollment key, derived from its public key with domain separation. It is the persisted
    ``enrollment_key_proof_id``: the signer recomputes it from the loaded private key's public half
    and compares it to the persisted identity, proving possession without transporting the key. The
    ``enrkp:`` domain prefix guarantees it can never collide with a plain ``sha256:`` source digest
    (so the controller-identity key-separation invariant always holds)."""
    raw = bytes.fromhex(public_key_hex)
    return "enrkp:" + hashlib.sha256(_ENROLLMENT_KEY_PROOF_DOMAIN + raw).hexdigest()


def claim_digest(claim: dict[str, str]) -> str:
    """The ``sha256:`` content address of a canonical claim — the digest that is actually signed."""
    return sha256_digest(claim)


#: The bounded outcome token a worker result must carry to advance the enrollment to ``healthy``. A
#: result attesting any other outcome is authenticated but never sufficient for healthy.
WORKER_RESULT_OUTCOME_HEALTHY = "healthy"

#: The closed set of CHECKED FACTS a worker's bounded, provider-neutral health-evidence structure
#: must attest (each a boolean the worker sets only after actually performing the check). Every one
#: must be present and ``True`` for the controller to mark the enrollment ``healthy`` — it is
#: never a caller convenience boolean. The last three are inertness proofs: the worker did NOT
#: contact a provider, run OpenTofu, or submit anything to the controlled-live path.
REQUIRED_HEALTH_CHECKS = (
    "invitation_and_offer_verified",
    "controller_key_pinned",
    "expected_transaction",
    "expected_predecessor",
    "exact_release",
    "worker_enrollment_key_protected",
    "local_enrollment_state_present",
    "operator_worker_disabled",
    "no_provider_contact",
    "no_opentofu_execution",
    "no_controlled_live_submission",
)


def health_evidence_complete(evidence: object) -> bool:
    """True iff the bounded health-evidence structure attests EVERY required check as ``True``. A
    missing key, a non-boolean, or any ``False`` fails closed (the enrollment cannot become
    healthy)."""
    if not isinstance(evidence, dict):
        return False
    return all(evidence.get(check) is True for check in REQUIRED_HEALTH_CHECKS)


__all__ = [
    "BINDING_SCHEMA",
    "ENROLLMENT_ATTESTATION_DOMAIN",
    "OFFER_KIND",
    "OWNERSHIP_KIND",
    "OWNERSHIP_SCHEMA",
    "OFFER_SCHEMA",
    "POP_KIND",
    "REQUIRED_HEALTH_CHECKS",
    "RESULT_KIND",
    "RESULT_SCHEMA",
    "controller_ownership_claim",
    "WORKER_RESULT_OUTCOME_HEALTHY",
    "AttestationError",
    "DetachedAttestation",
    "attestation_message",
    "claim_digest",
    "controller_offer_claim",
    "enrollment_key_proof_id_for",
    "health_evidence_complete",
    "key_id_for",
    "sign_detached",
    "verify_detached",
    "worker_binding_claim",
    "worker_result_claim",
]
