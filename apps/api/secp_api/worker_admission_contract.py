"""Shared, secret-free worker discovery-admission contract (SECP-B6 MB-1).

Both the CONTROL-PLANE admission verifier (``secp_api.services.worker_admission``) and the WORKER
admission client (``secp_worker.target_discovery.admission_client``) import this module so they
agree on the exact challenge grammar and the Ed25519 primitive. It is a genuine REMOTE proof
mechanism: the verifier issues a single-use nonce and checks the worker's signature against the
PUBLIC anchor whose fingerprint is pinned in the durable ``WorkerIdentityRegistration`` — never a
self-asserted key.

It stores/derives ONLY safe values: it never persists or logs a private key, a signature, or the
challenge bytes, and it imports no SSH/Proxmox/transport/mutation code.
"""

from __future__ import annotations

from datetime import datetime

from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint

# The only purpose a discovery admission may carry.
WORKER_ADMISSION_PURPOSE = "target_discovery_live_read_only"
# The pinned challenge grammar version (folded into the signed message so it cannot drift).
WORKER_ADMISSION_CHALLENGE_SCHEMA = "secp-b6/worker-discovery-admission/v1"
# Short admission TTL (seconds).
WORKER_ADMISSION_TTL_SECONDS = 90

__all__ = [
    "WORKER_ADMISSION_PURPOSE",
    "WORKER_ADMISSION_CHALLENGE_SCHEMA",
    "WORKER_ADMISSION_TTL_SECONDS",
    "admission_signing_message",
    "compute_verification_anchor_fingerprint",
    "ed25519_verify",
    "ed25519_sign",
    "generate_ed25519_keypair",
]


def admission_signing_message(
    *,
    nonce: str,
    organization_id: str,
    discovery_job_id: str,
    worker_registration_id: str,
    identity_version: int,
    endpoint_binding_hash: str,
    expires_at: datetime,
) -> bytes:
    """The exact bytes the worker signs — binds the nonce to the FULL admission context so a
    signature for one job/org/registration/endpoint can never be replayed for another."""
    return (
        f"{WORKER_ADMISSION_CHALLENGE_SCHEMA}|{nonce}|{organization_id}|{discovery_job_id}"
        f"|{worker_registration_id}|{identity_version}|{endpoint_binding_hash}"
        f"|{expires_at.isoformat()}"
    ).encode()


def ed25519_verify(*, public_anchor: str, message: bytes, signature: str) -> bool:
    """Verify a raw Ed25519 signature (hex) over ``message`` under the public anchor (32-byte hex).

    Uses ONLY the public key + signature — never a private key. Returns False on a malformed anchor/
    signature or a bad proof; never raises a raw crypto error.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        anchor = bytes.fromhex(public_anchor)
        sig = bytes.fromhex(signature)
    except (ValueError, TypeError):
        return False
    if len(anchor) != 32 or len(sig) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(anchor).verify(sig, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def ed25519_sign(*, private_key_hex: str, message: bytes) -> str:
    """Sign ``message`` with a raw Ed25519 private key (hex). Worker/test use only."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return private.sign(message).hex()


def generate_ed25519_keypair() -> tuple[str, str]:
    """Generate a fresh (private-key-hex, public-anchor-hex) pair (operator tooling / tests)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return raw_private.hex(), raw_public.hex()
