"""Reviewed asymmetric (Ed25519) release signature + pinned trust root (SECP-PR5E).

Release verification trust is anchored in a CODE-OWNED :class:`ReleaseTrustRoot` — a closed set of
pinned public key anchors. The SHIPPED production trust root is EMPTY: no reviewed release-signing
public key is committed yet, so every production release signature is refused until a reviewed
anchor
is added by a separately-reviewed change (sealed-by-default). Production contains NO private
release-signing key. Tests mint an EPHEMERAL, visibly test-only keypair + trust root at run time; no
private key material is ever committed.

The primitives never raise on bad input — ``verify_ed25519`` returns ``False`` — so a malformed key
or
signature can never crash verification or leak a stack trace.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_RAW = serialization.Encoding.Raw
_PUBLIC = serialization.PublicFormat.Raw
_PRIVATE = serialization.PrivateFormat.Raw
_NO_ENCRYPTION = serialization.NoEncryption()


def verify_ed25519(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    """True iff ``signature_hex`` is a valid Ed25519 signature of ``message`` under
    ``public_key_hex`` (a 32-byte raw public key, hex). Never raises: any malformed input, wrong
    length, or invalid signature returns ``False``."""
    try:
        pub = bytes.fromhex(public_key_hex)
        sig = bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False
    if len(pub) != 32 or len(sig) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
        return True
    except Exception:
        return False


def sign_ed25519(private_key_hex: str, message: bytes) -> str:
    """Sign ``message`` with a raw Ed25519 private key (hex) → hex signature. Used ONLY by tests
    with
    an ephemeral test key; production commits no private key."""
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return key.sign(message).hex()


def generate_keypair() -> tuple[str, str]:
    """Generate an EPHEMERAL Ed25519 keypair as ``(private_hex, public_hex)``. Test-only helper — it
    mints fresh keys at call time, so no key material is committed to the repository."""
    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(_RAW, _PRIVATE, _NO_ENCRYPTION).hex()
    pub = key.public_key().public_bytes(_RAW, _PUBLIC).hex()
    return priv, pub


@dataclass(frozen=True)
class TrustAnchor:
    """One pinned release-signing public key: a stable ``key_id`` bound to a raw Ed25519 public
    key."""

    key_id: str
    public_key_hex: str


@dataclass(frozen=True)
class ReleaseTrustRoot:
    """The closed set of pinned release-signing anchors. An empty trust root refuses every signature
    (the shipped production posture). ``test_only`` marks an ephemeral test trust root so it can
    never
    be mistaken for the reviewed production one."""

    anchors: tuple[TrustAnchor, ...]
    test_only: bool

    def verify(self, *, key_id: str, message: bytes, signature_hex: str) -> bool:
        """True iff ``key_id`` is a PINNED anchor and the signature verifies under it. An unknown /
        unpinned ``key_id`` is refused (never trusted)."""
        for anchor in self.anchors:
            if anchor.key_id == key_id:
                return verify_ed25519(anchor.public_key_hex, message, signature_hex)
        return False


# The shipped production trust root: EMPTY. No reviewed release-signing public key is committed, so
# every production release verification fails closed until a reviewed anchor is added here by a
# separately-reviewed change. Production carries no private key.
SHIPPED_TRUST_ROOT = ReleaseTrustRoot(anchors=(), test_only=False)
