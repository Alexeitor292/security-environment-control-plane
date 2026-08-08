"""The identity of the CA set a worker actually trusts (M1 pre-live anti-hijack).

ONE derivation, imported by both planes, for the same reason
:mod:`secp_commissioning.enrollment_attestation` is shared: the controller SIGNS this identity and
the worker COMPUTES it from the bundle it really built its TLS context from. If the two sides
derived it differently the comparison would be meaningless, and it would fail in the direction that
looks like success — a mismatch nobody notices because one side was never computing what the other
signed.

WHAT PROBLEM THIS SOLVES
-------------------------
The enrollment invitation carries the controller origin, the controller signing key AND the CA
bundle together. An attacker who substitutes the invitation substitutes all three, which
``worker_ownership``'s gate already catches by pinning the signing key. But a *proxying* attacker
does something the gate cannot see: it presents the REAL controller's signing key id, forwards the
exchange to the real controller so every signature verifies, and swaps only the CA — terminating
TLS itself. Every signature check passes, because no signature covers the CA.

So the controller signs this identity inside a domain-separated ownership claim, and the worker
compares it against the anchor it actually negotiated. A proxy that swapped the CA produces a
mismatch it cannot repair without the controller's signing key.

WHY A SET DIGEST RATHER THAN A CERTIFICATE FINGERPRINT
-------------------------------------------------------
A bundle may hold more than one certificate, and trusting it means trusting ALL of them. A
fingerprint of "the" certificate would answer a question the bundle does not ask, and an attacker
appending their own CA to a bundle containing the real one would leave that fingerprint unchanged
while adding a trust path. So the identity covers every certificate in the bundle.

The member digests are SORTED, so the identity is stable across a bundle that was re-ordered or
re-wrapped, and PEM comments/whitespace are excluded by digesting the parsed DER rather than the
file bytes. Those are properties of the same trust set; a different trust set — one more CA, one
fewer, or a different one — is a different identity.
"""

from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from secp_commissioning.canonical import sha256_digest

#: Domain separator folded into the identity, so a trust-anchor id can never be confused with, or
#: replayed as, any other ``sha256:`` digest in the system (a claim digest, a release digest, a
#: worker key id). Every one of those is a bare sha256 of something, and a bare digest carries no
#: statement about WHAT it identifies.
TRUST_ANCHOR_DOMAIN = "secp.controller-trust-anchor/v1"


class TrustAnchorError(Exception):
    """A bounded refusal. Carries a reason code only — never certificate bytes or a path."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def trust_anchor_id_for(ca_bundle_pem: str | bytes) -> str:
    """The identity of the trust set in ``ca_bundle_pem``.

    Deterministic across both planes: parse every certificate, digest each one's DER, sort, and
    content-address the domain-separated list. An empty bundle is refused rather than yielding the
    identity of "trust nothing" — a worker that computed an id for an empty bundle would compare
    equal to another empty bundle and read as agreement.
    """
    raw = ca_bundle_pem.encode("utf-8") if isinstance(ca_bundle_pem, str) else ca_bundle_pem
    if not raw or not raw.strip():
        raise TrustAnchorError("trust_anchor_bundle_empty")
    try:
        certificates = x509.load_pem_x509_certificates(raw)
    except Exception:
        raise TrustAnchorError("trust_anchor_bundle_unparseable") from None
    if not certificates:
        raise TrustAnchorError("trust_anchor_bundle_empty")

    members = sorted(
        hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        for cert in certificates
    )
    return sha256_digest({"domain": TRUST_ANCHOR_DOMAIN, "members": members})


__all__ = ["TRUST_ANCHOR_DOMAIN", "TrustAnchorError", "trust_anchor_id_for"]
