"""Byte-parity: the shared enrollment attestation primitive matches the deployment handoff verifier.

T2 moves the PURE canonical + signature-verification primitive into the shared
``secp_commissioning.enrollment_attestation`` package so the API and worker planes verify/sign the
SAME bytes without importing privileged deployment behavior. This proves the shared canonicalization
and the domain-separated message envelope are byte-for-byte identical to the reviewed deployment
``secp_discovery_activation.handoff`` implementation — so there is no loosely-duplicated protocol.
"""

from __future__ import annotations

from secp_commissioning import enrollment_attestation as ea
from secp_discovery_activation import handoff

_HANDOFF_DOMAIN = "secp.discovery-activation.cross-host-handoff/v1"


def test_attestation_message_bytes_match_the_deployment_handoff_message():
    digest = "sha256:" + "a" * 64
    for kind in ("controller-offer", "worker-result"):
        assert ea.attestation_message(
            domain=_HANDOFF_DOMAIN, kind=kind, digest=digest
        ) == handoff._message(kind, digest)


def test_shared_canonical_bytes_match_the_deployment_canonical_bytes():
    payload = {"domain": _HANDOFF_DOMAIN, "kind": "worker-result", "digest": "sha256:" + "b" * 64}
    from secp_commissioning.canonical import canonical_json

    assert canonical_json(payload).encode("ascii") + b"\n" == handoff._canonical_bytes(payload)


def test_key_id_derivation_matches_the_deployment_attestation():
    # both derive the key id as sha256 of the RAW 32-byte public key (not the ascii hex)
    from secp_management.signing import generate_keypair

    _, pub = generate_keypair()
    import hashlib

    assert ea.key_id_for(pub) == "sha256:" + hashlib.sha256(bytes.fromhex(pub)).hexdigest()


def test_enrollment_uses_a_distinct_domain_from_the_handoff():
    # the enrollment exchange is domain-separated from the discovery-activation handoff, so an
    # enrollment attestation can never be replayed as a handoff (their signed messages differ)
    assert ea.ENROLLMENT_ATTESTATION_DOMAIN != _HANDOFF_DOMAIN
    digest = "sha256:" + "c" * 64
    assert ea.attestation_message(
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN, kind="worker-enrollment-binding-pop", digest=digest
    ) != handoff._message("controller-offer", digest)
