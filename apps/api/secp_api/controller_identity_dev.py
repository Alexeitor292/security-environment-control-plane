"""TEST/DEV-only controller enrollment-identity proof factory (SECP-PR5H-B1, R1).

This deliberately lives OUTSIDE ``services/`` — the production service module carries no test-only
construction and no concrete placeholder endpoint. It stands in for the PR5H-B2 root-gated bootstrap
verification, which is the only production producer of a :class:`VerifiedControllerIdentity`. The
dev seed and the test suite construct proofs through here; NO production activation path imports it.
"""

from __future__ import annotations

from secp_api.services.controller_identity import VerifiedControllerIdentity
from secp_api.worker_enrollment_contract import sha256_digest_of_hex

# a reserved, non-routable RFC 6761 ``.test`` placeholder origin — never a real endpoint. This
# module lives outside ``services/`` so no test-only placeholder sits in production source.
_DEV_ORIGIN = "https://controller.example.test"


def build_test_verified_controller_identity(**over: str) -> VerifiedControllerIdentity:
    """Construct a well-formed :class:`VerifiedControllerIdentity` for dev seeding and tests.

    NEVER call this from a production activation path — production identity comes only from the
    PR5H-B2 root-gated bootstrap verification."""
    anchor = over.get("controller_trust_anchor_hex", "11" * 32)
    fields = dict(
        controller_installation_id="controller-dev0001",
        controller_key_id=sha256_digest_of_hex(anchor),
        controller_trust_anchor_hex=anchor,
        controller_origin=_DEV_ORIGIN,
        release_digest="sha256:" + "a" * 64,
        management_identity_digest="sha256:" + "e" * 64,
        bootstrap_evidence_digest="sha256:" + "f" * 64,
        enrollment_key_proof_id="enrollkeyproof-0001",
    )
    fields.update(over)
    if "controller_trust_anchor_hex" in over and "controller_key_id" not in over:
        fields["controller_key_id"] = sha256_digest_of_hex(over["controller_trust_anchor_hex"])
    return VerifiedControllerIdentity(**fields)  # type: ignore[arg-type]


__all__ = ["build_test_verified_controller_identity"]
