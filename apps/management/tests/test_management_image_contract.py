"""Complete typed image contract (SECP-PR5E round 5 blocker 6).

A :class:`VerifiedArtifact` for an image archive carries BOTH the archive-content digest (proving
the
exact signed bytes were read) AND the signed expected loaded-image digest AND the signed purpose.
The
host adapter verifies the LOADED image against the signed purpose-specific image digest — loading
the
right archive is not sufficient, the resulting image must match too. A mismatch fails closed.
"""

from __future__ import annotations

import pytest
from _mgmt_support import (
    WORKER_ORDINARY_IMAGE,
    deps_for,
    ephemeral_trust_root,
    fresh_worker_world,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import ManagementError
from secp_management.adapters import VerifiedArtifact
from secp_management.cli import run

_DOCS = (
    "/var/lib/secp/bootstrap/worker-identity.json",
    "/var/lib/secp/bootstrap/worker-evidence.json",
)


def _image_artifact(*, image_digest: str) -> VerifiedArtifact:
    body = b"fake image archive\n"
    return VerifiedArtifact(
        role="shared",
        kind="image_archive",
        name="images/ordinary.tar",
        digest="sha256:" + "1" * 64,  # archive-content digest
        size=len(body),
        reader=lambda: body,
        purpose="worker/ordinary",
        # the signed expected LOADED-image digest (distinct from the archive-content digest above)
        image_digest=image_digest,
    )


def test_artifact_carries_distinct_archive_and_image_digests():
    art = _image_artifact(image_digest=WORKER_ORDINARY_IMAGE)
    assert art.image_digest == WORKER_ORDINARY_IMAGE
    assert art.image_digest != art.digest  # the loaded-image digest is NOT the archive digest
    assert art.purpose == "worker/ordinary"


def test_matching_loaded_image_passes():
    art = _image_artifact(image_digest=WORKER_ORDINARY_IMAGE)
    art.verify_loaded_image(WORKER_ORDINARY_IMAGE)  # no raise


def test_mismatched_loaded_image_refused():
    art = _image_artifact(image_digest=WORKER_ORDINARY_IMAGE)
    with pytest.raises(ManagementError) as exc:
        art.verify_loaded_image("sha256:" + "9" * 64)
    assert exc.value.reason_code == "verified_artifact_image_digest_mismatch"


def test_artifact_without_signed_image_digest_cannot_be_proven():
    # an image artifact missing the signed loaded-image digest can never satisfy verification, so a
    # correct archive alone is never sufficient.
    art = _image_artifact(image_digest="")
    with pytest.raises(ManagementError) as exc:
        art.verify_loaded_image("sha256:" + "1" * 64)
    assert exc.value.reason_code == "verified_artifact_image_digest_mismatch"


def test_bootstrap_refuses_when_loaded_image_differs_from_signed_digest():
    # end to end: the archive verifies but the adapter reports a LOADED image that differs from the
    # signed purpose-specific digest → the bootstrap fails closed before any document is written.
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    deps = deps_for(fs, fresh_worker_world(load_wrong_image=True), trust)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "verified_artifact_image_digest_mismatch"
    assert not any(d in set(fs.paths()) for d in _DOCS)
