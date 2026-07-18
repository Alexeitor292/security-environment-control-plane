"""Offline release-bundle verification (SECP-PR5E) — signature before trust, no network.

``verify_release_bundle`` reads the manifest + detached signature from a bundle directory through
the
HARDENED filesystem, verifies the Ed25519 signature over the canonical manifest against the pinned
trust root BEFORE any artifact is trusted, then verifies EVERY artifact's exact SHA-256 (and size,
and — via the hardened read — its non-symlink / non-hardlink / regular-file trust) BEFORE any host
write can occur. It performs NO host write, contacts NO network, pulls NO registry, and trusts NO
floating image tag. The shipped trust root is empty, so a production bundle is refused until a
reviewed anchor is pinned.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass

from secp_commissioning.canonical import sha256_bytes

from secp_management import ManagementError
from secp_management.release_bundle import (
    MANIFEST_NAME,
    SIGNATURE_NAME,
    ReleaseManifest,
    ReleaseSignature,
    manifest_aggregate_digest,
    manifest_signing_message,
    parse_manifest_bytes,
    parse_signature_bytes,
)
from secp_management.signing import ReleaseTrustRoot

_MAX_MANIFEST_BYTES = 1 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 4 * 1024
_ROOT_UID = 0


@dataclass(frozen=True)
class VerifiedRelease:
    """The immutable result of a successful, fully-verified release bundle. Nonsecret.

    Carries the detached signature so the bootstrap transaction can install the exact reviewed
    ``installed-release`` record (manifest + signature) that ``status`` later reverifies without any
    caller-supplied bundle path."""

    manifest: ReleaseManifest
    aggregate_digest: str
    signature_key_id: str
    role: str
    signature: ReleaseSignature


def _read(fs: object, path: str, *, max_bytes: int, expected_uid: int, what: str) -> bytes:
    try:
        return fs.safe_read(path, max_bytes=max_bytes, expected_uid=expected_uid)  # type: ignore[attr-defined]
    except Exception as exc:
        raise ManagementError(getattr(exc, "reason_code", f"{what}_unreadable")) from None


def verify_release_bundle(
    bundle_dir: str,
    *,
    trust_root: ReleaseTrustRoot,
    fs: object,
    expected_uid: int = _ROOT_UID,
) -> VerifiedRelease:
    """Verify a release bundle end to end and return the :class:`VerifiedRelease`, or fail closed
    with
    a bounded reason. Order (each gate precedes the next): manifest read → parse → signature read →
    parse → signature verifies over the canonical manifest under a PINNED anchor → every artifact's
    exact digest + size + hardened trust. No host write, no network."""
    if not isinstance(bundle_dir, str) or not posixpath.isabs(bundle_dir):
        raise ManagementError("release_bundle_path_invalid")

    manifest_bytes = _read(
        fs,
        posixpath.join(bundle_dir, MANIFEST_NAME),
        max_bytes=_MAX_MANIFEST_BYTES,
        expected_uid=expected_uid,
        what="release_manifest",
    )
    manifest = parse_manifest_bytes(manifest_bytes)

    sig_bytes = _read(
        fs,
        posixpath.join(bundle_dir, SIGNATURE_NAME),
        max_bytes=_MAX_SIGNATURE_BYTES,
        expected_uid=expected_uid,
        what="release_signature",
    )
    signature = parse_signature_bytes(sig_bytes)

    # The signature's key id must be the manifest-pinned signing key, and it must be a PINNED
    # anchor.
    if signature.key_id != manifest.signing_anchor_id:
        raise ManagementError("release_signature_key_mismatch")
    if not trust_root.verify(
        key_id=signature.key_id,
        message=manifest_signing_message(manifest),
        signature_hex=signature.signature,
    ):
        # Signature invalid, wrong trust root, or an unpinned/absent anchor (the shipped posture).
        raise ManagementError("release_signature_untrusted")

    # Only NOW, after the signature is trusted, verify every artifact's exact content (before any
    # host write — this function performs none). The hardened read refuses a symlink/hardlink/
    # non-regular/oversized artifact; the digest+size refuse a modified or substituted one.
    for art in manifest.artifacts:
        data = _read(
            fs,
            posixpath.join(bundle_dir, art.name),
            max_bytes=art.size,
            expected_uid=expected_uid,
            what="release_artifact",
        )
        if len(data) != art.size:
            raise ManagementError("release_artifact_size_mismatch")
        if sha256_bytes(data) != art.sha256:
            raise ManagementError("release_artifact_digest_mismatch")

    return VerifiedRelease(
        manifest=manifest,
        aggregate_digest=manifest_aggregate_digest(manifest),
        signature_key_id=signature.key_id,
        role=manifest.role,
        signature=signature,
    )


def verify_release_record(
    manifest_bytes: bytes, signature_bytes: bytes, *, trust_root: ReleaseTrustRoot
) -> VerifiedRelease:
    """Reverify a stored ``installed-release`` record (manifest + detached signature) — the SAME
    signature-before-trust check as a bundle, minus the on-disk artifact byte reads (the record
    ships no artifacts; its purpose is to re-bind status to the exact signed release identity). The
    manifest binds every artifact digest, so a valid manifest signature reverifies the whole
    artifact IDENTITY set. Fails closed with a bounded reason."""
    manifest = parse_manifest_bytes(manifest_bytes)
    signature = parse_signature_bytes(signature_bytes)
    if signature.key_id != manifest.signing_anchor_id:
        raise ManagementError("release_signature_key_mismatch")
    if not trust_root.verify(
        key_id=signature.key_id,
        message=manifest_signing_message(manifest),
        signature_hex=signature.signature,
    ):
        raise ManagementError("release_signature_untrusted")
    return VerifiedRelease(
        manifest=manifest,
        aggregate_digest=manifest_aggregate_digest(manifest),
        signature_key_id=signature.key_id,
        role=manifest.role,
        signature=signature,
    )
