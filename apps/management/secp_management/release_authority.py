"""Offline release-authority tooling (SECP-PR5H-B2, commit 2b-1b).

A DISTINCT, offline entrypoint — separate from the production installer (``secpctl``) — that a
release engineer uses to mint the release-signing keypair and to build / sign / verify a
``v1alpha2`` release manifest. It runs entirely offline (no network, no Docker, no host mutation
beyond the one key file it is asked to write), and it NEVER lets private material leak:

* the generated Ed25519 private key is written ONLY to a protected, OUT-OF-REPOSITORY 0600 file
  (``O_EXCL`` create; refuses a destination inside the repo, a symlink/hardlink target, or a
  group/other-writable parent); the PUBLIC anchor ``{key_id, public_key_hex}`` is emitted apart;
* ``build`` assembles a strict, deterministic canonical ``v1alpha2`` manifest and refuses an
  incomplete installation profile (the release-contract well-formedness is authoritative);
* ``sign`` refuses a non-canonical manifest, a manifest whose ``signing_anchor_id`` is not THIS
  signer, or drifted artifact bytes; it signs only the canonical signing message;
* ``verify`` verifies a manifest + detached signature under ONLY the SUPPLIED public anchor;
* no raw private key or signature seed ever appears in a return value, report, log, repr, or error —
  every failure is a bounded reason code.

This module imports no network / subprocess / Docker capability. It is never imported by the runtime
API, the browser, or the worker exchange. Tests use ephemeral keys — never a candidate production
key.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from typing import NoReturn

from secp_commissioning.canonical import canonical_json, is_sha256_digest, sha256_bytes

from secp_management import ManagementError
from secp_management.controller_compose_validation import assert_controller_compose_contract
from secp_management.release_bundle import (
    MANIFEST_NAME,
    SIGNATURE_NAME,
    ReleaseManifest,
    manifest_signing_message,
    parse_manifest_bytes,
    parse_signature_bytes,
    require_b2_installation_profile,
)
from secp_management.signing import (
    ReleaseTrustRoot,
    TrustAnchor,
    generate_keypair,
    sign_ed25519,
)

EXIT_OK = 0
EXIT_REFUSED = 2

_MAX_KEY_BYTES = 128
_MAX_SPEC_BYTES = 256 * 1024
_MAX_MANIFEST_BYTES = 256 * 1024
_MAX_SIGNATURE_BYTES = 4 * 1024


class AuthorityError(ManagementError):
    """A bounded, closed release-authority refusal — only a reason code, never a key/signature/path
    value or a raw exception."""


def _reject(reason_code: str) -> NoReturn:
    raise AuthorityError(reason_code)


def derive_key_id(public_key_hex: str) -> str:
    """The stable release anchor id derived from a raw Ed25519 public key (hex): ``sha256:<hex>`` of
    the 32 key bytes — the SAME derivation the production trust-anchor loader enforces."""
    try:
        raw = bytes.fromhex(public_key_hex)
    except (ValueError, TypeError):
        _reject("release_authority_public_key_invalid")
    if len(raw) != 32:
        _reject("release_authority_public_key_invalid")
    return "sha256:" + sha256_bytes(raw).split(":", 1)[1]


# --------------------------------------------------------------------------- protected key file


def _repo_root() -> str | None:
    here = os.path.abspath(__file__)
    cur = os.path.dirname(here)
    while True:
        if os.path.isdir(os.path.join(cur, ".git")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def _assert_out_of_repo(path: str, repo_root: str | None) -> None:
    if repo_root is None:
        return
    real = os.path.realpath(path)
    root = os.path.realpath(repo_root)
    if real == root or real.startswith(root + os.sep):
        _reject("release_authority_key_inside_repo")


_SECURE_STORAGE_UNSUPPORTED = "release_authority_unsupported_secure_key_storage"
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _posix_uid() -> int:
    """The current process uid (POSIX-only; every caller sits behind the secure-storage gate).
    Reached via ``getattr`` so the module still type-checks on a non-POSIX developer host."""
    return int(getattr(os, "getuid")())  # noqa: B009 — POSIX-only; type-safe on a Windows dev host


def _require_posix_secure_storage() -> None:
    """Production key ``init``/``sign`` require a POSIX host where custody can be PROVEN
    (owner/mode/nlink + no-follow open + fstat-on-descriptor + fsync). On any other platform they
    fail closed with a bounded reason rather than claim an unverified equivalent — e.g. Windows ACL
    ownership/inheritance/link posture is NOT verified here. Windows may still run build/verify."""
    if os.name != "posix":
        _reject(_SECURE_STORAGE_UNSUPPORTED)


def _assert_trusted_key_ancestors(path: str) -> None:
    """The immediate parent must be a real, PRIVATE directory (mode 0700 or stricter); each ancestor
    up to ``/`` must be a real, non-group/other-writable directory (no symlink)."""
    parent = os.path.dirname(os.path.abspath(path)) or os.sep
    pst = os.lstat(parent)
    if not stat.S_ISDIR(pst.st_mode) or stat.S_ISLNK(pst.st_mode):
        _reject("release_authority_key_parent_unsafe")
    if pst.st_mode & 0o077:  # no group/other access on the private parent
        _reject("release_authority_key_parent_not_private")
    cur = parent
    while True:
        st = os.lstat(cur)
        # an ancestor is untrusted if it is a symlink, or group/other-writable WITHOUT the sticky
        # bit (a sticky world-writable dir like /tmp is safe: only the owner can rename/delete).
        if stat.S_ISLNK(st.st_mode) or ((st.st_mode & 0o022) and not (st.st_mode & stat.S_ISVTX)):
            _reject("release_authority_key_ancestor_unsafe")
        nxt = os.path.dirname(cur)
        if nxt == cur:
            return
        cur = nxt


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_private_key(path: str, private_hex: str, *, repo_root: str | None) -> None:
    """POSIX-only (caller has gated). Exclusive, no-follow create of a 0600 uid-owned single-link
    regular file; fstat the OPENED descriptor (no lstat-then-open TOCTOU); write 64 lower-hex chars
    hex; fsync the key and its parent directory."""
    if not os.path.isabs(path):
        _reject("release_authority_key_path_not_absolute")
    _assert_out_of_repo(path, repo_root)
    _assert_trusted_key_ancestors(path)
    if len(private_hex) != 64 or any(c not in "0123456789abcdef" for c in private_hex):
        _reject("release_authority_key_malformed")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
    except FileExistsError:
        _reject("release_authority_key_exists")
    except OSError:
        _reject("release_authority_key_write_failed")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != _posix_uid() or st.st_nlink != 1:
            _reject("release_authority_key_unsafe")
        getattr(os, "fchmod")(fd, 0o600)  # noqa: B009 — POSIX-only, caller behind the gate
        os.write(fd, private_hex.encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(os.path.dirname(os.path.abspath(path)) or os.sep)


def _decode_private_hex(raw: bytes) -> str:
    """Accept EXACTLY 64 lowercase hex chars, plus at most one final newline — never a broad
    ``.strip()``. Never expose bytes on failure."""
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if len(raw) != 64 or any(c not in b"0123456789abcdef" for c in raw):
        _reject("release_authority_key_malformed")
    return raw.decode("ascii")


def _read_private_key(path: str) -> str:
    """POSIX-only (caller has gated). No-follow open + fstat-on-descriptor (no TOCTOU); require the
    exact owner / mode 0600 / regular / nlink=1; decode 64 lower-hex (one optional newline)."""
    if not os.path.isabs(path):
        _reject("release_authority_key_path_not_absolute")
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
    except OSError:
        _reject("release_authority_key_unreadable")
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or stat.S_ISLNK(st.st_mode)
            or st.st_uid != _posix_uid()
            or (st.st_mode & 0o777) != 0o600
            or st.st_nlink != 1
        ):
            _reject("release_authority_key_unsafe")
        raw = os.read(fd, _MAX_KEY_BYTES + 1)
    finally:
        os.close(fd)
    return _decode_private_hex(raw)


# ----------------------------------------------------------------- init / build / sign / verify


def _write_public_anchor(path: str, anchor: dict) -> None:
    body = (canonical_json(anchor) + "\n").encode("ascii")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o644)
    except FileExistsError:
        _reject("release_authority_public_exists")
    except OSError:
        _reject("release_authority_public_write_failed")
    try:
        os.write(fd, body)
        os.fsync(fd)
    finally:
        os.close(fd)


def _verify_public_anchor(path: str, anchor: dict) -> None:
    fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
    try:
        raw = os.read(fd, 4096)
    finally:
        os.close(fd)
    if raw != (canonical_json(anchor) + "\n").encode("ascii"):
        _reject("release_authority_public_readback_mismatch")


def _compensate_private_key(path: str) -> None:
    """Remove a just-created private key and PROVE its absence; if that cannot be proven, surface a
    bounded recovery-required state (never a half-created authority)."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        _reject("release_authority_recovery_required")
    if os.path.lexists(path):
        _reject("release_authority_recovery_required")


def authority_init(*, key_path: str, repo_root: str | None) -> tuple[int, dict]:
    """Generate a fresh Ed25519 release-signing keypair and write it TRANSACTIONALLY: the protected
    0600 private key AND the 0644 public-anchor companion are both exclusive, no-follow creations,
    fsync'd with their parent; the public anchor is read-back verified; and if the public side (or
    the key read-back) fails, the just-created private key is removed and its absence proven (else
    recovery-required). The private key is never returned, logged, or written anywhere else."""
    _require_posix_secure_storage()
    private_hex, public_hex = generate_keypair()
    key_id = derive_key_id(public_hex)
    pub_path = key_path + ".pub.json"
    anchor = {"key_id": key_id, "public_key_hex": public_hex}
    _write_private_key(key_path, private_hex, repo_root=repo_root)
    try:
        _write_public_anchor(pub_path, anchor)
        _verify_public_anchor(pub_path, anchor)
        _fsync_dir(os.path.dirname(os.path.abspath(pub_path)) or os.sep)
        # prove the written key derives the emitted anchor (re-read through no-follow)
        if derive_key_id(_keypair_public(_read_private_key(key_path))[1]) != key_id:
            _reject("release_authority_key_readback_mismatch")
    except ManagementError:
        _compensate_private_key(key_path)
        raise
    # report the PUBLIC anchor only — never private_hex
    return EXIT_OK, {"command": "init", "anchor": anchor, "public_anchor_path": pub_path}


#: The signed artifact kind whose BYTES the controller installation contract constrains.
CONTROLLER_COMPOSE_KIND = "controller_compose_template"


def _require_controller_contract(
    manifest: ReleaseManifest, artifacts_dir: str | None, *, at_build: bool
) -> None:
    """Prove a CONTROLLER manifest's Compose contract wherever this command can see the bytes.

    Truthful scope, because overclaiming here would be the same defect this change exists to fix:

    * a controller manifest MUST declare a controller Compose artifact -- checked unconditionally,
      because it needs no bytes;
    * when an artifacts directory is supplied, the declared template's BYTES are verified (digest +
      hardened read) and then asserted against the installation contract.

    ``build`` and ``verify`` take the directory optionally -- ``build`` canonicalises a manifest and
    is routinely called with no artifacts at all. The guarantee that no controller bundle can be
    PRODUCED without the contract holding comes from ``sign``, where the artifacts directory is
    already MANDATORY and :func:`_verify_all_artifacts` asserts the contract on every artifact. The
    guarantee that none can be INSTALLED comes from
    :func:`~secp_management.release_verify.verify_release_bundle`, which always reads every
    artifact."""
    if manifest.role != "controller":
        return  # a worker bundle carries no controller template and is unaffected
    if not any(a.kind == CONTROLLER_COMPOSE_KIND for a in manifest.artifacts):
        _reject("release_authority_controller_compose_missing")
    if not artifacts_dir:
        return
    # NOT gated on POSIX secure storage: that control governs PRIVATE KEY custody, not reading a
    # public artifact, and gating here would make an off-POSIX command refuse for the wrong reason.
    _verify_all_artifacts(manifest, artifacts_dir)  # includes the Compose contract assertion
    _ = at_build  # the refusal set is identical at build and verify; the parameter documents intent


def authority_build(*, spec_bytes: bytes, artifacts_dir: str | None = None) -> tuple[int, dict]:
    """Assemble a deterministic canonical ``v1alpha2`` release manifest from a build spec (a strict
    manifest object). Refuses an incomplete installation profile or any well-formedness defect, and
    emits the exact canonical manifest bytes the signer will cover."""
    if len(spec_bytes) > _MAX_SPEC_BYTES:
        _reject("release_authority_spec_too_large")
    manifest = parse_manifest_bytes(spec_bytes)  # strict parse + wellformed (profile-complete)
    require_b2_installation_profile(manifest)  # release-building tooling emits ONLY v1alpha2
    _require_controller_contract(manifest, artifacts_dir, at_build=True)
    canonical = manifest.canonical()
    return EXIT_OK, {
        "command": "build",
        "manifest_name": MANIFEST_NAME,
        "manifest_bytes": canonical,
        "aggregate_digest": sha256_bytes(canonical.encode("utf-8")),
    }


def _read_exact(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= limit:
        block = os.read(fd, 1 << 16)
        if not block:
            break
        chunks.append(block)
        total += len(block)
    return b"".join(chunks)


def _verify_all_artifacts(manifest: ReleaseManifest, artifacts_dir: str) -> None:
    """TOCTOU-safe verification of EVERY manifest artifact (POSIX-only; caller gated): the dir is
    real; each artifact resolves BENEATH it (no traversal); each is opened no-follow (refusing a
    symlink), fstat'd on the descriptor (regular + nlink==1, refusing a hardlink/non-regular); the
    exact declared size + SHA-256 are enforced; and file identity is re-sampled AFTER the read to
    refuse a file that changed during reading. A caller cannot select a subset — all verified."""
    adir = os.path.realpath(artifacts_dir)
    if not stat.S_ISDIR(os.lstat(adir).st_mode):
        _reject("release_authority_artifacts_dir_invalid")
    for art in manifest.artifacts:
        target = os.path.join(adir, art.name)
        real = os.path.realpath(target)
        if real != adir and not real.startswith(adir + os.sep):
            _reject("release_authority_artifact_escape")
        try:
            fd = os.open(target, os.O_RDONLY | _NOFOLLOW)
        except OSError:
            _reject("release_authority_artifact_unreadable")
        try:
            st1 = os.fstat(fd)
            if not stat.S_ISREG(st1.st_mode) or st1.st_nlink != 1:
                _reject("release_authority_artifact_unsafe")  # symlink/hardlink/non-regular
            data = _read_exact(fd, art.size + 1)
            st2 = os.fstat(fd)
            if (st1.st_ino, st1.st_dev, st1.st_size, st1.st_mtime_ns) != (
                st2.st_ino,
                st2.st_dev,
                st2.st_size,
                st2.st_mtime_ns,
            ):
                _reject("release_authority_artifact_changed")  # changed during read
        finally:
            os.close(fd)
        if len(data) != art.size or sha256_bytes(data) != art.sha256:
            _reject("release_authority_artifact_drift")
        if art.kind == CONTROLLER_COMPOSE_KIND:
            # the artifact is authentic; now prove it is SEMANTICALLY valid. A controller
            # template that does not mount the readiness gate read-only into the ordinary API
            # would install and start cleanly and leave the readiness route permanently
            # unreachable, so it must never be signable.
            assert_controller_compose_contract(data)


def authority_sign(
    *, manifest_bytes: bytes, key_path: str, artifacts_dir: str | None
) -> tuple[int, dict]:
    """Sign a v1alpha2 manifest under the private key at ``key_path``. The artifacts directory is
    MANDATORY — no signature is produced without verifying EVERY release artifact (TOCTOU-safe).
    Refuses a non-canonical manifest, a manifest whose ``signing_anchor_id`` is not THIS signer, or
    any drifted/unsafe artifact. Emits the detached signature envelope; no private material leaks.
    """
    if len(manifest_bytes) > _MAX_MANIFEST_BYTES:
        _reject("release_authority_manifest_too_large")
    if artifacts_dir is None:
        _reject("release_authority_artifacts_dir_required")
    if not os.path.isabs(artifacts_dir):
        _reject("release_authority_artifacts_dir_not_absolute")
    manifest = parse_manifest_bytes(manifest_bytes)
    require_b2_installation_profile(manifest)
    # the on-disk manifest MUST already be canonical (deterministic) — else the signature would not
    # cover the exact bytes a verifier reconstructs.
    if manifest_bytes.decode("utf-8", errors="ignore") != manifest.canonical():
        _reject("release_authority_manifest_noncanonical")
    _require_posix_secure_storage()  # key + artifact TOCTOU-safe descriptor reads are POSIX-only
    private_hex = _read_private_key(key_path)
    _, public_hex = _keypair_public(private_hex)
    key_id = derive_key_id(public_hex)
    if manifest.signing_anchor_id != key_id:
        _reject("release_authority_signer_mismatch")
    _verify_all_artifacts(
        manifest, artifacts_dir
    )  # no signature without full artifact verification
    signature_hex = sign_ed25519(private_hex, manifest_signing_message(manifest))
    envelope = {"algorithm": "ed25519", "key_id": key_id, "signature": signature_hex}
    return EXIT_OK, {
        "command": "sign",
        "signature_name": SIGNATURE_NAME,
        "signature_bytes": canonical_json(envelope),
        "key_id": key_id,
    }


def _keypair_public(private_hex: str) -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    public_hex = (
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    return private_hex, public_hex


def authority_verify(
    *, manifest_bytes: bytes, signature_bytes: bytes, anchor: dict, artifacts_dir: str | None = None
) -> tuple[int, dict]:
    """Verify a manifest + detached signature under ONLY the supplied public anchor (never a shipped
    or ambient trust root)."""
    if len(manifest_bytes) > _MAX_MANIFEST_BYTES or len(signature_bytes) > _MAX_SIGNATURE_BYTES:
        _reject("release_authority_input_too_large")
    if set(anchor) != {"key_id", "public_key_hex"}:
        _reject("release_authority_anchor_invalid")
    key_id, public_hex = anchor["key_id"], anchor["public_key_hex"]
    if not is_sha256_digest(key_id) or derive_key_id(public_hex) != key_id:
        _reject("release_authority_anchor_invalid")
    manifest = parse_manifest_bytes(manifest_bytes)
    # F: use the STRICT release-signature parser (closed fields, no duplicate keys, ed25519, exact
    # hex grammar, no ignored extra fields) — never a permissive json.loads.
    sig = parse_signature_bytes(signature_bytes)
    canon = canonical_json(
        {"algorithm": sig.algorithm, "key_id": sig.key_id, "signature": sig.signature}
    )
    body = signature_bytes[:-1] if signature_bytes.endswith(b"\n") else signature_bytes
    if body != canon.encode("utf-8"):
        _reject("release_authority_signature_noncanonical")
    # the signature's key id AND the supplied anchor's key id must BOTH equal the manifest signer.
    if sig.key_id != manifest.signing_anchor_id or key_id != manifest.signing_anchor_id:
        _reject("release_authority_signature_mismatch")
    trust = ReleaseTrustRoot(
        anchors=(TrustAnchor(key_id=key_id, public_key_hex=public_hex),), test_only=False
    )
    if not trust.verify(
        key_id=sig.key_id,
        message=manifest_signing_message(manifest),
        signature_hex=sig.signature,
    ):
        _reject("release_authority_signature_untrusted")
    # a TRUSTED signature over a semantically invalid controller template is still refused.
    _require_controller_contract(manifest, artifacts_dir, at_build=False)
    return EXIT_OK, {"command": "verify", "verified": True, "key_id": sig.key_id}


# --------------------------------------------------------------------------- CLI


def _read_file(path: str, *, max_bytes: int) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(max_bytes + 1)


def run(argv: list[str]) -> tuple[int, dict]:
    parser = argparse.ArgumentParser(prog="secp-release-authority")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser("init")
    p_init.add_argument("--key-path", required=True)
    p_build = sub.add_parser("build")
    p_build.add_argument("--spec", required=True)
    p_build.add_argument("--artifacts-dir")
    p_sign = sub.add_parser("sign")
    p_sign.add_argument("--manifest", required=True)
    p_sign.add_argument("--key-path", required=True)
    p_sign.add_argument("--artifacts-dir")
    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--manifest", required=True)
    p_verify.add_argument("--signature", required=True)
    p_verify.add_argument("--anchor", required=True)
    p_verify.add_argument("--artifacts-dir")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "init":
            return authority_init(key_path=args.key_path, repo_root=_repo_root())
        if args.cmd == "build":
            return authority_build(
                spec_bytes=_read_file(args.spec, max_bytes=_MAX_SPEC_BYTES),
                artifacts_dir=args.artifacts_dir,
            )
        if args.cmd == "sign":
            return authority_sign(
                manifest_bytes=_read_file(args.manifest, max_bytes=_MAX_MANIFEST_BYTES),
                key_path=args.key_path,
                artifacts_dir=args.artifacts_dir,
            )
        if args.cmd == "verify":
            anchor = json.loads(_read_file(args.anchor, max_bytes=_MAX_SIGNATURE_BYTES))
            return authority_verify(
                manifest_bytes=_read_file(args.manifest, max_bytes=_MAX_MANIFEST_BYTES),
                signature_bytes=_read_file(args.signature, max_bytes=_MAX_SIGNATURE_BYTES),
                anchor=anchor,
                artifacts_dir=args.artifacts_dir,
            )
    except ManagementError as exc:  # AuthorityError + release_bundle-level bounded refusals
        return EXIT_REFUSED, {"command": args.cmd, "reason_code": exc.reason_code}
    except OSError:
        return EXIT_REFUSED, {"command": args.cmd, "reason_code": "release_authority_io_error"}
    return EXIT_REFUSED, {"command": args.cmd, "reason_code": "unknown_command"}


def main(argv: list[str] | None = None) -> int:
    exit_code, payload = run(list(sys.argv[1:] if argv is None else argv))
    # never write manifest/signature/anchor bytes with the private key; payload is public-only
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    return exit_code


__all__ = [
    "AuthorityError",
    "authority_build",
    "authority_init",
    "authority_sign",
    "authority_verify",
    "derive_key_id",
    "main",
    "run",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
