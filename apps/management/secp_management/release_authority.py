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
from secp_management.release_bundle import (
    MANIFEST_NAME,
    SIGNATURE_NAME,
    ReleaseManifest,
    manifest_signing_message,
    parse_manifest_bytes,
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


def _assert_safe_key_parent(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path)) or os.sep
    try:
        st = os.lstat(parent)
    except OSError:
        _reject("release_authority_key_parent_unsafe")
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        _reject("release_authority_key_parent_unsafe")
    if os.name == "posix" and (st.st_mode & 0o022):  # no group/other write on the parent
        _reject("release_authority_key_parent_unsafe")


def _write_private_key(path: str, private_hex: str, *, repo_root: str | None) -> None:
    if not os.path.isabs(path):
        _reject("release_authority_key_path_not_absolute")
    _assert_out_of_repo(path, repo_root)
    _assert_safe_key_parent(path)
    # O_EXCL refuses an existing target (regular OR symlink/dangling), so a hardlink/symlink swap or
    # an overwrite is impossible; the key is created 0600 and re-chmod'd on POSIX.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        _reject("release_authority_key_exists")
    except OSError:
        _reject("release_authority_key_write_failed")
    try:
        os.write(fd, private_hex.encode("ascii"))
    finally:
        os.close(fd)
    if os.name == "posix":
        os.chmod(path, 0o600)


def _read_private_key(path: str) -> str:
    if not os.path.isabs(path):
        _reject("release_authority_key_path_not_absolute")
    try:
        st = os.lstat(path)
    except OSError:
        _reject("release_authority_key_unreadable")
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
        _reject("release_authority_key_unsafe")
    if os.name == "posix" and ((st.st_mode & 0o777) != 0o600 or st.st_nlink != 1):
        _reject("release_authority_key_unsafe")
    try:
        with open(path, "rb") as fh:
            raw = fh.read(_MAX_KEY_BYTES + 1)
    except OSError:
        _reject("release_authority_key_unreadable")
    text = raw.decode("ascii", errors="ignore").strip()
    try:
        key_bytes = bytes.fromhex(text)
    except ValueError:
        _reject("release_authority_key_malformed")
    if len(key_bytes) != 32:
        _reject("release_authority_key_malformed")
    return text


# ----------------------------------------------------------------- init / build / sign / verify


def authority_init(*, key_path: str, repo_root: str | None) -> tuple[int, dict]:
    """Generate a fresh Ed25519 release-signing keypair, write the PRIVATE key to a protected
    out-of-repo 0600 file (write-once), and return the PUBLIC anchor. The private key is never
    returned, logged, or written anywhere else."""
    private_hex, public_hex = generate_keypair()
    key_id = derive_key_id(public_hex)
    _write_private_key(key_path, private_hex, repo_root=repo_root)
    pub_path = key_path + ".pub.json"
    anchor = {"key_id": key_id, "public_key_hex": public_hex}
    try:
        with open(pub_path, "w", encoding="ascii") as fh:
            fh.write(canonical_json(anchor) + "\n")
    except OSError:
        _reject("release_authority_public_write_failed")
    # report the PUBLIC anchor only — never private_hex
    return EXIT_OK, {"command": "init", "anchor": anchor, "public_anchor_path": pub_path}


def authority_build(*, spec_bytes: bytes) -> tuple[int, dict]:
    """Assemble a deterministic canonical ``v1alpha2`` release manifest from a build spec (a strict
    manifest object). Refuses an incomplete installation profile or any well-formedness defect, and
    emits the exact canonical manifest bytes the signer will cover."""
    if len(spec_bytes) > _MAX_SPEC_BYTES:
        _reject("release_authority_spec_too_large")
    manifest = parse_manifest_bytes(spec_bytes)  # strict parse + wellformed (profile-complete)
    require_b2_installation_profile(manifest)  # release-building tooling emits ONLY v1alpha2
    canonical = manifest.canonical()
    return EXIT_OK, {
        "command": "build",
        "manifest_name": MANIFEST_NAME,
        "manifest_bytes": canonical,
        "aggregate_digest": sha256_bytes(canonical.encode("utf-8")),
    }


def _reverify_artifacts(manifest: ReleaseManifest, artifacts_dir: str | None) -> None:
    if artifacts_dir is None:
        return
    for art in manifest.artifacts:
        path = os.path.join(artifacts_dir, art.name)
        try:
            with open(path, "rb") as fh:
                data = fh.read(art.size + 1)
        except OSError:
            _reject("release_authority_artifact_unreadable")
        if len(data) != art.size or sha256_bytes(data) != art.sha256:
            _reject("release_authority_artifact_drift")


def authority_sign(
    *, manifest_bytes: bytes, key_path: str, artifacts_dir: str | None = None
) -> tuple[int, dict]:
    """Sign a v1alpha2 manifest under the private key at ``key_path``. Refuses a non-canonical
    manifest, a manifest whose ``signing_anchor_id`` is not THIS signer, or drifted artifacts (when
    an artifacts dir is given). Emits the detached signature envelope; no private material leaks."""
    if len(manifest_bytes) > _MAX_MANIFEST_BYTES:
        _reject("release_authority_manifest_too_large")
    manifest = parse_manifest_bytes(manifest_bytes)
    require_b2_installation_profile(manifest)
    # the on-disk manifest MUST already be canonical (deterministic) — else the signature would not
    # cover the exact bytes a verifier reconstructs.
    if manifest_bytes.decode("utf-8", errors="ignore") != manifest.canonical():
        _reject("release_authority_manifest_noncanonical")
    private_hex = _read_private_key(key_path)
    _, public_hex = _keypair_public(private_hex)
    key_id = derive_key_id(public_hex)
    if manifest.signing_anchor_id != key_id:
        _reject("release_authority_signer_mismatch")
    _reverify_artifacts(manifest, artifacts_dir)
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
    *, manifest_bytes: bytes, signature_bytes: bytes, anchor: dict
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
    try:
        sig = json.loads(signature_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        _reject("release_authority_signature_malformed")
    if not isinstance(sig, dict) or sig.get("key_id") != manifest.signing_anchor_id:
        _reject("release_authority_signature_mismatch")
    trust = ReleaseTrustRoot(
        anchors=(TrustAnchor(key_id=key_id, public_key_hex=public_hex),), test_only=False
    )
    ok = trust.verify(
        key_id=manifest.signing_anchor_id,
        message=manifest_signing_message(manifest),
        signature_hex=str(sig.get("signature", "")),
    )
    if not ok:
        _reject("release_authority_signature_untrusted")
    return EXIT_OK, {"command": "verify", "verified": True, "key_id": manifest.signing_anchor_id}


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
    p_sign = sub.add_parser("sign")
    p_sign.add_argument("--manifest", required=True)
    p_sign.add_argument("--key-path", required=True)
    p_sign.add_argument("--artifacts-dir")
    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--manifest", required=True)
    p_verify.add_argument("--signature", required=True)
    p_verify.add_argument("--anchor", required=True)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "init":
            return authority_init(key_path=args.key_path, repo_root=_repo_root())
        if args.cmd == "build":
            return authority_build(spec_bytes=_read_file(args.spec, max_bytes=_MAX_SPEC_BYTES))
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
