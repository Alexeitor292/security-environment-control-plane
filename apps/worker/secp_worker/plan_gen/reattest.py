"""Fresh execution-time toolchain re-attestation (B1B-PR5B, ADR-022 §6) — worker filesystem only.

After combined durable readiness and the execution-lease ``begin_attempt``, but BEFORE any secret
resolution or process construction, the worker re-runs the real ``RealToolchainVerifier`` against
the
EXACT explicit ``ToolchainFilesystemLayout`` bound by the reviewed composition, then resolves and
pins the exact verified ABSOLUTE path handles (executable, provider mirror, provider lockfile, CLI
config, module bundle) with their inode/device identities. It:

* requires POSIX for a controlled-live execution;
* requires EVERY required facet to verify, and the durable record's exact profile hash + policy;
* derives every path from ``ToolchainFilesystemLayout.trusted_root`` — never from ``PATH``/cwd/HOME
—
  and lstat's EVERY path component (including the trusted-root's own components), refusing any
  symlinked component;
* returns a typed, in-memory :class:`AttestedToolchain` (the fresh evidence hash + the pinned path
  handles, incl. the executable's reviewed content digest); nothing here becomes durable.

The pre-spawn re-verification lives in the executor: it opens the executable through a retained
no-follow descriptor, re-verifies its content digest, and executes THAT exact object (never
re-resolving the pathname), so a same-path replacement — even one that immediately reuses the
removed inode — is caught before any process is created.
"""

from __future__ import annotations

import os
import stat as stat_lib
import sys
from dataclasses import dataclass

from secp_scenario_schema import content_hash

from secp_worker.plan_gen.composition import (
    CONTROLLED_LIVE_CLASSIFICATION,
    PlanExecutionComposition,
)
from secp_worker.provisioning.toolchain_verify import (
    ATTESTATION_POLICY_VERSION,
    RealToolchainVerifier,
)

_FRESH_ATTESTATION_VERSION = "secp-002b-1b-pr5b/fresh-execution-attestation/v1"


class FreshAttestationError(Exception):
    """Fresh execution-time re-attestation failed or drifted (bounded reason code)."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class AttestedPath:
    """A pinned, symlink-free absolute path handle with its inode/device/type identity.

    For a FILE handle, ``content_digest`` is the exact ``sha256:<hex>`` of its bytes (for the
    executable this is the REVIEWED ``binary_integrity`` digest the verifier proved on disk), so a
    pre-spawn re-check can detect a same-path replacement even when the removed inode is immediately
    reused (an inode/device comparison alone is defeated by inode reuse). A directory handle carries
    no content digest (``""``).
    """

    path: str
    st_ino: int
    st_dev: int
    st_mode: int
    is_dir: bool
    content_digest: str = ""


@dataclass(frozen=True)
class AttestedToolchain:
    """The typed, in-memory fresh-attestation result (paths + identities; nothing durable)."""

    evidence_hash: str
    executable: AttestedPath
    provider_mirror: AttestedPath
    provider_lockfile: AttestedPath
    cli_config: AttestedPath
    module_bundle: AttestedPath


def _lstat_no_symlink(path: str) -> os.stat_result:
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise FreshAttestationError("reattestation_failed") from exc
    if stat_lib.S_ISLNK(st.st_mode):
        raise FreshAttestationError("reattestation_drifted")
    return st


_HASH_CHUNK = 1 << 20  # 1 MiB streaming chunk
_MAX_HASHED_FILE_BYTES = 64 * 1024  # only small metadata files are hashed here (CLI config)


def _sha256_of_fd(fd: int, *, max_bytes: int) -> str:
    """Stream-hash the OPENED descriptor (never re-open the path), bounded, from offset 0."""
    import hashlib

    os.lseek(fd, 0, 0)
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(fd, _HASH_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise FreshAttestationError("reattestation_failed")
        digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _sha256_small_file(path: str) -> str:
    """No-follow open + fstat(regular) + bounded content digest of a small attested file.

    ``O_BINARY`` matches the executor's spawn-time re-hash so the attestation-time and re-check
    digests are byte-identical on every platform (a text-mode read would translate line endings).
    """
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    try:
        if not stat_lib.S_ISREG(os.fstat(fd).st_mode):
            raise FreshAttestationError("reattestation_failed")
        return _sha256_of_fd(fd, max_bytes=_MAX_HASHED_FILE_BYTES)
    finally:
        os.close(fd)


def _resolve_attested(
    trusted_root: str,
    rel: str,
    *,
    expect_dir: bool,
    content_digest: str = "",
    hash_content: bool = False,
) -> AttestedPath:
    """Resolve ``rel`` strictly beneath ``trusted_root``, lstat'ing EVERY component (root's own
    components too), refusing any symlink or bad type. Returns the pinned :class:`AttestedPath`.

    ``content_digest`` binds a FILE handle to an exact reviewed ``sha256:`` digest (the executable's
    ``binary_integrity``); ``hash_content`` instead digests the resolved small file on disk (the CLI
    config). Directory handles carry no digest.
    """
    root = trusted_root.replace("\\", "/")
    if not root or not os.path.isabs(root) or ".." in root.split("/"):
        raise FreshAttestationError("reattestation_failed")
    rel = rel.replace("\\", "/")
    parts = [p for p in rel.split("/") if p]
    if not parts or any(p in ("", ".", "..") for p in parts):
        raise FreshAttestationError("reattestation_failed")

    # lstat every component of the trusted root itself (parents must not be symlinks), then descend.
    root_parts = [p for p in root.split("/") if p]
    current = "/"
    for i, part in enumerate(root_parts):
        current = current + part if current == "/" else current + "/" + part
        st = _lstat_no_symlink(current)
        if not stat_lib.S_ISDIR(st.st_mode):
            raise FreshAttestationError("reattestation_failed")
        if i == 0 and current == "/" + part:
            pass  # first component under root
    # Descend the relative parts.
    last = len(parts) - 1
    for i, part in enumerate(parts):
        current = current + "/" + part
        st = _lstat_no_symlink(current)
        if i < last and not stat_lib.S_ISDIR(st.st_mode):
            raise FreshAttestationError("reattestation_failed")
    final = _lstat_no_symlink(current)
    is_dir = stat_lib.S_ISDIR(final.st_mode)
    if expect_dir and not is_dir:
        raise FreshAttestationError("reattestation_failed")
    if not expect_dir and not stat_lib.S_ISREG(final.st_mode):
        raise FreshAttestationError("reattestation_failed")
    digest = content_digest
    if hash_content and not is_dir:
        digest = _sha256_small_file(current)
    return AttestedPath(
        path=current,
        st_ino=final.st_ino,
        st_dev=final.st_dev,
        st_mode=final.st_mode,
        is_dir=is_dir,
        content_digest=digest,
    )


def fresh_execution_attestation(
    composition: PlanExecutionComposition,
    *,
    profile_content: dict,
    durable_profile_hash: str,
    durable_policy_version: str,
    durable_attestation_id: str,
) -> AttestedToolchain:
    """Re-attest the on-disk toolchain and return a typed :class:`AttestedToolchain`, or fail
    closed.

    ``profile_content`` is the immutable ``ToolchainProfile`` content; ``durable_*`` come from the
    authoritative ``ToolchainAttestationRecord``. Raises :class:`FreshAttestationError` on a
    non-POSIX
    controlled-live host, a failed facet, any drift from the durable record, or a symlinked
    component.
    """
    layout = composition.toolchain_layout
    if layout is None:
        raise FreshAttestationError("reattestation_failed")
    if composition.classification == CONTROLLED_LIVE_CLASSIFICATION and sys.platform == "win32":
        raise FreshAttestationError("reattestation_failed")

    verifier = RealToolchainVerifier(layout)
    evidence = verifier.safe_evidence(profile_content)
    if not evidence.ok:
        raise FreshAttestationError("reattestation_failed")
    if evidence.policy_version != ATTESTATION_POLICY_VERSION:
        raise FreshAttestationError("reattestation_drifted")
    if durable_policy_version != ATTESTATION_POLICY_VERSION:
        raise FreshAttestationError("reattestation_drifted")
    if not evidence.profile_content_hash or evidence.profile_content_hash != durable_profile_hash:
        raise FreshAttestationError("reattestation_drifted")

    # The reviewed executable content digest (``binary_integrity``): the verifier above already
    # proved the on-disk executable hashes to it, so the fresh handle binds the execution boundary
    # to
    # that exact reviewed digest without re-reading the (large) binary here.
    try:
        from secp_api.toolchain_profile import validate_toolchain_profile

        binary_integrity = validate_toolchain_profile(profile_content).binary_integrity
    except Exception as exc:  # noqa: BLE001 - a valid profile already verified above; fail closed
        raise FreshAttestationError("reattestation_failed") from exc

    # Pin the exact verified ABSOLUTE path handles from the layout (never from PATH). The executable
    # binds the reviewed content digest; the CLI config (a small file re-read by the child by path)
    # binds its on-disk content digest so a same-path replacement is detected before spawn.
    executable = _resolve_attested(
        layout.trusted_root, layout.executable, expect_dir=False, content_digest=binary_integrity
    )
    provider_mirror = _resolve_attested(
        layout.trusted_root, layout.provider_mirror, expect_dir=True
    )
    provider_lockfile = _resolve_attested(
        layout.trusted_root, layout.provider_lockfile, expect_dir=False
    )
    cli_config = _resolve_attested(
        layout.trusted_root, layout.cli_config, expect_dir=False, hash_content=True
    )
    module_bundle = _resolve_attested(layout.trusted_root, layout.module_bundle, expect_dir=True)

    evidence_hash = content_hash(
        {
            "kind": _FRESH_ATTESTATION_VERSION,
            "policy_version": evidence.policy_version,
            "profile_content_hash": evidence.profile_content_hash,
            "verified": sorted(evidence.verified),
            "durable_attestation_id": durable_attestation_id,
        }
    )
    return AttestedToolchain(
        evidence_hash=evidence_hash,
        executable=executable,
        provider_mirror=provider_mirror,
        provider_lockfile=provider_lockfile,
        cli_config=cli_config,
        module_bundle=module_bundle,
    )
