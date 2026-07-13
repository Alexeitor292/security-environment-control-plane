"""Toolchain provenance verification seam (SECP-002B-1A + 1B-PR2, ADR-013 / ADR-020) — worker-only.

Before init/plan/apply/destroy, the ``OpenTofuRunner`` requires *proof* that the pinned toolchain
provenance holds: executable identity, exact version, binary-integrity digest, module-bundle
identity/hash, provider lockfile hash, offline provider-mirror identity, renderer version, the
offline CLI configuration, the remote-state backend class, and that runtime download is disabled.

* ``FakeToolchainVerifier`` (B1-A default) attests the pinned facet NAMES without touching any real
  binary, file, provider, or mirror. It remains the ONLY verifier wired into the execution path;
  the runner and ``run_real_provisioning`` still default to it (fake-only, sealed).
* ``RealToolchainVerifier`` (B1B-PR2) performs bounded, containment-checked, race-detected,
  worker-local **filesystem** attestation of an EXPLICIT ``ToolchainFilesystemLayout``. It reads
  only the supplied trusted root, never executes the binary, never reads PATH, never opens a network
  socket, resolves no secret, touches no database/audit, and renders no workspace. It is constructed
  only by an explicit worker-local caller/test with a complete layout, is never selected by default
  or configuration, and performs NO I/O at import or construction time.

The cryptographic binary digest is the artifact identity. Because this phase does not execute the
binary, the version string is a profile/deployment-manifest label cross-checked against that
immutable digest — this is NOT independent vendor-signature verification. Both B1-A subprocess seals
remain ``True``; this module unseals no execution and adds no executor or process path.

Residual limitation (documented honestly): pathname-based inspection with ``lstat`` + ``O_NOFOLLOW``
+ before/after identity re-checks defends against ordinary symlink/replacement tricks, but it cannot
fully defend against a PRIVILEGED attacker who controls the worker kernel or filesystem — e.g.
swapping a PARENT directory to a symlink in the window between component resolution and ``open`` (no
``openat``/dirfd traversal here). A compromised worker remains a residual risk this verifier does
not claim to solve; the reviewed B1-B live activation runs on a trusted worker platform. On
non-POSIX platforms the no-follow-at-open and inode/permission guarantees are best-effort only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat as stat_lib
import unicodedata
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Protocol, runtime_checkable

from secp_worker.provisioning.identifiers import (
    IdentifierError,
    validate_executable,
    validate_identifier,
)
from secp_worker.provisioning.rendering import RENDERER_VERSION

# The provenance facets the runner requires proof of before executing. Expanded in B1B-PR2 with the
# CLI-config, remote-state-class, and runtime-download-disabled facets. ``ToolchainVerification.ok``
# and ``.missing()`` read this tuple live, so the FakeToolchainVerifier default auto-covers them.
_REQUIRED_FACETS = (
    "executable",
    "version",
    "binary_digest",
    "module_bundle",
    "lockfile",
    "mirror",
    "renderer",
    "cli_config",
    "remote_state_class",
    "runtime_download_disabled",
)

# Real-attestation policy identity (bound into safe evidence + the optional local manifest).
ATTESTATION_POLICY_VERSION = "secp-002b-1b/toolchain-attest/v1"

# --- bounded, testable limits (conservative; nothing is read whole into memory) -----------------
_HASH_CHUNK_SIZE = 1 << 20  # 1 MiB streaming chunk
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_VERSION_META_BYTES = 4 * 1024
_MAX_CLI_CONFIG_BYTES = 64 * 1024
_MAX_LOCKFILE_BYTES = 4 * 1024 * 1024
_MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
_MAX_TREE_FILE_BYTES = 64 * 1024 * 1024
_MAX_TREE_FILE_COUNT = 20_000
_MAX_TREE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
_MAX_TREE_DEPTH = 32

# Real B1-B attestation requires exact SHA-256 content identities (lowercase). The generic profile
# validator stays compatible with fake B1-A fixtures; the real verifier is stricter (below).
_SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_OFFLINE_NETWORK_TOKENS = frozenset({"offline", "none", "air-gapped", "airgapped", "mirror-only"})
_LOCAL_STATE_TOKENS = frozenset({"local", "local-state", "localfs", "file", "disk", ""})

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)  # POSIX no-follow-at-open; 0 (no-op) elsewhere
_O_BINARY = getattr(os, "O_BINARY", 0)
_POSIX = os.name == "posix"

# Bounded, content-free reason categories. NEVER a path, filename, file content, or exception text.
R_LAYOUT_INVALID = "layout_invalid"
R_PATH_OUTSIDE_ROOT = "path_outside_root"
R_SYMLINK_REFUSED = "symlink_refused"
R_OBJECT_TYPE_INVALID = "object_type_invalid"
R_PERMISSION_INVALID = "permission_invalid"
R_SIZE_LIMIT_EXCEEDED = "size_limit_exceeded"
R_TREE_LIMIT_EXCEEDED = "tree_limit_exceeded"
R_OBJECT_CHANGED = "object_changed_during_read"
R_PATH_COLLISION = "path_collision"
R_MANIFEST_INVALID = "manifest_invalid"
R_PROFILE_INVALID = "profile_invalid"
R_EXECUTABLE_MISMATCH = "executable_mismatch"
R_VERSION_MISMATCH = "version_mismatch"
R_BINARY_DIGEST_MISMATCH = "binary_digest_mismatch"
R_MODULE_BUNDLE_MISMATCH = "module_bundle_mismatch"
R_LOCKFILE_MISMATCH = "lockfile_mismatch"
R_MIRROR_MISMATCH = "mirror_mismatch"
R_RENDERER_MISMATCH = "renderer_mismatch"
R_CLI_CONFIG_INVALID = "cli_config_invalid"
R_RUNTIME_DOWNLOAD_NOT_DISABLED = "runtime_download_not_disabled"
R_STATE_BACKEND_CLASS_INVALID = "state_backend_class_invalid"
R_UNSUPPORTED_DIGEST = "unsupported_digest_algorithm"


@dataclass(frozen=True)
class ToolchainVerification:
    """Attestation that each pinned provenance facet has been verified."""

    verified: frozenset[str] = field(default_factory=frozenset)
    reasons: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return set(_REQUIRED_FACETS).issubset(self.verified)

    def missing(self) -> list[str]:
        return sorted(set(_REQUIRED_FACETS) - set(self.verified))


@dataclass(frozen=True)
class ToolchainAttestationEvidence:
    """Safe, secret-free projection of an attestation (in-memory only; not persisted in PR2)."""

    ok: bool
    verified: tuple[str, ...]  # sorted facet names
    reasons: tuple[str, ...]  # bounded reason codes
    profile_content_hash: str  # canonical secret-free profile hash (safe) or "" if unavailable
    policy_version: str


@runtime_checkable
class ToolchainVerifier(Protocol):
    """Attest pinned toolchain provenance without leaking secrets."""

    def verify(self, profile: dict) -> ToolchainVerification: ...


class FakeToolchainVerifier:
    """B1-A verifier. Attests provenance facets without touching real binaries/files.

    ``attest`` selects which facets are attested (default: all), so tests can simulate a verifier
    that fails a specific facet. Its default auto-covers any newly-added required facet.
    """

    def __init__(self, attest: frozenset[str] | set[str] | None = None) -> None:
        self._attest = frozenset(attest if attest is not None else _REQUIRED_FACETS)

    def verify(self, profile: dict) -> ToolchainVerification:
        # No I/O: a fake attestation of the pinned values already in the (validated) profile.
        missing = set(_REQUIRED_FACETS) - set(self._attest)
        reasons = tuple(f"facet not attested: {m}" for m in sorted(missing))
        return ToolchainVerification(verified=frozenset(self._attest), reasons=reasons)


@dataclass(frozen=True)
class ToolchainFilesystemLayout:
    """Immutable, explicit worker-local filesystem layout for real attestation.

    ``trusted_root`` is an absolute directory; every other member is a root-RELATIVE POSIX path that
    must resolve strictly beneath it (no ``..``, no symlinked component). Nothing is inferred from
    the cwd, PATH, HOME, environment, repo location, or default ``/opt`` paths — the caller supplies
    the complete layout explicitly. No I/O happens until :meth:`RealToolchainVerifier.verify`.
    """

    trusted_root: str
    executable: str
    version_metadata: str
    module_bundle: str
    provider_lockfile: str
    provider_mirror: str
    cli_config: str
    manifest: str | None = None


def render_offline_cli_config(mirror_abs_path: str) -> bytes:
    """The canonical worker-local OpenTofu CLI configuration for offline, mirror-only installation.

    A filesystem mirror at the exact attested directory and NO ``direct`` block — so there is no
    direct-installation fallback, no network/registry mirror, no HTTP(S) source, no plugin-cache
    outside the trusted root, no credential helper, and no environment interpolation. The real
    verifier compares the on-disk CLI config to these exact bytes, so comments or alternate syntax
    cannot provide a bypass. Both the verifier and callers must use this one generator.
    """
    return (
        "provider_installation {\n"
        "  filesystem_mirror {\n"
        f'    path    = "{mirror_abs_path}"\n'
        '    include = ["*/*"]\n'
        "  }\n"
        "}\n"
        "disable_checkpoint = true\n"
    ).encode()


class _AttestError(Exception):
    """Internal control-flow signal carrying only a bounded reason code (no path/content/text)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _require_sha256(value: object) -> str:
    if not isinstance(value, str) or not _SHA256_DIGEST_RE.match(value):
        raise _AttestError(R_UNSUPPORTED_DIGEST)
    return value


def _check_no_unsafe_write(st: os.stat_result) -> None:
    """POSIX: refuse group-/world-writable objects. No-op where those bits are not meaningful."""
    if _POSIX and (st.st_mode & (stat_lib.S_IWGRP | stat_lib.S_IWOTH)):
        raise _AttestError(R_PERMISSION_INVALID)


def _check_executable_perms(st: os.stat_result) -> None:
    """POSIX: executable must be owner-executable, not setuid/setgid, not group-/world-writable."""
    if not _POSIX:
        return
    mode = st.st_mode
    if mode & (stat_lib.S_ISUID | stat_lib.S_ISGID):
        raise _AttestError(R_PERMISSION_INVALID)
    if mode & (stat_lib.S_IWGRP | stat_lib.S_IWOTH):
        raise _AttestError(R_PERMISSION_INVALID)
    if not (mode & stat_lib.S_IXUSR):
        raise _AttestError(R_PERMISSION_INVALID)


def _validate_root(root: object) -> str:
    if not isinstance(root, str) or not root or not os.path.isabs(root):
        raise _AttestError(R_LAYOUT_INVALID)
    if ".." in PurePosixPath(root.replace("\\", "/")).parts:
        raise _AttestError(R_LAYOUT_INVALID)
    try:
        st = os.lstat(root)
    except OSError:
        raise _AttestError(R_OBJECT_TYPE_INVALID) from None
    if stat_lib.S_ISLNK(st.st_mode):
        raise _AttestError(R_SYMLINK_REFUSED)
    if not stat_lib.S_ISDIR(st.st_mode):
        raise _AttestError(R_OBJECT_TYPE_INVALID)
    _check_no_unsafe_write(st)
    return root


def _safe_resolve(root: str, rel: object) -> str:
    """Resolve ``rel`` strictly beneath ``root``: reject absolute/backslash/drive/``..``/empty
    parts, and lstat every component (parents + final) refusing any symlink or non-dir parent."""
    if not isinstance(rel, str) or not rel:
        raise _AttestError(R_LAYOUT_INVALID)
    if "\\" in rel or ":" in rel:
        raise _AttestError(R_PATH_OUTSIDE_ROOT)
    pure = PurePosixPath(rel)
    if pure.is_absolute():
        raise _AttestError(R_PATH_OUTSIDE_ROOT)
    parts = pure.parts
    if not parts or any(p in ("", ".", "..") for p in parts):
        raise _AttestError(R_PATH_OUTSIDE_ROOT)
    current = root
    last = len(parts) - 1
    for i, part in enumerate(parts):
        current = os.path.join(current, part)
        try:
            st = os.lstat(current)
        except OSError:
            raise _AttestError(R_OBJECT_TYPE_INVALID) from None
        if stat_lib.S_ISLNK(st.st_mode):
            raise _AttestError(R_SYMLINK_REFUSED)
        if i < last and not stat_lib.S_ISDIR(st.st_mode):
            raise _AttestError(R_OBJECT_TYPE_INVALID)
    return current


def _hash_regular_file(path: str, *, max_bytes: int, require_exec: bool = False) -> tuple[str, int]:
    """Stream a regular file through SHA-256 with bounded size and file-replacement race detection.

    lstat before (regular, not a symlink, size bound, permissions); open no-follow; fstat-compare
    the opened object; stream in bounded chunks; lstat after, refusing if identity/size/mtime moved.
    Returns ``("sha256:<64 hex>", size)``. Never reads the whole file into memory.
    """
    before = os.lstat(path)
    if stat_lib.S_ISLNK(before.st_mode):
        raise _AttestError(R_SYMLINK_REFUSED)
    if not stat_lib.S_ISREG(before.st_mode):
        raise _AttestError(R_OBJECT_TYPE_INVALID)
    if before.st_size > max_bytes:
        raise _AttestError(R_SIZE_LIMIT_EXCEEDED)
    if require_exec:
        _check_executable_perms(before)
    else:
        _check_no_unsafe_write(before)

    digest = hashlib.sha256()
    total = 0
    fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY)
    try:
        opened = os.fstat(fd)
        if stat_lib.S_ISLNK(opened.st_mode) or not stat_lib.S_ISREG(opened.st_mode):
            raise _AttestError(R_OBJECT_TYPE_INVALID)
        if _POSIX and (opened.st_ino != before.st_ino or opened.st_dev != before.st_dev):
            raise _AttestError(R_OBJECT_CHANGED)
        while True:
            chunk = os.read(fd, _HASH_CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise _AttestError(R_SIZE_LIMIT_EXCEEDED)
            digest.update(chunk)
        after_fd = os.fstat(fd)
    finally:
        os.close(fd)

    after = os.lstat(path)
    if (
        total != before.st_size
        or after.st_size != before.st_size
        or after_fd.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
    ):
        raise _AttestError(R_OBJECT_CHANGED)
    if _POSIX and (after.st_ino != before.st_ino or after.st_dev != before.st_dev):
        raise _AttestError(R_OBJECT_CHANGED)
    return "sha256:" + digest.hexdigest(), total


def _read_small_file(path: str, *, max_bytes: int) -> bytes:
    """Bounded read of a small regular file (version metadata / CLI config / manifest) with the same
    symlink/type/permission/race protections as :func:`_hash_regular_file`."""
    before = os.lstat(path)
    if stat_lib.S_ISLNK(before.st_mode):
        raise _AttestError(R_SYMLINK_REFUSED)
    if not stat_lib.S_ISREG(before.st_mode):
        raise _AttestError(R_OBJECT_TYPE_INVALID)
    if before.st_size > max_bytes:
        raise _AttestError(R_SIZE_LIMIT_EXCEEDED)
    _check_no_unsafe_write(before)
    data = bytearray()
    fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY)
    try:
        opened = os.fstat(fd)
        if not stat_lib.S_ISREG(opened.st_mode):
            raise _AttestError(R_OBJECT_TYPE_INVALID)
        if _POSIX and (opened.st_ino != before.st_ino or opened.st_dev != before.st_dev):
            raise _AttestError(R_OBJECT_CHANGED)
        while True:
            chunk = os.read(fd, _HASH_CHUNK_SIZE)
            if not chunk:
                break
            data += chunk
            if len(data) > max_bytes:
                raise _AttestError(R_SIZE_LIMIT_EXCEEDED)
    finally:
        os.close(fd)
    after = os.lstat(path)
    if after.st_size != before.st_size or after.st_mtime_ns != before.st_mtime_ns:
        raise _AttestError(R_OBJECT_CHANGED)
    if _POSIX and (after.st_ino != before.st_ino or after.st_dev != before.st_dev):
        raise _AttestError(R_OBJECT_CHANGED)
    return bytes(data)


def _walk_metadata(dir_path: str) -> list[tuple[str, str, int, int]]:
    """Deterministic sorted tree inventory: ``(posix_relpath, kind, size, mtime_ns)`` per entry.

    Refuses symlinks, special files (FIFO/socket/device), unsafe-write bits, normalized-path
    collisions, and any tree/size/depth limit. Files and directories only.
    """
    results: list[tuple[str, str, int, int]] = []
    seen_norm: set[str] = set()
    counters = {"files": 0, "bytes": 0}

    def _recurse(cur: str, rel_prefix: str, depth: int) -> None:
        if depth > _MAX_TREE_DEPTH:
            raise _AttestError(R_TREE_LIMIT_EXCEEDED)
        try:
            names = sorted(os.listdir(cur))
        except OSError:
            raise _AttestError(R_OBJECT_TYPE_INVALID) from None
        for name in names:
            child = os.path.join(cur, name)
            rel = name if rel_prefix == "" else f"{rel_prefix}/{name}"
            st = os.lstat(child)
            if stat_lib.S_ISLNK(st.st_mode):
                raise _AttestError(R_SYMLINK_REFUSED)
            norm = unicodedata.normalize("NFC", rel).casefold()
            if norm in seen_norm:
                raise _AttestError(R_PATH_COLLISION)
            seen_norm.add(norm)
            if stat_lib.S_ISDIR(st.st_mode):
                _check_no_unsafe_write(st)
                results.append((rel, "dir", 0, st.st_mtime_ns))
                _recurse(child, rel, depth + 1)
            elif stat_lib.S_ISREG(st.st_mode):
                _check_no_unsafe_write(st)
                if st.st_size > _MAX_TREE_FILE_BYTES:
                    raise _AttestError(R_SIZE_LIMIT_EXCEEDED)
                counters["files"] += 1
                counters["bytes"] += st.st_size
                if counters["files"] > _MAX_TREE_FILE_COUNT:
                    raise _AttestError(R_TREE_LIMIT_EXCEEDED)
                if counters["bytes"] > _MAX_TREE_TOTAL_BYTES:
                    raise _AttestError(R_TREE_LIMIT_EXCEEDED)
                results.append((rel, "file", st.st_size, st.st_mtime_ns))
            else:
                raise _AttestError(R_OBJECT_TYPE_INVALID)

    _recurse(dir_path, "", 1)
    results.sort(key=lambda e: e[0])
    return results


def _hash_tree(dir_path: str) -> tuple[str, int]:
    """Deterministic SHA-256 directory-tree hash bound to (normalized POSIX relpath, entry type,
    file length, SHA-256 of each regular file's bytes). Sorted, UTF-8, canonical-JSON framed; no abs
    path, timestamp, owner, or nondeterministic order. Symlinks/special files refused. An empty tree
    yields the fixed hash of ``[]``. Refuses if the tree changes while hashing. Returns
    ``("sha256:<hex>", entry_count)``.
    """
    st = os.lstat(dir_path)
    if stat_lib.S_ISLNK(st.st_mode):
        raise _AttestError(R_SYMLINK_REFUSED)
    if not stat_lib.S_ISDIR(st.st_mode):
        raise _AttestError(R_OBJECT_TYPE_INVALID)
    _check_no_unsafe_write(st)

    meta_before = _walk_metadata(dir_path)
    entries: list[list[object]] = []
    for rel, kind, size, _mtime in meta_before:
        if kind == "file":
            child = _safe_resolve(dir_path, rel)  # re-verify no symlinked component at hash time
            file_hash, _sz = _hash_regular_file(child, max_bytes=_MAX_TREE_FILE_BYTES)
            entries.append([rel, "file", size, file_hash])
        else:
            entries.append([rel, "dir", 0, ""])
    meta_after = _walk_metadata(dir_path)
    if meta_before != meta_after:
        raise _AttestError(R_OBJECT_CHANGED)

    canonical = json.dumps(entries, ensure_ascii=True, separators=(",", ":"))
    tree_hash = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return tree_hash, len(entries)


_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "opentofu_version",
        "executable",
        "binary_integrity",
        "module_bundle_id",
        "module_bundle_hash",
        "provider_lockfile_hash",
        "provider_mirror_identity",
        "renderer_version",
        "cli_config_policy_version",
        "remote_state_backend_class",
        "runtime_download_allowed",
    }
)


class RealToolchainVerifier:
    """Worker-local, filesystem-only real toolchain attestation (B1B-PR2).

    Constructed with an explicit :class:`ToolchainFilesystemLayout`. Performs NO I/O until
    :meth:`verify` is called; never executes the binary, reads PATH, opens a socket, resolves a
    secret, touches the database/audit, or renders a workspace. It unseals no execution.
    """

    def __init__(self, layout: ToolchainFilesystemLayout) -> None:
        self._layout = layout

    # -- public API ------------------------------------------------------------

    def verify(self, profile: dict) -> ToolchainVerification:
        """Attest the pinned provenance against the on-disk layout. Never raises; returns a
        ``ToolchainVerification`` whose ``reasons`` are bounded, path/content-free reason codes."""
        try:
            spec = self._validate_profile(profile)
        except _AttestError as exc:
            return ToolchainVerification(frozenset(), (exc.reason,))

        try:
            root = _validate_root(self._layout.trusted_root)
        except _AttestError as exc:
            return ToolchainVerification(frozenset(), (exc.reason,))

        # Optional local manifest: a mismatch fails the whole attestation closed.
        if self._layout.manifest is not None:
            try:
                self._attest_manifest(root, spec)
            except _AttestError as exc:
                return ToolchainVerification(frozenset(), (exc.reason,))
            except Exception:
                return ToolchainVerification(frozenset(), (R_MANIFEST_INVALID,))

        verified: set[str] = set()
        reasons: list[str] = []

        def _reason(code: str) -> None:
            if code not in reasons:
                reasons.append(code)

        # executable + binary_digest (share the streamed executable hash)
        exec_hash: str | None = None
        try:
            exec_path = _safe_resolve(root, self._layout.executable)
            exec_hash, _ = _hash_regular_file(
                exec_path, max_bytes=_MAX_EXECUTABLE_BYTES, require_exec=True
            )
            self._attest_executable_identity(spec, exec_path)
            verified.add("executable")
        except _AttestError as exc:
            _reason(exc.reason)
        except Exception:
            _reason(R_OBJECT_TYPE_INVALID)
        if exec_hash is not None:
            try:
                _require_sha256(spec.binary_integrity)
                if not hmac.compare_digest(exec_hash, spec.binary_integrity):
                    raise _AttestError(R_BINARY_DIGEST_MISMATCH)
                verified.add("binary_digest")
            except _AttestError as exc:
                _reason(exc.reason)

        self._facet(
            verified,
            _reason,
            "version",
            R_VERSION_MISMATCH,
            lambda: self._attest_version(root, spec),
        )
        self._facet(
            verified,
            _reason,
            "module_bundle",
            R_MODULE_BUNDLE_MISMATCH,
            lambda: self._attest_module_bundle(root, spec),
        )
        self._facet(
            verified,
            _reason,
            "lockfile",
            R_LOCKFILE_MISMATCH,
            lambda: self._attest_lockfile(root, spec),
        )

        mirror_abs: str | None = None
        try:
            mirror_abs = _safe_resolve(root, self._layout.provider_mirror)
            self._attest_mirror(mirror_abs, spec)
            verified.add("mirror")
        except _AttestError as exc:
            _reason(exc.reason)
        except Exception:
            _reason(R_MIRROR_MISMATCH)

        self._facet(
            verified, _reason, "renderer", R_RENDERER_MISMATCH, lambda: self._attest_renderer(spec)
        )

        cli_ok = False
        try:
            self._attest_cli_config(root, mirror_abs)
            verified.add("cli_config")
            cli_ok = True
        except _AttestError as exc:
            _reason(exc.reason)
        except Exception:
            _reason(R_CLI_CONFIG_INVALID)

        try:
            self._attest_runtime_download_disabled(spec, cli_ok)
            verified.add("runtime_download_disabled")
        except _AttestError as exc:
            _reason(exc.reason)

        self._facet(
            verified,
            _reason,
            "remote_state_class",
            R_STATE_BACKEND_CLASS_INVALID,
            lambda: self._attest_remote_state_class(spec),
        )

        return ToolchainVerification(verified=frozenset(verified), reasons=tuple(reasons))

    def safe_evidence(self, profile: dict) -> ToolchainAttestationEvidence:
        """Bounded, secret-free evidence projection (in-memory; not persisted in PR2)."""
        verification = self.verify(profile)
        try:
            from secp_api.toolchain_profile import toolchain_profile_hash

            profile_hash = toolchain_profile_hash(profile)
        except Exception:
            profile_hash = ""
        return ToolchainAttestationEvidence(
            ok=verification.ok,
            verified=tuple(sorted(verification.verified)),
            reasons=verification.reasons,
            profile_content_hash=profile_hash,
            policy_version=ATTESTATION_POLICY_VERSION,
        )

    # -- facet helpers ---------------------------------------------------------

    @staticmethod
    def _facet(verified, reason_fn, name, default_code, fn) -> None:
        try:
            fn()
            verified.add(name)
        except _AttestError as exc:
            reason_fn(exc.reason)
        except Exception:
            reason_fn(default_code)

    @staticmethod
    def _validate_profile(profile: dict):
        from secp_api.errors import ValidationFailedError
        from secp_api.toolchain_profile import validate_toolchain_profile

        try:
            return validate_toolchain_profile(profile)
        except ValidationFailedError:
            raise _AttestError(R_PROFILE_INVALID) from None
        except Exception:
            raise _AttestError(R_PROFILE_INVALID) from None

    @staticmethod
    def _attest_executable_identity(spec, exec_path: str) -> None:
        try:
            prof_exec = validate_executable(spec.executable)
        except IdentifierError:
            raise _AttestError(R_EXECUTABLE_MISMATCH) from None
        if prof_exec.startswith("/"):
            if os.path.normpath(exec_path) != os.path.normpath(prof_exec):
                raise _AttestError(R_EXECUTABLE_MISMATCH)
        elif os.path.basename(exec_path) != prof_exec:
            raise _AttestError(R_EXECUTABLE_MISMATCH)

    def _attest_version(self, root: str, spec) -> None:
        path = _safe_resolve(root, self._layout.version_metadata)
        raw = _read_small_file(path, max_bytes=_MAX_VERSION_META_BYTES)
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise _AttestError(R_VERSION_MISMATCH) from None
        if not isinstance(parsed, dict) or set(parsed) != {"opentofu_version"}:
            raise _AttestError(R_VERSION_MISMATCH)
        if parsed["opentofu_version"] != spec.opentofu_version:
            raise _AttestError(R_VERSION_MISMATCH)

    def _attest_module_bundle(self, root: str, spec) -> None:
        _require_sha256(spec.module_bundle_hash)
        bundle_abs = _safe_resolve(root, self._layout.module_bundle)
        tree_hash, _count = _hash_tree(bundle_abs)
        if not hmac.compare_digest(tree_hash, spec.module_bundle_hash):
            raise _AttestError(R_MODULE_BUNDLE_MISMATCH)

    def _attest_lockfile(self, root: str, spec) -> None:
        _require_sha256(spec.provider_lockfile_hash)
        path = _safe_resolve(root, self._layout.provider_lockfile)
        file_hash, size = _hash_regular_file(path, max_bytes=_MAX_LOCKFILE_BYTES)
        if size == 0:
            raise _AttestError(R_LOCKFILE_MISMATCH)
        if not hmac.compare_digest(file_hash, spec.provider_lockfile_hash):
            raise _AttestError(R_LOCKFILE_MISMATCH)

    def _attest_mirror(self, mirror_abs: str, spec) -> None:
        mirror = spec.provider_mirror
        if mirror.network_access not in _OFFLINE_NETWORK_TOKENS or mirror.allow_runtime_download:
            raise _AttestError(R_MIRROR_MISMATCH)
        _require_sha256(mirror.identity)
        tree_hash, count = _hash_tree(mirror_abs)
        if count == 0:  # an empty offline mirror is refused for real attestation
            raise _AttestError(R_MIRROR_MISMATCH)
        if not hmac.compare_digest(tree_hash, mirror.identity):
            raise _AttestError(R_MIRROR_MISMATCH)

    @staticmethod
    def _attest_renderer(spec) -> None:
        if spec.renderer_version != RENDERER_VERSION:
            raise _AttestError(R_RENDERER_MISMATCH)

    def _attest_cli_config(self, root: str, mirror_abs: str | None) -> None:
        if mirror_abs is None:
            raise _AttestError(R_CLI_CONFIG_INVALID)
        path = _safe_resolve(root, self._layout.cli_config)
        raw = _read_small_file(path, max_bytes=_MAX_CLI_CONFIG_BYTES)
        expected = render_offline_cli_config(mirror_abs)
        if len(raw) != len(expected) or not hmac.compare_digest(raw, expected):
            raise _AttestError(R_CLI_CONFIG_INVALID)

    @staticmethod
    def _attest_runtime_download_disabled(spec, cli_ok: bool) -> None:
        mirror = spec.provider_mirror
        if mirror.allow_runtime_download or mirror.network_access not in _OFFLINE_NETWORK_TOKENS:
            raise _AttestError(R_RUNTIME_DOWNLOAD_NOT_DISABLED)
        if not cli_ok:
            raise _AttestError(R_RUNTIME_DOWNLOAD_NOT_DISABLED)

    @staticmethod
    def _attest_remote_state_class(spec) -> None:
        backend = spec.state_backend
        if not isinstance(backend.kind, str) or backend.kind.strip().lower() in _LOCAL_STATE_TOKENS:
            raise _AttestError(R_STATE_BACKEND_CLASS_INVALID)
        try:
            validate_identifier(backend.kind, "state_backend.kind")
            validate_identifier(backend.reference, "state_backend.reference")
        except IdentifierError:
            raise _AttestError(R_STATE_BACKEND_CLASS_INVALID) from None

    def _attest_manifest(self, root: str, spec) -> None:
        path = _safe_resolve(root, self._layout.manifest)
        raw = _read_small_file(path, max_bytes=_MAX_MANIFEST_BYTES)
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise _AttestError(R_MANIFEST_INVALID) from None
        if not isinstance(parsed, dict) or set(parsed) != _MANIFEST_KEYS:
            raise _AttestError(R_MANIFEST_INVALID)
        if parsed["runtime_download_allowed"] is not False:
            raise _AttestError(R_MANIFEST_INVALID)
        # Every security-relevant field must AGREE with the authoritative profile (never overrides).
        agreements = {
            "opentofu_version": spec.opentofu_version,
            "executable": spec.executable,
            "binary_integrity": spec.binary_integrity,
            "module_bundle_id": spec.module_bundle_id,
            "module_bundle_hash": spec.module_bundle_hash,
            "provider_lockfile_hash": spec.provider_lockfile_hash,
            "provider_mirror_identity": spec.provider_mirror.identity,
            "renderer_version": spec.renderer_version,
            "remote_state_backend_class": spec.state_backend.kind,
            "cli_config_policy_version": ATTESTATION_POLICY_VERSION,
        }
        for key, expected in agreements.items():
            if parsed.get(key) != expected:
                raise _AttestError(R_MANIFEST_INVALID)
        if not isinstance(parsed["schema_version"], str) or not parsed["schema_version"]:
            raise _AttestError(R_MANIFEST_INVALID)
