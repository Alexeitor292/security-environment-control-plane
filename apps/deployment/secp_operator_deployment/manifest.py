"""Deterministic implementation MANIFEST over the reviewed package modules (SECP-PR5D, blocker #5).

The package's implementation identity is NOT a hash of the label string
``PACKAGE_IMPLEMENTATION_ID``
— it is a deterministic manifest over the actual reviewed executable modules: a FIXED, closed file
inventory, one SHA-256 content digest per covered module (read with symlink/hardlink/type refusal,
on POSIX, a non-group/other-writable trust check), and a canonical aggregate SHA-256 over that
map. A
missing, extra, modified, symlinked, hardlinked, untrusted, or unreadable covered module refuses.

Installed-package verification recomputes this identity; the profile +
`ExpectedDeploymentIdentities`
bind the exact aggregate, so package content that changes while ``PACKAGE_IMPLEMENTATION_ID`` is
kept
constant is detected. Content hashing is deterministic cross-platform (the aggregate is identical on
any host); the POSIX trust checks are enforced by the real reader and modelled by the in-memory one.

Two readers, one aggregate. :class:`RealManifestReader` computes the content aggregate from a
package directory with per-module symlink/hardlink/type/write refusal; it is cross-platform and
needs no root (so provenance, fixtures, and the read-only ``verify`` can compute the digest
anywhere). For the INSTALLED package on a real POSIX operator host,
:func:`verify_installed_package_trust` uses :class:`TrustedManifestReader`, which anchors trust in
DIRECTORY FILE DESCRIPTORS — every ancestor from ``/`` opened with
``O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`` relative to its parent fd and required to be a real directory,
root-owned, and non-group/other-writable; the package dir fd is kept and BOTH enumeration and
module reads happen relative to it (never a re-resolvable path, never ``Path.resolve()`` as a trust
boundary). The two readers hash identical bytes, so a trusted install's aggregate equals the source
aggregate.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Protocol

from secp_operator_deployment import DeploymentPackageError

# The FIXED, closed inventory of reviewed executable modules. A covered module missing from disk,
# or a
# ``*.py`` on disk that is NOT covered here, refuses — the inventory can only change by review.
COVERED_MODULES: tuple[str, ...] = (
    "__init__.py",
    "__main__.py",
    "cli.py",
    "compositions.py",
    "host_adapters.py",
    "host_process.py",
    "identities.py",
    "manifest.py",
    "pinned_exec.py",
    "production_context.py",
    "profile.py",
    "runner.py",
    "runtime_seams.py",
    "verify.py",
)

_MANIFEST_VERSION = "secp.operator-deployment.manifest/v1"
_MAX_MODULE_BYTES = 512 * 1024
_WRITE_MASK = 0o022  # no group/other write on a covered module
# Trusted directory-fd walk flags (POSIX): a real directory, never a symlink, close-on-exec.
_TRUST_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


class ManifestError(DeploymentPackageError):
    """A covered module failed the implementation-manifest integrity check (bounded reason code)."""


class ManifestReader(Protocol):
    def list_modules(self) -> tuple[str, ...]: ...
    def read(self, name: str) -> bytes: ...


class RealManifestReader:
    """Reads the covered modules from a real package directory. On POSIX each read is O_NOFOLLOW +
    fstat (regular, single hardlink, non-group/other-writable); content is bounded + streamed."""

    def __init__(self, package_dir: str) -> None:
        self._dir = package_dir

    def list_modules(self) -> tuple[str, ...]:
        try:
            names = os.listdir(self._dir)
        except OSError:
            raise ManifestError("manifest_dir_unreadable") from None
        return tuple(sorted(n for n in names if n.endswith(".py")))

    def read(self, name: str) -> bytes:
        path = os.path.join(self._dir, name)
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0))
        except OSError:
            raise ManifestError("manifest_module_unreadable") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ManifestError("manifest_module_not_regular")
            if os.name == "posix":
                if st.st_nlink != 1:
                    raise ManifestError("manifest_module_hardlinked")
                if stat.S_IMODE(st.st_mode) & _WRITE_MASK:
                    raise ManifestError("manifest_module_untrusted_mode")
            if st.st_size > _MAX_MODULE_BYTES:
                raise ManifestError("manifest_module_too_large")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, 1 << 16)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_MODULE_BYTES:
                    raise ManifestError("manifest_module_too_large")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)


def _require_trusted_dir(fd: int) -> None:
    """A trusted ancestor / package directory: a real directory, root-owned, and
    non-group/other-writable (symlink refusal is enforced by O_NOFOLLOW at open time, so this fd is
    never a symlink target)."""
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode):
        raise ManifestError("manifest_ancestor_not_directory")
    if os.name == "posix" and st.st_uid != 0:
        raise ManifestError("manifest_ancestor_not_root_owned")
    if stat.S_IMODE(st.st_mode) & _WRITE_MASK:
        raise ManifestError("manifest_ancestor_world_writable")


def open_trusted_package_dir_fd(package_dir: str) -> int:
    """Open the installed package directory through a chain of trusted directory fds from ``/`` and
    return the package-dir fd (the caller must close it). Each ancestor — and the package dir
    itself — is opened with ``O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`` RELATIVE to its parent's fd
    (``openat``) and required to be a real directory, root-owned, and non-group/other-writable. A
    symlinked ancestor or package dir fails at ``O_NOFOLLOW``; a non-directory, non-root-owned, or
    writable component fails the fstat gate. Trust is anchored in the fd chain — never
    ``Path.resolve()`` — so a path swap after
    the walk cannot redirect enumeration or reads to a different tree."""
    if os.name != "posix":
        raise ManifestError("manifest_trust_non_posix")
    if not os.path.isabs(package_dir):
        raise ManifestError("manifest_package_path_not_absolute")
    parts = [p for p in package_dir.split("/") if p]
    try:
        fd = os.open("/", _TRUST_OPEN_FLAGS)
    except OSError:
        raise ManifestError("manifest_ancestor_open_failed") from None
    try:
        _require_trusted_dir(fd)
        for comp in parts:
            if comp in (".", ".."):
                raise ManifestError("manifest_package_path_not_normalized")
            try:
                child = os.open(comp, _TRUST_OPEN_FLAGS, dir_fd=fd)
            except OSError:
                # ELOOP (a symlink, refused by O_NOFOLLOW), ENOTDIR, ENOENT, EACCES → untrusted.
                raise ManifestError("manifest_ancestor_open_failed") from None
            os.close(fd)
            fd = child
            _require_trusted_dir(fd)
        return fd
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


class TrustedManifestReader:
    """Enumerates + reads covered modules RELATIVE to a trusted package-directory fd (from
    :func:`open_trusted_package_dir_fd`) — never by a re-resolvable path. Each module is opened
    ``O_NOFOLLOW|O_CLOEXEC`` relative to the dir fd and required regular, single-hardlink,
    root-owned, non-group/other-writable, and size-bounded, then stream-hashed. Because every
    operation uses the
    fd, a directory-replacement race at the path cannot substitute a different tree."""

    def __init__(self, dir_fd: int) -> None:
        self._fd = dir_fd

    @classmethod
    def open(cls, package_dir: str) -> TrustedManifestReader:
        return cls(open_trusted_package_dir_fd(package_dir))

    def list_modules(self) -> tuple[str, ...]:
        try:
            names = os.listdir(self._fd)
        except OSError:
            raise ManifestError("manifest_dir_unreadable") from None
        return tuple(sorted(n for n in names if n.endswith(".py")))

    def read(self, name: str) -> bytes:
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(
                name, os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0), dir_fd=self._fd
            )
        except OSError:
            raise ManifestError("manifest_module_unreadable") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ManifestError("manifest_module_not_regular")
            if st.st_nlink != 1:
                raise ManifestError("manifest_module_hardlinked")
            if os.name == "posix" and st.st_uid != 0:
                raise ManifestError("manifest_module_not_root_owned")
            if stat.S_IMODE(st.st_mode) & _WRITE_MASK:
                raise ManifestError("manifest_module_untrusted_mode")
            if st.st_size > _MAX_MODULE_BYTES:
                raise ManifestError("manifest_module_too_large")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, 1 << 16)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_MODULE_BYTES:
                    raise ManifestError("manifest_module_too_large")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def close(self) -> None:
        try:
            os.close(self._fd)
        except OSError:
            pass

    def __enter__(self) -> TrustedManifestReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class InMemoryManifestReader:
    """Deterministic reader for tests: a name->bytes map plus an explicit on-disk listing (so
    extra /
    missing / symlinked modules can be modelled). ``symlinks`` names refuse on read."""

    def __init__(
        self,
        files: dict[str, bytes],
        *,
        listing: tuple[str, ...] | None = None,
        symlinks: frozenset[str] = frozenset(),
    ) -> None:
        self._files = dict(files)
        self._listing = tuple(sorted(listing)) if listing is not None else tuple(sorted(files))
        self._symlinks = symlinks

    def list_modules(self) -> tuple[str, ...]:
        return self._listing

    def read(self, name: str) -> bytes:
        if name in self._symlinks:
            raise ManifestError("manifest_module_not_regular")
        if name not in self._files:
            raise ManifestError("manifest_module_unreadable")
        return self._files[name]


def compute_manifest(reader: ManifestReader) -> tuple[dict[str, str], str]:
    """Return (per-module digest map, canonical aggregate digest). Refuses a missing/extra covered
    module (the on-disk ``*.py`` listing must equal the fixed inventory exactly)."""
    present = set(reader.list_modules())
    covered = set(COVERED_MODULES)
    if present != covered:
        # missing covered module OR an unexpected .py present — either fails the fixed inventory
        raise ManifestError("manifest_inventory_mismatch")
    per_module: dict[str, str] = {}
    for name in COVERED_MODULES:
        data = reader.read(name)
        per_module[name] = "sha256:" + hashlib.sha256(data).hexdigest()
    payload = json.dumps(
        {"v": _MANIFEST_VERSION, "modules": dict(sorted(per_module.items()))},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    aggregate = "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return per_module, aggregate


def _default_reader() -> RealManifestReader:
    return RealManifestReader(str(Path(__file__).resolve().parent))


def implementation_manifest_digest(reader: ManifestReader | None = None) -> str:
    """The canonical aggregate implementation digest over the reviewed package modules."""
    _per, aggregate = compute_manifest(reader if reader is not None else _default_reader())
    return aggregate


def verify_installed_package_trust(
    package_dir: str, *, expected_aggregate: str | None = None
) -> str:
    """Verify an INSTALLED package directory is root-trusted end to end (blocker #2), then recompute
    the implementation manifest over its modules THROUGH the trusted dir fd. Fails closed on a
    symlinked/untrusted ancestor or package dir, a hardlinked/symlinked/writable/non-root/oversized
    module, or an on-disk inventory that differs from :data:`COVERED_MODULES`. Returns the
    aggregate;
    if ``expected_aggregate`` is given it must match exactly. POSIX / root-installed only."""
    reader = TrustedManifestReader.open(package_dir)
    try:
        _per, aggregate = compute_manifest(reader)
    finally:
        reader.close()
    if expected_aggregate is not None and aggregate != expected_aggregate:
        raise ManifestError("manifest_installed_aggregate_mismatch")
    return aggregate
