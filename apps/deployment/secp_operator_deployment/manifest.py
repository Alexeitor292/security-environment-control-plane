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
    "queue_check.py",
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
        """Every ``.py`` under the package dir, at ANY depth, as a package-relative POSIX name.

        This was a flat ``os.listdir`` filtered to ``.py``. A nested module therefore appeared in
        neither the listing nor :data:`COVERED_MODULES`, so the inventory equality check did not
        trip and the file sat SILENTLY OUTSIDE the implementation aggregate — tampering with it
        would not change the digest. That is a hole in a tamper-detection guarantee, and it makes
        ``provenance``'s "the installed content recomputes to its reviewed aggregate" true of a
        subset while reading as true of the package.

        The reviewed inventory is FLAT, so a nested name can never be in it: returning the nested
        name is what makes ``compute_manifest`` refuse with ``manifest_inventory_mismatch``.

        Note there is NO name-keyed exemption here, deliberately. ``__pycache__`` needs none — it
        contains ``.pyc`` and no ``.py``, so the content filter already ignores it. A name-based
        skip would be the very trap that makes a recursive scan worse than a flat one: something
        could then hide behind the exempt name.
        """
        found: list[str] = []
        try:
            # followlinks=False (the default) — a symlinked subdirectory is not descended.
            for root, _dirs, names in os.walk(self._dir):
                rel_root = os.path.relpath(root, self._dir)
                for n in names:
                    if not n.endswith(".py"):
                        continue
                    rel = n if rel_root == "." else f"{rel_root}/{n}"
                    found.append(rel.replace(os.sep, "/"))
        except OSError:
            raise ManifestError("manifest_dir_unreadable") from None
        return tuple(sorted(found))

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
        """Every ``.py`` at ANY depth, package-relative, enumerated through the trusted dir fd.

        Same defect and same fix as :meth:`RealManifestReader.list_modules` — a nested module was
        invisible to the flat listing and so sat outside the aggregate without tripping the
        inventory check. Enumeration descends by FD (``O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`` relative
        to the parent fd), never by a re-resolvable path, so the property that makes this reader
        trusted is preserved: a directory-replacement race at the path cannot substitute a tree.

        Descent is bounded to ONE level and refuses deeper rather than guessing. That is
        deliberate: the reviewed inventory is flat, so anything nested already fails, and a
        directory it cannot enumerate within that bound is refused
        (``manifest_nested_directory_unverifiable``) instead of silently contributing nothing —
        which is the failure mode this whole change is about.

        No name-keyed exemption: ``__pycache__`` holds no ``.py`` and is ignored by the content
        filter, so nothing can hide behind an exempt name.
        """
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        try:
            names = os.listdir(self._fd)
        except OSError:
            raise ManifestError("manifest_dir_unreadable") from None

        found = [n for n in names if n.endswith(".py")]
        for entry in names:
            if entry.endswith(".py"):
                continue
            try:
                st = os.stat(entry, dir_fd=self._fd, follow_symlinks=False)
            except OSError:
                raise ManifestError("manifest_dir_unreadable") from None
            if not stat.S_ISDIR(st.st_mode):
                continue  # a non-.py regular file is not a module and never was
            found.extend(f"{entry}/{n}" for n in self._list_subdirectory(entry, flags))
        return tuple(sorted(found))

    def _list_subdirectory(self, entry: str, flags: int) -> list[str]:
        """The ``.py`` names one level down, by fd. Refuses a further nested directory."""
        try:
            sub_fd = os.open(entry, flags, dir_fd=self._fd)
        except OSError:
            raise ManifestError("manifest_dir_unreadable") from None
        try:
            try:
                names = os.listdir(sub_fd)
            except OSError:
                raise ManifestError("manifest_dir_unreadable") from None
            for n in names:
                if n.endswith(".py"):
                    continue
                try:
                    st = os.stat(n, dir_fd=sub_fd, follow_symlinks=False)
                except OSError:
                    raise ManifestError("manifest_dir_unreadable") from None
                if stat.S_ISDIR(st.st_mode):
                    # Beyond the bounded descent. Refuse rather than enumerate nothing.
                    raise ManifestError("manifest_nested_directory_unverifiable")
            return [n for n in names if n.endswith(".py")]
        finally:
            os.close(sub_fd)

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
