"""Injectable, symlink-safe runtime seams (SECP-PR5C, ADR-023, defects #2, #8).

The installer / inspector / status / readers touch the filesystem and the local container runtime
ONLY through these injected seams, so the full logic runs deterministically in CI without real root,
real chown, real symlinks, or a real container runtime.

:class:`FilesystemBackend` is a HARDENED root-controlled boundary. Every directory / file / evidence
operation walks the path component-by-component refusing symlinks and non-directory ancestors, opens
with ``O_NOFOLLOW`` via directory descriptors (``openat``), re-validates the final parent by
descriptor, refuses a final target that already exists as a symlink / directory / device / socket /
FIFO / foreign hardlink, never follows a symlink during ``chmod``/``chown``, reads the EXACT
``fstat``
size in a bounded loop (refusing short reads, growth, and trailing bytes), writes ALL bytes, and
removes temporaries on every failure path. The production :class:`RealFilesystem` uses real ``os``
``dir_fd`` operations; :class:`InMemoryFilesystem` models the same refusals over an in-memory tree
(including seeded symlinks) so every path-race / ownership / type check is testable anywhere.

No seam contacts the network, Temporal, PostgreSQL, Proxmox, OpenBao, or remote state.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from typing import NoReturn, Protocol

from secp_commissioning.errors import CommissioningError

_WRITE_MASK = 0o022  # no group/other write on a managed dir/file


class FilesystemError(CommissioningError):
    """A hardened filesystem operation failed a safety check (bounded reason code; no path)."""


@dataclass(frozen=True)
class FileStat:
    """A platform-neutral ``lstat`` snapshot (None from ``lstat`` means the path is absent)."""

    is_dir: bool
    is_symlink: bool
    is_regular: bool
    is_special: bool  # socket / FIFO / device / other non-regular non-dir
    uid: int
    gid: int
    mode: int
    size: int
    nlink: int


class FilesystemBackend(Protocol):
    def lstat(self, path: str) -> FileStat | None: ...
    def safe_read(self, path: str, *, max_bytes: int, expected_uid: int) -> bytes: ...
    def sha256(self, path: str) -> str: ...
    def makedir(self, path: str, *, uid: int, gid: int, mode: int) -> None: ...
    def atomic_install(self, path: str, data: bytes, *, uid: int, gid: int, mode: int) -> None: ...
    def remove_file(self, path: str) -> None: ...
    def remove_dir(self, path: str) -> None: ...
    def list_dir(self, path: str) -> tuple[str, ...] | None: ...


class ContainerRuntime(Protocol):
    def image_present(self, digest: str) -> bool: ...


class SealedContainerRuntime:
    """Shipped default: every image reported ABSENT. A real image check needs an injected adapter;
    this never pulls, queries, or contacts a registry."""

    def image_present(self, digest: str) -> bool:
        return False


class InMemoryContainerRuntime:
    def __init__(self, present: tuple[str, ...] = ()) -> None:
        self._present = frozenset(present)
        self.observations: list[str] = []

    def image_present(self, digest: str) -> bool:
        self.observations.append(digest)
        return digest in self._present


@dataclass(frozen=True)
class ImagePresenceSnapshot:
    """One immutable image-presence observation: each DISTINCT digest queried exactly once."""

    present: frozenset[str]

    def is_present(self, digest: str) -> bool:
        return digest in self.present


def snapshot_images(runtime: ContainerRuntime, digests: tuple[str, ...]) -> ImagePresenceSnapshot:
    """Observe each DISTINCT digest exactly once, returning one immutable snapshot (so a stateful
    adapter cannot yield inconsistent decisions across repeated queries within one operation)."""
    present = {d for d in dict.fromkeys(digests) if runtime.image_present(d)}
    return ImagePresenceSnapshot(present=frozenset(present))


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _components(path: str) -> list[str]:
    return [p for p in path.split("/") if p != ""]


# --------------------------------------------------------------------------- in-memory filesystem


@dataclass
class _Node:
    is_dir: bool
    uid: int
    gid: int
    mode: int
    data: bytes = b""
    is_symlink: bool = False
    is_special: bool = False
    nlink: int = 1


# The bootstrap-owned, root-controlled ancestor directories that MUST pre-exist for any managed
# write. Modelled as root-owned, non-group/other-writable dirs so the in-memory backend enforces the
# SAME "trusted ancestor" invariant the production backend enforces by fstat-ing every component
# (defect #3). The evidence parent is included here so a managed write NEVER silently relies on an
# absent parent — it must be a bootstrap-owned directory that already exists.
_TRUSTED_ANCESTORS: tuple[str, ...] = (
    "/opt",
    "/opt/secp",
    "/var",
    "/var/lib",
    "/var/lib/secp",
    "/var/lib/secp/commissioning",
    "/etc",
    "/etc/secp",
    "/etc/secp/commissioning",
)


class InMemoryFilesystem:
    """Deterministic in-memory backend enforcing the same symlink/type/ownership refusals as the
    production backend, over an explicit path->node map. Never touches disk.

    The trusted, root-controlled ancestor directories are pre-seeded root-owned + restrictive so a
    managed write is refused unless EVERY ancestor exists, is a real directory, is root-owned, and
    is not group/other-writable — the same invariant :class:`RealFilesystem` enforces by fstat."""

    def __init__(self) -> None:
        self._nodes: dict[str, _Node] = {}
        for anc in _TRUSTED_ANCESTORS:
            self._nodes[anc] = _Node(is_dir=True, uid=0, gid=0, mode=0o755)

    # --- test seeding (not part of the protocol) ---
    def seed_dir(self, path: str, *, uid: int = 0, gid: int = 0, mode: int = 0o755) -> None:
        self._nodes[path] = _Node(is_dir=True, uid=uid, gid=gid, mode=mode)

    def seed_file(
        self,
        path: str,
        data: bytes,
        *,
        uid: int = 0,
        gid: int = 0,
        mode: int = 0o640,
        nlink: int = 1,
    ) -> None:
        self._nodes[path] = _Node(is_dir=False, uid=uid, gid=gid, mode=mode, data=data, nlink=nlink)

    def seed_symlink(self, path: str, *, uid: int = 0, gid: int = 0) -> None:
        self._nodes[path] = _Node(is_dir=False, uid=uid, gid=gid, mode=0o777, is_symlink=True)

    def seed_special(self, path: str, *, uid: int = 0, gid: int = 0) -> None:
        self._nodes[path] = _Node(is_dir=False, uid=uid, gid=gid, mode=0o660, is_special=True)

    def paths(self) -> tuple[str, ...]:
        return tuple(sorted(self._nodes))

    # --- protocol ---
    def lstat(self, path: str) -> FileStat | None:
        node = self._nodes.get(path)
        if node is None:
            return None
        return FileStat(
            is_dir=node.is_dir and not node.is_symlink,
            is_symlink=node.is_symlink,
            is_regular=not node.is_dir and not node.is_symlink and not node.is_special,
            is_special=node.is_special,
            uid=node.uid,
            gid=node.gid,
            mode=node.mode,
            size=len(node.data),
            nlink=node.nlink,
        )

    def _assert_safe_ancestors(self, path: str) -> None:
        # Every ancestor directory must EXIST, be a real directory (never a symlink), be root-owned,
        # and NOT be group/other-writable — so no symlinked, missing, or attacker-writable ancestor
        # can redirect or capture the operation (defect #3). A missing ancestor is refused (a
        # write never silently relies on an absent parent).
        comps = _components(path)
        cumulative = ""
        for comp in comps[:-1]:
            cumulative += "/" + comp
            node = self._nodes.get(cumulative)
            if node is None:
                reject_fs("fs_ancestor_absent")
            if node.is_symlink:
                reject_fs("fs_ancestor_symlink")
            if not node.is_dir:
                reject_fs("fs_ancestor_not_directory")
            if node.uid != 0 or node.gid != 0:
                reject_fs("fs_ancestor_untrusted_owner")
            if node.mode & _WRITE_MASK:
                reject_fs("fs_ancestor_world_writable")

    def makedir(self, path: str, *, uid: int, gid: int, mode: int) -> None:
        self._assert_safe_ancestors(path)
        existing = self._nodes.get(path)
        if existing is not None:
            if existing.is_symlink:
                reject_fs("fs_target_symlink")
            if not existing.is_dir:
                reject_fs("fs_target_not_directory")
            # An existing directory is left as-is (idempotent makedir); ownership/mode are the
            # installer's concern (it refuses a drifted dir before calling makedir).
            return
        self._nodes[path] = _Node(is_dir=True, uid=uid, gid=gid, mode=mode)

    def atomic_install(self, path: str, data: bytes, *, uid: int, gid: int, mode: int) -> None:
        self._assert_safe_ancestors(path)
        existing = self._nodes.get(path)
        if existing is not None:
            if existing.is_symlink:
                reject_fs("fs_target_symlink")
            if existing.is_dir:
                reject_fs("fs_target_is_directory")
            if existing.is_special:
                reject_fs("fs_target_special")
            if existing.nlink != 1:
                reject_fs("fs_target_hardlinked")
        self._nodes[path] = _Node(is_dir=False, uid=uid, gid=gid, mode=mode, data=data)

    def safe_read(self, path: str, *, max_bytes: int, expected_uid: int) -> bytes:
        self._assert_safe_ancestors(path)
        node = self._nodes.get(path)
        if node is None or node.is_symlink or node.is_dir or node.is_special:
            reject_fs("fs_read_not_regular")
        if node.nlink != 1:
            reject_fs("fs_read_hardlinked")
        if node.uid != expected_uid or (node.mode & _WRITE_MASK):
            reject_fs("fs_read_untrusted_owner_or_mode")
        if len(node.data) == 0 or len(node.data) > max_bytes:
            reject_fs("fs_read_size_invalid")
        return node.data

    def sha256(self, path: str) -> str:
        self._assert_safe_ancestors(path)  # parity with RealFilesystem.sha256 (via _open_parent)
        node = self._nodes.get(path)
        if node is None or node.is_dir or node.is_symlink or node.is_special:
            reject_fs("fs_read_not_regular")
        return _sha256_bytes(node.data)

    def remove_file(self, path: str) -> None:
        self._assert_safe_ancestors(path)
        node = self._nodes.get(path)
        if node is None:
            return
        if node.is_dir:
            reject_fs("fs_remove_file_is_dir")
        if node.is_symlink:
            reject_fs("fs_remove_file_is_symlink")
        del self._nodes[path]

    def remove_dir(self, path: str) -> None:
        self._assert_safe_ancestors(path)
        node = self._nodes.get(path)
        if node is None:
            return
        if not node.is_dir or node.is_symlink:
            reject_fs("fs_remove_dir_not_dir")
        if any(p != path and p.startswith(path + "/") for p in self._nodes):
            reject_fs("fs_remove_dir_not_empty")
        del self._nodes[path]

    def list_dir(self, path: str) -> tuple[str, ...] | None:
        self._assert_safe_ancestors(path)  # parity with RealFilesystem.list_dir (via _open_parent)
        node = self._nodes.get(path)
        if node is None or not node.is_dir or node.is_symlink:
            return None
        prefix = path.rstrip("/") + "/"
        children: set[str] = set()
        for p in self._nodes:
            if p.startswith(prefix):
                rest = p[len(prefix) :]
                if rest and "/" not in rest:
                    children.add(rest)
        return tuple(sorted(children))


def reject_fs(reason_code: str) -> NoReturn:
    raise FilesystemError(reason_code)


# --------------------------------------------------------------------------- real (POSIX) backend

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_EXCL = os.O_EXCL
_AT_SYMLINK_NOFOLLOW = getattr(os, "AT_SYMLINK_NOFOLLOW", 0)
_IS_POSIX = os.name == "posix"


class RealFilesystem:
    """Production symlink-safe backend using ``dir_fd``/``openat`` operations. POSIX + root only."""

    def __init__(self) -> None:
        if not _IS_POSIX:  # pragma: no cover - non-POSIX has no faithful equivalent
            raise FilesystemError("filesystem_backend_non_posix")

    def _assert_trusted_dir(self, fd: int) -> None:
        """Every ancestor (including ``/``) must be a real directory, root-owned, and NOT group/
        other writable — fstat-verified by descriptor so no symlink/ownership race subverts it."""
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            reject_fs("fs_ancestor_not_directory")
        if st.st_uid != 0 or st.st_gid != 0:
            reject_fs("fs_ancestor_untrusted_owner")
        if stat.S_IMODE(st.st_mode) & _WRITE_MASK:
            reject_fs("fs_ancestor_world_writable")

    def _open_parent(self, path: str) -> tuple[int, str]:
        """Open the parent directory of ``path`` via an O_NOFOLLOW component walk; return (dir_fd,
        leaf). ``/`` and every ancestor is fstat-verified to be a real, root-owned, non-group/other-
        writable directory (defect #3). The returned dir_fd stays open for the caller to operate
        through."""
        comps = _components(path)
        if not comps:
            reject_fs("fs_path_root")
        fd = os.open("/", os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC)
        try:
            self._assert_trusted_dir(fd)  # / itself must be safe
            for comp in comps[:-1]:
                nxt = os.open(
                    comp, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=fd
                )
                os.close(fd)
                fd = nxt
                self._assert_trusted_dir(fd)
        except FilesystemError:
            os.close(fd)
            raise
        except OSError:
            os.close(fd)
            reject_fs("fs_ancestor_open_failed")
        return fd, comps[-1]

    def lstat(self, path: str) -> FileStat | None:
        try:
            st = os.lstat(path)
        except OSError:
            return None
        m = st.st_mode
        return FileStat(
            is_dir=stat.S_ISDIR(m),
            is_symlink=stat.S_ISLNK(m),
            is_regular=stat.S_ISREG(m),
            is_special=not (stat.S_ISDIR(m) or stat.S_ISLNK(m) or stat.S_ISREG(m)),
            uid=st.st_uid,
            gid=st.st_gid,
            mode=stat.S_IMODE(m),
            size=st.st_size,
            nlink=st.st_nlink,
        )

    def makedir(self, path: str, *, uid: int, gid: int, mode: int) -> None:
        """Transactional makedir (defect #4): if ANY post-mkdir validation/open/chmod/chown fails,
        the directory THIS call created is removed through the still-open trusted parent dir_fd, so
        no half-initialised (wrong-owner / wrong-mode) directory is left behind. A pre-existing
        directory is never removed. If the compensating rmdir itself fails, a distinct
        ``fs_makedir_cleanup_failed`` reason is raised (absolute atomicity cannot be guaranteed
        past a cleanup failure — documented in ADR-023)."""
        dir_fd, leaf = self._open_parent(path)
        created = False
        try:
            try:
                os.mkdir(leaf, mode, dir_fd=dir_fd)
                created = True
            except FileExistsError:
                created = False
            except OSError:
                reject_fs("fs_makedir_failed")
            fd = os.open(leaf, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=dir_fd)
            try:
                st = os.fstat(fd)
                if not stat.S_ISDIR(st.st_mode):
                    reject_fs("fs_target_not_directory")
                if created:
                    os.fchmod(fd, mode)  # type: ignore[attr-defined]
                    os.fchown(fd, uid, gid)  # type: ignore[attr-defined]
            finally:
                os.close(fd)
        except BaseException as exc:
            if created:
                try:
                    os.rmdir(leaf, dir_fd=dir_fd)
                except OSError:
                    os.close(dir_fd)
                    reject_fs("fs_makedir_cleanup_failed")
            os.close(dir_fd)
            if isinstance(exc, FilesystemError):
                raise  # preserve the original bounded reason (e.g. fs_target_not_directory)
            reject_fs("fs_makedir_failed")
        os.close(dir_fd)

    def atomic_install(self, path: str, data: bytes, *, uid: int, gid: int, mode: int) -> None:
        dir_fd, leaf = self._open_parent(path)
        tmp = ".secp-commissioning-" + leaf + ".tmp"
        try:
            # Refuse a final target that already exists as anything other than a plain regular file.
            try:
                est = os.lstat(leaf, dir_fd=dir_fd)
            except FileNotFoundError:
                est = None
            if est is not None:
                if stat.S_ISLNK(est.st_mode):
                    reject_fs("fs_target_symlink")
                if stat.S_ISDIR(est.st_mode):
                    reject_fs("fs_target_is_directory")
                if not stat.S_ISREG(est.st_mode):
                    reject_fs("fs_target_special")
                if est.st_nlink != 1:
                    reject_fs("fs_target_hardlinked")
            fd = os.open(
                tmp,
                os.O_WRONLY | os.O_CREAT | _O_EXCL | _O_NOFOLLOW | _O_CLOEXEC,
                mode,
                dir_fd=dir_fd,
            )
            wrote = False
            try:
                _write_all(fd, data)
                os.fchmod(fd, mode)  # type: ignore[attr-defined]
                os.fchown(fd, uid, gid)  # type: ignore[attr-defined]
                wrote = True
            finally:
                os.close(fd)
                if not wrote:
                    _silent_unlink(tmp, dir_fd)
            os.replace(tmp, leaf, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except FilesystemError:
            _silent_unlink(tmp, dir_fd)
            raise
        except OSError:
            _silent_unlink(tmp, dir_fd)
            reject_fs("fs_install_failed")
        finally:
            os.close(dir_fd)

    def _open_leaf(self, path: str) -> tuple[int, int]:
        """Open the leaf O_RDONLY|O_NOFOLLOW|O_NONBLOCK (a planted FIFO never blocks) via the safe
        parent walk. Returns (fd, dir_fd) — caller closes both."""
        dir_fd, leaf = self._open_parent(path)
        try:
            fd = os.open(leaf, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC, dir_fd=dir_fd)
        except OSError:
            os.close(dir_fd)
            reject_fs("fs_read_open_failed")
        return fd, dir_fd

    def safe_read(self, path: str, *, max_bytes: int, expected_uid: int) -> bytes:
        fd, dir_fd = self._open_leaf(path)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                reject_fs("fs_read_not_regular")
            if st.st_nlink != 1:
                reject_fs("fs_read_hardlinked")
            if st.st_uid != expected_uid or (stat.S_IMODE(st.st_mode) & _WRITE_MASK):
                reject_fs("fs_read_untrusted_owner_or_mode")
            size = st.st_size
            if size <= 0 or size > max_bytes:
                reject_fs("fs_read_size_invalid")
            data = _read_exact(fd, size)
            if os.read(fd, 1) != b"":  # growth / trailing bytes
                reject_fs("fs_read_grew")
            st2 = os.fstat(fd)
            if st2.st_size != size or st2.st_ino != st.st_ino:
                reject_fs("fs_read_changed")
            return data
        finally:
            os.close(fd)
            os.close(dir_fd)

    def sha256(self, path: str) -> str:
        # A plain content hash of a REGULAR file (no-follow, O_NONBLOCK). Ownership / mode /
        # hardlink
        # drift is the CALLER's concern (status re-checks via lstat), so — matching
        # InMemoryFilesystem
        # — this never raises on a merely-non-pristine file; it only refuses a non-regular type.
        fd, dir_fd = self._open_leaf(path)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                reject_fs("fs_read_not_regular")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(fd, 1 << 16)
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(len(c) for c in chunks) > 8 * 1024 * 1024:
                    reject_fs("fs_read_size_invalid")
            return _sha256_bytes(b"".join(chunks))
        finally:
            os.close(fd)
            os.close(dir_fd)

    def remove_file(self, path: str) -> None:
        dir_fd, leaf = self._open_parent(path)
        try:
            try:
                est = os.lstat(leaf, dir_fd=dir_fd)
            except FileNotFoundError:
                return
            if stat.S_ISLNK(est.st_mode):
                reject_fs("fs_remove_file_is_symlink")
            if stat.S_ISDIR(est.st_mode):
                reject_fs("fs_remove_file_is_dir")
            os.unlink(leaf, dir_fd=dir_fd)
        except OSError:
            reject_fs("fs_remove_file_failed")
        finally:
            os.close(dir_fd)

    def remove_dir(self, path: str) -> None:
        dir_fd, leaf = self._open_parent(path)
        try:
            try:
                est = os.lstat(leaf, dir_fd=dir_fd)
            except FileNotFoundError:
                return
            if stat.S_ISLNK(est.st_mode) or not stat.S_ISDIR(est.st_mode):
                reject_fs("fs_remove_dir_not_dir")
            os.rmdir(leaf, dir_fd=dir_fd)  # refuses closed if non-empty
        except OSError:
            reject_fs("fs_remove_dir_failed")
        finally:
            os.close(dir_fd)

    def list_dir(self, path: str) -> tuple[str, ...] | None:
        """Safely enumerate the immediate entries of ``path`` through the trusted parent dir_fd
        (O_NOFOLLOW, fstat-verified directory). Returns basenames, or None if it is absent / not a
        real directory — never following a symlink."""
        dir_fd, leaf = self._open_parent(path)
        try:
            try:
                fd = os.open(
                    leaf, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=dir_fd
                )
            except OSError:
                return None
            try:
                st = os.fstat(fd)
                if not stat.S_ISDIR(st.st_mode):
                    return None
                return tuple(sorted(os.listdir(fd)))
            finally:
                os.close(fd)
        finally:
            os.close(dir_fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    total = 0
    while total < len(data):
        written = os.write(fd, view[total:])
        if written <= 0:
            reject_fs("fs_write_short")
        total += written


def _read_exact(fd: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            reject_fs("fs_read_short")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _silent_unlink(name: str, dir_fd: int) -> None:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except OSError:
        pass
