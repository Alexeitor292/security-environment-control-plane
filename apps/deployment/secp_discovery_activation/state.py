"""Fixed-layout, no-follow worker state preparation for B8 activation.

The ordinary worker is the only process allowed to own and mutate this tree.  The host installer
creates it once, using the independently configured worker uid/gid, and subsequently treats every
pre-existing object as evidence to validate rather than something to repair.  Unknown, partial,
linked, mis-owned, or permissive state is refused before a container-runtime operation can run.

The production backend deliberately exposes no caller-selected path.  It walks the one code-owned
parent by descriptor and uses ``openat``/``fstat``/``O_NOFOLLOW`` throughout.  It never reads key
bytes.  The in-memory backend is a deterministic test seam with the same public contract.
"""

from __future__ import annotations

import os
import secrets
import stat
import sys
from dataclasses import dataclass
from typing import Protocol

from secp_discovery_activation import DiscoveryActivationError
from secp_discovery_activation.layout import PRODUCTION_LAYOUT

_STATE_PARENT = "/var/lib/secp"
_STATE_LEAF = "discovery-worker"
_KEYS_LEAF = "worker-keys"
_BUNDLE_LEAF = "discovery-bundle"
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_RENAME_NOREPLACE = 1
_QUARANTINE_ATTEMPTS = 4

# These are the existing B8 bundle-manager contract.  No arbitrary worker-state entry is accepted.
_KEY_FILES: dict[str, int] = {
    "admission_key": 256,
    "admission_anchor": 256,
    "ssh_id_ed25519": 64 * 1024,
    "ssh_id_ed25519.pub": 8 * 1024,
}
_BUNDLE_FILES: dict[str, int] = {
    "manifest.json": 64 * 1024,
    "id_key": 64 * 1024,
    "known_hosts": 256 * 1024,
    "binding.json": 64 * 1024,
}


class WorkerStateError(DiscoveryActivationError):
    """A worker-state object failed a closed metadata check."""


@dataclass(frozen=True)
class WorkerStateMetadata:
    """Nonsecret state facts safe for status/evidence.

    Counts and booleans are intentionally used instead of filenames, content, or content digests.
    """

    present: bool
    prepared: bool
    owner_uid: int | None
    owner_gid: int | None
    mode: int | None
    key_directory_present: bool
    bundle_directory_present: bool
    key_file_count: int
    bundle_file_count: int
    keys_generated: bool
    bundle_populated: bool

    def canonical(self) -> dict[str, object]:
        return {
            "present": self.present,
            "prepared": self.prepared,
            "owner_uid": self.owner_uid,
            "owner_gid": self.owner_gid,
            "mode": self.mode,
            "key_directory_present": self.key_directory_present,
            "bundle_directory_present": self.bundle_directory_present,
            "key_file_count": self.key_file_count,
            "bundle_file_count": self.bundle_file_count,
            "keys_generated": self.keys_generated,
            "bundle_populated": self.bundle_populated,
        }


@dataclass(frozen=True)
class PreparedStateReceipt:
    """Opaque inode binding used only for same-transaction compensation/journaling."""

    classification: str
    root_created: bool
    keys_created: bool
    bundle_created: bool
    root_device: int
    root_inode: int
    keys_inode: int
    bundle_inode: int

    def canonical(self) -> dict[str, object]:
        return {
            "classification": self.classification,
            "root_created": self.root_created,
            "keys_created": self.keys_created,
            "bundle_created": self.bundle_created,
            "root_device": self.root_device,
            "root_inode": self.root_inode,
            "keys_inode": self.keys_inode,
            "bundle_inode": self.bundle_inode,
        }


class WorkerStateBackend(Protocol):
    def inspect(self, *, uid: int, gid: int) -> WorkerStateMetadata: ...

    def prepare(self, *, uid: int, gid: int) -> PreparedStateReceipt: ...

    def compensate(self, receipt: PreparedStateReceipt, *, uid: int, gid: int) -> bool: ...


def _reject(reason: str) -> None:
    raise WorkerStateError(reason)


def _require_ids(uid: int, gid: int) -> None:
    if (
        isinstance(uid, bool)
        or isinstance(gid, bool)
        or not isinstance(uid, int)
        or not isinstance(gid, int)
        or not (1 <= uid <= 65533)
        or not (1 <= gid <= 65533)
    ):
        _reject("worker_state_identity_invalid")


def _same_object(st: os.stat_result, *, device: int, inode: int) -> bool:
    return st.st_dev == device and st.st_ino == inode


def _rename_noreplace_at(directory_fd: int, source: str, destination: str) -> None:
    """Atomically rename one entry without replacing a destination (production Linux only)."""

    if not sys.platform.startswith("linux"):
        raise OSError("atomic no-replace rename unavailable")
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError:
        raise OSError("atomic no-replace rename unavailable") from None
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(destination),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination)


def _quarantine_directory_at(
    parent_fd: int,
    name: str,
    *,
    expected_device: int,
    expected_inode: int,
) -> str | None:
    """Detach ``name`` and return it only when the moved directory is the receipt inode."""

    quarantine: str | None = None
    for _attempt in range(_QUARANTINE_ATTEMPTS):
        candidate = f".secp-pr5f-rollback-{secrets.token_hex(16)}"
        try:
            _rename_noreplace_at(parent_fd, name, candidate)
        except FileExistsError:
            continue
        except OSError:
            return None
        quarantine = candidate
        break
    if quarantine is None:
        return None
    try:
        moved = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        try:
            _rename_noreplace_at(parent_fd, quarantine, name)
        except OSError:
            pass
        return None
    if stat.S_ISDIR(moved.st_mode) and _same_object(
        moved, device=expected_device, inode=expected_inode
    ):
        return quarantine
    # A foreign directory won the source-name race.  Restore it atomically and never remove it.
    try:
        _rename_noreplace_at(parent_fd, quarantine, name)
    except OSError:
        pass
    return None


class RealWorkerStateFilesystem:
    """POSIX/root implementation for the single production worker-state path."""

    def __init__(self) -> None:
        if os.name != "posix":  # pragma: no cover - production-only platform refusal
            _reject("worker_state_backend_non_posix")

    @staticmethod
    def _open_parent() -> int:
        fd: int | None = None
        try:
            fd = os.open("/", os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC)
            for component in ("var", "lib", "secp"):
                st = os.fstat(fd)
                if (
                    not stat.S_ISDIR(st.st_mode)
                    or st.st_uid != 0
                    or st.st_gid != 0
                    or stat.S_IMODE(st.st_mode) & 0o022
                ):
                    _reject("worker_state_parent_untrusted")
                next_fd = os.open(
                    component,
                    os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
                    dir_fd=fd,
                )
                os.close(fd)
                fd = next_fd
        except WorkerStateError:
            if fd is not None:
                os.close(fd)
            raise
        except OSError:
            if fd is not None:
                os.close(fd)
            _reject("worker_state_parent_open_failed")
        assert fd is not None
        st = os.fstat(fd)
        if (
            not stat.S_ISDIR(st.st_mode)
            or st.st_uid != 0
            or st.st_gid != 0
            or stat.S_IMODE(st.st_mode) & 0o022
        ):
            os.close(fd)
            _reject("worker_state_parent_untrusted")
        return fd

    @staticmethod
    def _open_directory_at(
        parent_fd: int,
        name: str,
        *,
        uid: int,
        gid: int,
        device: int | None = None,
        reason: str,
    ) -> tuple[int, os.stat_result]:
        try:
            fd = os.open(
                name,
                os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
                dir_fd=parent_fd,
            )
        except OSError:
            _reject(reason + "_open_failed")
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            os.close(fd)
            _reject(reason + "_not_directory")
        if st.st_uid != uid or st.st_gid != gid:
            os.close(fd)
            _reject(reason + "_wrong_owner")
        if stat.S_IMODE(st.st_mode) != _DIRECTORY_MODE:
            os.close(fd)
            _reject(reason + "_unsafe_mode")
        if device is not None and st.st_dev != device:
            os.close(fd)
            _reject(reason + "_cross_device")
        return fd, st

    @staticmethod
    def _validate_files(
        directory_fd: int,
        *,
        allowed: dict[str, int],
        uid: int,
        gid: int,
        device: int,
        reason: str,
    ) -> tuple[int, bool]:
        try:
            names = tuple(sorted(os.listdir(directory_fd)))
        except OSError:
            _reject(reason + "_list_failed")
        if any(name not in allowed for name in names):
            _reject(reason + "_foreign_entry")
        # A half-created keypair or bundle is never treated as reusable state.
        if names and set(names) != set(allowed):
            _reject(reason + "_partial")
        for name in names:
            try:
                lst = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                _reject(reason + "_stat_failed")
            if stat.S_ISLNK(lst.st_mode):
                _reject(reason + "_symlink")
            if not stat.S_ISREG(lst.st_mode):
                _reject(reason + "_not_regular")
            try:
                fd = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=directory_fd)
            except OSError:
                _reject(reason + "_open_failed")
            try:
                st = os.fstat(fd)
                if not _same_object(st, device=lst.st_dev, inode=lst.st_ino):
                    _reject(reason + "_changed")
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    _reject(reason + "_hardlinked_or_not_regular")
                if st.st_dev != device:
                    _reject(reason + "_cross_device")
                if st.st_uid != uid or st.st_gid != gid:
                    _reject(reason + "_wrong_owner")
                if stat.S_IMODE(st.st_mode) != _FILE_MODE:
                    _reject(reason + "_unsafe_mode")
                if not (0 < st.st_size <= allowed[name]):
                    _reject(reason + "_size_invalid")
            finally:
                os.close(fd)
        return len(names), bool(names)

    def _inspect_open_root(
        self, parent_fd: int, *, uid: int, gid: int
    ) -> tuple[WorkerStateMetadata, int, os.stat_result, os.stat_result, os.stat_result]:
        root_fd, root_st = self._open_directory_at(
            parent_fd, _STATE_LEAF, uid=uid, gid=gid, reason="worker_state_root"
        )
        keys_fd: int | None = None
        bundle_fd: int | None = None
        try:
            entries = tuple(sorted(os.listdir(root_fd)))
            if set(entries) != {_KEYS_LEAF, _BUNDLE_LEAF}:
                _reject("worker_state_root_foreign_or_partial")
            keys_fd, keys_st = self._open_directory_at(
                root_fd,
                _KEYS_LEAF,
                uid=uid,
                gid=gid,
                device=root_st.st_dev,
                reason="worker_state_keys",
            )
            bundle_fd, bundle_st = self._open_directory_at(
                root_fd,
                _BUNDLE_LEAF,
                uid=uid,
                gid=gid,
                device=root_st.st_dev,
                reason="worker_state_bundle",
            )
            key_count, keys_generated = self._validate_files(
                keys_fd,
                allowed=_KEY_FILES,
                uid=uid,
                gid=gid,
                device=root_st.st_dev,
                reason="worker_state_key_file",
            )
            bundle_count, bundle_populated = self._validate_files(
                bundle_fd,
                allowed=_BUNDLE_FILES,
                uid=uid,
                gid=gid,
                device=root_st.st_dev,
                reason="worker_state_bundle_file",
            )
            metadata = WorkerStateMetadata(
                present=True,
                prepared=True,
                owner_uid=root_st.st_uid,
                owner_gid=root_st.st_gid,
                mode=stat.S_IMODE(root_st.st_mode),
                key_directory_present=True,
                bundle_directory_present=True,
                key_file_count=key_count,
                bundle_file_count=bundle_count,
                keys_generated=keys_generated,
                bundle_populated=bundle_populated,
            )
            return metadata, root_fd, root_st, keys_st, bundle_st
        except BaseException:
            os.close(root_fd)
            raise
        finally:
            if keys_fd is not None:
                os.close(keys_fd)
            if bundle_fd is not None:
                os.close(bundle_fd)

    def inspect(self, *, uid: int, gid: int) -> WorkerStateMetadata:
        _require_ids(uid, gid)
        parent_fd = self._open_parent()
        try:
            try:
                os.stat(_STATE_LEAF, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return WorkerStateMetadata(
                    present=False,
                    prepared=False,
                    owner_uid=None,
                    owner_gid=None,
                    mode=None,
                    key_directory_present=False,
                    bundle_directory_present=False,
                    key_file_count=0,
                    bundle_file_count=0,
                    keys_generated=False,
                    bundle_populated=False,
                )
            except OSError:
                _reject("worker_state_root_stat_failed")
            metadata, root_fd, _root_st, _keys_st, _bundle_st = self._inspect_open_root(
                parent_fd, uid=uid, gid=gid
            )
            os.close(root_fd)
            return metadata
        finally:
            os.close(parent_fd)

    @staticmethod
    def _create_directory_at(parent_fd: int, name: str, *, uid: int, gid: int) -> os.stat_result:
        created = False
        try:
            os.mkdir(name, _DIRECTORY_MODE, dir_fd=parent_fd)
            created = True
            fd = os.open(
                name,
                os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
                dir_fd=parent_fd,
            )
            try:
                os.fchmod(fd, _DIRECTORY_MODE)  # type: ignore[attr-defined]  # POSIX-only
                os.fchown(fd, uid, gid)  # type: ignore[attr-defined]  # POSIX-only
                st = os.fstat(fd)
                if (
                    not stat.S_ISDIR(st.st_mode)
                    or st.st_uid != uid
                    or st.st_gid != gid
                    or stat.S_IMODE(st.st_mode) != _DIRECTORY_MODE
                ):
                    _reject("worker_state_create_validation_failed")
                return st
            finally:
                os.close(fd)
        except BaseException as exc:
            if created:
                try:
                    os.rmdir(name, dir_fd=parent_fd)
                except OSError:
                    raise WorkerStateError("worker_state_create_compensation_failed") from None
            if isinstance(exc, WorkerStateError):
                raise
            raise WorkerStateError("worker_state_create_failed") from None

    def prepare(self, *, uid: int, gid: int) -> PreparedStateReceipt:
        """Create an entirely absent tree or adopt an already complete, validated tree.

        A partial pre-existing root is foreign and is never repaired.  This gives the installer a
        clean distinction between objects created by this transaction and objects merely adopted.
        """

        _require_ids(uid, gid)
        parent_fd = self._open_parent()
        root_created = False
        keys_created = False
        bundle_created = False
        root_fd: int | None = None
        try:
            try:
                os.stat(_STATE_LEAF, dir_fd=parent_fd, follow_symlinks=False)
                exists = True
            except FileNotFoundError:
                exists = False
            except OSError:
                _reject("worker_state_root_stat_failed")

            if exists:
                _metadata, root_fd, root_st, keys_st, bundle_st = self._inspect_open_root(
                    parent_fd, uid=uid, gid=gid
                )
                return PreparedStateReceipt(
                    classification="adopted",
                    root_created=False,
                    keys_created=False,
                    bundle_created=False,
                    root_device=root_st.st_dev,
                    root_inode=root_st.st_ino,
                    keys_inode=keys_st.st_ino,
                    bundle_inode=bundle_st.st_ino,
                )

            root_st = self._create_directory_at(parent_fd, _STATE_LEAF, uid=uid, gid=gid)
            root_created = True
            root_fd, reopened_root = self._open_directory_at(
                parent_fd, _STATE_LEAF, uid=uid, gid=gid, reason="worker_state_root"
            )
            if not _same_object(reopened_root, device=root_st.st_dev, inode=root_st.st_ino):
                _reject("worker_state_root_changed")
            keys_st = self._create_directory_at(root_fd, _KEYS_LEAF, uid=uid, gid=gid)
            keys_created = True
            bundle_st = self._create_directory_at(root_fd, _BUNDLE_LEAF, uid=uid, gid=gid)
            bundle_created = True
            return PreparedStateReceipt(
                classification="created",
                root_created=True,
                keys_created=True,
                bundle_created=True,
                root_device=root_st.st_dev,
                root_inode=root_st.st_ino,
                keys_inode=keys_st.st_ino,
                bundle_inode=bundle_st.st_ino,
            )
        except BaseException:
            # Compensation is inode-bound and removes only empty directories made by this call.
            if root_fd is not None:
                if bundle_created:
                    try:
                        os.rmdir(_BUNDLE_LEAF, dir_fd=root_fd)
                    except OSError:
                        pass
                if keys_created:
                    try:
                        os.rmdir(_KEYS_LEAF, dir_fd=root_fd)
                    except OSError:
                        pass
            if root_created:
                try:
                    os.rmdir(_STATE_LEAF, dir_fd=parent_fd)
                except OSError:
                    raise WorkerStateError("worker_state_prepare_compensation_failed") from None
            raise
        finally:
            if root_fd is not None:
                os.close(root_fd)
            os.close(parent_fd)

    def compensate(self, receipt: PreparedStateReceipt, *, uid: int, gid: int) -> bool:
        """Remove only still-empty objects created by ``receipt``; never adopted/worker data."""

        _require_ids(uid, gid)
        if type(receipt) is not PreparedStateReceipt:
            _reject("worker_state_receipt_invalid")
        if receipt.classification not in ("created", "adopted"):
            _reject("worker_state_receipt_invalid")
        if not receipt.root_created:
            return not (receipt.keys_created or receipt.bundle_created)
        if (
            receipt.classification != "created"
            or not receipt.keys_created
            or not receipt.bundle_created
        ):
            return False
        parent_fd = self._open_parent()
        root_fd: int | None = None
        child_fds: list[int] = []
        root_quarantine: str | None = None
        child_quarantines: list[tuple[str, str, int | None]] = []
        deletion_started = False
        try:
            root_fd, root_st = self._open_directory_at(
                parent_fd, _STATE_LEAF, uid=uid, gid=gid, reason="worker_state_root"
            )
            if not _same_object(root_st, device=receipt.root_device, inode=receipt.root_inode):
                _reject("worker_state_rollback_root_drift")
            # First pass proves the COMPLETE removal set is still exact and empty.  Nothing is
            # removed until every child passes, so a later refusal cannot leave a partial tree.
            removal_names: list[str] = []
            expected_entries: set[str] = set()
            for name, was_created, inode in (
                (_BUNDLE_LEAF, receipt.bundle_created, receipt.bundle_inode),
                (_KEYS_LEAF, receipt.keys_created, receipt.keys_inode),
            ):
                if not was_created:
                    continue
                expected_entries.add(name)
                child_fd, child_st = self._open_directory_at(
                    root_fd,
                    name,
                    uid=uid,
                    gid=gid,
                    device=root_st.st_dev,
                    reason="worker_state_rollback_child",
                )
                try:
                    if child_st.st_ino != inode or os.listdir(child_fd):
                        return False
                finally:
                    os.close(child_fd)
                removal_names.append(name)
            if set(os.listdir(root_fd)) != expected_entries:
                return False

            # Atomically detach the exact root inode from its public name before removing any
            # child.  A source-name substitution is moved aside, identified as foreign, restored
            # without replacement, and never passed to rmdir.
            os.close(root_fd)
            root_fd = None
            root_quarantine = _quarantine_directory_at(
                parent_fd,
                _STATE_LEAF,
                expected_device=receipt.root_device,
                expected_inode=receipt.root_inode,
            )
            if root_quarantine is None:
                return False
            root_fd, quarantined_root = self._open_directory_at(
                parent_fd,
                root_quarantine,
                uid=uid,
                gid=gid,
                reason="worker_state_rollback_root_quarantine",
            )
            if not _same_object(
                quarantined_root,
                device=receipt.root_device,
                inode=receipt.root_inode,
            ):
                return False

            # Once detached into the root-owned parent, revoke the ordinary worker's path access.
            # Existing directory descriptors are also denied subsequent mutations by the new
            # root-only ownership/mode checks in the kernel.
            os.fchown(root_fd, 0, 0)  # type: ignore[attr-defined]  # POSIX-only
            os.fchmod(root_fd, _DIRECTORY_MODE)  # type: ignore[attr-defined]  # POSIX-only
            locked_root = os.fstat(root_fd)
            if (
                not _same_object(
                    locked_root,
                    device=receipt.root_device,
                    inode=receipt.root_inode,
                )
                or locked_root.st_uid != 0
                or locked_root.st_gid != 0
                or stat.S_IMODE(locked_root.st_mode) != _DIRECTORY_MODE
                or set(os.listdir(root_fd)) != expected_entries
            ):
                return False

            expected_inodes = {
                _BUNDLE_LEAF: receipt.bundle_inode,
                _KEYS_LEAF: receipt.keys_inode,
            }
            for name in removal_names:
                quarantine = _quarantine_directory_at(
                    root_fd,
                    name,
                    expected_device=receipt.root_device,
                    expected_inode=expected_inodes[name],
                )
                if quarantine is None:
                    return False
                child_quarantines.append((name, quarantine, None))
                child_fd, child_st = self._open_directory_at(
                    root_fd,
                    quarantine,
                    uid=uid,
                    gid=gid,
                    device=receipt.root_device,
                    reason="worker_state_rollback_child_quarantine",
                )
                child_fds.append(child_fd)
                child_quarantines[-1] = (name, quarantine, child_fd)
                if child_st.st_ino != expected_inodes[name]:
                    return False
                os.fchown(child_fd, 0, 0)  # type: ignore[attr-defined]  # POSIX-only
                os.fchmod(child_fd, _DIRECTORY_MODE)  # type: ignore[attr-defined]  # POSIX-only
                locked_child = os.fstat(child_fd)
                if (
                    not _same_object(
                        locked_child,
                        device=receipt.root_device,
                        inode=expected_inodes[name],
                    )
                    or locked_child.st_uid != 0
                    or locked_child.st_gid != 0
                    or stat.S_IMODE(locked_child.st_mode) != _DIRECTORY_MODE
                    or os.listdir(child_fd)
                ):
                    return False

            if set(os.listdir(root_fd)) != {
                quarantine for _name, quarantine, _fd in child_quarantines
            }:
                return False

            # No destructive operation begins until the complete receipt set has been atomically
            # rebound, root-locked, and re-proven empty under its quarantine names.
            for _name, _quarantine, quarantined_child_fd in child_quarantines:
                if quarantined_child_fd is None:
                    return False
                current = os.fstat(quarantined_child_fd)
                if not _same_object(
                    current,
                    device=receipt.root_device,
                    inode=expected_inodes[_name],
                ) or os.listdir(quarantined_child_fd):
                    return False
            if set(os.listdir(root_fd)) != {
                quarantine for _name, quarantine, _fd in child_quarantines
            }:
                return False
            deletion_started = True
            for _name, quarantine, _quarantined_child_fd in child_quarantines:
                try:
                    os.rmdir(quarantine, dir_fd=root_fd)
                except OSError:
                    return False
            if os.listdir(root_fd):
                return False
            os.close(root_fd)
            root_fd = None
            try:
                os.rmdir(root_quarantine, dir_fd=parent_fd)
            except OSError:
                return False
            root_quarantine = None
            return True
        except (OSError, WorkerStateError):
            return False
        finally:
            # Before the first rmdir, every quarantine rename is reversible.  Restore ownership
            # through the pinned descriptors and names with no-replace semantics.  Once deletion
            # has begun, a partial quarantine is deliberately left for recovery instead of
            # fabricating a replacement tree or risking deletion of an unproven object.
            if root_quarantine is not None and not deletion_started:
                for name, quarantine, quarantined_child_fd in reversed(child_quarantines):
                    try:
                        if quarantined_child_fd is not None:
                            os.fchown(  # type: ignore[attr-defined]  # POSIX-only
                                quarantined_child_fd, uid, gid
                            )
                            os.fchmod(  # type: ignore[attr-defined]  # POSIX-only
                                quarantined_child_fd, _DIRECTORY_MODE
                            )
                        _rename_noreplace_at(root_fd, quarantine, name)  # type: ignore[arg-type]
                    except OSError:
                        pass
                if root_fd is not None:
                    try:
                        os.fchown(root_fd, uid, gid)  # type: ignore[attr-defined]  # POSIX-only
                        os.fchmod(root_fd, _DIRECTORY_MODE)  # type: ignore[attr-defined]
                    except OSError:
                        pass
                try:
                    _rename_noreplace_at(parent_fd, root_quarantine, _STATE_LEAF)
                    root_quarantine = None
                except OSError:
                    pass
            for child_fd in child_fds:
                try:
                    os.close(child_fd)
                except OSError:
                    pass
            if root_fd is not None:
                os.close(root_fd)
            os.close(parent_fd)


class InMemoryWorkerStateFilesystem:
    """Small deterministic seam used by activation transaction tests."""

    def __init__(self) -> None:
        self.present = False
        self.prepared = False
        self.keys_generated = False
        self.bundle_populated = False
        self.unsafe_reason: str | None = None
        self.compensation_succeeds = True
        self.operations: list[str] = []
        self._generation = 0

    def inspect(self, *, uid: int, gid: int) -> WorkerStateMetadata:
        _require_ids(uid, gid)
        self.operations.append("inspect")
        if self.unsafe_reason is not None:
            _reject(self.unsafe_reason)
        return WorkerStateMetadata(
            present=self.present,
            prepared=self.prepared,
            owner_uid=uid if self.present else None,
            owner_gid=gid if self.present else None,
            mode=_DIRECTORY_MODE if self.present else None,
            key_directory_present=self.prepared,
            bundle_directory_present=self.prepared,
            key_file_count=len(_KEY_FILES) if self.keys_generated else 0,
            bundle_file_count=len(_BUNDLE_FILES) if self.bundle_populated else 0,
            keys_generated=self.keys_generated,
            bundle_populated=self.bundle_populated,
        )

    def prepare(self, *, uid: int, gid: int) -> PreparedStateReceipt:
        before = self.inspect(uid=uid, gid=gid)
        self.operations.append("prepare")
        if before.present and not before.prepared:
            _reject("worker_state_root_foreign_or_partial")
        created = not before.present
        self.present = True
        self.prepared = True
        self._generation += 1
        return PreparedStateReceipt(
            classification="created" if created else "adopted",
            root_created=created,
            keys_created=created,
            bundle_created=created,
            root_device=1,
            root_inode=self._generation,
            keys_inode=self._generation + 100,
            bundle_inode=self._generation + 200,
        )

    def compensate(self, receipt: PreparedStateReceipt, *, uid: int, gid: int) -> bool:
        _require_ids(uid, gid)
        self.operations.append("compensate")
        if not self.compensation_succeeds:
            return False
        if receipt.root_created and not self.keys_generated and not self.bundle_populated:
            self.present = False
            self.prepared = False
        return True


assert PRODUCTION_LAYOUT.worker_state_host_path == _STATE_PARENT + "/" + _STATE_LEAF

__all__ = [
    "WorkerStateError",
    "WorkerStateMetadata",
    "PreparedStateReceipt",
    "WorkerStateBackend",
    "RealWorkerStateFilesystem",
    "InMemoryWorkerStateFilesystem",
]
