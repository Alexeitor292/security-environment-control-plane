"""Bounded cross-process serialization for one operator credential account.

The OS keystore APIs used by :mod:`secp_management.operator_credential_store` replace and delete
individual values atomically, but none offers compare-and-swap.  This module supplies the missing
serialization primitive without putting credential material on disk: a lock file contains one
fixed byte, and its name is a SHA-256 digest of the code-owned service and controller-derived
account identifiers.

On production-supported POSIX hosts the lock directory is a fixed, per-UID directory under
``/tmp`` whose ownership and permissions are checked before use.  Windows uses the current user's
private temporary directory so the implemented Credential Manager backend remains testable; the
same byte-range lock is visible to every process in that logon context.  Acquisition is bounded,
and every failure is reduced to one secret-free reason code.
"""

from __future__ import annotations

import errno
import hashlib
import importlib
import os
import stat
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import NoReturn

from secp_management import ManagementError

_LOCK_TIMEOUT_SECONDS = 5.0
_LOCK_RETRY_SECONDS = 0.01
_LOCK_DIRECTORY_MODE = 0o700
_LOCK_FILE_MODE = 0o600


class OperatorCredentialLockError(ManagementError):
    """A bounded lock refusal carrying no account, path, or operating-system detail."""


def _reject() -> NoReturn:
    raise OperatorCredentialLockError("secpctl_credential_lock_unavailable")


def _posix_uid() -> int:
    try:
        getter = os.__dict__.get("getuid")
        if not callable(getter):
            _reject()
        value = getter()
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            _reject()
        return value
    except ManagementError:
        raise
    except Exception:  # pragma: no cover - supported POSIX hosts expose a numeric UID
        _reject()


def _lock_root() -> str:
    if os.name == "posix":
        root = f"/tmp/secp-secpctl-credential-locks-{_posix_uid()}"
    else:
        # No credential or controller identity is used in this directory name.  The per-account
        # digest below is the only differentiator, and the lock file itself contains one fixed byte.
        root = os.path.join(tempfile.gettempdir(), "secp-secpctl-credential-locks")

    try:
        os.mkdir(root, _LOCK_DIRECTORY_MODE)
    except FileExistsError:
        pass
    except Exception:  # noqa: BLE001 - never expose a filesystem path or OS exception
        _reject()

    try:
        metadata = os.lstat(root)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            _reject()
        if os.name == "posix" and (
            metadata.st_uid != _posix_uid()
            or stat.S_IMODE(metadata.st_mode) != _LOCK_DIRECTORY_MODE
        ):
            _reject()
    except ManagementError:
        raise
    except Exception:  # noqa: BLE001 - never expose a filesystem path or OS exception
        _reject()
    return root


def _lock_path(service: str, account: str) -> str:
    identity = hashlib.sha256(f"{service}\0{account}".encode()).hexdigest()
    return os.path.join(_lock_root(), f"{identity}.lock")


def _open_lock_file(path: str) -> int:
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, _LOCK_FILE_MODE)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or (os.name == "posix" and metadata.st_nlink != 1):
            os.close(descriptor)
            _reject()
        if os.name == "posix" and (
            metadata.st_uid != _posix_uid() or stat.S_IMODE(metadata.st_mode) != _LOCK_FILE_MODE
        ):
            os.close(descriptor)
            _reject()
        if metadata.st_size == 0:
            os.write(descriptor, b"\0")
        return descriptor
    except ManagementError:
        raise
    except Exception:  # noqa: BLE001 - never expose a filesystem path or OS exception
        _reject()


def _try_lock(descriptor: int) -> bool:
    if os.name == "nt":
        msvcrt = importlib.import_module("msvcrt")

        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            return True
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK, errno.EPERM}:
                return False
            _reject()

    fcntl = importlib.import_module("fcntl")

    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN}:
            return False
        _reject()


def _unlock(descriptor: int) -> None:
    try:
        if os.name == "nt":
            msvcrt = importlib.import_module("msvcrt")

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            fcntl = importlib.import_module("fcntl")

            fcntl.flock(descriptor, fcntl.LOCK_UN)
    except Exception:  # noqa: BLE001 - closing the descriptor releases the process lock
        pass


@contextmanager
def credential_account_lock(service: str, account: str) -> Iterator[None]:
    """Hold the real cross-process lock for ``(service, account)`` for at most a short wait.

    Callers validate both identifiers before reaching this seam.  Neither value nor the derived
    lock path can appear in a refusal.
    """
    descriptor = _open_lock_file(_lock_path(service, account))
    acquired = False
    try:
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        while not acquired:
            acquired = _try_lock(descriptor)
            if acquired:
                break
            if time.monotonic() >= deadline:
                _reject()
            time.sleep(_LOCK_RETRY_SECONDS)
        yield
    finally:
        if acquired:
            _unlock(descriptor)
        try:
            os.close(descriptor)
        except OSError:
            pass


__all__ = ["OperatorCredentialLockError", "credential_account_lock"]
