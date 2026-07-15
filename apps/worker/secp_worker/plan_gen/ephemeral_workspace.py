"""The safe, ephemeral plan-only workspace materializer (B1B-PR5B, ADR-022 §6/§8) — worker-only.

A controlled-live plan-only run needs a real on-disk workspace: the secret-free ``*.tf`` files the
controlled-live renderer produced, plus a transient binary plan file that OpenTofu writes during
``plan`` and reads back during ``show``. This module creates that workspace under an EXPLICIT
trusted
root, writes every file fail-closed, and — no matter how the run ends — always deletes it. If
residue
survives deletion the caller is told ``recovery_required`` (ADR-022 §8: a restart discards the
transient plan). The offline provider mirror is NOT a workspace concern: it is the exact freshly
attested mirror directory passed separately to ``init -plugin-dir=``.

Hard guarantees:

* the trusted root must be an ABSOLUTE directory whose EVERY path component is lstat'd and refused
if
  symlinked (a symlinked PARENT is refused, not only a symlinked final component), and it must not
  be
  group-/world-writable on POSIX;
* each workspace is a FRESH ``0700`` subdirectory; each file is written ``0600`` with ``O_EXCL`` +
  (where supported) ``O_NOFOLLOW`` and a partial-write-safe loop, so a pre-planted symlink can never
  be followed and a short write can never truncate a source file;
* filenames are validated against a strict ``<name>.tf`` allowlist — no separator, ``..``, or
absolute
  path;
* :func:`validate_transient_plan_file` re-checks the plan file after ``plan`` and before ``show``
  (regular file, not a symlink, contained in the workspace, restrictive mode);
* the workspace is removed in a ``finally``; residue raises ``EphemeralWorkspaceError`` with
  ``workspace_residue`` so the operation is marked ``recovery_required``.
"""

from __future__ import annotations

import os
import posixpath
import re
import shutil
import stat
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass

_DIR_MODE = 0o700
_FILE_MODE = 0o600
_TF_FILENAME_RE = re.compile(r"^[a-z0-9_]+\.tf$")
_PLAN_FILENAME_RE = re.compile(r"^[a-z0-9_]+\.tfplan$")
_MAX_FILE_BYTES = 256 * 1024
_POSIX = os.name == "posix"


class EphemeralWorkspaceError(Exception):
    """A workspace could not be created/materialized/removed safely (bounded reason code)."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class PlanOnlyWorkspace:
    """A live, materialized plan-only workspace (paths only; never file content)."""

    workspace_dir: str
    plan_file: str


def _lstat_component_chain(abs_path: str, *, reason: str) -> os.stat_result:
    """lstat EVERY component of ``abs_path`` from the filesystem root down, refusing any symlink;
    return the final lstat. Every intermediate component must be a directory.

    The controlled-live worker is POSIX (root ``/``); a Windows drive root (``C:/``) is handled only
    so the cross-platform fake-executor tests can materialize a workspace under a drive-letter path.
    """
    p = abs_path.replace("\\", "/")
    drive = p[:2] if len(p) >= 2 and p[1] == ":" else ""
    parts = [c for c in p[len(drive) :].split("/") if c]
    current = drive + "/" if drive else "/"
    last = len(parts) - 1
    for i, part in enumerate(parts):
        current = current + part if current.endswith("/") else current + "/" + part
        try:
            st = os.lstat(current)
        except OSError as exc:
            raise EphemeralWorkspaceError(reason) from exc
        if stat.S_ISLNK(st.st_mode):
            raise EphemeralWorkspaceError(reason)
        if i < last and not stat.S_ISDIR(st.st_mode):
            raise EphemeralWorkspaceError(reason)
    return os.lstat(abs_path)


def _validate_trusted_root(trusted_root: str) -> None:
    if not trusted_root or not os.path.isabs(trusted_root):
        raise EphemeralWorkspaceError("workspace_root_untrusted")
    if ".." in trusted_root.replace("\\", "/").split("/"):
        raise EphemeralWorkspaceError("workspace_root_untrusted")
    st = _lstat_component_chain(trusted_root, reason="workspace_root_untrusted")
    if not stat.S_ISDIR(st.st_mode):
        raise EphemeralWorkspaceError("workspace_root_untrusted")
    if _POSIX and bool(st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise EphemeralWorkspaceError("workspace_root_untrusted")


def _safe_open_flags() -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _write_all(fd: int, data: bytes) -> None:
    """Write every byte, tolerating short ``os.write`` returns; refuse a truncated write."""
    view = memoryview(data)
    written = 0
    while written < len(data):
        n = os.write(fd, view[written:])
        if n <= 0:  # pragma: no cover - a non-positive write is a failure
            raise EphemeralWorkspaceError("workspace_unsafe")
        written += n


def _write_file(directory: str, name: str, content: str) -> None:
    if os.sep in name or (os.altsep and os.altsep in name) or "/" in name or "\\" in name:
        raise EphemeralWorkspaceError("workspace_unsafe")
    if name in ("", ".", "..") or ".." in name or not _TF_FILENAME_RE.match(name):
        raise EphemeralWorkspaceError("workspace_unsafe")
    data = content.encode("utf-8")
    if len(data) > _MAX_FILE_BYTES:
        raise EphemeralWorkspaceError("workspace_unsafe")
    path = posixpath.join(directory, name)
    if os.path.islink(path) or os.path.exists(path):
        raise EphemeralWorkspaceError("workspace_unsafe")
    fd = os.open(path, _safe_open_flags(), _FILE_MODE)
    try:
        _write_all(fd, data)
    finally:
        os.close(fd)
    try:
        os.chmod(path, _FILE_MODE)
    except OSError:  # pragma: no cover - platform without chmod semantics
        pass


def validate_transient_plan_file(plan_file: str, *, workspace_dir: str) -> None:
    """Re-validate the plan file after ``plan`` and before ``show`` (fail closed).

    It must be an absolute, non-symlink, regular file that is a direct child of the exact workspace
    with a restrictive (non group/world-writable) mode.
    """
    p = plan_file.replace("\\", "/")
    ws = workspace_dir.replace("\\", "/").rstrip("/")
    if not os.path.isabs(p) or posixpath.dirname(p) != ws:
        raise EphemeralWorkspaceError("workspace_unsafe")
    try:
        st = os.lstat(plan_file)
    except OSError as exc:
        raise EphemeralWorkspaceError("workspace_unsafe") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise EphemeralWorkspaceError("workspace_unsafe")
    if _POSIX and bool(st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise EphemeralWorkspaceError("workspace_unsafe")


@contextmanager
def plan_only_workspace(
    files: Mapping[str, str],
    *,
    trusted_root: str,
    plan_filename: str = "plan.tfplan",
) -> Iterator[PlanOnlyWorkspace]:
    """Materialize ``files`` into a fresh ``0700`` workspace under ``trusted_root``; always clean
    up.

    The whole workspace is removed on exit; residue raises ``EphemeralWorkspaceError`` with
    ``workspace_residue`` so the operation is marked ``recovery_required``.
    """
    if not files:
        raise EphemeralWorkspaceError("workspace_unsafe")
    if not _PLAN_FILENAME_RE.match(plan_filename):
        raise EphemeralWorkspaceError("workspace_unsafe")
    _validate_trusted_root(trusted_root)

    # POSIX-style paths only: the plan-only command grammar forbids backslashes, and the real
    # workers
    # are Linux. Windows accepts forward-slash paths for the underlying calls (kept testable on
    # both).
    root_posix = trusted_root.replace("\\", "/").rstrip("/")
    workspace_dir = f"{root_posix}/secp-plan-{uuid.uuid4().hex}"
    if os.path.exists(workspace_dir) or os.path.islink(workspace_dir):  # pragma: no cover - uuid
        raise EphemeralWorkspaceError("workspace_unsafe")
    os.mkdir(workspace_dir, _DIR_MODE)
    try:
        try:
            os.chmod(workspace_dir, _DIR_MODE)
        except OSError:  # pragma: no cover
            pass
        for name in sorted(files):
            _write_file(workspace_dir, name, files[name])
        yield PlanOnlyWorkspace(
            workspace_dir=workspace_dir,
            plan_file=posixpath.join(workspace_dir, plan_filename),
        )
    finally:
        shutil.rmtree(workspace_dir, ignore_errors=True)
        if os.path.exists(workspace_dir):
            raise EphemeralWorkspaceError("workspace_residue")
