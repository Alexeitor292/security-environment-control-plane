"""Durable fixed-path restart-step markers for the worker-enrollment exchange (SECP WS-B, W4).

The production :class:`~secp_worker.enrollment_driver.WorkerEnrollmentStateStore` that replaces
:class:`~secp_worker.enrollment_driver.InMemoryWorkerEnrollmentStateStore` — whose own docstring
says it exists "for TESTS" and "is never the shipped default" — and the no-op
:class:`~secp_worker.enrollment_driver.SealedWorkerEnrollmentStateStore`.

What it stores is deliberately minimal: the LAST COMPLETED exchange step for one enrollment, and
nothing else. No key, offer, claim, attestation, controller origin, or timestamp is written — only
one token from a CLOSED set. The marker is a retry HINT; the driver never trusts it as the
authoritative outcome (it always re-drives the idempotent exchange and reconciles against the
controller's reported state), so this store can only ever save work — it can never manufacture a
result.

Hardening:

* the root and the marker directory are reviewed CODE constants under the same host-local
  enrollment root as the protected key — never caller-selected;
* the enrollment id NEVER enters a path. The marker file is named by the id's SHA-256, so no
  caller-supplied string can traverse, escape, or collide with another object;
* every read is a hardened, bounded, root-owned read; a marker that is not a plain unlinked
  root-owned 0600 file carrying EXACTLY one known step token reads as ABSENT rather than as data;
* ``record`` refuses an unknown step outright (a contract violation), but treats a filesystem fault
  as best-effort: an unpersistable marker simply degrades to the shipped sealed default, whose
  documented behaviour — a restarted worker safely re-drives — is already correct. A local disk
  fault therefore never fails an enrollment the controller has already advanced.
"""

from __future__ import annotations

import hashlib

from secp_commissioning.runtime import FileStat, FilesystemBackend

from secp_worker.enrollment_driver import WorkerEnrollmentDriverError
from secp_worker.enrollment_key import WORKER_ENROLLMENT_ROOT

#: The EXACT marker directory (root-owned, 0700) beneath the shared host-local enrollment root.
WORKER_ENROLLMENT_STATE_DIR = f"{WORKER_ENROLLMENT_ROOT}/state"
#: The CLOSED set of step tokens a marker may carry, in exchange order. These byte-match the
#: driver's own step constants; a guard test proves the two cannot drift.
WORKER_ENROLLMENT_STEPS: tuple[str, ...] = ("offer_verified", "healthy")

_DIR_MODE = 0o700
_MARKER_MODE = 0o600
_MAX_MARKER_BYTES = 64
_MAX_ENROLLMENT_ID_BYTES = 256


def _reject(reason_code: str) -> None:
    raise WorkerEnrollmentDriverError(reason_code)


def _marker_path(enrollment_id: str) -> str:
    """The marker path for one enrollment. The id is never a path component — only its SHA-256 is,
    so a hostile id can neither traverse out of the marker directory nor name another object."""
    digest = hashlib.sha256(enrollment_id.encode("utf-8")).hexdigest()
    return f"{WORKER_ENROLLMENT_STATE_DIR}/{digest}.step"


def _valid_enrollment_id(enrollment_id: object) -> bool:
    return (
        isinstance(enrollment_id, str)
        and bool(enrollment_id)
        and len(enrollment_id.encode("utf-8")) <= _MAX_ENROLLMENT_ID_BYTES
    )


def _marker_trusted(st: FileStat | None) -> bool:
    """A marker is trusted only as a plain, unlinked, root-owned 0600 regular file. Anything else
    (absent, symlink, hardlinked, foreign owner, loosened mode) reads as ABSENT."""
    return bool(
        st is not None
        and not st.is_symlink
        and st.is_regular
        and not st.is_dir
        and not st.is_special
        and st.nlink == 1
        and st.uid == 0
        and st.gid == 0
        and st.mode == _MARKER_MODE
    )


def _ensure_dirs(fs: FilesystemBackend) -> None:
    """Create the root and the marker directory when absent, then RE-OBSERVE each. An idempotent
    makedir must not let a concurrently planted directory bypass the ownership/type/mode contract a
    pre-existing directory is held to."""
    for path in (WORKER_ENROLLMENT_ROOT, WORKER_ENROLLMENT_STATE_DIR):
        if fs.lstat(path) is None:
            fs.makedir(path, uid=0, gid=0, mode=_DIR_MODE)
        st = fs.lstat(path)
        if (
            st is None
            or not st.is_dir
            or st.is_symlink
            or st.uid != 0
            or st.gid != 0
            or st.mode != _DIR_MODE
        ):
            _reject("enrollment_worker_state_root_unsafe")


class DurableWorkerEnrollmentStateStore:
    """The shipped production restart-state store: one hardened fixed-path marker per enrollment.

    It survives a worker restart (unlike the sealed default, which persists nothing) while keeping
    the sealed default's SAFETY property — an absent or untrusted marker is simply "no marker", and
    the driver then re-drives the idempotent exchange and reconciles against the controller.
    """

    __slots__ = ("_fs",)

    def __init__(self, fs: FilesystemBackend) -> None:
        self._fs = fs

    def __repr__(self) -> str:  # never a path or a marker value
        return "DurableWorkerEnrollmentStateStore(<redacted>)"

    def load(self, enrollment_id: str) -> str | None:
        """The last completed step for this enrollment, or ``None``. Every failure mode — absent,
        drifted metadata, unreadable, oversized, malformed, or an unknown token — is ``None``; the
        store never raises on a read and never returns an unrecognized value."""
        if not _valid_enrollment_id(enrollment_id):
            return None
        path = _marker_path(enrollment_id)
        try:
            if not _marker_trusted(self._fs.lstat(path)):
                return None
            raw = self._fs.safe_read(path, max_bytes=_MAX_MARKER_BYTES, expected_uid=0)
        except Exception:  # noqa: BLE001 - an unreadable marker is simply no marker
            return None
        try:
            step = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            return None
        return step if step in WORKER_ENROLLMENT_STEPS else None

    def record(self, enrollment_id: str, step: str) -> None:
        """Persist the last completed step. An unknown step or a malformed enrollment id is a
        CONTRACT violation and refuses closed; a filesystem fault is best-effort (see the module
        docstring) — the enrollment continues and the missing marker only costs a safe re-drive."""
        if step not in WORKER_ENROLLMENT_STEPS:
            _reject("enrollment_worker_state_step_invalid")
        if not _valid_enrollment_id(enrollment_id):
            _reject("enrollment_worker_state_enrollment_id_invalid")
        try:
            _ensure_dirs(self._fs)
            self._fs.atomic_install(
                _marker_path(enrollment_id),
                (step + "\n").encode("ascii"),
                uid=0,
                gid=0,
                mode=_MARKER_MODE,
            )
        except Exception:  # noqa: BLE001 - an unpersistable hint degrades to the sealed default
            return None
        return None


__all__ = [
    "WORKER_ENROLLMENT_STATE_DIR",
    "WORKER_ENROLLMENT_STEPS",
    "DurableWorkerEnrollmentStateStore",
]
