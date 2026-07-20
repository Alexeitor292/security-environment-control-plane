"""Process-local worker readiness signal (SECP-B1B PR5B worker-startup hotfix).

The deployment reported the worker container HEALTHY even though no Temporal Worker had started —
the
legacy fail-open loops were running. Liveness is now handled by ``main`` (any Temporal failure exits
the process non-zero, so the orchestrator restarts it). Readiness answers the separate question "is
THIS process actually hosting the Temporal Worker on the ordinary queue?" with a trustworthy,
process-local signal — no unauthenticated network listener.

Design:

* readiness is FALSE until :func:`mark_ready` is called, which happens ONLY after the ``Worker`` has
  been constructed (its workflows/activities validated) on the configured ordinary queue and is
  about
  to run;
* readiness becomes FALSE again on :func:`clear_ready` (called on any worker exit) AND independently
  whenever the recorded worker PID is no longer alive — so a hard kill (where ``clear_ready`` never
  runs) still flips readiness false rather than leaving a stale "ready";
* the marker lives under a writable runtime dir (default ``/tmp``, a tmpfs) so it works even when
the
  container root filesystem is read-only;
* configuration/settings parsing alone can NEVER make readiness pass — only a running, validated
  Worker can.

A deployment readiness probe runs ``python -m secp_worker.health check`` (exit 0 == ready) — an exec
probe, NOT an HTTP listener.
"""

from __future__ import annotations

import os

# The FIXED default marker path: tmpfs-backed, writable even when the container root filesystem is
# read-only. This is a constant (not env-derived at import) so it is deterministic; the env override
# below is read per-call. Never a network address.
READY_FILE = "/tmp/secp-worker.ready"  # noqa: S108 - tmpfs, intentional


def _ready_path() -> str:
    # Read the env each call (not frozen at import), so a deployment / test override is always
    # honored
    # and the default stays the fixed tmpfs constant.
    return os.environ.get("SECP_WORKER_READY_FILE", READY_FILE)


def mark_ready(task_queue: str) -> None:
    """Atomically publish readiness. Called ONLY after the Worker is validated + about to run.

    Records this process's PID and the ordinary task queue it serves. Written atomically (temp file
    +
    ``os.replace``) so a probe never observes a partial file.
    """
    path = _ready_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(f"{os.getpid()} {task_queue}\n")
    os.replace(tmp, path)  # atomic on a single filesystem (incl. tmpfs)


def clear_ready() -> None:
    """Remove the readiness marker. Best-effort; a missing marker is already 'not ready'."""
    try:
        os.unlink(_ready_path())
    except FileNotFoundError:
        pass


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)  # signal 0 sends nothing; it only checks the process exists (POSIX)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by another uid — still alive
    except OSError:
        return False
    except AttributeError:  # pragma: no cover - non-POSIX dev host without os.kill semantics
        return True
    return True


def readiness_status() -> tuple[bool, str]:
    """Return ``(ready, task_queue)``.

    ``ready`` is True only if the marker exists AND its recorded PID is still alive.
    """
    try:
        with open(_ready_path(), encoding="utf-8") as fh:
            parts = fh.read().split()
        pid = int(parts[0])
        task_queue = parts[1] if len(parts) > 1 else ""
    except (FileNotFoundError, ValueError, IndexError):
        return False, ""
    if not _pid_alive(pid):
        return False, task_queue
    return True, task_queue


def readiness_process_id() -> int | None:
    """Return the live PID bound to the current readiness marker, or ``None``.

    This narrow projection lets another fixed, process-local marker bind itself to the same
    ordinary worker without exposing marker contents or accepting a caller-selected path.
    """

    try:
        with open(_ready_path(), encoding="utf-8") as fh:
            parts = fh.read().split()
        pid = int(parts[0])
        if len(parts) < 2 or not _pid_alive(pid):
            return None
    except (FileNotFoundError, ValueError, IndexError):
        return None
    return pid


def is_ready() -> bool:
    """True only if the readiness marker exists AND the recorded worker PID is still alive."""
    return readiness_status()[0]


def _main(argv: list[str]) -> int:  # pragma: no cover - exercised via __main__ / deployment probe
    if len(argv) >= 1 and argv[0] == "check":
        return 0 if is_ready() else 1
    return 2  # unknown command


if __name__ == "__main__":  # pragma: no cover - deployment readiness probe entrypoint
    import sys

    raise SystemExit(_main(sys.argv[1:]))
