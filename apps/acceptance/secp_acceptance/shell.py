"""The single bounded process seam the harness drives real infrastructure through.

Every host effect the harness makes goes through :func:`run` — one ``subprocess.run`` with an argv
list, ``shell=False``, stdin from the null device, a timeout, and a bounded captured output. There
is no shell string anywhere in the harness, so no argument the harness composes can be reinterpreted
as a command.

Output handling is the part worth reading twice. A completed process's stdout/stderr is returned to
the caller for parsing, but it is NEVER placed in an exception, a log line, or an evidence document:
the harness runs ``docker inspect``, ``systemctl show`` and ``secpctl --json`` against real hosts,
and their output routinely carries absolute paths, container ids, and origins. Failures therefore
surface as a bounded reason code plus the exit status, and the caller decides what bounded
projection of the output (if any) is worth recording.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from secp_acceptance import AcceptanceError

#: Captured output cap. Large enough for a full ``docker inspect`` of a stack, small enough that a
#: runaway process cannot exhaust the harness.
MAX_OUTPUT_BYTES = 4 * 1024 * 1024

DEFAULT_TIMEOUT = 300


@dataclass(frozen=True)
class Result:
    """One completed process. ``stdout``/``stderr`` are for the caller to PARSE, never to log."""

    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def __repr__(self) -> str:  # never the captured output
        return f"Result(exit_code={self.exit_code}, stdout_len={len(self.stdout)})"


def run(
    argv: tuple[str, ...] | list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
    check: bool = False,
    stdin_bytes: bytes | None = None,
) -> Result:
    """Run one command with an argv list. ``check=True`` refuses non-zero with a bounded code."""
    if not argv or not all(isinstance(a, str) for a in argv):
        raise AcceptanceError("acceptance_host_command_failed")
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, shell=False, bounded, no user string
            list(argv),
            capture_output=True,
            timeout=timeout,
            input=stdin_bytes,
            stdin=None if stdin_bytes is not None else subprocess.DEVNULL,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise AcceptanceError("acceptance_host_command_timeout") from None
    except (OSError, ValueError):
        raise AcceptanceError("acceptance_host_command_failed") from None
    if len(completed.stdout) > MAX_OUTPUT_BYTES or len(completed.stderr) > MAX_OUTPUT_BYTES:
        raise AcceptanceError("acceptance_host_output_too_large")
    result = Result(
        exit_code=completed.returncode,
        stdout=completed.stdout.decode("utf-8", errors="replace"),
        stderr=completed.stderr.decode("utf-8", errors="replace"),
    )
    if check and not result.ok:
        # The captured output is deliberately dropped here. It is the caller's job to decide what
        # bounded projection of a failure is safe to surface; a generic re-raise that carried
        # stderr would put host paths and origins into every traceback.
        raise AcceptanceError("acceptance_host_command_failed")
    return result


def docker(*args: str, timeout: int = DEFAULT_TIMEOUT, check: bool = False) -> Result:
    """Run the OUTER container runtime (the developer's or CI runner's Docker)."""
    return run(("docker", *args), timeout=timeout, check=check)


def require_container_runtime() -> str:
    """Prove the outer container runtime exists and serves Linux containers; return its version."""
    result = docker("version", "--format", "{{.Server.Os}} {{.Server.Version}}", timeout=60)
    if not result.ok:
        raise AcceptanceError("acceptance_container_runtime_unavailable")
    parts = result.stdout.strip().split()
    if len(parts) != 2 or parts[0] != "linux":
        # A Windows-container daemon cannot run any part of this harness; fail here with a bounded
        # code rather than 40 confusing lines into the fleet build.
        raise AcceptanceError("acceptance_container_runtime_unavailable")
    return parts[1]


__all__ = [
    "DEFAULT_TIMEOUT",
    "MAX_OUTPUT_BYTES",
    "Result",
    "docker",
    "require_container_runtime",
    "run",
]
