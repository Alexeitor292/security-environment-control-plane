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

from secp_commissioning.canonical import sha256_digest

from secp_acceptance import AcceptanceError

#: Captured output cap. Large enough for a full ``docker inspect`` of a stack, small enough that a
#: runaway process cannot exhaust the harness.
MAX_OUTPUT_BYTES = 4 * 1024 * 1024

DEFAULT_TIMEOUT = 300

# --------------------------------------------------------------------------- execution provenance

#: Domain separation for the seam chain.
_SEAM_SCHEMA = "secp.acceptance.seam-chain/v1"

_seam_calls = 0
_seam_chain = sha256_digest({"v": _SEAM_SCHEMA, "genesis": True})


def seam_position() -> tuple[int, str]:
    """How many commands this process has run through the seam, and the chain over their shapes.

    THE PROPERTY THIS EXISTS FOR
    ----------------------------
    An evidence document cannot tell a real observation from a literal. ``observation_digest``
    hashes whatever it is handed, so a stage that recorded ``{"check": check}`` for every check
    produces a structurally perfect, fully-covered, ``passed`` document having touched nothing. That
    is the single cheapest false green available to this program, and no amount of validating the
    document can see it — the document is correct.

    So the harness measures EXECUTION instead. Every host effect goes through :func:`run`, which
    advances this counter. A stage that opened, recorded its checks, and never moved the counter did
    not reach a host, whatever its observations say.

    WHY THIS IS IMMUNE TO THE HOLE THAT BITES A STATIC SWEEP
    -------------------------------------------------------
    ``test_acceptance_process_seam.py`` proves no module OTHER than this one can spawn a process,
    but it enumerates git-tracked files — so an unstaged module that imports ``subprocess`` passes
    the sweep over an absence.

    This counter enumerates nothing. It asks whether the seam advanced, so a module that bypasses
    :func:`run` — staged, unstaged, renamed, or imported dynamically — simply does not advance it,
    and its stage fails the provenance check. **There is no list for it to be missing from.**

    The two are complementary in the useful direction: the sweep says the harness cannot acquire a
    SECOND seam; the counter says a stage actually went through the one it has. B's finding weakens
    the first and leaves the second untouched. Do not "simplify" this into a static check.
    """
    return _seam_calls, _seam_chain


def _advance(argv: tuple[str, ...] | list[str]) -> None:
    """Advance the chain over the SHAPE of one command — never its arguments.

    ``argv[0]`` and the arity only. The harness composes argv from real host output, so the
    arguments routinely carry container names, absolute paths and origins; chaining over them would
    put exactly that material into a digest the evidence document publishes. The shape is enough:
    two runs that did the same work chain identically, and a stage that did NO work cannot chain at
    all.
    """
    global _seam_calls, _seam_chain
    _seam_calls += 1
    _seam_chain = sha256_digest(
        {"v": _SEAM_SCHEMA, "prev": _seam_chain, "argv0": argv[0], "arity": len(argv)}
    )


def reset_seam() -> None:
    """Reset the chain. For the hermetic tests OF this mechanism only."""
    global _seam_calls, _seam_chain
    _seam_calls = 0
    _seam_chain = sha256_digest({"v": _SEAM_SCHEMA, "genesis": True})


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
    # Advanced BEFORE the call, and deliberately not conditioned on success: the question this
    # answers is "did this stage reach a host", not "did the command work". A stage whose every
    # command failed still executed, and its checks will say so as `unproven` or `violated`.
    _advance(argv)
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
    "reset_seam",
    "run",
    "seam_position",
]
