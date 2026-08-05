"""A thin, argument-vector-only wrapper around the ``docker`` CLI.

Deliberately the CLI rather than an SDK: it adds no dependency, it is the same surface an operator
would use to check our work by hand, and its exit codes are stable. Every call passes an explicit
argument list — there is no ``shell=True`` anywhere in this module and no caller-supplied string is
ever concatenated into a command.

THE ONE IDEA THIS MODULE EXISTS FOR
-----------------------------------
``docker inspect X`` failing does not mean X is gone. It means one of two very different things:

    "Error: No such object: X"                  -> X is absent
    "failed to connect to the docker API ..."   -> we have no idea whether X is absent

Both are exit code 1. A teardown probe that treats the second as the first reports "clean" at
exactly the moment it is least entitled to — because the removal it just attempted failed for the
same reason the check did. So :func:`object_exists` never decides from the error text alone. It
independently re-establishes that the daemon is answering (:func:`daemon_health`) and only then is
a "no such object" allowed to count as proof of absence. If the liveness check does not answer,
the result is ``None`` — unknown — and the caller must propagate that as ``unproven``.

Error-string matching is used only as a fast negative signal, never as the thing that promotes an
answer to "proved".
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass

logger = logging.getLogger("secp.api.range.docker")

#: Hard ceiling on any single docker invocation. Pull gets its own, larger, budget.
DEFAULT_TIMEOUT_SECONDS = 60
PULL_TIMEOUT_SECONDS = 900

#: Substrings that indicate the DAEMON could not be reached (as opposed to the object being
#: absent). Used only to short-circuit; the authoritative answer always comes from
#: :func:`daemon_health`.
_DAEMON_DOWN_MARKERS = (
    "cannot connect to the docker daemon",
    "failed to connect to the docker api",
    "error during connect",
    "is the docker daemon running",
    "the system cannot find the file specified",
    "docker daemon is not running",
    "connection refused",
)

#: Phrasings the daemon uses for "that object does not exist". Docker is NOT consistent about this
#: and the difference is load-bearing, so both families are listed and both were captured from a
#: live daemon (29.4.0) rather than recalled:
#:     docker container inspect X -> "Error response from daemon: No such container: X"
#:     docker image     inspect X -> "Error response from daemon: No such image: X"
#:     docker network   inspect X -> "Error response from daemon: network X not found"
#: Missing the network phrasing meant every ordinary teardown reported its network as ``unproven``.
#: That is the safe direction, but a signal that fires on every clean run is a signal operators
#: learn to ignore — which costs exactly as much as a false ``clean`` in the end.
_NOT_FOUND_MARKERS = (
    "no such object",
    "no such container",
    "no such network",
    "no such image",
)


class DockerUnavailableError(RuntimeError):
    """The Docker control API could not be reached. Callers must translate this to ``unproven``,
    never to a success or a clean verdict."""


class DockerCommandError(RuntimeError):
    """A docker command failed for a reason other than the daemon being unreachable."""

    def __init__(self, message: str, *, stderr: str = "", returncode: int = 1) -> None:
        super().__init__(message)
        self.stderr = stderr
        self.returncode = returncode


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _looks_like_daemon_down(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _DAEMON_DOWN_MARKERS)


def looks_like_not_found(text: str, reference: str | None = None) -> bool:
    """Is this stderr the daemon saying "that object does not exist"?

    ``reference`` makes the second phrasing precise: rather than accepting any message containing
    "not found" — which would also swallow unrelated failures like a missing manifest — the message
    must name the very object we asked about. Only consulted once the daemon has independently
    confirmed it is answering, so a live daemon naming our reference as absent is real evidence.
    """
    lowered = text.lower()
    if any(marker in lowered for marker in _NOT_FOUND_MARKERS):
        return True
    if reference and "not found" in lowered and reference.lower() in lowered:
        return True
    return False


def docker_binary() -> str | None:
    return shutil.which("docker")


def run(
    args: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    check: bool = True,
) -> CommandResult:
    """Run ``docker <args>``.

    Raises :class:`DockerUnavailableError` when the binary is missing or the daemon is unreachable,
    and :class:`DockerCommandError` for an ordinary non-zero exit when ``check`` is set.
    """
    binary = docker_binary()
    if binary is None:
        raise DockerUnavailableError("the docker CLI is not on PATH")
    try:
        completed = subprocess.run(  # noqa: S603 - fixed binary, argument vector, never a shell
            [binary, *args],
            capture_output=True,
            text=True,
            # MUST be explicit. ``text=True`` alone decodes with the LOCALE encoding, which is
            # cp1252 on a default Windows host — and Docker speaks UTF-8. This is not theoretical:
            # ``bkimminich/juice-shop:v17.1.0`` carries an image label containing U+201D, whose
            # UTF-8 byte 0x9d is undefined in cp1252. Decoding raised inside subprocess's reader
            # THREAD, so ``run`` still returned — with empty stdout. ``inspect_json`` then saw no
            # labels, the ownership check found no owner stamp, and teardown refused to remove a
            # container it had created itself. It failed safe, but for an entirely wrong reason,
            # and the cascade ended in a teardown that reported "clean" while resources were still
            # running. ``errors="replace"`` guarantees a decode never fails: a mangled character in
            # someone else's label must never be able to change what we conclude about ownership.
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DockerUnavailableError(
            f"docker {args[0] if args else ''} timed out after {timeout}s"
        ) from exc
    except OSError as exc:
        raise DockerUnavailableError(f"could not execute the docker CLI: {exc}") from exc

    result = CommandResult(
        returncode=completed.returncode,
        stdout=(completed.stdout or "").strip(),
        stderr=(completed.stderr or "").strip(),
    )
    if not result.ok and _looks_like_daemon_down(result.stderr):
        raise DockerUnavailableError(result.stderr.splitlines()[0] if result.stderr else "")
    if check and not result.ok:
        raise DockerCommandError(
            result.stderr.splitlines()[0] if result.stderr else f"docker {args[0]} failed",
            stderr=result.stderr,
            returncode=result.returncode,
        )
    return result


@dataclass(frozen=True)
class DaemonHealth:
    reachable: bool
    #: The daemon's own unique id. Recorded at create time and re-checked at teardown so a probe
    #: pointed at a DIFFERENT daemon cannot report our resources "absent" and be believed.
    daemon_id: str | None = None
    version: str | None = None
    detail: str | None = None


def daemon_health() -> DaemonHealth:
    """Ask the daemon to identify itself. Never raises."""
    try:
        version = run(["version", "--format", "{{.Server.Version}}"], check=True)
    except (DockerUnavailableError, DockerCommandError) as exc:
        return DaemonHealth(reachable=False, detail=str(exc))
    daemon_id: str | None = None
    try:
        info = run(["info", "--format", "{{.ID}}"], check=True)
        daemon_id = info.stdout or None
    except (DockerUnavailableError, DockerCommandError):
        # A daemon that answers `version` but not `info` is still reachable; we simply have no
        # identity to pin. Absence of the id weakens the teardown claim, it does not void it.
        daemon_id = None
    return DaemonHealth(reachable=True, daemon_id=daemon_id, version=version.stdout or None)


def object_exists(kind: str, reference: str) -> bool | None:
    """Does this container/network exist?

    Returns ``True`` (present), ``False`` (PROVED absent), or ``None`` (unknown — the probe could
    not be trusted). ``None`` is the answer whenever the daemon does not independently confirm it
    is answering, and it is the reason this function does not simply return a bool.
    """
    args = (
        ["container", "inspect", reference]
        if kind == "container"
        else ["network", "inspect", reference]
    )
    try:
        result = run([*args, "--format", "{{.Id}}"], check=False)
    except DockerUnavailableError:
        return None
    if result.ok:
        return True

    # A non-zero exit is only evidence of absence if the daemon is demonstrably answering RIGHT
    # NOW. Re-establish that independently rather than trusting the error text.
    health = daemon_health()
    if not health.reachable:
        return None
    if looks_like_not_found(result.stderr, reference):
        return False
    # Non-zero, daemon up, but not a recognisable "not found" — refuse to guess.
    logger.warning(
        "unrecognised docker inspect failure for %s %s: %s", kind, reference, result.stderr
    )
    return None


def inspect_json(kind: str, reference: str) -> dict | None:
    """Full inspect payload, or ``None`` if absent/unreadable."""
    args = (
        ["container", "inspect", reference]
        if kind == "container"
        else ["network", "inspect", reference]
    )
    try:
        result = run(args, check=False)
    except DockerUnavailableError:
        return None
    if not result.ok:
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, list) and payload:
        first = payload[0]
        return first if isinstance(first, dict) else None
    return None


def image_digest(image: str) -> str | None:
    """The resolved repo digest of a locally present image — evidence of what actually ran."""
    try:
        result = run(["image", "inspect", image, "--format", "{{json .RepoDigests}}"], check=False)
    except DockerUnavailableError:
        return None
    if not result.ok:
        return None
    try:
        digests = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(digests, list) and digests:
        first = str(digests[0])
        _, _, digest = first.partition("@")
        return digest or None
    return None
