"""Shared, mutation-free hardened system-OpenSSH channel primitives (SECP-B5).

This module holds ONLY the pure SSH transport primitives — fixed executable paths, the hardened
option set, the deployment-local bundle, the known-hosts binding verifier, and the fixed-argv
command
runner. It renders and executes NOTHING host-specific: it neither knows about host mutations nor
about
read-only probes, and it cannot itself construct a mutating command. Both the deployment bootstrap
executor (which layers the mutation operation set on top) and the SECP-B5 read-only discovery probe
executor (which layers a closed read-only probe set on top) build on these primitives, so the
read-only discovery path can use the exact same hardened channel WITHOUT importing any mutation-
capable module.

Every connection is publickey-only, ``BatchMode``, strict pinned host keys, no agent/X11 forwarding,
no proxy discovery, no password/interactive auth, bounded timeouts, and ``shell=False`` fixed argv —
never ``sh -c`` and never a caller-provided argv. Nothing here is a shipped default: the bundle
source
and the known-hosts verifier both default to SEALED (refuse). No host is contacted at import.
"""

from __future__ import annotations

import subprocess  # noqa: S404 - the ONLY subprocess use; shell=False, fixed argv, closed op sets
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# Fixed executable paths — never discovered from PATH or a caller value.
_SSH_BIN = "/usr/bin/ssh"
_SCP_BIN = "/usr/bin/scp"
# Bounded timeouts (app-owned constants, not user values).
_CONNECT_TIMEOUT_SECONDS = 15
_OVERALL_TIMEOUT_SECONDS = 120
# The closed, hardened SSH option set applied to EVERY connection.
_SSH_HARDENING = (
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "GlobalKnownHostsFile=/dev/null",
    "-o",
    "PasswordAuthentication=no",
    "-o",
    "KbdInteractiveAuthentication=no",
    "-o",
    "PreferredAuthentications=publickey",
    "-o",
    "PubkeyAuthentication=yes",
    "-o",
    "ForwardAgent=no",
    "-o",
    "ForwardX11=no",
    "-o",
    "ProxyCommand=none",
    "-o",
    "ClearAllForwardings=yes",
    "-o",
    f"ConnectTimeout={_CONNECT_TIMEOUT_SECONDS}",
)


class SshChannelError(Exception):
    """Fail-closed channel error carrying ONLY a closed reason code (no host/credential value)."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"ssh channel refused: {reason_code}")
        self.reason_code = reason_code


# Kept for back-compat with the deployment bootstrap module which subclasses/aliases these.
SshBootstrapError = SshChannelError


class BootstrapBundleUnavailable(SshChannelError):
    def __init__(self) -> None:
        super().__init__("bootstrap_unavailable")


@dataclass(frozen=True)
class SshBootstrapBundle:
    """A typed, deployment-local SSH bundle. Holds only mounted deployment-local FILE PATHS to the
    private key + pinned ``known_hosts`` plus host/port/account/host-key fingerprint. Redacted repr;
    not serializable; disposed after use. The SAME bundle type is used by bootstrap and read-only
    discovery — it grants a channel, not an operation."""

    ssh_host: str
    ssh_port: int
    account: str
    private_key_path: str
    known_hosts_path: str
    host_key_fingerprint: str

    def target(self) -> str:
        return f"{self.account}@{self.ssh_host}"

    def __repr__(self) -> str:  # never expose host/account/paths/fingerprint
        return "SshBootstrapBundle(<redacted>)"

    def __reduce__(self):  # not serializable — the bundle must never leave the process
        raise TypeError("SshBootstrapBundle is not serializable")


@runtime_checkable
class WorkerBootstrapBundleSource(Protocol):
    """Deployment-local seam that yields the mounted SSH bundle. The shipped default refuses; a real
    source (mounted worker secret interface) is injected only into the worker executor."""

    def acquire(self) -> SshBootstrapBundle: ...

    def dispose(self) -> None: ...


class SealedWorkerBootstrapBundleSource:
    """The shipped default: NO bundle. Refuses — reads no mount, contacts nothing."""

    def acquire(self) -> SshBootstrapBundle:
        raise BootstrapBundleUnavailable

    def dispose(self) -> None:
        return None


@runtime_checkable
class KnownHostsBindingVerifier(Protocol):
    """Proves the mounted ``known_hosts`` binds the exact target host + port to the bundle's
    expected
    host-key fingerprint BEFORE ssh is invoked. A real implementation parses the deployment-local
    ``known_hosts`` file (local mount read; contacts no host). The shipped default refuses."""

    def verify(self, bundle: SshBootstrapBundle) -> bool: ...


class SealedKnownHostsBindingVerifier:
    """The shipped default: cannot prove the binding — refuses (fail closed)."""

    def verify(self, bundle: SshBootstrapBundle) -> bool:
        return False


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    # stdout/stderr are captured for closed classification only; never logged/persisted/returned.
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False


@runtime_checkable
class HostCommandRunner(Protocol):
    """Runs a discrete-token argv with ``shell=False`` and a bounded timeout."""

    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult: ...


class SubprocessHostCommandRunner:
    """The real runner: ``subprocess.run`` with ``shell=False`` (no shell, no interpolation), a
    fixed
    argv, captured output, and a hard timeout. Never runs a shell or a caller-provided string. This
    is
    the ONE reviewed subprocess call site the read-only discovery path is permitted to use."""

    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        try:
            completed = subprocess.run(  # noqa: S603 - shell=False, fixed argv, closed op set
                list(argv),
                shell=False,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(exit_code=124, timed_out=True)
        return CommandResult(
            exit_code=completed.returncode,
            stdout=completed.stdout or b"",
            stderr=completed.stderr or b"",
        )


class RefusingHostCommandRunner:
    """A runner that must never execute (used in a sealed composition, where acquire refuses first).
    If it is ever reached, it fails closed rather than run anything."""

    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        raise SshChannelError("host_command_runner_sealed")


# ssh host-key mismatch is reported by OpenSSH on stderr with these stable markers.
_HOST_KEY_MARKERS = (b"host key verification failed", b"remote host identification has changed")


def build_ssh_argv(bundle: SshBootstrapBundle, remote_argv: Sequence[str]) -> tuple[str, ...]:
    """Build the fixed, hardened ssh argv: fixed ssh binary + hardened options + pinned known_hosts
    +
    identity + port, then ``--`` and the discrete-token remote argv (no shell, no interpolation)."""
    return (
        _SSH_BIN,
        *_SSH_HARDENING,
        "-o",
        f"UserKnownHostsFile={bundle.known_hosts_path}",
        "-i",
        bundle.private_key_path,
        "-p",
        str(int(bundle.ssh_port)),
        "--",  # end of options; the remote argv follows as discrete exec tokens (no shell)
        bundle.target(),
        *remote_argv,
    )
