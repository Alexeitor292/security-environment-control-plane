"""Real worker-only SSH bootstrap executor via the system OpenSSH client (SECP-B4 §3).

This is the ONLY place a real host is touched during bootstrap, and only from the isolated worker
after a deployment-local bootstrap bundle is mounted. It runs the system ``ssh``/``scp`` binaries
with FIXED executable paths and a FIXED, discrete-token argv — never ``sh -c``, never a shell
never caller-provided argv. Every remote action is one of the finite, typed
:class:`HostBootstrapOperation` values rendered to a discrete-token argv by the reviewed
:func:`render_host_command`; the executor appends that argv as separate exec arguments (no shell).

Hardening enforced on every connection: strict pinned host keys (a deployment-local ``known_hosts``
+ ``StrictHostKeyChecking=yes`` + ``UserKnownHostsFile`` + ``GlobalKnownHostsFile=/dev/null``),
``BatchMode=yes`` (no interactive/TTY), publickey-only with password + keyboard-interactive auth
disabled, no agent/X11 forwarding, no proxy discovery (``ProxyCommand=none``), and bounded connect +
overall timeouts. The bundle (host/port/account/key path/known_hosts path/host-key fingerprint) is
worker-only and deployment-local; none of it enters the API/UI/database/audit/logs/exceptions/repo,
and it is disposed after bootstrap completes or fails. Failures return ONLY a closed reason code.

Nothing here is a shipped default: the bundle source defaults to sealed (refuses). Fully testable
with an injected fake command runner + fake bundle source; no real ssh/host is contacted in tests.
"""

from __future__ import annotations

import subprocess  # noqa: S404 - fixed-argv, shell=False, closed operation set only
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from secp_worker.staging_live.bootstrap.host_operations import (
    HostBootstrapOperation,
    render_host_command,
)
from secp_worker.staging_live.bootstrap.ownership import SecpOwnershipNamespace

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


class SshBootstrapError(Exception):
    """Fail-closed bootstrap error carrying ONLY a closed reason code (no host/credential value)."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"ssh bootstrap refused: {reason_code}")
        self.reason_code = reason_code


class BootstrapBundleUnavailable(SshBootstrapError):
    def __init__(self) -> None:
        super().__init__("bootstrap_unavailable")


@dataclass(frozen=True)
class SshBootstrapBundle:
    """A typed, deployment-local bootstrap bundle. Holds only mounted deployment-local FILE PATHS
    the private key + pinned ``known_hosts`` (the material stays in the mount, not in memory) plus
    host/port/account/host-key fingerprint. Redacted repr; not serializable; disposed after use."""

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
    """Deployment-local seam that yields the mounted bootstrap bundle. The shipped default refuses;
    a real source (mounted worker secret interface) is injected only into the deployment engine."""

    def acquire(self) -> SshBootstrapBundle: ...

    def dispose(self) -> None: ...


class SealedWorkerBootstrapBundleSource:
    """The shipped default: NO bundle. Refuses — reads no mount, contacts nothing."""

    def acquire(self) -> SshBootstrapBundle:
        raise BootstrapBundleUnavailable

    def dispose(self) -> None:
        return None


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    # stdout/stderr are captured for closed-code classification only; never logged/persisted raw.
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False


@runtime_checkable
class HostCommandRunner(Protocol):
    """Runs a discrete-token argv with ``shell=False`` and a bounded timeout. The real
    is :class:`SubprocessHostCommandRunner`; tests inject a fake that records argv and never"""

    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult: ...


class SubprocessHostCommandRunner:
    """The real runner: ``subprocess.run`` with ``shell=False`` (no shell, no interpolation), a
    argv, captured output, and a hard timeout. Never runs a shell or a caller-provided string."""

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


@dataclass(frozen=True)
class BootstrapExecutionResult:
    """A closed, redacted bootstrap outcome. ``reason_code`` is a closed code; never a"""

    ok: bool
    operation_code: str
    reason_code: str
    # The exact discrete-token argv issued (fixed ssh path + hardening + generated op tokens). Safe:
    # it contains no secret, only the pinned option set + the account@host + generated resource
    argv: tuple[str, ...] = field(default_factory=tuple)


# ssh host-key mismatch is reported by OpenSSH on stderr with these stable markers.
_HOST_KEY_MARKERS = (b"host key verification failed", b"remote host identification has changed")


class SshBootstrapExecutor:
    """Executes ONE finite host-bootstrap operation over hardened SSH. Constructed only with an
    injected bundle source (sealed default refuses) + command runner; never a shipped default."""

    def __init__(
        self,
        *,
        bundle_source: WorkerBootstrapBundleSource,
        runner: HostCommandRunner,
        overall_timeout_seconds: float = _OVERALL_TIMEOUT_SECONDS,
    ) -> None:
        self._bundle_source = bundle_source
        self._runner = runner
        self._timeout = overall_timeout_seconds

    def _ssh_argv(self, bundle: SshBootstrapBundle, remote_argv: Sequence[str]) -> tuple[str, ...]:
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

    def execute(
        self, operation: HostBootstrapOperation, namespace: SecpOwnershipNamespace
    ) -> BootstrapExecutionResult:
        """Render the typed operation to a discrete-token remote argv, run it over hardened SSH, and
        return a closed result. Disposes the bundle on completion OR failure."""
        code = operation.operation_code
        rendered = render_host_command(operation, namespace)
        try:
            bundle = self._bundle_source.acquire()
        except BootstrapBundleUnavailable:
            return BootstrapExecutionResult(False, code, "bootstrap_unavailable")
        try:
            if int(bundle.ssh_port) <= 0 or int(bundle.ssh_port) > 65535:
                return BootstrapExecutionResult(False, code, "bootstrap_operation_refused")
            argv = self._ssh_argv(bundle, rendered.argv)
            result = self._runner.run(argv, timeout=self._timeout)
            if result.timed_out:
                return BootstrapExecutionResult(False, code, "bootstrap_timeout", argv=argv)
            low = result.stderr.lower()
            if any(marker in low for marker in _HOST_KEY_MARKERS):
                return BootstrapExecutionResult(
                    False, code, "bootstrap_host_key_mismatch", argv=argv
                )
            if result.exit_code != 0:
                return BootstrapExecutionResult(
                    False, code, "bootstrap_operation_refused", argv=argv
                )
            return BootstrapExecutionResult(True, code, "completed", argv=argv)
        finally:
            # Dispose the bundle whether bootstrap succeeded or failed — it must not linger.
            self._bundle_source.dispose()
