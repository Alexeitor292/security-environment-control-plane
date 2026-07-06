"""Real worker-only SSH bootstrap executor via the system OpenSSH client (SECP-B4 §3; SECP-B5).

The ONLY place a real host is MUTATED during bootstrap, and only from the isolated worker after a
deployment-local bootstrap bundle is mounted. It builds on the shared, mutation-free
:mod:`secp_worker.ssh_channel` primitives (fixed executable paths, hardened options, bundle, known-
hosts binding verifier, fixed-argv runner) and layers the finite, typed
:class:`HostBootstrapOperation` mutation set on top, rendered to a discrete-token argv by the
reviewed
:func:`render_host_command`. Every remote action is one of those closed operations — never ``sh
-c``,
never a shell, never caller-provided argv.

Corrective hardening (SECP-B4): a :class:`KnownHostsBindingVerifier` must PROVE the pinned host-key
binding before ssh; the returned :class:`BootstrapExecutionResult` carries ONLY closed status/codes
(never argv/host/account/port/paths/fingerprint/stdout/stderr); the bundle is disposed on EVERY
path.

The bundle source defaults to sealed (refuses). Fully testable with injected fakes; no real ssh/host
is contacted in tests. The read-only SECP-B5 discovery path uses the SAME shared channel but a
separate, read-only executor — it does NOT import this mutation-capable module.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

# Shared, mutation-free channel primitives (re-exported here for B4 back-compat).
from secp_worker.ssh_channel import (
    _HOST_KEY_MARKERS,
    _OVERALL_TIMEOUT_SECONDS,
    BootstrapBundleUnavailable,
    CommandResult,
    HostCommandRunner,
    KnownHostsBindingVerifier,
    RefusingHostCommandRunner,
    SealedKnownHostsBindingVerifier,
    SealedWorkerBootstrapBundleSource,
    SshBootstrapBundle,
    SshChannelError,
    SubprocessHostCommandRunner,
    WorkerBootstrapBundleSource,
    build_ssh_argv,
)
from secp_worker.staging_live.bootstrap.host_operations import (
    HostBootstrapOperation,
    render_host_command,
)
from secp_worker.staging_live.bootstrap.ownership import SecpOwnershipNamespace

# Back-compat alias: the bootstrap module historically raised ``SshBootstrapError``.
SshBootstrapError = SshChannelError

__all__ = [
    "BootstrapBundleUnavailable",
    "BootstrapExecutionResult",
    "CommandResult",
    "HostCommandRunner",
    "KnownHostsBindingVerifier",
    "RefusingHostCommandRunner",
    "SealedKnownHostsBindingVerifier",
    "SealedWorkerBootstrapBundleSource",
    "SshBootstrapBundle",
    "SshBootstrapError",
    "SshBootstrapExecutor",
    "SubprocessHostCommandRunner",
    "WorkerBootstrapBundleSource",
]


@dataclass(frozen=True)
class BootstrapExecutionResult:
    """A closed, redacted bootstrap outcome. Carries ONLY a closed status + code — never argv, host,
    account, port, key path, known_hosts path, fingerprint, stdout, or stderr."""

    ok: bool
    operation_code: str
    reason_code: str


class SshBootstrapExecutor:
    """Executes ONE finite host-bootstrap MUTATION over hardened SSH. Constructed only with an
    injected bundle source (sealed default refuses) + command runner + host-key binding verifier."""

    def __init__(
        self,
        *,
        bundle_source: WorkerBootstrapBundleSource,
        runner: HostCommandRunner,
        host_key_verifier: KnownHostsBindingVerifier | None = None,
        overall_timeout_seconds: float = _OVERALL_TIMEOUT_SECONDS,
    ) -> None:
        self._bundle_source = bundle_source
        self._runner = runner
        self._host_key_verifier = host_key_verifier or SealedKnownHostsBindingVerifier()
        self._timeout = overall_timeout_seconds

    def _ssh_argv(self, bundle: SshBootstrapBundle, remote_argv: Sequence[str]) -> tuple[str, ...]:
        return build_ssh_argv(bundle, remote_argv)

    def execute(
        self, operation: HostBootstrapOperation, namespace: SecpOwnershipNamespace
    ) -> BootstrapExecutionResult:
        """Render the typed operation to a discrete-token remote argv, verify the pinned host-key
        binding, run it over hardened SSH, and return a CLOSED result. Disposes the bundle on EVERY
        path (including an unexpected failure during acquire)."""
        code = operation.operation_code
        rendered = render_host_command(operation, namespace)
        bundle: SshBootstrapBundle | None = None
        try:
            try:
                bundle = self._bundle_source.acquire()
            except BootstrapBundleUnavailable:
                return BootstrapExecutionResult(False, code, "bootstrap_unavailable")
            if int(bundle.ssh_port) <= 0 or int(bundle.ssh_port) > 65535:
                return BootstrapExecutionResult(False, code, "bootstrap_operation_refused")
            # Enforce the pinned host-key binding BEFORE any ssh invocation (fail closed if
            # unproven).
            if not self._host_key_verifier.verify(bundle):
                return BootstrapExecutionResult(False, code, "host_key_binding_unverified")
            argv = self._ssh_argv(bundle, rendered.argv)
            result = self._runner.run(argv, timeout=self._timeout)
            if result.timed_out:
                return BootstrapExecutionResult(False, code, "bootstrap_timeout")
            if any(marker in result.stderr.lower() for marker in _HOST_KEY_MARKERS):
                return BootstrapExecutionResult(False, code, "bootstrap_host_key_mismatch")
            if result.exit_code != 0:
                return BootstrapExecutionResult(False, code, "bootstrap_operation_refused")
            return BootstrapExecutionResult(True, code, "completed")
        finally:
            # Dispose the bundle whether bootstrap succeeded, failed, or acquire raised.
            self._bundle_source.dispose()
