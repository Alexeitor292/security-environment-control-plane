"""Read-only Proxmox probe executor over the shared hardened SSH channel (SECP-B5 §2).

The real :class:`HostProbeSource`: it runs the CLOSED read-only probe set over the SAME hardened
system-OpenSSH channel the deployment bootstrap uses (fixed argv, pinned host keys, BatchMode, no
shell, publickey-only, bounded timeout) — but it can ONLY ever emit read-only probes (every rendered
argv passes :func:`assert_read_only`). It imports NO mutation-capable module: only the shared,
mutation-free :mod:`secp_worker.ssh_channel` primitives, the read-only probe contract, and the typed
seams. Raw command output stays in worker memory and is parsed into typed, bounded facts here; it
never
crosses the seam. The bundle is disposed on EVERY path, and the pinned host-key binding is verified
before any ssh invocation. Constructed only out of band on the isolated worker; the shipped
discovery
composition uses the sealed :class:`SealedHostProbeSource` instead.
"""

from __future__ import annotations

from collections.abc import Sequence

from secp_worker.deployment.locators import ResourceLocator
from secp_worker.ssh_channel import (
    _HOST_KEY_MARKERS,
    _OVERALL_TIMEOUT_SECONDS,
    BootstrapBundleUnavailable,
    CommandResult,
    HostCommandRunner,
    KnownHostsBindingVerifier,
    SealedKnownHostsBindingVerifier,
    SshBootstrapBundle,
    WorkerBootstrapBundleSource,
    build_ssh_argv,
)
from secp_worker.target_discovery.probes import (
    ProbeCandidateLocatorPresence,
    ProbeClusterStatus,
    ProbeError,
    ProbeNestedVirtualization,
    ProbeNodeCapacity,
    ProbeNodeIdentity,
    ProbeStorage,
    ProbeVersion,
    ProbeVmidAvailability,
    ReadOnlyHostProbe,
    parse_is_clustered,
    parse_locator_present,
    parse_nested_enabled,
    parse_node_capacity,
    parse_node_identity,
    parse_owner_marker,
    parse_storages,
    parse_used_vmids,
    parse_version_major_minor,
    render_probe_argv,
)
from secp_worker.target_discovery.seams import (
    InventoryFacts,
    LocatorPresence,
    ProbeSourceUnavailable,
    StorageOption,
)

# The closed nested-virtualization module set the executor probes (from the read-only probe
# contract).
_NESTED_MODULES = ("kvm_intel", "kvm_amd")


class _ProbeSession:
    """One acquired-bundle session: verifies the pinned host-key binding once, runs read-only
    probes,
    and disposes the bundle on exit — including on any error."""

    def __init__(
        self,
        *,
        bundle_source: WorkerBootstrapBundleSource,
        runner: HostCommandRunner,
        host_key_verifier: KnownHostsBindingVerifier,
        timeout: float,
    ) -> None:
        self._bundle_source = bundle_source
        self._runner = runner
        self._verifier = host_key_verifier
        self._timeout = timeout
        self._bundle: SshBootstrapBundle | None = None

    def __enter__(self) -> _ProbeSession:
        # Acquire + verify the pinned host-key binding. On ANY failure here the bundle source is
        # disposed before propagating, since ``__exit__`` is not called when ``__enter__`` raises —
        # so disposal is guaranteed on every path (sealed acquire, bad port, unverified binding, or
        # an unexpected acquire error).
        try:
            self._bundle = self._bundle_source.acquire()
            port = int(self._bundle.ssh_port)
            if port <= 0 or port > 65535:
                raise ProbeSourceUnavailable("probe_refused")
            if not self._verifier.verify(self._bundle):
                raise ProbeSourceUnavailable("host_key_binding_unverified")
        except BootstrapBundleUnavailable:
            self._bundle_source.dispose()
            raise ProbeSourceUnavailable("bootstrap_unavailable") from None
        except BaseException:
            self._bundle_source.dispose()
            raise
        return self

    def __exit__(self, *_exc: object) -> None:
        self._bundle_source.dispose()  # dispose on EVERY path

    def run(self, probe: ReadOnlyHostProbe) -> CommandResult:
        assert self._bundle is not None
        remote_argv: Sequence[str] = render_probe_argv(probe)  # asserts read-only internally
        argv = build_ssh_argv(self._bundle, remote_argv)
        result = self._runner.run(argv, timeout=self._timeout)
        if result.timed_out:
            raise ProbeSourceUnavailable("probe_timeout")
        if any(marker in result.stderr.lower() for marker in _HOST_KEY_MARKERS):
            raise ProbeSourceUnavailable("host_key_binding_unverified")
        return result

    def run_ok(self, probe: ReadOnlyHostProbe) -> bytes:
        result = self.run(probe)
        if result.exit_code != 0:
            raise ProbeSourceUnavailable("probe_refused")
        return result.stdout


class ReadOnlyProbeExecutor:
    """The real read-only probe source. Constructed only with an injected bundle source (sealed
    default refuses) + runner + host-key verifier. Never emits or represents a mutating command."""

    def __init__(
        self,
        *,
        bundle_source: WorkerBootstrapBundleSource,
        runner: HostCommandRunner,
        host_key_verifier: KnownHostsBindingVerifier | None = None,
        timeout: float = _OVERALL_TIMEOUT_SECONDS,
    ) -> None:
        self._bundle_source = bundle_source
        self._runner = runner
        self._host_key_verifier = host_key_verifier or SealedKnownHostsBindingVerifier()
        self._timeout = timeout

    def _session(self) -> _ProbeSession:
        return _ProbeSession(
            bundle_source=self._bundle_source,
            runner=self._runner,
            host_key_verifier=self._host_key_verifier,
            timeout=self._timeout,
        )

    def read_inventory(self) -> InventoryFacts:
        try:
            with self._session() as session:
                major, minor = parse_version_major_minor(session.run_ok(ProbeVersion()))
                is_clustered = parse_is_clustered(session.run_ok(ProbeClusterStatus()))
                node, node_count = parse_node_identity(session.run_ok(ProbeNodeIdentity()))
                cpu, mem_total, mem_free = parse_node_capacity(
                    session.run_ok(ProbeNodeCapacity(node))
                )
                storages = tuple(
                    StorageOption(sid, avail, usable)
                    for sid, avail, usable in parse_storages(session.run_ok(ProbeStorage(node)))
                )
                used_vmids = parse_used_vmids(session.run_ok(ProbeVmidAvailability()))
                nested = self._probe_nested(session)
        except ProbeError as exc:
            # Never surface a raw parse error; collapse to a closed malformed/unsupported reason.
            reason = getattr(exc, "args", ["malformed_probe_output"])[0]
            raise ProbeSourceUnavailable(str(reason)) from None
        return InventoryFacts(
            version_major=major,
            version_minor=minor,
            is_clustered=is_clustered,
            node=node,
            node_count=node_count,
            cpu_total=cpu,
            mem_total_mb=mem_total,
            mem_free_mb=mem_free,
            nested_available=nested,
            storages=storages,
            used_vmids=used_vmids,
        )

    def _probe_nested(self, session: _ProbeSession) -> bool:
        for module in _NESTED_MODULES:
            result = session.run(ProbeNestedVirtualization(module))
            if result.exit_code == 0 and parse_nested_enabled(result.stdout):
                return True
        return False

    def probe_candidate_presence(
        self, locators: tuple[ResourceLocator, ...]
    ) -> dict[str, LocatorPresence]:
        out: dict[str, LocatorPresence] = {}
        try:
            with self._session() as session:
                for locator in locators:
                    result = session.run(ProbeCandidateLocatorPresence(locator))
                    present = parse_locator_present(result.exit_code)
                    marker = parse_owner_marker(result.stdout) if present else None
                    out[locator.observe_key()] = LocatorPresence(present, marker)
        except ProbeError:
            raise ProbeSourceUnavailable("malformed_probe_output") from None
        return out
