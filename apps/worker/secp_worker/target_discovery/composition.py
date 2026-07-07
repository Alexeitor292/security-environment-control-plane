"""Worker discovery composition factory (SECP-B6 §3).

Selects the discovery composition the worker consumer runs. The shipped default is SEALED (zero
I/O).
The REAL read-only probe source is wired ONLY when an explicit, DEPLOYMENT-LOCAL
controlled-integration
profile is enabled (a worker settings flag set in the worker container's deploy manifest — never
API/UI/DB controlled, and carrying no SSH/credential material). Even then, the real source only
*acts* when, at runtime, the mounted bundle validates (:class:`MountedWorkerBootstrapBundleSource`
fails closed otherwise) AND the host-key binding is proven (:class:`FileKnownHostsBindingVerifier`
refuses otherwise) BEFORE any ssh invocation. So a disabled profile OR a missing/invalid bundle
leaves
discovery sealed.

This module lives inside the discovery package and imports NO mutation/transport/apply/artifact/
OpenBao code — only the shared read-only SSH channel runner, the mounted bundle source, the
known-hosts
verifier, and the read-only probe executor.
"""

from __future__ import annotations

from secp_worker.known_hosts import FileKnownHostsBindingVerifier
from secp_worker.mounted_bundle import MountedWorkerBootstrapBundleSource
from secp_worker.ssh_channel import SubprocessHostCommandRunner
from secp_worker.target_discovery.admission_client import (
    SealedWorkerAdmissionClient,
    SignedWorkerAdmissionClient,
    WorkerAdmissionClient,
)
from secp_worker.target_discovery.engine import (
    DiscoveryComposition,
    sealed_discovery_composition,
)
from secp_worker.target_discovery.probe_executor import ReadOnlyProbeExecutor


def build_discovery_composition(settings=None) -> DiscoveryComposition:
    """Return the real read-only composition iff the deployment-local controlled-integration profile
    is enabled; otherwise the SEALED composition. Never reads a bundle field from config/env — only
    the fixed mount path + the enable flag come from deployment-local settings."""
    if settings is None:
        from secp_api.config import get_settings

        settings = get_settings()

    if not getattr(settings, "discovery_controlled_integration_enabled", False):
        return sealed_discovery_composition()

    mount_path = getattr(settings, "discovery_bootstrap_mount", "")
    # One mounted-bundle source serves BOTH roles: the read-only probe executor's SSH bundle source
    # AND the engine's single prepared-snapshot preparer (Phase C / F-BIND). The live composition
    # always carries ``bundle_binding`` + ``admission_client``, so the engine's mandatory
    # control-plane worker-admission and endpoint-binding gates are ALWAYS enforced before any host
    # contact. strict=True selects the hardened descriptor-based validation + read-only-mount
    # requirement + worker-private inode-pinned copy for ssh (SECP-B6 F-FS).
    bundle_source = MountedWorkerBootstrapBundleSource(mount_path, strict=True)
    probe_source = ReadOnlyProbeExecutor(
        bundle_source=bundle_source,
        runner=SubprocessHostCommandRunner(),
        host_key_verifier=FileKnownHostsBindingVerifier(),
    )
    return DiscoveryComposition(
        probe_source=probe_source,
        bundle_binding=bundle_source,
        admission_client=_build_admission_client(settings),
    )


def _build_admission_client(settings) -> WorkerAdmissionClient:
    """Build the worker admission client from deployment-local Ed25519 identity material. When the
    material is absent/unreadable the client is SEALED (refuses), so live discovery fails closed."""
    key_path = getattr(settings, "discovery_worker_mtls_key", "")
    cert_path = getattr(settings, "discovery_worker_mtls_cert", "")
    if not (key_path and cert_path):
        return SealedWorkerAdmissionClient()
    try:
        with open(key_path, encoding="utf-8") as fh:
            private_key_hex = fh.read().strip()
        with open(cert_path, encoding="utf-8") as fh:
            public_anchor_hex = fh.read().strip()
    except OSError:
        return SealedWorkerAdmissionClient()
    if not (private_key_hex and public_anchor_hex):
        return SealedWorkerAdmissionClient()
    return SignedWorkerAdmissionClient(
        private_key_hex=private_key_hex, public_anchor_hex=public_anchor_hex
    )
