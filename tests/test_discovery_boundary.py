"""SECP-B5 §6 — hard architectural no-mutation guard for the read-only discovery package.

Static (AST) proof that ``secp_worker/target_discovery`` (the worker-owned read-only discovery
layer)
is architecturally incapable of mutating infrastructure: it imports NO mutation executor/transport,
mutation-op module, deployment apply engine, host-helper/bootstrap mutation renderer, artifact
pipeline, OpenBao handoff, provider client, or legacy provider-mutation discovery — and it uses NO
subprocess directly (the ONLY permitted subprocess is the reviewed fixed-argv SSH runner in the
shared
``secp_worker.ssh_channel``). It also proves the read-only probe contract can render only read-only
argv. This is the architectural half of the "cannot mutate" guarantee; the behavioral half lives in
the discovery engine/probe tests.
"""

from __future__ import annotations

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_DISCOVERY_PKG = _ROOT / "apps" / "worker" / "secp_worker" / "target_discovery"

# Modules the read-only discovery package must NEVER import (anything that can mutate a host,
# contact
# a provider, run a shell, or reach the deployment apply/mutation path).
_FORBIDDEN_MODULE_ROOTS = frozenset(
    {
        "subprocess",
        "os",  # discovery must not shell out or touch the process env directly
        "paramiko",
        "fabric",
        "asyncssh",
        "proxmoxer",
        "httpx",
        "requests",
        "aiohttp",
    }
)
# Fully-qualified worker/plugin modules that are mutation-capable and thus forbidden to discovery.
_FORBIDDEN_FULL_MODULES = frozenset(
    {
        "secp_worker.deployment.mutation_executor",
        "secp_worker.deployment.mutations",
        "secp_worker.deployment.engine",
        "secp_worker.deployment.consumer",
        "secp_worker.deployment.seams",
        "secp_worker.deployment.artifacts",
        "secp_worker.deployment.ssh_bootstrap",  # the bootstrap MUTATION executor + renderer
        "secp_worker.deployment.durable_pop",
        "secp_worker.deployment.remote_pop",
        "secp_worker.deployment.runtime",
        "secp_worker.staging_live.bootstrap.host_operations",  # host mutation op renderer
        "secp_plugin_proxmox.mutation_transport",
        "secp_plugin_proxmox",
        "secp_worker.discovery",  # the LEGACY provider-mutation discovery module (distinct from B5)
    }
)


def _discovery_files() -> list[Path]:
    return [p for p in _DISCOVERY_PKG.rglob("*.py") if "__pycache__" not in p.parts]


def _imported_modules(tree: ast.AST) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mods.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_discovery_package_exists_and_is_scanned():
    files = _discovery_files()
    assert files, "expected the secp_worker/target_discovery package to exist"


def test_discovery_imports_no_mutation_or_subprocess_module():
    for path in _discovery_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        mods = _imported_modules(tree)
        for mod in mods:
            root = mod.split(".")[0]
            assert root not in _FORBIDDEN_MODULE_ROOTS, (
                f"{path.name} imports forbidden module root {mod!r}"
            )
            # Exact-or-prefix match against the fully-qualified forbidden set.
            for forbidden in _FORBIDDEN_FULL_MODULES:
                assert not (mod == forbidden or mod.startswith(forbidden + ".")), (
                    f"{path.name} imports mutation-capable module {mod!r}"
                )


def test_only_ssh_channel_may_touch_subprocess():
    # Defense in depth: prove no discovery module references ``subprocess`` even as an attribute.
    for path in _discovery_files():
        src = path.read_text(encoding="utf-8")
        assert "subprocess" not in src, f"{path.name} references subprocess directly"
        # No write-capable Proxmox verb literals may appear anywhere in the discovery package.
        for forbidden in ("pvesh create", "pvesh set", "pvesh delete", "pvesh push"):
            assert forbidden not in src, f"{path.name} contains a write verb {forbidden!r}"


def test_render_probe_argv_is_always_read_only():
    """Behavioral-structural: every representable probe renders a read-only argv, and no write verb
    is representable by the closed probe type."""
    from secp_worker.deployment.locators import BridgeLocator, GuestLocator, ServiceIdentityLocator
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
        assert_read_only,
        render_probe_argv,
    )

    probes = [
        ProbeVersion(),
        ProbeClusterStatus(),
        ProbeNodeIdentity(),
        ProbeNodeCapacity("pve-a"),
        ProbeStorage("pve-a"),
        ProbeVmidAvailability(),
        ProbeNestedVirtualization("kvm_intel"),
        ProbeNestedVirtualization("kvm_amd"),
        ProbeCandidateLocatorPresence(BridgeLocator("pve-a", "secpbr")),
        ProbeCandidateLocatorPresence(ServiceIdentityLocator("secpabc@pam")),
        ProbeCandidateLocatorPresence(GuestLocator("pve-a", 9001)),
    ]
    for probe in probes:
        argv = render_probe_argv(probe)  # asserts read-only internally
        assert argv[0] in ("pvesh", "pveversion", "cat")
        if argv[0] == "pvesh":
            assert argv[1] == "get"  # only the read verb
        assert_read_only(argv)  # explicit second gate

    # A write verb cannot pass the read-only guard even if hand-constructed.
    import pytest

    for bad in [
        ("pvesh", "create", "/nodes/pve/qemu"),
        ("pvesh", "set", "/nodes/pve/network"),
        ("pvesh", "delete", "/access/users/x"),
        ("rm", "-rf", "/"),
        ("cat", "/etc/shadow"),
        ("bash", "-c", "x"),
    ]:
        with pytest.raises(ProbeError):
            assert_read_only(bad)
