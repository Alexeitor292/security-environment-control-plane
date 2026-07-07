"""SECP-B6 §3/§4/§6 — live discovery composition gating, path-only contact, plan-hash binding.

Proves: the composition is sealed unless the deployment-local profile is enabled; the real
composition
integrates the real mounted-bundle source + real known-hosts verifier + read-only executor and reads
inventory ONLY via the fixed read-only SSH probe path; a failed host-key binding refuses before ssh;
the guest candidate uses the lighter status probe; the candidate-plan content hash changes with org
/
registration / enrollment; and the new modules import no mutation/apply/OpenBao/artifact/provider
code.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from secp_api.config import Settings
from secp_api.discovery_contract import build_candidate_plan_document, discovery_candidate_plan_hash
from secp_worker.deployment.locators import GuestLocator
from secp_worker.ssh_channel import CommandResult
from secp_worker.target_discovery.composition import build_discovery_composition
from secp_worker.target_discovery.probe_executor import ReadOnlyProbeExecutor
from secp_worker.target_discovery.probes import ProbeCandidateLocatorPresence, render_probe_argv
from secp_worker.target_discovery.seams import ProbeSourceUnavailable

_POSIX = os.name == "posix"


def _host_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    openssh = (
        key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    kt, kb = openssh.split()[:2]
    digest = hashlib.sha256(base64.b64decode(kb)).digest()
    fp = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    return kt, kb, fp


def _valid_mount(tmp_path, *, fingerprint, host="pve-a", known_hosts) -> str:
    mount = tmp_path / "bundle"
    mount.mkdir()
    manifest = {
        "ssh_host": host,
        "ssh_port": 22,
        "account": "secp",
        "host_key_fingerprint": fingerprint,
    }
    (mount / "manifest.json").write_text(json.dumps(manifest))
    (mount / "id_key").write_bytes(b"KEY")
    (mount / "known_hosts").write_text(known_hosts)
    if _POSIX:
        os.chmod(mount, 0o700)
        for f in ("manifest.json", "id_key", "known_hosts"):
            os.chmod(mount / f, 0o600)
    return str(mount)


class _ReadOnlyFakeRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, *, timeout):
        self.calls.append(list(argv))
        idx = argv.index("--")
        cmd = " ".join(argv[idx + 2 :])
        table = {
            "pvesh get /version --output-format json": json.dumps({"version": "8.1.4"}),
            "pvesh get /cluster/status --output-format json": "[]",
            "pvesh get /nodes --output-format json": json.dumps([{"node": "pve-a"}]),
            "pvesh get /nodes/pve-a/status --output-format json": json.dumps(
                {"cpuinfo": {"cpus": 16}, "memory": {"total": 68719476736, "free": 34359738368}}
            ),
            "pvesh get /nodes/pve-a/storage --output-format json": json.dumps(
                [{"storage": "local-lvm", "avail": 536870912000, "active": 1, "content": "images"}]
            ),
            "pvesh get /cluster/resources --type vm --output-format json": "[]",
        }
        if cmd in table:
            return CommandResult(0, table[cmd].encode())
        if argv[idx + 2] == "cat":
            return CommandResult(0, b"Y\n")
        return CommandResult(1, b"")


def test_profile_off_is_sealed():
    comp = build_discovery_composition(Settings())
    assert type(comp.probe_source).__name__ == "SealedHostProbeSource"


def test_profile_on_wires_real_executor():
    comp = build_discovery_composition(Settings(discovery_controlled_integration_enabled=True))
    assert isinstance(comp.probe_source, ReadOnlyProbeExecutor)


def test_live_composition_reads_inventory_via_read_only_ssh_only(tmp_path):
    from secp_worker.known_hosts import FileKnownHostsBindingVerifier
    from secp_worker.mounted_bundle import MountedWorkerBootstrapBundleSource

    kt, kb, fp = _host_key()
    mount = _valid_mount(tmp_path, fingerprint=fp, known_hosts=f"pve-a {kt} {kb}\n")
    runner = _ReadOnlyFakeRunner()
    ex = ReadOnlyProbeExecutor(
        bundle_source=MountedWorkerBootstrapBundleSource(mount),
        runner=runner,
        host_key_verifier=FileKnownHostsBindingVerifier(),
    )
    facts = ex.read_inventory()
    assert facts.node == "pve-a" and facts.nested_available is True and facts.cpu_total == 16
    # Contact happened ONLY via the fixed hardened ssh read-only probe path.
    assert runner.calls, "expected probes to run once the bundle + binding validated"
    for argv in runner.calls:
        assert argv[0] == "/usr/bin/ssh" and "BatchMode=yes" in argv
        remote = argv[argv.index("--") + 2 :]
        assert remote[0] in ("pvesh", "pveversion", "cat")
        if remote[0] == "pvesh":
            assert remote[1] == "get"


def test_live_composition_refuses_when_binding_fails(tmp_path):
    from secp_worker.known_hosts import FileKnownHostsBindingVerifier
    from secp_worker.mounted_bundle import MountedWorkerBootstrapBundleSource

    kt, kb, _ = _host_key()
    _, _, wrong_fp = _host_key()  # manifest pins a fingerprint the known_hosts key does NOT match
    mount = _valid_mount(tmp_path, fingerprint=wrong_fp, known_hosts=f"pve-a {kt} {kb}\n")
    runner = _ReadOnlyFakeRunner()
    ex = ReadOnlyProbeExecutor(
        bundle_source=MountedWorkerBootstrapBundleSource(mount),
        runner=runner,
        host_key_verifier=FileKnownHostsBindingVerifier(),
    )
    with pytest.raises(ProbeSourceUnavailable) as exc:
        ex.read_inventory()
    assert exc.value.reason_code == "host_key_binding_unverified"
    assert runner.calls == []  # ssh was never invoked


def test_guest_candidate_uses_lightweight_status_probe():
    argv = render_probe_argv(ProbeCandidateLocatorPresence(GuestLocator("pve-a", 9001)))
    assert argv == (
        "pvesh",
        "get",
        "/nodes/pve-a/qemu/9001/status/current",
        "--output-format",
        "json",
    )
    assert "/config" not in " ".join(argv)


def _plan(**over):
    base = dict(
        ownership_label="secp-discover-abc123def456",
        organization_id=uuid.UUID(int=1),
        enrollment_id=uuid.UUID(int=2),
        worker_registration_id=uuid.UUID(int=3),
        resource_profile="small_lab",
        node="pve-a",
        storage="local-lvm",
        control_plane_vmid=9001,
        nested_target_vmid=9002,
        capacity_snapshot_hash="sha256:cc",
        evidence_hash="sha256:ee",
        worker_identity_version=4,
        artifact_manifest_id="secp-b4/artifact-catalog/v1/small_lab",
        enrollment_version=1,
        expires_at=datetime(2026, 7, 6, 12, tzinfo=UTC),
    )
    base.update(over)
    return discovery_candidate_plan_hash(build_candidate_plan_document(**base))


def test_plan_hash_binds_org_registration_enrollment():
    base = _plan()
    assert _plan(organization_id=uuid.UUID(int=99)) != base
    assert _plan(enrollment_id=uuid.UUID(int=99)) != base
    assert _plan(worker_registration_id=uuid.UUID(int=99)) != base
    # Still non-executable.
    doc = build_candidate_plan_document(
        ownership_label="secp-discover-abc123def456",
        organization_id=uuid.UUID(int=1),
        enrollment_id=uuid.UUID(int=2),
        worker_registration_id=None,
        resource_profile="small_lab",
        node="pve-a",
        storage="local-lvm",
        control_plane_vmid=9001,
        nested_target_vmid=9002,
        capacity_snapshot_hash="sha256:cc",
        evidence_hash="sha256:ee",
        worker_identity_version=0,
        artifact_manifest_id="m",
        enrollment_version=1,
        expires_at=datetime(2026, 7, 6, 12, tzinfo=UTC),
    )
    assert doc["executable"] is False


def test_new_modules_import_no_mutation_or_provider_code():
    root = Path(__file__).resolve().parents[3]
    files = [
        root / "apps/worker/secp_worker/mounted_bundle.py",
        root / "apps/worker/secp_worker/known_hosts.py",
        root / "apps/worker/secp_worker/target_discovery/composition.py",
    ]
    forbidden_roots = {"httpx", "requests", "proxmoxer", "paramiko"}
    forbidden_full = {
        "secp_worker.deployment.mutation_executor",
        "secp_worker.deployment.mutations",
        "secp_worker.deployment.engine",
        "secp_worker.deployment.seams",
        "secp_worker.deployment.artifacts",
        "secp_worker.deployment.ssh_bootstrap",
        "secp_worker.staging_live.bootstrap.host_operations",
        "secp_plugin_proxmox.mutation_transport",
    }
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        mods: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods.add(node.module)
        for m in mods:
            assert m.split(".")[0] not in forbidden_roots, f"{path.name} imports {m}"
            assert m not in forbidden_full, f"{path.name} imports mutation module {m}"
