"""SECP-B8 — worker-managed mounted-bundle mode (POSIX-gated).

The worker OWNS + writes its bundle into a worker-private WRITABLE directory, so the strict
mounted-bundle source must accept it with ``require_read_only_mount=False`` while retaining EVERY
other strict protection (descriptor pinning, owner==uid, no group/other perms, single hardlink,
same-device, bounded size, worker-private validated copy for ssh). With the default
``require_read_only_mount=True`` the same writable-fs bundle is refused (``mount_not_read_only``) —
proving the RO relaxation is the ONLY thing that changed.

POSIX-gated: the strict descriptor path uses ``openat``/``fstat``/``O_NOFOLLOW`` + owner/permission
semantics not present on non-POSIX hosts (where the strict path fails closed by design).
"""

from __future__ import annotations

import base64
import hashlib
import os

import pytest
from secp_worker import bundle_manager as bm
from secp_worker.mounted_bundle import MountedBundleRejected, MountedWorkerBootstrapBundleSource

_POSIX = os.name == "posix"

pytestmark = pytest.mark.skipif(
    not _POSIX, reason="strict descriptor/owner/permission semantics are POSIX-only"
)


def _host_public_key_and_fp() -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    line = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    blob = line.split()[1]
    fp = "SHA256:" + base64.b64encode(
        hashlib.sha256(base64.b64decode(blob)).digest()
    ).decode().rstrip("=")
    return line, fp


def _write_worker_bundle(tmp_path) -> str:
    kd = str(tmp_path / "keys")
    bm.ensure_worker_keys(kd)
    host_line, fp = _host_public_key_and_fp()
    bundle_dir = str(tmp_path / "state" / "discovery-bundle")
    os.makedirs(os.path.dirname(bundle_dir), exist_ok=True)
    descriptor = {
        "organization_id": "11111111-1111-1111-1111-111111111111",
        "execution_target_id": "22222222-2222-2222-2222-222222222222",
        "onboarding_id": "33333333-3333-3333-3333-333333333333",
        "enrollment_id": "44444444-4444-4444-4444-444444444444",
        "authorization_id": "55555555-5555-5555-5555-555555555555",
        "authorization_version": 2,
        "endpoint_binding_hash": "sha256:" + "a" * 64,
        "ssh_host": "pve.local",
        "ssh_port": 22,
        "account": "secpdisc",
        "host_key_fingerprint": fp,
        "host_public_key": host_line,
    }
    bm.write_bundle(
        descriptor, bundle_dir=bundle_dir, ssh_private_key_path=bm.worker_ssh_private_key_path(kd)
    )
    return bundle_dir


def test_worker_managed_bundle_validates_on_writable_fs(tmp_path):
    bundle_dir = _write_worker_bundle(tmp_path)
    src = MountedWorkerBootstrapBundleSource(bundle_dir, strict=True, require_read_only_mount=False)
    prepared = src.prepare_metadata()
    # Non-secret metadata + anchor validate.
    assert prepared.endpoint.ssh_host == "pve.local"
    assert prepared.endpoint.account == "secpdisc"
    assert str(prepared.anchor.enrollment_id) == "44444444-4444-4444-4444-444444444444"
    assert prepared.anchor.authorization_version == 2
    # Post-admission key material load succeeds and hands ssh a worker-private copy.
    src.finalize_key_material()
    bundle = src.acquire()
    assert bundle.ssh_host == "pve.local"
    assert os.path.isfile(bundle.private_key_path)
    assert os.path.isfile(bundle.known_hosts_path)
    src.dispose()


def test_writable_fs_bundle_refused_when_read_only_required(tmp_path):
    """The SAME writable-fs bundle is refused by the default (RO-required) strict mode — the ONLY
    difference from the accepting case above is the RO relaxation."""
    bundle_dir = _write_worker_bundle(tmp_path)
    src = MountedWorkerBootstrapBundleSource(
        bundle_dir, strict=True
    )  # require_read_only_mount=True
    with pytest.raises(MountedBundleRejected) as exc:
        src.prepare_metadata()
    assert exc.value.reason_code == "mount_not_read_only"


def test_worker_managed_mode_still_enforces_owner_only_perms(tmp_path):
    """Relaxing RO does NOT relax the owner-only permission gate: a group/other-writable bundle dir
    still fails closed."""
    bundle_dir = _write_worker_bundle(tmp_path)
    os.chmod(bundle_dir, 0o777)  # group/other-writable
    src = MountedWorkerBootstrapBundleSource(bundle_dir, strict=True, require_read_only_mount=False)
    with pytest.raises(MountedBundleRejected) as exc:
        src.prepare_metadata()
    assert exc.value.reason_code == "mount_bad_permissions"
