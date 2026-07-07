"""SECP-B6 §1/§6 — real worker-local mounted bootstrap-bundle source (no host contact).

Proves: a valid mounted bundle yields a redacted, non-serializable SshBootstrapBundle; and a
missing,
malformed, oversized, wrong-shaped, symlinked, or (POSIX) mis-permissioned bundle refuses BEFORE any
use with a CLOSED reason code that never echoes a raw bundle value.
"""

from __future__ import annotations

import json
import os

import pytest
from secp_worker.mounted_bundle import MountedBundleRejected, MountedWorkerBootstrapBundleSource

_POSIX = os.name == "posix"
_VALID_MANIFEST = {
    "ssh_host": "pve-a.lab.internal",
    "ssh_port": 22,
    "account": "secp-discovery",
    "host_key_fingerprint": "SHA256:" + "A" * 43,
}


def _make_bundle(
    tmp_path,
    *,
    manifest=None,
    key=b"PRIVATE-KEY-BYTES",
    known_hosts=b"pve-a ssh-ed25519 AAAA\n",
):
    mount = tmp_path / "bundle"
    mount.mkdir()
    body = json.dumps(manifest if manifest is not None else _VALID_MANIFEST)
    (mount / "manifest.json").write_text(body)
    (mount / "id_key").write_bytes(key)
    (mount / "known_hosts").write_bytes(known_hosts)
    if _POSIX:
        os.chmod(mount, 0o700)
        os.chmod(mount / "manifest.json", 0o600)
        os.chmod(mount / "id_key", 0o600)
        os.chmod(mount / "known_hosts", 0o600)
    return str(mount)


def test_valid_bundle_acquires_redacted_nonserializable(tmp_path):
    src = MountedWorkerBootstrapBundleSource(_make_bundle(tmp_path))
    bundle = src.acquire()
    assert bundle.ssh_host == "pve-a.lab.internal" and bundle.ssh_port == 22
    assert bundle.account == "secp-discovery"
    assert bundle.private_key_path.endswith("id_key")
    assert bundle.known_hosts_path.endswith("known_hosts")
    # Redacted repr — never exposes host/account/paths/fingerprint.
    assert repr(bundle) == "SshBootstrapBundle(<redacted>)"
    for secret in ("pve-a", "secp-discovery", "id_key", "known_hosts", "SHA256"):
        assert secret not in repr(bundle)
    # Not serializable — the bundle must never leave the process.
    import pickle

    with pytest.raises(TypeError):
        pickle.dumps(bundle)
    src.dispose()  # no-op, callable on every path


def test_missing_mount_refuses(tmp_path):
    src = MountedWorkerBootstrapBundleSource(str(tmp_path / "nope"))
    with pytest.raises(MountedBundleRejected) as exc:
        src.acquire()
    assert exc.value.reason_code == "bundle_path_missing"


def test_unset_mount_refuses():
    with pytest.raises(MountedBundleRejected) as exc:
        MountedWorkerBootstrapBundleSource("").acquire()
    assert exc.value.reason_code == "mount_path_unset"


def test_mount_not_directory_refuses(tmp_path):
    f = tmp_path / "afile"
    f.write_text("x")
    with pytest.raises(MountedBundleRejected) as exc:
        MountedWorkerBootstrapBundleSource(str(f)).acquire()
    assert exc.value.reason_code == "mount_not_directory"


def test_missing_manifest_refuses(tmp_path):
    mount = _make_bundle(tmp_path)
    os.remove(os.path.join(mount, "manifest.json"))
    with pytest.raises(MountedBundleRejected) as exc:
        MountedWorkerBootstrapBundleSource(mount).acquire()
    assert exc.value.reason_code == "bundle_path_missing"


@pytest.mark.parametrize(
    "manifest,reason",
    [
        ({**_VALID_MANIFEST, "ssh_host": "bad host!"}, "manifest_host_invalid"),
        ({**_VALID_MANIFEST, "ssh_port": 0}, "manifest_port_invalid"),
        ({**_VALID_MANIFEST, "ssh_port": 70000}, "manifest_port_invalid"),
        ({**_VALID_MANIFEST, "ssh_port": True}, "manifest_port_invalid"),
        ({**_VALID_MANIFEST, "account": "a/b"}, "manifest_account_invalid"),
        ({**_VALID_MANIFEST, "host_key_fingerprint": "MD5:xx"}, "manifest_fingerprint_invalid"),
        ({"ssh_host": "h", "ssh_port": 22}, "manifest_shape_invalid"),
        ({**_VALID_MANIFEST, "extra": 1}, "manifest_shape_invalid"),
    ],
)
def test_malformed_manifest_values_refuse(tmp_path, manifest, reason):
    src = MountedWorkerBootstrapBundleSource(_make_bundle(tmp_path, manifest=manifest))
    with pytest.raises(MountedBundleRejected) as exc:
        src.acquire()
    assert exc.value.reason_code == reason


def test_non_json_manifest_refuses(tmp_path):
    mount = _make_bundle(tmp_path)
    (tmp_path / "bundle" / "manifest.json").write_text("{not json")
    with pytest.raises(MountedBundleRejected) as exc:
        MountedWorkerBootstrapBundleSource(mount).acquire()
    assert exc.value.reason_code == "manifest_malformed"


def test_oversized_manifest_refuses(tmp_path):
    mount = _make_bundle(tmp_path)
    (tmp_path / "bundle" / "manifest.json").write_bytes(b"{" + b"x" * (64 * 1024 + 10))
    with pytest.raises(MountedBundleRejected) as exc:
        MountedWorkerBootstrapBundleSource(mount).acquire()
    assert exc.value.reason_code == "manifest_size_invalid"


def test_empty_key_refuses(tmp_path):
    src = MountedWorkerBootstrapBundleSource(_make_bundle(tmp_path, key=b""))
    with pytest.raises(MountedBundleRejected) as exc:
        src.acquire()
    assert exc.value.reason_code == "key_size_invalid"


@pytest.mark.skipif(not _POSIX, reason="POSIX symlink/permission semantics")
def test_symlinked_manifest_refuses(tmp_path):
    mount = _make_bundle(tmp_path)
    real = tmp_path / "elsewhere.json"
    real.write_text(json.dumps(_VALID_MANIFEST))
    os.remove(os.path.join(mount, "manifest.json"))
    os.symlink(str(real), os.path.join(mount, "manifest.json"))
    with pytest.raises(MountedBundleRejected) as exc:
        MountedWorkerBootstrapBundleSource(mount).acquire()
    assert exc.value.reason_code == "manifest_symlink"


@pytest.mark.skipif(not _POSIX, reason="POSIX symlink semantics")
def test_symlinked_mount_refuses(tmp_path):
    real = _make_bundle(tmp_path)
    link = tmp_path / "linkmount"
    os.symlink(real, str(link))
    with pytest.raises(MountedBundleRejected) as exc:
        MountedWorkerBootstrapBundleSource(str(link)).acquire()
    assert exc.value.reason_code == "mount_symlink"


@pytest.mark.skipif(not _POSIX, reason="POSIX permission semantics")
def test_group_writable_key_refuses(tmp_path):
    mount = _make_bundle(tmp_path)
    os.chmod(os.path.join(mount, "id_key"), 0o640)  # group-readable => not owner-only
    with pytest.raises(MountedBundleRejected) as exc:
        MountedWorkerBootstrapBundleSource(mount).acquire()
    assert exc.value.reason_code == "key_bad_permissions"


@pytest.mark.skipif(not _POSIX, reason="POSIX permission semantics")
def test_world_writable_mount_refuses(tmp_path):
    mount = _make_bundle(tmp_path)
    os.chmod(mount, 0o777)
    with pytest.raises(MountedBundleRejected) as exc:
        MountedWorkerBootstrapBundleSource(mount).acquire()
    assert exc.value.reason_code == "mount_bad_permissions"
