"""SECP-B8 — worker-owned bundle manager unit tests.

The worker generates + OWNS its SSH + Ed25519 admission keypairs and assembles the mounted bundle
from a SECRET-FREE descriptor. These tests prove the security invariants of that worker-side code:
  * key generation returns only PUBLIC material (no private key on the returned object) and is
    idempotent (a restart never rotates the identity / authorized key);
  * ``write_bundle`` assembles a valid four-file bundle from a valid descriptor;
  * it fails closed on a reserved/root account, a host-key-fingerprint / host-public-key mismatch, a
    malformed host public key, a bad endpoint digest, and a missing binding field;
  * a private key is never transmitted (the only key that leaves is the OpenSSH PUBLIC line).

The strict mounted-bundle round-trip (worker-managed mode) is POSIX-gated (owner/perm/descriptor
semantics) and lives in ``test_worker_managed_mount_b8.py``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest
from secp_worker import bundle_manager as bm


def _host_public_key_and_fp() -> tuple[str, str]:
    """A synthetic Proxmox host ed25519 PUBLIC key line + its SHA256 fingerprint (non-secret)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    line = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    blob = line.split()[1]
    raw = base64.b64decode(blob)
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    return line, fp


def _descriptor(host_line: str, fp: str, **overrides) -> dict:
    d = {
        "organization_id": "11111111-1111-1111-1111-111111111111",
        "execution_target_id": "22222222-2222-2222-2222-222222222222",
        "onboarding_id": "33333333-3333-3333-3333-333333333333",
        "enrollment_id": "44444444-4444-4444-4444-444444444444",
        "authorization_id": "55555555-5555-5555-5555-555555555555",
        "authorization_version": 3,
        "endpoint_binding_hash": "sha256:" + "a" * 64,
        "ssh_host": "pve.local",
        "ssh_port": 22,
        "account": "secpdisc",
        "host_key_fingerprint": fp,
        "host_public_key": host_line,
    }
    d.update(overrides)
    return d


def test_ensure_worker_keys_returns_public_only_and_is_idempotent(tmp_path):
    kd = str(tmp_path / "keys")
    mat = bm.ensure_worker_keys(kd)
    assert mat.ssh_public_key.startswith("ssh-ed25519 ")
    assert len(mat.admission_anchor_hex) == 64 and all(
        c in "0123456789abcdef" for c in mat.admission_anchor_hex
    )
    assert mat.admission_anchor_fingerprint.startswith("sha256:")
    # No private material is present anywhere on the returned object.
    assert "PRIVATE" not in repr(mat)
    assert not hasattr(mat, "ssh_private_key") and not hasattr(mat, "admission_private")
    # Idempotent: a second call returns the SAME public key + anchor (identity is stable).
    mat2 = bm.ensure_worker_keys(kd)
    assert mat2.ssh_public_key == mat.ssh_public_key
    assert mat2.admission_anchor_hex == mat.admission_anchor_hex


def test_write_bundle_assembles_valid_four_file_bundle(tmp_path):
    kd = str(tmp_path / "keys")
    bm.ensure_worker_keys(kd)
    host_line, fp = _host_public_key_and_fp()
    bundle_dir = str(tmp_path / "bundle")
    bm.write_bundle(
        _descriptor(host_line, fp),
        bundle_dir=bundle_dir,
        ssh_private_key_path=bm.worker_ssh_private_key_path(kd),
    )
    assert bm.bundle_is_present(bundle_dir)
    manifest = json.loads((tmp_path / "bundle" / "manifest.json").read_text())
    assert manifest == {
        "ssh_host": "pve.local",
        "ssh_port": 22,
        "account": "secpdisc",
        "host_key_fingerprint": fp,
    }
    binding = json.loads((tmp_path / "bundle" / "binding.json").read_text())
    assert set(binding) == {
        "organization_id",
        "execution_target_id",
        "onboarding_id",
        "enrollment_id",
        "authorization_id",
        "authorization_version",
        "endpoint_binding_hash",
    }
    assert binding["authorization_version"] == 3 and isinstance(
        binding["authorization_version"], int
    )
    kh = (tmp_path / "bundle" / "known_hosts").read_text()
    assert kh.startswith("pve.local ssh-ed25519 ")
    # id_key is the worker's OWN private key on the worker fs — never uploaded/returned by the app.
    assert "PRIVATE KEY" in (tmp_path / "bundle" / "id_key").read_text()


def test_write_bundle_rejects_root_and_reserved_accounts(tmp_path):
    kd = str(tmp_path / "keys")
    bm.ensure_worker_keys(kd)
    host_line, fp = _host_public_key_and_fp()
    key_path = bm.worker_ssh_private_key_path(kd)
    for i, account in enumerate(("root", "admin", "administrator", "toor", "sysadmin")):
        with pytest.raises(bm.BundleManagerError) as exc:
            bm.write_bundle(
                _descriptor(host_line, fp, account=account),
                bundle_dir=str(tmp_path / f"b{i}"),
                ssh_private_key_path=key_path,
            )
        assert exc.value.reason_code == "account_privileged"


def test_write_bundle_rejects_fingerprint_host_key_mismatch(tmp_path):
    kd = str(tmp_path / "keys")
    bm.ensure_worker_keys(kd)
    host_line, _fp = _host_public_key_and_fp()
    # A fingerprint that does not match the host public key must fail closed.
    with pytest.raises(bm.BundleManagerError) as exc:
        bm.write_bundle(
            _descriptor(host_line, "SHA256:" + "B" * 43),
            bundle_dir=str(tmp_path / "b"),
            ssh_private_key_path=bm.worker_ssh_private_key_path(kd),
        )
    assert exc.value.reason_code == "host_key_fingerprint_mismatch"


def test_write_bundle_rejects_malformed_host_public_key(tmp_path):
    kd = str(tmp_path / "keys")
    bm.ensure_worker_keys(kd)
    _line, fp = _host_public_key_and_fp()
    with pytest.raises(bm.BundleManagerError):
        bm.write_bundle(
            _descriptor("not-a-key", fp),
            bundle_dir=str(tmp_path / "b"),
            ssh_private_key_path=bm.worker_ssh_private_key_path(kd),
        )


def test_write_bundle_rejects_bad_endpoint_binding_hash(tmp_path):
    kd = str(tmp_path / "keys")
    bm.ensure_worker_keys(kd)
    host_line, fp = _host_public_key_and_fp()
    with pytest.raises(bm.BundleManagerError) as exc:
        bm.write_bundle(
            _descriptor(host_line, fp, endpoint_binding_hash="nope"),
            bundle_dir=str(tmp_path / "b"),
            ssh_private_key_path=bm.worker_ssh_private_key_path(kd),
        )
    assert exc.value.reason_code == "endpoint_binding_hash_invalid"


def test_write_bundle_rejects_missing_binding_field(tmp_path):
    kd = str(tmp_path / "keys")
    bm.ensure_worker_keys(kd)
    host_line, fp = _host_public_key_and_fp()
    d = _descriptor(host_line, fp)
    del d["authorization_id"]
    with pytest.raises(bm.BundleManagerError) as exc:
        bm.write_bundle(
            d,
            bundle_dir=str(tmp_path / "b"),
            ssh_private_key_path=bm.worker_ssh_private_key_path(kd),
        )
    assert "authorization_id" in exc.value.reason_code


def test_write_bundle_rejects_missing_ssh_private_key(tmp_path):
    host_line, fp = _host_public_key_and_fp()
    with pytest.raises(bm.BundleManagerError) as exc:
        bm.write_bundle(
            _descriptor(host_line, fp),
            bundle_dir=str(tmp_path / "b"),
            ssh_private_key_path=str(tmp_path / "does-not-exist"),
        )
    assert exc.value.reason_code == "ssh_private_key_missing"


def test_write_bundle_is_atomic_replace(tmp_path):
    """A second write replaces the bundle cleanly (no leftover staging dirs in the parent)."""
    kd = str(tmp_path / "keys")
    bm.ensure_worker_keys(kd)
    host_line, fp = _host_public_key_and_fp()
    bundle_dir = str(tmp_path / "bundle")
    key_path = bm.worker_ssh_private_key_path(kd)
    bm.write_bundle(
        _descriptor(host_line, fp), bundle_dir=bundle_dir, ssh_private_key_path=key_path
    )
    bm.write_bundle(
        _descriptor(host_line, fp, ssh_host="pve2.local"),
        bundle_dir=bundle_dir,
        ssh_private_key_path=key_path,
    )
    manifest = json.loads((tmp_path / "bundle" / "manifest.json").read_text())
    assert manifest["ssh_host"] == "pve2.local"
    leftovers = [n for n in os.listdir(tmp_path) if n.startswith(".secp-")]
    assert leftovers == [], f"leftover staging dirs: {leftovers}"
