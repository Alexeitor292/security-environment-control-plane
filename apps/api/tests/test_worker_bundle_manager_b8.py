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


def _private_dir(path):
    path.mkdir(mode=0o700)
    if os.name == "posix":
        os.chmod(path, 0o700)
    return path


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


def test_inspect_worker_keys_is_read_only_and_binds_both_persisted_pairs(tmp_path):
    key_dir = tmp_path / "keys"
    with pytest.raises(bm.BundleManagerError) as missing:
        bm.inspect_worker_keys(str(key_dir))
    assert missing.value.reason_code == "key_dir_missing"
    assert not key_dir.exists()

    generated = bm.ensure_worker_keys(str(key_dir))
    before = {path.name: path.read_bytes() for path in key_dir.iterdir()}
    inspected = bm.inspect_worker_keys(str(key_dir))
    after = {path.name: path.read_bytes() for path in key_dir.iterdir()}

    assert inspected == generated
    assert after == before
    assert not hasattr(inspected, "ssh_private_key")


def test_inspect_worker_keys_never_repairs_or_generates_an_incomplete_set(tmp_path):
    key_dir = tmp_path / "keys"
    bm.ensure_worker_keys(str(key_dir))
    (key_dir / "ssh_id_ed25519.pub").unlink()
    remaining = {path.name: path.read_bytes() for path in key_dir.iterdir()}

    with pytest.raises(bm.BundleManagerError) as incomplete:
        bm.inspect_worker_keys(str(key_dir))

    assert incomplete.value.reason_code == "worker_key_set_incomplete"
    assert {path.name: path.read_bytes() for path in key_dir.iterdir()} == remaining


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
    key_dir = tmp_path / "keys"
    key_dir.mkdir(mode=0o700)
    if os.name == "posix":
        os.chmod(key_dir, 0o700)
    with pytest.raises(bm.BundleManagerError) as exc:
        bm.write_bundle(
            _descriptor(host_line, fp),
            bundle_dir=str(tmp_path / "b"),
            ssh_private_key_path=str(key_dir / "ssh_id_ed25519"),
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


def test_bundle_destination_appearance_race_never_overwrites_foreign_directory(
    tmp_path, monkeypatch
):
    key_dir = str(tmp_path / "keys")
    bm.ensure_worker_keys(key_dir)
    host_line, fingerprint = _host_public_key_and_fp()
    bundle_dir = tmp_path / "bundle"
    original = bm._replace_path
    injected = False

    def inject_destination(src, dst):
        nonlocal injected
        if (
            not injected
            and os.path.basename(src).startswith(".secp-bundle-")
            and os.path.abspath(dst) == os.path.abspath(bundle_dir)
        ):
            injected = True
            bundle_dir.mkdir()
            (bundle_dir / "foreign-marker").write_text("do-not-touch", encoding="utf-8")
        return original(src, dst)

    monkeypatch.setattr(bm, "_replace_path", inject_destination)
    with pytest.raises(bm.BundleManagerError) as exc:
        bm.write_bundle(
            _descriptor(host_line, fingerprint),
            bundle_dir=str(bundle_dir),
            ssh_private_key_path=bm.worker_ssh_private_key_path(key_dir),
        )

    assert exc.value.reason_code == "bundle_swap_failed"
    assert (bundle_dir / "foreign-marker").read_text(encoding="utf-8") == "do-not-touch"
    assert not any(path.name.startswith(".secp-bundle-") for path in tmp_path.iterdir())


def test_partial_admission_pair_is_refused_without_repair(tmp_path):
    key_dir = _private_dir(tmp_path / "keys")
    private = key_dir / "admission_key"
    private.write_text("f" * 64)
    if os.name == "posix":
        os.chmod(private, 0o600)

    with pytest.raises(bm.BundleManagerError) as exc:
        bm.ensure_worker_keys(str(key_dir))

    assert exc.value.reason_code == "admission_key_pair_incomplete"
    assert private.read_text() == "f" * 64
    assert not (key_dir / "admission_anchor").exists()
    assert not (key_dir / "ssh_id_ed25519").exists()


def test_foreign_key_directory_entry_is_refused_without_deletion(tmp_path):
    key_dir = _private_dir(tmp_path / "keys")
    foreign = key_dir / "foreign-material"
    foreign.write_text("do-not-touch")
    if os.name == "posix":
        os.chmod(foreign, 0o600)

    with pytest.raises(bm.BundleManagerError) as exc:
        bm.ensure_worker_keys(str(key_dir))

    assert exc.value.reason_code == "key_dir_foreign_entry"
    assert foreign.read_text() == "do-not-touch"
    assert set(os.listdir(key_dir)) == {"foreign-material"}


def test_partial_pair_install_compensates_created_file(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    original = bm._replace_path

    def fail_second(src, dst):
        if os.path.basename(dst) == "admission_anchor":
            raise OSError("synthetic replace failure")
        return original(src, dst)

    monkeypatch.setattr(bm, "_replace_path", fail_second)
    with pytest.raises(bm.BundleManagerError) as exc:
        bm.ensure_worker_keys(str(key_dir))

    assert exc.value.reason_code == "worker_key_set_write_failed"
    assert not (key_dir / "admission_key").exists()
    assert not (key_dir / "admission_anchor").exists()
    assert not any(p.name.startswith(".secp-key-") for p in key_dir.iterdir())


def test_second_pair_failure_compensates_the_entire_four_file_keyset(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    original = bm._replace_path

    def fail_ssh_pair(src, dst):
        if os.path.basename(dst) == "ssh_id_ed25519":
            raise OSError("synthetic second-pair failure")
        return original(src, dst)

    monkeypatch.setattr(bm, "_replace_path", fail_ssh_pair)
    with pytest.raises(bm.BundleManagerError) as exc:
        bm.ensure_worker_keys(str(key_dir))

    assert exc.value.reason_code == "worker_key_set_write_failed"
    assert list(key_dir.iterdir()) == []


def test_key_destination_appearance_race_never_overwrites_foreign_entry(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    original = bm._replace_path
    foreign = b"foreign-do-not-overwrite"
    injected = False

    def inject_destination(src, dst):
        nonlocal injected
        if not injected and os.path.basename(dst) == "admission_key":
            injected = True
            with open(dst, "wb") as handle:
                handle.write(foreign)
            if os.name == "posix":
                os.chmod(dst, 0o600)
        return original(src, dst)

    monkeypatch.setattr(bm, "_replace_path", inject_destination)
    with pytest.raises(bm.BundleManagerError) as exc:
        bm.ensure_worker_keys(str(key_dir))

    assert exc.value.reason_code == "worker_key_set_write_failed"
    assert (key_dir / "admission_key").read_bytes() == foreign
    assert set(path.name for path in key_dir.iterdir()) == {"admission_key"}


def test_inode_cleanup_quarantines_and_restores_a_swapped_foreign_file(tmp_path, monkeypatch):
    directory = _private_dir(tmp_path / "private")
    victim = directory / "victim"
    retained = directory / "owned-retained"
    victim.write_bytes(b"owned")
    if os.name == "posix":
        os.chmod(victim, 0o600)
    expected = os.lstat(victim)
    original = bm._rename_noreplace
    swapped = False

    def swap_before_quarantine(src, dst):
        nonlocal swapped
        if not swapped and os.path.abspath(src) == os.path.abspath(victim):
            swapped = True
            os.rename(victim, retained)
            victim.write_bytes(b"foreign")
            if os.name == "posix":
                os.chmod(victim, 0o600)
        return original(src, dst)

    monkeypatch.setattr(bm, "_rename_noreplace", swap_before_quarantine)

    assert bm._unlink_if_inode(str(victim), expected) is False
    assert victim.read_bytes() == b"foreign"
    assert retained.read_bytes() == b"owned"
    assert not any(path.name.startswith(".secp-quarantine-") for path in directory.iterdir())


def test_mismatched_admission_pair_is_refused(tmp_path):
    from secp_api.worker_admission_contract import generate_ed25519_keypair

    key_dir = tmp_path / "keys"
    bm.ensure_worker_keys(str(key_dir))
    _other_private, other_anchor = generate_ed25519_keypair()
    (key_dir / "admission_anchor").write_text(other_anchor)
    if os.name == "posix":
        os.chmod(key_dir / "admission_anchor", 0o600)

    with pytest.raises(bm.BundleManagerError) as exc:
        bm.ensure_worker_keys(str(key_dir))
    assert exc.value.reason_code == "admission_key_pair_mismatch"


def test_special_file_in_key_pair_is_refused_without_overwrite(tmp_path):
    key_dir = _private_dir(tmp_path / "keys")
    (key_dir / "admission_key").mkdir()
    anchor = key_dir / "admission_anchor"
    anchor.write_text("a" * 64)
    if os.name == "posix":
        os.chmod(anchor, 0o600)

    with pytest.raises(bm.BundleManagerError) as exc:
        bm.ensure_worker_keys(str(key_dir))
    assert exc.value.reason_code == "admission_private_key_not_regular"
    assert (key_dir / "admission_key").is_dir()


def test_hardlinked_key_is_refused(tmp_path):
    key_dir = tmp_path / "keys"
    bm.ensure_worker_keys(str(key_dir))
    try:
        os.link(key_dir / "admission_key", tmp_path / "admission-key-alias")
    except OSError:
        pytest.skip("hardlinks unavailable on this filesystem")

    with pytest.raises(bm.BundleManagerError) as exc:
        bm.ensure_worker_keys(str(key_dir))
    assert exc.value.reason_code == "admission_private_key_hardlinked"


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode semantics")
def test_wrong_owner_and_unsafe_mode_are_refused_not_repaired(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    bm.ensure_worker_keys(str(key_dir))
    os.chmod(key_dir / "admission_key", 0o640)

    with pytest.raises(bm.BundleManagerError) as mode_exc:
        bm.ensure_worker_keys(str(key_dir))
    assert mode_exc.value.reason_code == "admission_private_key_bad_permissions"
    assert (os.stat(key_dir / "admission_key").st_mode & 0o777) == 0o640

    os.chmod(key_dir / "admission_key", 0o600)
    monkeypatch.setattr(bm, "_GETUID", lambda: os.getuid() + 1)
    with pytest.raises(bm.BundleManagerError) as owner_exc:
        bm.ensure_worker_keys(str(key_dir))
    assert owner_exc.value.reason_code == "key_dir_not_owned"


@pytest.mark.skipif(os.name != "posix", reason="reliable symlink semantics are POSIX-only")
def test_symlinked_key_is_refused_without_following(tmp_path):
    key_dir = tmp_path / "keys"
    bm.ensure_worker_keys(str(key_dir))
    private = key_dir / "admission_key"
    outside = tmp_path / "outside-private"
    private.replace(outside)
    private.symlink_to(outside)

    with pytest.raises(bm.BundleManagerError) as exc:
        bm.ensure_worker_keys(str(key_dir))
    assert exc.value.reason_code == "admission_private_key_symlink"
    assert outside.exists()


def test_foreign_existing_bundle_is_never_overwritten_or_deleted(tmp_path):
    key_dir = tmp_path / "keys"
    bm.ensure_worker_keys(str(key_dir))
    bundle_dir = _private_dir(tmp_path / "bundle")
    marker = bundle_dir / "foreign-marker"
    marker.write_text("belongs-to-someone-else")
    if os.name == "posix":
        os.chmod(marker, 0o600)
    host_line, fp = _host_public_key_and_fp()

    with pytest.raises(bm.BundleManagerError) as exc:
        bm.write_bundle(
            _descriptor(host_line, fp),
            bundle_dir=str(bundle_dir),
            ssh_private_key_path=bm.worker_ssh_private_key_path(str(key_dir)),
        )

    assert exc.value.reason_code == "bundle_existing_foreign"
    assert marker.read_text() == "belongs-to-someone-else"
    assert not (tmp_path / "bundle.old").exists()


def test_bundle_from_a_different_worker_key_is_foreign(tmp_path):
    key_a = tmp_path / "keys-a"
    key_b = tmp_path / "keys-b"
    bm.ensure_worker_keys(str(key_a))
    bm.ensure_worker_keys(str(key_b))
    host_line, fp = _host_public_key_and_fp()
    bundle_dir = tmp_path / "bundle"
    bm.write_bundle(
        _descriptor(host_line, fp),
        bundle_dir=str(bundle_dir),
        ssh_private_key_path=bm.worker_ssh_private_key_path(str(key_a)),
    )
    original_key = (bundle_dir / "id_key").read_bytes()

    with pytest.raises(bm.BundleManagerError) as exc:
        bm.write_bundle(
            _descriptor(host_line, fp, ssh_host="replacement.invalid"),
            bundle_dir=str(bundle_dir),
            ssh_private_key_path=bm.worker_ssh_private_key_path(str(key_b)),
        )

    assert exc.value.reason_code == "bundle_existing_foreign"
    assert (bundle_dir / "id_key").read_bytes() == original_key
    assert json.loads((bundle_dir / "manifest.json").read_text())["ssh_host"] == "pve.local"


def test_hardlinked_existing_bundle_file_is_refused(tmp_path):
    key_dir = tmp_path / "keys"
    bm.ensure_worker_keys(str(key_dir))
    host_line, fp = _host_public_key_and_fp()
    bundle_dir = tmp_path / "bundle"
    key_path = bm.worker_ssh_private_key_path(str(key_dir))
    bm.write_bundle(
        _descriptor(host_line, fp), bundle_dir=str(bundle_dir), ssh_private_key_path=key_path
    )
    try:
        os.link(bundle_dir / "manifest.json", tmp_path / "manifest-alias")
    except OSError:
        pytest.skip("hardlinks unavailable on this filesystem")

    with pytest.raises(bm.BundleManagerError) as exc:
        bm.write_bundle(
            _descriptor(host_line, fp, ssh_host="pve2.local"),
            bundle_dir=str(bundle_dir),
            ssh_private_key_path=key_path,
        )
    assert exc.value.reason_code == "bundle_manifest_hardlinked"
    assert (bundle_dir / "manifest.json").exists()


def test_special_file_in_existing_bundle_is_refused_without_repair(tmp_path):
    key_dir = tmp_path / "keys"
    bm.ensure_worker_keys(str(key_dir))
    host_line, fp = _host_public_key_and_fp()
    bundle_dir = tmp_path / "bundle"
    key_path = bm.worker_ssh_private_key_path(str(key_dir))
    bm.write_bundle(
        _descriptor(host_line, fp), bundle_dir=str(bundle_dir), ssh_private_key_path=key_path
    )
    (bundle_dir / "known_hosts").unlink()
    (bundle_dir / "known_hosts").mkdir()

    with pytest.raises(bm.BundleManagerError) as exc:
        bm.write_bundle(
            _descriptor(host_line, fp, ssh_host="pve2.local"),
            bundle_dir=str(bundle_dir),
            ssh_private_key_path=key_path,
        )
    assert exc.value.reason_code == "bundle_known_hosts_not_regular"
    assert (bundle_dir / "known_hosts").is_dir()


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink/mode semantics")
def test_symlink_and_unsafe_mode_in_existing_bundle_are_refused(tmp_path):
    key_dir = tmp_path / "keys"
    bm.ensure_worker_keys(str(key_dir))
    host_line, fp = _host_public_key_and_fp()
    bundle_dir = tmp_path / "bundle"
    key_path = bm.worker_ssh_private_key_path(str(key_dir))
    bm.write_bundle(
        _descriptor(host_line, fp), bundle_dir=str(bundle_dir), ssh_private_key_path=key_path
    )
    manifest = bundle_dir / "manifest.json"
    os.chmod(manifest, 0o640)
    with pytest.raises(bm.BundleManagerError) as mode_exc:
        bm.write_bundle(
            _descriptor(host_line, fp, ssh_host="pve2.local"),
            bundle_dir=str(bundle_dir),
            ssh_private_key_path=key_path,
        )
    assert mode_exc.value.reason_code == "bundle_manifest_bad_permissions"
    assert (os.stat(manifest).st_mode & 0o777) == 0o640

    os.chmod(manifest, 0o600)
    outside = tmp_path / "outside-manifest"
    manifest.replace(outside)
    manifest.symlink_to(outside)
    with pytest.raises(bm.BundleManagerError) as link_exc:
        bm.write_bundle(
            _descriptor(host_line, fp, ssh_host="pve2.local"),
            bundle_dir=str(bundle_dir),
            ssh_private_key_path=key_path,
        )
    assert link_exc.value.reason_code == "bundle_manifest_symlink"
    assert outside.exists()


def test_failed_bundle_swap_restores_prior_bundle(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    bm.ensure_worker_keys(str(key_dir))
    host_line, fp = _host_public_key_and_fp()
    bundle_dir = tmp_path / "bundle"
    key_path = bm.worker_ssh_private_key_path(str(key_dir))
    bm.write_bundle(
        _descriptor(host_line, fp), bundle_dir=str(bundle_dir), ssh_private_key_path=key_path
    )
    original = bm._replace_path

    def fail_new_bundle(src, dst):
        if os.path.basename(src).startswith(".secp-bundle-") and dst == str(bundle_dir):
            raise OSError("synthetic swap failure")
        return original(src, dst)

    monkeypatch.setattr(bm, "_replace_path", fail_new_bundle)
    with pytest.raises(bm.BundleManagerError) as exc:
        bm.write_bundle(
            _descriptor(host_line, fp, ssh_host="pve2.local"),
            bundle_dir=str(bundle_dir),
            ssh_private_key_path=key_path,
        )

    assert exc.value.reason_code == "bundle_swap_failed"
    assert json.loads((bundle_dir / "manifest.json").read_text())["ssh_host"] == "pve.local"
    assert bm.bundle_is_present(str(bundle_dir))
    assert not (tmp_path / "bundle.old").exists()


def test_failed_backup_fsync_restores_prior_bundle(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    bm.ensure_worker_keys(str(key_dir))
    host_line, fp = _host_public_key_and_fp()
    bundle_dir = tmp_path / "bundle"
    key_path = bm.worker_ssh_private_key_path(str(key_dir))
    bm.write_bundle(
        _descriptor(host_line, fp), bundle_dir=str(bundle_dir), ssh_private_key_path=key_path
    )
    original = bm._fsync_directory
    failed = False

    def fail_first_parent_fsync(path, reason):
        nonlocal failed
        if reason == "bundle_parent" and not failed:
            failed = True
            raise bm.BundleManagerError("synthetic_fsync_failure")
        return original(path, reason)

    monkeypatch.setattr(bm, "_fsync_directory", fail_first_parent_fsync)
    with pytest.raises(bm.BundleManagerError) as exc:
        bm.write_bundle(
            _descriptor(host_line, fp, ssh_host="pve2.local"),
            bundle_dir=str(bundle_dir),
            ssh_private_key_path=key_path,
        )

    assert exc.value.reason_code == "bundle_backup_failed"
    assert json.loads((bundle_dir / "manifest.json").read_text())["ssh_host"] == "pve.local"
    assert bm.bundle_is_present(str(bundle_dir))
    assert not (tmp_path / "bundle.old").exists()


def test_identical_bundle_write_does_not_swap(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    bm.ensure_worker_keys(str(key_dir))
    host_line, fp = _host_public_key_and_fp()
    bundle_dir = tmp_path / "bundle"
    key_path = bm.worker_ssh_private_key_path(str(key_dir))
    descriptor = _descriptor(host_line, fp)
    bm.write_bundle(descriptor, bundle_dir=str(bundle_dir), ssh_private_key_path=key_path)
    before = os.stat(bundle_dir)

    def unexpected_swap(_src, _dst):
        raise AssertionError("identical bundle must not be replaced")

    monkeypatch.setattr(bm, "_replace_path", unexpected_swap)
    bm.write_bundle(descriptor, bundle_dir=str(bundle_dir), ssh_private_key_path=key_path)
    after = os.stat(bundle_dir)
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)


def test_bundle_manager_error_does_not_echo_private_content(tmp_path):
    key_dir = _private_dir(tmp_path / "keys")
    secret = "THIS-MUST-NOT-LEAK" * 4
    private = key_dir / "admission_key"
    anchor = key_dir / "admission_anchor"
    private.write_text(secret)
    anchor.write_text("a" * 64)
    if os.name == "posix":
        os.chmod(private, 0o600)
        os.chmod(anchor, 0o600)

    with pytest.raises(bm.BundleManagerError) as exc:
        bm.ensure_worker_keys(str(key_dir))
    assert secret not in str(exc.value)
    assert secret not in repr(exc.value)
