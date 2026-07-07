"""SECP-B6 item-4 — the worker reads the private SSH key material ONLY after admission.

The mounted bundle is split into two phases: :meth:`prepare_metadata` validates ONLY the non-secret
manifest + binding (enough to compute the endpoint-binding digest and cross admission), and
:meth:`finalize_key_material` reads/copies the private ``id_key`` + ``known_hosts`` — reached only
AFTER the control-plane admission succeeds. These unit tests prove prepare touches no key bytes and
finalize is the only place they are read, on both the POSIX strict descriptor path and the
path-based path.
"""

from __future__ import annotations

import json
import os
import uuid

import pytest
from secp_worker.mounted_bundle import (
    MountedBundleRejected,
    MountedWorkerBootstrapBundleSource,
)

_POSIX = os.name == "posix"
_FP = "SHA256:" + "A" * 43


def _anchor(tmp_path) -> dict:
    return {
        "organization_id": str(uuid.uuid4()),
        "execution_target_id": str(uuid.uuid4()),
        "onboarding_id": str(uuid.uuid4()),
        "enrollment_id": str(uuid.uuid4()),
        "authorization_id": str(uuid.uuid4()),
        "authorization_version": 1,
        "endpoint_binding_hash": "sha256:" + "ab" * 32,
    }


def _mount(tmp_path, *, with_key: bool = True) -> str:
    mount = tmp_path / "bundle"
    mount.mkdir()
    (mount / "manifest.json").write_text(
        json.dumps(
            {"ssh_host": "pve-a", "ssh_port": 22, "account": "secp", "host_key_fingerprint": _FP}
        )
    )
    (mount / "binding.json").write_text(json.dumps(_anchor(tmp_path)))
    (mount / "known_hosts").write_bytes(b"pve-a ssh-ed25519 AAAA\n")
    if with_key:
        (mount / "id_key").write_bytes(b"PRIVATE-KEY-BYTES")
    if _POSIX:
        os.chmod(mount, 0o700)
        for f in ("manifest.json", "binding.json", "known_hosts"):
            os.chmod(mount / f, 0o600)
        if with_key:
            os.chmod(mount / "id_key", 0o600)
    return str(mount)


def test_pathbased_prepare_reads_no_key_finalize_reads_it(tmp_path):
    src = MountedWorkerBootstrapBundleSource(_mount(tmp_path), strict=False)
    prepared = src.prepare_metadata()
    # Metadata phase: the non-secret anchor + endpoint are populated; NO private key bundle yet.
    assert prepared.anchor.endpoint_binding_hash == "sha256:" + "ab" * 32
    assert prepared.endpoint.ssh_host == "pve-a"
    assert prepared.ssh_bundle is None
    assert prepared.key_material_loaded is False
    assert src._private_dir is None
    # Key-material phase (post-admission): now the SSH bundle exists.
    src.finalize_key_material()
    assert prepared.ssh_bundle is not None
    assert prepared.key_material_loaded is True


def test_pathbased_prepare_succeeds_even_when_key_absent(tmp_path):
    # prepare_metadata must NOT depend on the private key: with id_key removed it still validates
    # the non-secret metadata; only finalize_key_material (post-admission) fails closed on the key.
    src = MountedWorkerBootstrapBundleSource(_mount(tmp_path, with_key=False), strict=False)
    prepared = src.prepare_metadata()  # no key read → succeeds
    assert prepared.key_material_loaded is False
    with pytest.raises(MountedBundleRejected) as exc:
        src.finalize_key_material()
    # A missing key file fails closed (a generic missing-path reason precedes the key checks).
    rc = exc.value.reason_code
    assert rc == "bundle_path_missing" or rc.startswith("key_")


def test_acquire_before_finalize_refuses(tmp_path):
    # The probe executor's acquire() must refuse if key material has not been finalized (i.e. the
    # engine tried to probe before admission completed) — fail closed, never an empty/None key path.
    src = MountedWorkerBootstrapBundleSource(_mount(tmp_path), strict=False)
    src.prepare_metadata()
    with pytest.raises(MountedBundleRejected) as exc:
        src.acquire()
    assert exc.value.reason_code == "bundle_key_material_not_loaded"


def test_dispose_after_prepare_only_is_clean(tmp_path):
    # Disposing after prepare_metadata (admission refused before finalize) must not raise and must
    # leave nothing behind — no private dir was ever created.
    src = MountedWorkerBootstrapBundleSource(_mount(tmp_path), strict=False)
    prepared = src.prepare_metadata()
    prepared.dispose()
    assert src._private_dir is None
    assert src._dir_fd is None


@pytest.mark.skipif(not _POSIX, reason="POSIX descriptor semantics")
def test_strict_prepare_reads_no_key_bytes_then_finalize_copies(tmp_path, monkeypatch):
    import secp_worker.mounted_bundle as mb

    monkeypatch.setattr(mb, "_statvfs", lambda _fd: type("V", (), {"f_flag": mb._ST_RDONLY})())
    src = MountedWorkerBootstrapBundleSource(_mount(tmp_path), strict=True)
    prepared = src.prepare_metadata()
    # The mount descriptor is pinned; NO worker-private copy of the key exists yet.
    assert prepared.ssh_bundle is None
    assert src._private_dir is None
    assert src._dir_fd is not None
    # No secp-b6 temp bundle dir has been created (the private key was never copied out).
    tmp_root = tmp_path
    assert not any(p.name.startswith("secp-b6-bundle-") for p in tmp_root.glob("secp-b6-bundle-*"))

    src.finalize_key_material()
    assert prepared.ssh_bundle is not None
    # The private copy now exists OUTSIDE the mount and holds the validated key bytes.
    assert not prepared.ssh_bundle.private_key_path.startswith(str(tmp_path / "bundle"))
    with open(prepared.ssh_bundle.private_key_path, "rb") as fh:
        assert fh.read() == b"PRIVATE-KEY-BYTES"
    # The pinned descriptor is closed once the key material is read.
    assert src._dir_fd is None

    # The engine owns the prepared snapshot's lifecycle, so the source-level dispose() is a no-op
    # while a snapshot is prepared; the private copy is removed via the prepared bundle's dispose().
    prepared.dispose()
    assert not os.path.exists(prepared.ssh_bundle.private_key_path)


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
