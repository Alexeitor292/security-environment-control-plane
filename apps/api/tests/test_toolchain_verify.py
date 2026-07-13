"""RealToolchainVerifier — worker-local, filesystem-only toolchain attestation (SECP-002B-1B PR2).

Every test uses a temporary fixture toolchain of INERT data built by the test suite. No installed
OpenTofu, PATH, real provider, real lockfile, network, Docker, Proxmox, or secret manager is
touched; the fake executable is never run. These prove one successful full attestation, an
independent refusal for every facet, the deterministic tree-hash contract, bounded reason output,
no path/content leakage, and that attestation performs no process/network/PATH/secret/DB/render/
activation work and leaves both B1-A subprocess seals ``True``.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess  # noqa: F401 — imported only to monkeypatch it and prove it is never called

import pytest
import secp_worker.provisioning.toolchain_verify as tv
from secp_worker.provisioning import (
    FakeToolchainVerifier,
    RealToolchainVerifier,
    ToolchainAttestationEvidence,
    ToolchainFilesystemLayout,
    ToolchainVerification,
    render_offline_cli_config,
)
from secp_worker.provisioning.toolchain_verify import (
    ATTESTATION_POLICY_VERSION,
    R_BINARY_DIGEST_MISMATCH,
    R_CLI_CONFIG_INVALID,
    R_EXECUTABLE_MISMATCH,
    R_LOCKFILE_MISMATCH,
    R_MANIFEST_INVALID,
    R_MIRROR_MISMATCH,
    R_MODULE_BUNDLE_MISMATCH,
    R_OBJECT_CHANGED,
    R_OBJECT_TYPE_INVALID,
    R_PATH_OUTSIDE_ROOT,
    R_PERMISSION_INVALID,
    R_PROFILE_INVALID,
    R_RENDERER_MISMATCH,
    R_RUNTIME_DOWNLOAD_NOT_DISABLED,
    R_SYMLINK_REFUSED,
    R_TREE_LIMIT_EXCEEDED,
    R_UNSUPPORTED_DIGEST,
    R_VERSION_MISMATCH,
    _hash_tree,
)

_ALL_REASONS = {
    tv.R_LAYOUT_INVALID,
    tv.R_PATH_OUTSIDE_ROOT,
    tv.R_SYMLINK_REFUSED,
    tv.R_OBJECT_TYPE_INVALID,
    tv.R_PERMISSION_INVALID,
    tv.R_SIZE_LIMIT_EXCEEDED,
    tv.R_TREE_LIMIT_EXCEEDED,
    tv.R_OBJECT_CHANGED,
    tv.R_PATH_COLLISION,
    tv.R_MANIFEST_INVALID,
    tv.R_PROFILE_INVALID,
    tv.R_EXECUTABLE_MISMATCH,
    tv.R_VERSION_MISMATCH,
    tv.R_BINARY_DIGEST_MISMATCH,
    tv.R_MODULE_BUNDLE_MISMATCH,
    tv.R_LOCKFILE_MISMATCH,
    tv.R_MIRROR_MISMATCH,
    tv.R_RENDERER_MISMATCH,
    tv.R_CLI_CONFIG_INVALID,
    tv.R_RUNTIME_DOWNLOAD_NOT_DISABLED,
    tv.R_STATE_BACKEND_CLASS_INVALID,
    tv.R_UNSUPPORTED_DIGEST,
}

_EXEC_BYTES = b"#!/bin/sh\necho TOOLCHAIN_SENTINEL_SHOULD_NEVER_RUN > sentinel.txt\n"
_RENDERER_VERSION = "secp-002b-1a/renderer/v1"


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write(path: str, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)


def _symlinks_supported(tmp: str) -> bool:
    probe = os.path.join(tmp, "__symlink_probe__")
    try:
        os.symlink(os.path.join(tmp, "nonexistent"), probe)
    except (OSError, NotImplementedError, AttributeError):
        return False
    os.remove(probe)
    return True


def build_fixture(root: str) -> tuple[ToolchainFilesystemLayout, dict]:
    """Build a complete, valid inert toolchain under ``root`` and a matching secret-free profile."""
    os.mkdir(os.path.join(root, "bin"))
    os.mkdir(os.path.join(root, "meta"))
    os.mkdir(os.path.join(root, "bundle"))
    os.mkdir(os.path.join(root, "bundle", "sub"))
    os.mkdir(os.path.join(root, "mirror"))
    os.mkdir(os.path.join(root, "mirror", "registry.fake"))

    exec_path = os.path.join(root, "bin", "tofu")
    _write(exec_path, _EXEC_BYTES)
    if os.name == "posix":
        os.chmod(exec_path, 0o755)

    _write(
        os.path.join(root, "meta", "version.json"),
        json.dumps({"opentofu_version": "9.9.9"}).encode(),
    )
    _write(os.path.join(root, "bundle", "main.tf"), b"module fake {}\n")
    _write(os.path.join(root, "bundle", "sub", "vars.tf"), b"variable fake {}\n")
    lock_bytes = b'provider "fake" {\n  version = "1.0.0"\n}\n'
    _write(os.path.join(root, "meta", "provider.lock"), lock_bytes)
    _write(
        os.path.join(root, "mirror", "registry.fake", "provider_plugin.bin"),
        b"inert fake provider plugin\n",
    )

    mirror_abs = os.path.join(root, "mirror")
    _write(os.path.join(root, "meta", "cli.tofurc"), render_offline_cli_config(mirror_abs))

    if os.name == "posix":
        # Deterministic non-group/world-writable perms so containment checks pass under any umask.
        for dirpath, dirnames, filenames in os.walk(root):
            for name in dirnames:
                os.chmod(os.path.join(dirpath, name), 0o755)
            for name in filenames:
                os.chmod(os.path.join(dirpath, name), 0o644)
        os.chmod(exec_path, 0o755)

    bundle_hash, _ = _hash_tree(os.path.join(root, "bundle"))
    mirror_hash, _ = _hash_tree(mirror_abs)

    layout = ToolchainFilesystemLayout(
        trusted_root=root,
        executable="bin/tofu",
        version_metadata="meta/version.json",
        module_bundle="bundle",
        provider_lockfile="meta/provider.lock",
        provider_mirror="mirror",
        cli_config="meta/cli.tofurc",
        manifest=None,
    )
    profile = {
        "runner_kind": "opentofu",
        "executable": "tofu",
        "opentofu_version": "9.9.9",
        "binary_integrity": _sha256(_EXEC_BYTES),
        "adapter_kind": "proxmox",
        "module_bundle_id": "secp-fake-lab-bundle",
        "module_bundle_hash": bundle_hash,
        "provider_lockfile_hash": _sha256(lock_bytes),
        "renderer_version": _RENDERER_VERSION,
        "state_backend": {"kind": "http", "reference": "secp-fake-remote-state/lab"},
        "provider_mirror": {
            "identity": mirror_hash,
            "network_access": "offline",
            "allow_runtime_download": False,
        },
        "activation_class": "isolated_lab",
    }
    return layout, profile


def _verify(root: str, layout: ToolchainFilesystemLayout, profile: dict) -> ToolchainVerification:
    return RealToolchainVerifier(layout).verify(profile)


# --- one successful full attestation ------------------------------------------------------------


def test_full_attestation_succeeds(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    result = _verify(str(tmp_path), layout, profile)
    assert result.ok, result.reasons
    assert result.missing() == []
    assert result.reasons == ()
    assert set(result.verified) == {
        "executable",
        "version",
        "binary_digest",
        "module_bundle",
        "lockfile",
        "mirror",
        "renderer",
        "cli_config",
        "remote_state_class",
        "runtime_download_disabled",
    }


def test_attestation_never_runs_the_executable(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    result = _verify(str(tmp_path), layout, profile)
    assert result.ok
    # The fake executable would create a sentinel file if run; it must be absent.
    assert not os.path.exists(os.path.join(str(tmp_path), "sentinel.txt"))
    assert not os.path.exists(os.path.join(os.getcwd(), "sentinel.txt"))


def test_safe_evidence_is_bounded_and_secret_free(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    ev = RealToolchainVerifier(layout).safe_evidence(profile)
    assert isinstance(ev, ToolchainAttestationEvidence)
    assert ev.ok is True
    assert ev.policy_version == ATTESTATION_POLICY_VERSION
    assert ev.profile_content_hash  # canonical, secret-free
    blob = json.dumps(
        {"verified": ev.verified, "reasons": ev.reasons, "hash": ev.profile_content_hash}
    )
    for leak in (
        str(tmp_path),
        "tofu",
        "sha256:" + hashlib.sha256(_EXEC_BYTES).hexdigest(),
        _RENDERER_VERSION,
    ):
        assert leak not in blob, f"evidence leaked {leak!r}"


# --- deterministic module-bundle tree-hash contract ---------------------------------------------


def test_tree_hash_identical_trees_hash_identically(tmp_path):
    a, b = str(tmp_path / "a"), str(tmp_path / "b")
    for d in (a, b):
        os.makedirs(os.path.join(d, "x"))
        _write(os.path.join(d, "x", "f1"), b"one")
        _write(os.path.join(d, "f2"), b"two")
    assert _hash_tree(a)[0] == _hash_tree(b)[0]


def test_tree_hash_changes_on_content_path_add_remove_but_not_order(tmp_path):
    base = str(tmp_path / "base")
    os.makedirs(base)
    _write(os.path.join(base, "a"), b"aaa")
    _write(os.path.join(base, "b"), b"bbb")
    h0 = _hash_tree(base)[0]
    # content change
    _write(os.path.join(base, "a"), b"AAA")
    assert _hash_tree(base)[0] != h0
    _write(os.path.join(base, "a"), b"aaa")
    assert _hash_tree(base)[0] == h0  # order/enumeration is deterministic → back to h0
    # path change
    os.rename(os.path.join(base, "b"), os.path.join(base, "c"))
    assert _hash_tree(base)[0] != h0
    # add / remove
    os.rename(os.path.join(base, "c"), os.path.join(base, "b"))
    assert _hash_tree(base)[0] == h0
    _write(os.path.join(base, "d"), b"ddd")
    assert _hash_tree(base)[0] != h0
    os.remove(os.path.join(base, "d"))
    assert _hash_tree(base)[0] == h0


def test_tree_hash_empty_tree_is_deterministic(tmp_path):
    e1, e2 = str(tmp_path / "e1"), str(tmp_path / "e2")
    os.makedirs(e1)
    os.makedirs(e2)
    assert _hash_tree(e1)[0] == _hash_tree(e2)[0]
    assert _hash_tree(e1)[1] == 0


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink semantics")
def test_tree_hash_refuses_symlink(tmp_path):
    if not _symlinks_supported(str(tmp_path)):
        pytest.skip("symlinks unavailable")
    d = str(tmp_path / "d")
    os.makedirs(d)
    _write(os.path.join(d, "real"), b"x")
    os.symlink(os.path.join(d, "real"), os.path.join(d, "link"))
    with pytest.raises(tv._AttestError) as exc:
        _hash_tree(d)
    assert exc.value.reason == R_SYMLINK_REFUSED


# --- per-facet refusals: executable + binary digest ---------------------------------------------


def test_executable_missing(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    os.remove(os.path.join(str(tmp_path), "bin", "tofu"))
    result = _verify(str(tmp_path), layout, profile)
    assert "executable" not in result.verified and "binary_digest" not in result.verified
    assert R_OBJECT_TYPE_INVALID in result.reasons


def test_executable_outside_root(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    bad = ToolchainFilesystemLayout(**{**layout.__dict__, "executable": "../evil"})
    result = _verify(str(tmp_path), bad, profile)
    assert "executable" not in result.verified
    assert R_PATH_OUTSIDE_ROOT in result.reasons


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink semantics")
def test_executable_final_symlink(tmp_path):
    if not _symlinks_supported(str(tmp_path)):
        pytest.skip("symlinks unavailable")
    layout, profile = build_fixture(str(tmp_path))
    tofu = os.path.join(str(tmp_path), "bin", "tofu")
    os.rename(tofu, os.path.join(str(tmp_path), "bin", "tofu.real"))
    os.symlink(os.path.join(str(tmp_path), "bin", "tofu.real"), tofu)
    result = _verify(str(tmp_path), layout, profile)
    assert "executable" not in result.verified
    assert R_SYMLINK_REFUSED in result.reasons


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink semantics")
def test_executable_parent_symlink(tmp_path):
    if not _symlinks_supported(str(tmp_path)):
        pytest.skip("symlinks unavailable")
    layout, profile = build_fixture(str(tmp_path))
    # replace bin/ with a symlink to a sibling real dir holding the executable
    real_bin = os.path.join(str(tmp_path), "bin_real")
    os.mkdir(real_bin)
    _write(os.path.join(real_bin, "tofu"), _EXEC_BYTES)
    import shutil

    shutil.rmtree(os.path.join(str(tmp_path), "bin"))
    os.symlink(real_bin, os.path.join(str(tmp_path), "bin"))
    result = _verify(str(tmp_path), layout, profile)
    assert "executable" not in result.verified
    assert R_SYMLINK_REFUSED in result.reasons


@pytest.mark.skipif(os.name != "posix", reason="fifo/special files are POSIX")
def test_special_file_refused(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    tofu = os.path.join(str(tmp_path), "bin", "tofu")
    os.remove(tofu)
    try:
        os.mkfifo(tofu)  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pytest.skip("mkfifo unavailable")
    result = _verify(str(tmp_path), layout, profile)
    assert "executable" not in result.verified
    assert R_OBJECT_TYPE_INVALID in result.reasons


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_setuid_executable_refused(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    tofu = os.path.join(str(tmp_path), "bin", "tofu")
    os.chmod(tofu, 0o4755)  # setuid
    result = _verify(str(tmp_path), layout, profile)
    assert "executable" not in result.verified
    assert R_PERMISSION_INVALID in result.reasons


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_group_writable_executable_refused(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    tofu = os.path.join(str(tmp_path), "bin", "tofu")
    os.chmod(tofu, 0o775)  # group-writable
    result = _verify(str(tmp_path), layout, profile)
    assert "executable" not in result.verified
    assert R_PERMISSION_INVALID in result.reasons


def test_wrong_binary_digest(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    profile["binary_integrity"] = _sha256(b"different bytes")
    result = _verify(str(tmp_path), layout, profile)
    assert "executable" in result.verified  # the file is fine…
    assert "binary_digest" not in result.verified  # …but its digest disagrees
    assert R_BINARY_DIGEST_MISMATCH in result.reasons


def test_unsupported_digest_algorithm(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    # A well-formed but non-sha256 / uppercase digest is refused by the strict real policy.
    profile["binary_integrity"] = "md5:" + "a" * 32
    result = _verify(str(tmp_path), layout, profile)
    assert "binary_digest" not in result.verified
    assert R_UNSUPPORTED_DIGEST in result.reasons


def test_uppercase_sha256_digest_refused(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    profile["binary_integrity"] = "sha256:" + hashlib.sha256(_EXEC_BYTES).hexdigest().upper()
    result = _verify(str(tmp_path), layout, profile)
    assert "binary_digest" not in result.verified
    assert R_UNSUPPORTED_DIGEST in result.reasons


def test_executable_identity_mismatch(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    profile["executable"] = "opentofu"  # bare name that does not match the layout basename 'tofu'
    result = _verify(str(tmp_path), layout, profile)
    assert "executable" not in result.verified
    assert R_EXECUTABLE_MISMATCH in result.reasons


# --- version -------------------------------------------------------------------------------------


def test_version_mismatch(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    _write(
        os.path.join(str(tmp_path), "meta", "version.json"),
        json.dumps({"opentofu_version": "1.2.3"}).encode(),
    )
    result = _verify(str(tmp_path), layout, profile)
    assert "version" not in result.verified
    assert R_VERSION_MISMATCH in result.reasons


def test_malformed_version_metadata(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    _write(
        os.path.join(str(tmp_path), "meta", "version.json"),
        b'{"opentofu_version": "9.9.9", "extra": 1}',
    )
    result = _verify(str(tmp_path), layout, profile)
    assert "version" not in result.verified
    assert R_VERSION_MISMATCH in result.reasons


# --- module bundle -------------------------------------------------------------------------------


def test_module_file_content_changed(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    _write(os.path.join(str(tmp_path), "bundle", "main.tf"), b"module fake { changed = true }\n")
    result = _verify(str(tmp_path), layout, profile)
    assert "module_bundle" not in result.verified
    assert R_MODULE_BUNDLE_MISMATCH in result.reasons


def test_module_path_changed(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    os.rename(
        os.path.join(str(tmp_path), "bundle", "main.tf"),
        os.path.join(str(tmp_path), "bundle", "renamed.tf"),
    )
    result = _verify(str(tmp_path), layout, profile)
    assert "module_bundle" not in result.verified
    assert R_MODULE_BUNDLE_MISMATCH in result.reasons


def test_module_tree_too_large(tmp_path, monkeypatch):
    layout, profile = build_fixture(str(tmp_path))
    monkeypatch.setattr(tv, "_MAX_TREE_FILE_COUNT", 1)
    result = _verify(str(tmp_path), layout, profile)
    assert "module_bundle" not in result.verified
    assert R_TREE_LIMIT_EXCEEDED in result.reasons


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink semantics")
def test_module_symlink_refused(tmp_path):
    if not _symlinks_supported(str(tmp_path)):
        pytest.skip("symlinks unavailable")
    layout, profile = build_fixture(str(tmp_path))
    os.symlink(
        os.path.join(str(tmp_path), "bundle", "main.tf"),
        os.path.join(str(tmp_path), "bundle", "link.tf"),
    )
    result = _verify(str(tmp_path), layout, profile)
    assert "module_bundle" not in result.verified
    assert R_SYMLINK_REFUSED in result.reasons


# --- lockfile ------------------------------------------------------------------------------------


def test_lockfile_empty(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    _write(os.path.join(str(tmp_path), "meta", "provider.lock"), b"")
    profile["provider_lockfile_hash"] = _sha256(b"")
    result = _verify(str(tmp_path), layout, profile)
    assert "lockfile" not in result.verified
    assert R_LOCKFILE_MISMATCH in result.reasons


def test_lockfile_digest_mismatch(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    profile["provider_lockfile_hash"] = _sha256(b"different lock")
    result = _verify(str(tmp_path), layout, profile)
    assert "lockfile" not in result.verified
    assert R_LOCKFILE_MISMATCH in result.reasons


# --- mirror --------------------------------------------------------------------------------------


def test_mirror_identity_mismatch(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    profile["provider_mirror"]["identity"] = _sha256(b"not the mirror")
    result = _verify(str(tmp_path), layout, profile)
    assert "mirror" not in result.verified
    assert R_MIRROR_MISMATCH in result.reasons


def test_mirror_empty_refused(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    import shutil

    shutil.rmtree(os.path.join(str(tmp_path), "mirror"))
    os.mkdir(os.path.join(str(tmp_path), "mirror"))
    profile["provider_mirror"]["identity"] = _hash_tree(os.path.join(str(tmp_path), "mirror"))[0]
    result = _verify(str(tmp_path), layout, profile)
    assert "mirror" not in result.verified
    assert R_MIRROR_MISMATCH in result.reasons


def test_runtime_download_or_online_mirror_in_profile_refused(tmp_path):
    # The strict profile schema refuses an online / runtime-download mirror at validation →
    # PROFILE_INVALID (defense in depth: fail closed before any facet is attested).
    layout, profile = build_fixture(str(tmp_path))
    online = {
        **profile,
        "provider_mirror": {**profile["provider_mirror"], "network_access": "online"},
    }
    result = _verify(str(tmp_path), layout, online)
    assert not result.ok and R_PROFILE_INVALID in result.reasons
    download = {
        **profile,
        "provider_mirror": {**profile["provider_mirror"], "allow_runtime_download": True},
    }
    result2 = _verify(str(tmp_path), layout, download)
    assert not result2.ok and R_PROFILE_INVALID in result2.reasons


# --- CLI config + runtime-download-disabled ------------------------------------------------------


@pytest.mark.parametrize(
    "bad_config",
    [
        b"provider_installation {\n  direct {}\n}\n",  # direct fallback
        b'provider_installation {\n  network_mirror {\n    url = "https://m/"\n  }\n}\n',  # network
        b'provider_installation {\n  filesystem_mirror {\n    path = "/x"\n  }\n}\n',  # wrong dir
        b"# just a comment, nothing pinned\n",  # permissive/empty
        b'credentials "x" { token = "t" }\n',  # credential helper
    ],
)
def test_permissive_or_wrong_cli_config_refused(tmp_path, bad_config):
    layout, profile = build_fixture(str(tmp_path))
    _write(os.path.join(str(tmp_path), "meta", "cli.tofurc"), bad_config)
    result = _verify(str(tmp_path), layout, profile)
    assert "cli_config" not in result.verified
    assert R_CLI_CONFIG_INVALID in result.reasons
    # a broken CLI config also fails the runtime-download-disabled facet (it depends on cli_config)
    assert "runtime_download_disabled" not in result.verified
    assert R_RUNTIME_DOWNLOAD_NOT_DISABLED in result.reasons


def test_cli_config_outside_root_refused(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    bad = ToolchainFilesystemLayout(**{**layout.__dict__, "cli_config": "../cli.tofurc"})
    result = _verify(str(tmp_path), bad, profile)
    assert "cli_config" not in result.verified
    assert R_PATH_OUTSIDE_ROOT in result.reasons


# --- renderer ------------------------------------------------------------------------------------


def test_renderer_mismatch(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    monkeypatch_profile = {**profile, "renderer_version": _RENDERER_VERSION}
    # Force a divergence by pretending the worker renderer moved on.
    import unittest.mock as mock

    import secp_worker.provisioning.rendering as rendering

    with mock.patch.object(tv, "RENDERER_VERSION", "secp-002b-1a/renderer/v2"):
        result = _verify(str(tmp_path), layout, monkeypatch_profile)
    assert "renderer" not in result.verified
    assert R_RENDERER_MISMATCH in result.reasons
    assert rendering.RENDERER_VERSION == _RENDERER_VERSION  # unchanged


# --- remote-state class --------------------------------------------------------------------------


def test_local_state_backend_refused(tmp_path):
    # A local backend is refused by the strict profile schema → PROFILE_INVALID (fail closed).
    layout, profile = build_fixture(str(tmp_path))
    bad = {**profile, "state_backend": {"kind": "local", "reference": "x"}}
    result = _verify(str(tmp_path), layout, bad)
    assert not result.ok and R_PROFILE_INVALID in result.reasons


# --- optional local manifest ---------------------------------------------------------------------


def _valid_manifest(profile: dict) -> dict:
    return {
        "schema_version": "1",
        "opentofu_version": profile["opentofu_version"],
        "executable": profile["executable"],
        "binary_integrity": profile["binary_integrity"],
        "module_bundle_id": profile["module_bundle_id"],
        "module_bundle_hash": profile["module_bundle_hash"],
        "provider_lockfile_hash": profile["provider_lockfile_hash"],
        "provider_mirror_identity": profile["provider_mirror"]["identity"],
        "renderer_version": profile["renderer_version"],
        "cli_config_policy_version": ATTESTATION_POLICY_VERSION,
        "remote_state_backend_class": profile["state_backend"]["kind"],
        "runtime_download_allowed": False,
    }


def test_valid_manifest_accepted(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    _write(
        os.path.join(str(tmp_path), "meta", "manifest.json"),
        json.dumps(_valid_manifest(profile)).encode(),
    )
    layout = ToolchainFilesystemLayout(**{**layout.__dict__, "manifest": "meta/manifest.json"})
    result = _verify(str(tmp_path), layout, profile)
    assert result.ok, result.reasons


def test_manifest_unknown_field_refused(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    man = {**_valid_manifest(profile), "unexpected": "x"}
    _write(os.path.join(str(tmp_path), "meta", "manifest.json"), json.dumps(man).encode())
    layout = ToolchainFilesystemLayout(**{**layout.__dict__, "manifest": "meta/manifest.json"})
    result = _verify(str(tmp_path), layout, profile)
    assert not result.ok
    assert result.reasons == (R_MANIFEST_INVALID,)


def test_manifest_profile_mismatch_fails_closed(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    man = {**_valid_manifest(profile), "opentofu_version": "0.0.0"}  # disagrees with the profile
    _write(os.path.join(str(tmp_path), "meta", "manifest.json"), json.dumps(man).encode())
    layout = ToolchainFilesystemLayout(**{**layout.__dict__, "manifest": "meta/manifest.json"})
    result = _verify(str(tmp_path), layout, profile)
    assert not result.ok and result.reasons == (R_MANIFEST_INVALID,)


def test_manifest_cannot_enable_runtime_download(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    man = {**_valid_manifest(profile), "runtime_download_allowed": True}
    _write(os.path.join(str(tmp_path), "meta", "manifest.json"), json.dumps(man).encode())
    layout = ToolchainFilesystemLayout(**{**layout.__dict__, "manifest": "meta/manifest.json"})
    result = _verify(str(tmp_path), layout, profile)
    assert not result.ok and result.reasons == (R_MANIFEST_INVALID,)


# --- races ---------------------------------------------------------------------------------------


def test_executable_replacement_during_hash_refused(tmp_path, monkeypatch):
    layout, profile = build_fixture(str(tmp_path))
    exec_abs = os.path.join(str(tmp_path), "bin", "tofu")
    orig_open = os.open
    bumped = {"done": False}

    def racing_open(path, *args, **kwargs):
        fd = orig_open(path, *args, **kwargs)
        if not bumped["done"] and os.path.normpath(path) == os.path.normpath(exec_abs):
            bumped["done"] = True
            st = os.stat(exec_abs)
            os.utime(exec_abs, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
        return fd

    monkeypatch.setattr(tv.os, "open", racing_open)
    result = _verify(str(tmp_path), layout, profile)
    assert "executable" not in result.verified
    assert R_OBJECT_CHANGED in result.reasons


def test_tree_replacement_during_hash_refused(tmp_path, monkeypatch):
    layout, profile = build_fixture(str(tmp_path))
    bundle_abs = os.path.join(str(tmp_path), "bundle")
    main_tf = os.path.join(bundle_abs, "main.tf")
    orig_open = os.open
    injected = {"done": False}

    def racing_open(path, *args, **kwargs):
        fd = orig_open(path, *args, **kwargs)
        if not injected["done"] and os.path.normpath(path) == os.path.normpath(main_tf):
            injected["done"] = True
            _write(os.path.join(bundle_abs, "sneaked.tf"), b"injected mid-hash")
        return fd

    monkeypatch.setattr(tv.os, "open", racing_open)
    result = _verify(str(tmp_path), layout, profile)
    assert "module_bundle" not in result.verified
    assert R_OBJECT_CHANGED in result.reasons


# --- bounded reasons, no leakage -----------------------------------------------------------------


def test_all_reasons_are_bounded_and_leak_no_path_or_content(tmp_path):
    layout, profile = build_fixture(str(tmp_path))
    # Break several facets at once.
    profile["binary_integrity"] = _sha256(b"x")
    profile["provider_lockfile_hash"] = _sha256(b"y")
    _write(
        os.path.join(str(tmp_path), "meta", "version.json"),
        json.dumps({"opentofu_version": "0.0.0"}).encode(),
    )
    _write(os.path.join(str(tmp_path), "meta", "cli.tofurc"), b"# broken\n")
    result = _verify(str(tmp_path), layout, profile)
    assert not result.ok
    assert set(result.reasons) <= _ALL_REASONS
    blob = " ".join(result.reasons)
    assert str(tmp_path) not in blob
    for token in ("main.tf", "provider.lock", "tofu", "/", "\\", "module fake"):
        assert token not in blob


def test_layout_paths_are_immutable(tmp_path):
    layout, _ = build_fixture(str(tmp_path))
    with pytest.raises((AttributeError, TypeError)):
        layout.executable = "other"  # type: ignore[misc]


def test_construction_and_import_do_no_filesystem_io(tmp_path):
    # A verifier over non-existent paths constructs without error (no I/O until verify()).
    layout = ToolchainFilesystemLayout(
        trusted_root=os.path.join(str(tmp_path), "does-not-exist"),
        executable="x",
        version_metadata="v",
        module_bundle="m",
        provider_lockfile="l",
        provider_mirror="p",
        cli_config="c",
    )
    v = RealToolchainVerifier(layout)  # no error
    result = v.verify({})  # empty profile → PROFILE_INVALID, no crash
    assert not result.ok and R_PROFILE_INVALID in result.reasons


# --- FakeToolchainVerifier compatibility ---------------------------------------------------------


def test_fake_verifier_default_attests_expanded_facets(tmp_path):
    v = FakeToolchainVerifier()
    result = v.verify({})
    assert result.ok
    assert set(result.verified) == {
        "executable",
        "version",
        "binary_digest",
        "module_bundle",
        "lockfile",
        "mirror",
        "renderer",
        "cli_config",
        "remote_state_class",
        "runtime_download_disabled",
    }


def test_fake_verifier_subset_still_refuses(tmp_path):
    v = FakeToolchainVerifier(attest={"executable", "version", "renderer"})
    assert not v.verify({}).ok


# --- no forbidden runtime seams / seals unchanged ------------------------------------------------


def test_attestation_makes_no_process_or_network_or_secret_call(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("forbidden seam invoked during attestation")

    monkeypatch.setattr(subprocess, "run", boom, raising=False)
    monkeypatch.setattr(subprocess, "Popen", boom, raising=False)
    monkeypatch.setattr(subprocess, "call", boom, raising=False)
    monkeypatch.setattr(os, "system", boom, raising=False)
    monkeypatch.setattr(socket, "socket", boom, raising=False)
    monkeypatch.setattr(socket, "create_connection", boom, raising=False)
    layout, profile = build_fixture(str(tmp_path))
    assert _verify(str(tmp_path), layout, profile).ok


def test_module_source_has_no_forbidden_seams():
    with open(tv.__file__, encoding="utf-8") as fh:
        text = fh.read()
    # Actual import/usage patterns (not prose mentions in docstrings, which honestly describe what
    # the module refuses to do). The module must not import or call any process/network/PATH/secret/
    # render/activation/provider seam.
    for banned in (
        "import subprocess",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "os.system(",
        "os.popen(",
        "shutil",
        "which(",
        "import socket",
        "socket.",
        "import httpx",
        "import requests",
        "import urllib",
        "os.environ",
        "getenv",
        "os.getcwd",
        "WorkspaceRenderer",
        ".render(",
        "SecretResolver",
        "resolve_secret",
        "reveal_secret",
        "RealLabActivationGrant",
        "SubprocessProcessExecutor",
        "AuditEvent",
        "proxmoxer",
        "paramiko",
        "session.query",
        "session.add",
    ):
        assert banned not in text, f"toolchain_verify.py must not import/use {banned!r}"


def test_importing_and_using_verifier_leaves_both_seals_true(tmp_path):
    from secp_worker.provisioning import activation as act
    from secp_worker.provisioning import process_executor as pe

    layout, profile = build_fixture(str(tmp_path))
    _verify(str(tmp_path), layout, profile)
    assert pe._B1A_SUBPROCESS_SEALED is True
    assert act._B1A_SUBPROCESS_SEALED is True
