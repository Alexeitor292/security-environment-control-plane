"""Offline release-authority tooling — hardened (SECP-PR5H-B2, commit 2b-1c).

Ephemeral keys only (never a candidate production key), under pytest tmp dirs (outside the repo).
Production key ``init``/``sign`` are POSIX-only (they PROVE custody via no-follow open + fstat +
nlink + fsync); on Windows/non-POSIX they fail closed. ``build``/``verify`` and the strict signature
checks are platform-independent. Signing REQUIRES full TOCTOU-safe artifact verification.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest
from _mgmt_support import default_artifacts, manifest_dict
from secp_commissioning.canonical import canonical_json, sha256_bytes
from secp_management import BOOTSTRAP_CONTRACT_VERSION_V1ALPHA2 as V2
from secp_management import ManagementError
from secp_management.release_authority import (
    AuthorityError,
    authority_build,
    authority_init,
    authority_sign,
    authority_verify,
    derive_key_id,
)
from secp_management.release_bundle import manifest_signing_message, parse_manifest_bytes
from secp_management.signing import generate_keypair, sign_ed25519

_POSIX = os.name == "posix"
_posix_only = pytest.mark.skipif(
    not _POSIX, reason="POSIX-only secure key custody (no-follow/fstat/fsync)"
)

_PROFILE = {
    "platform_profile": {
        "os": "linux",
        "arch": "x86_64",
        "installation_profile_version": "secp.controller-install/v1",
    },
    "runtime_profile": {
        "pins": [
            {
                "capability": "container_runtime",
                "path": "/usr/bin/docker",
                "sha256": "sha256:" + "1" * 64,
                "invocation": [],
                "allowed_subcommands": ["load", "image"],
            },
            {
                "capability": "compose",
                "path": "/usr/bin/docker",
                "sha256": "sha256:" + "1" * 64,
                "invocation": ["compose"],
                "allowed_subcommands": ["up", "down"],
            },
            {
                "capability": "service_manager",
                "path": "/usr/bin/systemctl",
                "sha256": "sha256:" + "2" * 64,
                "invocation": [],
                "allowed_subcommands": ["daemon-reload"],
            },
        ]
    },
    "controller_tls_policy": {
        "allowed_modes": ["generated_local_ca"],
        "key_algorithm": "ecdsa-p256",
        "signature_algorithm": "ecdsa-with-sha256",
        "max_validity_days": 825,
        "require_san": True,
        "server_auth_eku_required": True,
        "ca_pathlen_zero": True,
        "min_tls_version": "1.3",
        "allow_ip_origin": False,
        "allow_generated_local_ca": True,
    },
}


def _v2(key_id: str, **over) -> dict:
    d = manifest_dict("controller", default_artifacts("controller"))
    d["bootstrap_contract_version"] = V2
    d["signing_anchor_id"] = key_id
    d.update(_PROFILE)
    d.update(over)
    return d


def _canonical_v2(key_id: str) -> bytes:
    return authority_build(spec_bytes=json.dumps(_v2(key_id)).encode())[1][
        "manifest_bytes"
    ].encode()


def _manual_signed():
    """A valid signed v2 manifest + anchor produced WITHOUT authority_sign (verify testable
    off-POSIX): the anchor key_id == derive_key_id(pub)."""
    priv, pub = generate_keypair()
    key_id = derive_key_id(pub)
    manifest_bytes = _canonical_v2(key_id)
    msg = manifest_signing_message(parse_manifest_bytes(manifest_bytes))
    envelope = canonical_json(
        {"algorithm": "ed25519", "key_id": key_id, "signature": sign_ed25519(priv, msg)}
    )
    return manifest_bytes, envelope.encode(), {"key_id": key_id, "public_key_hex": pub}


def _priv_dir(tmp_path: Path, name: str = "keys") -> str:
    d = tmp_path / name
    d.mkdir()
    if _POSIX:
        os.chmod(d, 0o700)
    return str(d)


def _real_artifacts(tmp_path: Path, key_id: str) -> tuple[bytes, str]:
    """Write real artifact bytes whose sha256+size the manifest records, and return the canonical
    manifest + the artifacts dir. The manifest keeps the signed controller purpose set intact."""
    arts = default_artifacts("controller")
    adir = tmp_path / "artifacts"
    adir.mkdir(exist_ok=True)
    real = []
    for i, art in enumerate(arts):
        data = (f"secp-artifact-{i}-{art['name']}".encode()) * 2
        dest = adir / art["name"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        real.append({**art, "sha256": sha256_bytes(data), "size": len(data)})
    d = _v2(key_id, artifacts=real)
    manifest_bytes = authority_build(spec_bytes=json.dumps(d).encode())[1][
        "manifest_bytes"
    ].encode()
    return manifest_bytes, str(adir)


# --- platform-independent: build --------------------------------------------------------------


def test_build_is_deterministic_and_signs_the_profile():
    key_id = derive_key_id(generate_keypair()[1])
    a = authority_build(spec_bytes=json.dumps(_v2(key_id)).encode())[1]
    b = authority_build(spec_bytes=json.dumps(_v2(key_id)).encode())[1]
    assert a["manifest_bytes"] == b["manifest_bytes"]
    assert a["aggregate_digest"] == b["aggregate_digest"]
    assert '"platform_profile"' in a["manifest_bytes"]


def test_build_refuses_a_legacy_v1alpha1_bundle():
    with pytest.raises(ManagementError) as e:
        authority_build(
            spec_bytes=json.dumps(
                manifest_dict("controller", default_artifacts("controller"))
            ).encode()
        )
    assert e.value.reason_code == "release_b2_installation_profile_required"


# --- platform-independent: verify (strict) ----------------------------------------------------


def test_verify_roundtrips_under_the_supplied_anchor():
    manifest_bytes, sig_bytes, anchor = _manual_signed()
    code, v = authority_verify(
        manifest_bytes=manifest_bytes, signature_bytes=sig_bytes, anchor=anchor
    )
    assert code == 0 and v["verified"] is True


def test_verify_refuses_a_different_anchor():
    manifest_bytes, sig_bytes, _anchor = _manual_signed()
    _, other_pub = generate_keypair()
    wrong = {"key_id": derive_key_id(other_pub), "public_key_hex": other_pub}
    with pytest.raises(AuthorityError) as e:
        authority_verify(manifest_bytes=manifest_bytes, signature_bytes=sig_bytes, anchor=wrong)
    assert e.value.reason_code == "release_authority_signature_mismatch"


@pytest.mark.parametrize(
    "mutate,prefix",
    [
        (
            lambda s: b'{"algorithm":"ed25519","key_id":"x"}',
            "release_signature_invalid",
        ),  # missing field
        (
            lambda s: json.dumps({**json.loads(s), "extra": 1}).encode(),
            "release_signature_invalid",
        ),  # extra
        (
            lambda s: json.dumps({**json.loads(s), "algorithm": "rsa"}).encode(),
            "release_signature_algorithm_unsupported",
        ),
        (
            lambda s: (json.dumps(json.loads(s), indent=2)).encode(),
            "release_authority_signature_noncanonical",
        ),
    ],
)
def test_verify_uses_the_strict_signature_parser(mutate, prefix):
    manifest_bytes, sig_bytes, anchor = _manual_signed()
    with pytest.raises(ManagementError) as e:
        authority_verify(
            manifest_bytes=manifest_bytes, signature_bytes=mutate(sig_bytes), anchor=anchor
        )
    assert e.value.reason_code.startswith(prefix)


def test_verify_refuses_a_duplicate_key_signature():
    manifest_bytes, sig_bytes, anchor = _manual_signed()
    d = json.loads(sig_bytes)
    dup = (
        f'{{"algorithm":"ed25519","algorithm":"ed25519",'
        f'"key_id":"{d["key_id"]}","signature":"{d["signature"]}"}}'
    ).encode()
    with pytest.raises(ManagementError) as e:
        authority_verify(manifest_bytes=manifest_bytes, signature_bytes=dup, anchor=anchor)
    assert e.value.reason_code == "release_signature_duplicate_key"


# --- platform-independent: sign argument validation -------------------------------------------


def test_sign_requires_an_artifacts_directory():
    manifest_bytes, _sig, _anchor = _manual_signed()
    with pytest.raises(AuthorityError) as e:
        authority_sign(manifest_bytes=manifest_bytes, key_path="/x/k.key", artifacts_dir=None)
    assert e.value.reason_code == "release_authority_artifacts_dir_required"


def test_sign_refuses_a_relative_artifacts_directory():
    manifest_bytes, _sig, _anchor = _manual_signed()
    with pytest.raises(AuthorityError) as e:
        authority_sign(manifest_bytes=manifest_bytes, key_path="/x/k.key", artifacts_dir="rel/dir")
    assert e.value.reason_code == "release_authority_artifacts_dir_not_absolute"


def test_sign_refuses_a_noncanonical_manifest():
    manifest_bytes, _sig, _anchor = _manual_signed()
    noncanonical = json.dumps(json.loads(manifest_bytes), indent=2).encode()
    with pytest.raises(AuthorityError) as e:
        authority_sign(manifest_bytes=noncanonical, key_path="/x/k.key", artifacts_dir="/abs/dir")
    assert e.value.reason_code == "release_authority_manifest_noncanonical"


# --- non-POSIX: production init/sign fail closed ----------------------------------------------


@pytest.mark.skipif(_POSIX, reason="the non-POSIX secure-storage refusal")
def test_production_init_and_sign_are_refused_off_posix(tmp_path):
    with pytest.raises(AuthorityError) as e:
        authority_init(key_path=str(tmp_path / "k.key"), repo_root="/other")
    assert e.value.reason_code == "release_authority_unsupported_secure_key_storage"
    manifest_bytes, _sig, _anchor = _manual_signed()
    with pytest.raises(AuthorityError) as e2:  # past arg/canonical checks, the POSIX gate fires
        authority_sign(
            manifest_bytes=manifest_bytes, key_path="/x/k.key", artifacts_dir=str(tmp_path)
        )
    assert e2.value.reason_code == "release_authority_unsupported_secure_key_storage"


# --- POSIX-only: full custody + transaction + TOCTOU ------------------------------------------


@_posix_only
def test_init_writes_protected_key_and_emits_only_the_public_anchor(tmp_path):
    kp = os.path.join(_priv_dir(tmp_path), "release-signing.key")
    code, report = authority_init(key_path=kp, repo_root="/other/repo")
    assert code == 0
    st = os.lstat(kp)
    assert (st.st_mode & 0o777) == 0o600 and st.st_nlink == 1
    anchor = report["anchor"]
    assert derive_key_id(anchor["public_key_hex"]) == anchor["key_id"]
    priv = Path(kp).read_text()
    assert len(priv) == 64 and priv not in json.dumps(report)  # private key never in the report


@_posix_only
def test_init_is_transactional_public_failure_compensates_the_private_key(tmp_path):
    kp = os.path.join(_priv_dir(tmp_path), "release-signing.key")
    Path(kp + ".pub.json").write_text("{}")  # pre-existing public target -> O_EXCL fails
    with pytest.raises(AuthorityError) as e:
        authority_init(key_path=kp, repo_root="/other")
    assert e.value.reason_code == "release_authority_public_exists"
    assert not os.path.lexists(kp)  # the private key was removed (no half-created authority)


@_posix_only
def test_init_refuses_a_non_private_parent(tmp_path):
    d = tmp_path / "loose"
    d.mkdir()
    os.chmod(d, 0o755)  # group/other readable -> not private
    with pytest.raises(AuthorityError) as e:
        authority_init(key_path=str(d / "k.key"), repo_root="/other")
    assert e.value.reason_code == "release_authority_key_parent_not_private"


@_posix_only
def test_init_refuses_a_destination_inside_the_repo(tmp_path):
    with pytest.raises(AuthorityError) as e:
        authority_init(key_path=str(tmp_path / "k.key"), repo_root=str(tmp_path))
    assert e.value.reason_code == "release_authority_key_inside_repo"


@_posix_only
def test_read_private_key_refuses_wrong_mode_and_a_symlink(tmp_path):
    from secp_management.release_authority import _read_private_key

    kp = os.path.join(_priv_dir(tmp_path), "k.key")
    authority_init(key_path=kp, repo_root="/other")
    os.chmod(kp, 0o640)  # loosen mode -> refuse (fstat on the descriptor)
    with pytest.raises(AuthorityError) as e:
        _read_private_key(kp)
    assert e.value.reason_code == "release_authority_key_unsafe"
    os.chmod(kp, 0o600)
    link = os.path.join(_priv_dir(tmp_path, "keys2"), "link.key")
    os.symlink(kp, link)  # a symlink target is refused by the no-follow open
    with pytest.raises(AuthorityError) as e2:
        _read_private_key(link)
    assert e2.value.reason_code == "release_authority_key_unreadable"


@_posix_only
def test_sign_then_verify_roundtrips_with_real_artifacts(tmp_path):
    kp = os.path.join(_priv_dir(tmp_path), "k.key")
    anchor = authority_init(key_path=kp, repo_root="/other")[1]["anchor"]
    manifest_bytes, adir = _real_artifacts(tmp_path, anchor["key_id"])
    s = authority_sign(manifest_bytes=manifest_bytes, key_path=kp, artifacts_dir=adir)[1]
    v = authority_verify(
        manifest_bytes=manifest_bytes, signature_bytes=s["signature_bytes"].encode(), anchor=anchor
    )[1]
    assert v["verified"] is True
    assert Path(kp).read_text() not in json.dumps(s)  # no private material in the signature output


@_posix_only
def test_sign_refuses_a_wrong_signer(tmp_path):
    kp = os.path.join(_priv_dir(tmp_path), "k.key")
    authority_init(key_path=kp, repo_root="/other")
    manifest_bytes, adir = _real_artifacts(tmp_path, derive_key_id(generate_keypair()[1]))
    with pytest.raises(AuthorityError) as e:
        authority_sign(manifest_bytes=manifest_bytes, key_path=kp, artifacts_dir=adir)
    assert e.value.reason_code == "release_authority_signer_mismatch"


@_posix_only
def test_sign_refuses_a_drifted_artifact(tmp_path):
    kp = os.path.join(_priv_dir(tmp_path), "k.key")
    anchor = authority_init(key_path=kp, repo_root="/other")[1]["anchor"]
    manifest_bytes, adir = _real_artifacts(tmp_path, anchor["key_id"])
    first = json.loads(manifest_bytes)["artifacts"][0]["name"]
    Path(adir, first).write_bytes(b"tampered")  # drift after the manifest was built
    with pytest.raises(AuthorityError) as e:
        authority_sign(manifest_bytes=manifest_bytes, key_path=kp, artifacts_dir=adir)
    assert e.value.reason_code == "release_authority_artifact_drift"


@_posix_only
def test_sign_refuses_a_symlinked_artifact(tmp_path):
    # a symlink whose target is INSIDE the dir passes the beneath-check, so this isolates the
    # no-follow open refusal (the artifact path itself is a symlink).
    kp = os.path.join(_priv_dir(tmp_path), "k.key")
    anchor = authority_init(key_path=kp, repo_root="/other")[1]["anchor"]
    manifest_bytes, adir = _real_artifacts(tmp_path, anchor["key_id"])
    first = json.loads(manifest_bytes)["artifacts"][0]["name"]
    target = Path(adir, first)
    sibling = Path(adir, "_original.bin")  # keep the real bytes beneath adir (no escape)
    sibling.write_bytes(target.read_bytes())
    target.unlink()
    os.symlink(str(sibling), str(target))  # the artifact path is now a symlink -> no-follow refuses
    with pytest.raises(AuthorityError) as e:
        authority_sign(manifest_bytes=manifest_bytes, key_path=kp, artifacts_dir=adir)
    assert e.value.reason_code == "release_authority_artifact_unreadable"


@_posix_only
def test_sign_refuses_an_artifact_symlink_escaping_the_dir(tmp_path):
    # a symlink resolving OUTSIDE the artifacts dir is caught by the realpath-beneath check.
    kp = os.path.join(_priv_dir(tmp_path), "k.key")
    anchor = authority_init(key_path=kp, repo_root="/other")[1]["anchor"]
    manifest_bytes, adir = _real_artifacts(tmp_path, anchor["key_id"])
    first = json.loads(manifest_bytes)["artifacts"][0]["name"]
    target = Path(adir, first)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(target.read_bytes())
    target.unlink()
    os.symlink(str(outside), str(target))
    with pytest.raises(AuthorityError) as e:
        authority_sign(manifest_bytes=manifest_bytes, key_path=kp, artifacts_dir=adir)
    assert e.value.reason_code == "release_authority_artifact_escape"


# --- posture guard ----------------------------------------------------------------------------


def test_release_authority_reaches_no_network_or_subprocess_capability():
    src = Path("apps/management/secp_management/release_authority.py").read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for forbidden in ("socket", "http", "httpx", "requests", "urllib", "subprocess", "asyncio"):
        assert forbidden not in imported, forbidden
