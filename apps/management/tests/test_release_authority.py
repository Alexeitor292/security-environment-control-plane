"""Offline release-authority tooling (SECP-PR5H-B2, commit 2b-1b).

Ephemeral keys only (never a candidate production key), under pytest tmp dirs (outside the repo).
Proves: init mints a protected out-of-repo key + emits the PUBLIC anchor (never the private key);
build assembles a deterministic canonical v1alpha2 manifest and refuses a legacy/incomplete one;
sign refuses a non-canonical manifest, a wrong signer, or drifted artifacts; verify verifies only
under the SUPPLIED anchor; and no private material appears in any report.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from _mgmt_support import default_artifacts, manifest_dict
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

_PROFILE = {
    "platform_profile": {
        "os": "linux",
        "arch": "amd64",
        "installation_profile_version": "secp.controller-install/v1",
    },
    "runtime_profile": {
        "pins": [
            {
                "capability": "container_runtime",
                "path": "/usr/bin/docker",
                "sha256": "sha256:" + "1" * 64,
                "invocation": ["docker"],
                "allowed_subcommands": ["load"],
            },
            {
                "capability": "compose",
                "path": "/usr/bin/docker",
                "sha256": "sha256:" + "1" * 64,
                "invocation": ["docker", "compose"],
                "allowed_subcommands": ["up"],
            },
            {
                "capability": "service_manager",
                "path": "/usr/bin/systemctl",
                "sha256": "sha256:" + "2" * 64,
                "invocation": ["systemctl"],
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


def _init(tmp_path: Path) -> tuple[str, dict]:
    key_path = str(tmp_path / "release-signing.key")
    code, report = authority_init(key_path=key_path, repo_root="/some/other/repo")
    assert code == 0
    return key_path, report


# --- init ----------------------------------------------------------------------------------------


def test_init_writes_protected_key_and_emits_only_the_public_anchor(tmp_path):
    key_path, report = _init(tmp_path)
    assert Path(key_path).is_file()
    anchor = report["anchor"]
    assert set(anchor) == {"key_id", "public_key_hex"}
    assert derive_key_id(anchor["public_key_hex"]) == anchor["key_id"]
    # the private key file content is a 32-byte hex; it must NEVER appear in the report
    private_hex = Path(key_path).read_text().strip()
    assert len(bytes.fromhex(private_hex)) == 32
    assert private_hex not in json.dumps(report)
    # a separate public anchor file is emitted (public material only)
    assert Path(key_path + ".pub.json").is_file()


def test_init_refuses_a_destination_inside_the_repo(tmp_path):
    with pytest.raises(AuthorityError) as e:
        authority_init(key_path=str(tmp_path / "k.key"), repo_root=str(tmp_path))
    assert e.value.reason_code == "release_authority_key_inside_repo"


def test_init_refuses_an_existing_key_and_a_relative_path(tmp_path):
    key_path, _ = _init(tmp_path)
    with pytest.raises(AuthorityError) as e:
        authority_init(key_path=key_path, repo_root="/other")  # O_EXCL -> exists
    assert e.value.reason_code == "release_authority_key_exists"
    with pytest.raises(AuthorityError) as e2:
        authority_init(key_path="relative.key", repo_root="/other")
    assert e2.value.reason_code == "release_authority_key_path_not_absolute"


# --- build ---------------------------------------------------------------------------------------


def test_build_emits_a_deterministic_canonical_v1alpha2_manifest(tmp_path):
    _, report = _init(tmp_path)
    spec = json.dumps(_v2(report["anchor"]["key_id"])).encode()
    code, out = authority_build(spec_bytes=spec)
    assert code == 0
    # deterministic: build again -> identical canonical bytes + aggregate digest
    code2, out2 = authority_build(spec_bytes=spec)
    assert out["manifest_bytes"] == out2["manifest_bytes"]
    assert out["aggregate_digest"] == out2["aggregate_digest"]
    assert '"platform_profile"' in out["manifest_bytes"]  # v1alpha2 signs the profile


def test_build_refuses_a_legacy_v1alpha1_bundle():
    spec = json.dumps(manifest_dict("controller", default_artifacts("controller"))).encode()
    with pytest.raises(ManagementError) as e:  # release-contract-level bounded refusal
        authority_build(spec_bytes=spec)
    assert e.value.reason_code == "release_b2_installation_profile_required"


# --- sign + verify -------------------------------------------------------------------------------


def _built(tmp_path) -> tuple[str, dict, bytes]:
    key_path, report = _init(tmp_path)
    _, out = authority_build(spec_bytes=json.dumps(_v2(report["anchor"]["key_id"])).encode())
    return key_path, report["anchor"], out["manifest_bytes"].encode()


def test_sign_then_verify_roundtrips_under_the_supplied_anchor(tmp_path):
    key_path, anchor, manifest_bytes = _built(tmp_path)
    code, s = authority_sign(manifest_bytes=manifest_bytes, key_path=key_path)
    assert code == 0
    sig_bytes = s["signature_bytes"].encode()
    code2, v = authority_verify(
        manifest_bytes=manifest_bytes, signature_bytes=sig_bytes, anchor=anchor
    )
    assert code2 == 0 and v["verified"] is True
    # the signature envelope carries no private material
    assert Path(key_path).read_text().strip() not in json.dumps(s)


def test_verify_refuses_a_different_anchor(tmp_path):
    from secp_management.signing import generate_keypair

    key_path, _anchor, manifest_bytes = _built(tmp_path)
    _, s = authority_sign(manifest_bytes=manifest_bytes, key_path=key_path)
    # a DIFFERENT (valid) anchor does not match the manifest's declared signer -> refused
    _, other_pub = generate_keypair()
    wrong = {"key_id": derive_key_id(other_pub), "public_key_hex": other_pub}
    with pytest.raises(AuthorityError) as e:
        authority_verify(
            manifest_bytes=manifest_bytes,
            signature_bytes=s["signature_bytes"].encode(),
            anchor=wrong,
        )
    # the manifest's declared signer is not the supplied (wrong) anchor -> untrusted, never verified
    assert e.value.reason_code == "release_authority_signature_untrusted"


def test_sign_refuses_a_noncanonical_manifest(tmp_path):
    key_path, anchor, manifest_bytes = _built(tmp_path)
    # re-emit the manifest with extra whitespace -> not canonical
    noncanonical = json.dumps(json.loads(manifest_bytes), indent=2).encode()
    with pytest.raises(AuthorityError) as e:
        authority_sign(manifest_bytes=noncanonical, key_path=key_path)
    assert e.value.reason_code == "release_authority_manifest_noncanonical"


def test_sign_refuses_a_manifest_signed_for_a_different_key(tmp_path):
    key_path, _init_report = _init(tmp_path)
    # build a v2 manifest whose signing_anchor_id is a DIFFERENT key than key_path
    from secp_management.signing import generate_keypair

    _, other_pub = generate_keypair()
    _, out = authority_build(spec_bytes=json.dumps(_v2(derive_key_id(other_pub))).encode())
    with pytest.raises(AuthorityError) as e:
        authority_sign(manifest_bytes=out["manifest_bytes"].encode(), key_path=key_path)
    assert e.value.reason_code == "release_authority_signer_mismatch"


def test_sign_refuses_drifted_artifacts(tmp_path):
    key_path, anchor, manifest_bytes = _built(tmp_path)
    # write an artifacts dir whose files do NOT match the manifest digests -> drift
    manifest = json.loads(manifest_bytes)
    adir = tmp_path / "artifacts"
    adir.mkdir()
    for art in manifest["artifacts"]:
        dest = adir / art["name"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"tampered")
    with pytest.raises(AuthorityError) as e:
        authority_sign(manifest_bytes=manifest_bytes, key_path=key_path, artifacts_dir=str(adir))
    assert e.value.reason_code == "release_authority_artifact_drift"


# --- posture guard -------------------------------------------------------------------------------


def test_release_authority_reaches_no_network_or_subprocess_capability():
    src = Path("apps/management/secp_management/release_authority.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for forbidden in ("socket", "http", "httpx", "requests", "urllib", "subprocess", "asyncio"):
        assert forbidden not in imported, forbidden
