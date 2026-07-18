"""Signed offline release-bundle verification (SECP-PR5E, section 2 + 15)."""

from __future__ import annotations

import json

import pytest
from _mgmt_support import (
    default_artifacts,
    ephemeral_trust_root,
    manifest_dict,
    seed_signed_bundle,
)
from secp_commissioning.canonical import canonical_json, sha256_bytes
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import ManagementError
from secp_management.release_bundle import (
    ReleaseManifest,
    manifest_signing_message,
    parse_manifest_bytes,
)
from secp_management.release_verify import verify_release_bundle
from secp_management.signing import (
    SHIPPED_TRUST_ROOT,
    ReleaseTrustRoot,
    TrustAnchor,
    generate_keypair,
)


def _fs_bundle(role="worker", artifacts=None):
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/r"
    seed_signed_bundle(fs, bd, role, kid, priv, artifacts=artifacts)
    return fs, bd, trust, kid, priv


def test_valid_signature_accepted():
    fs, bd, trust, _kid, _priv = _fs_bundle()
    vr = verify_release_bundle(bd, trust_root=trust, fs=fs)
    assert vr.role == "worker" and vr.aggregate_digest.startswith("sha256:")


def test_shipped_empty_trust_root_refuses():
    fs, bd, _trust, _kid, _priv = _fs_bundle()
    with pytest.raises(ManagementError) as exc:
        verify_release_bundle(bd, trust_root=SHIPPED_TRUST_ROOT, fs=fs)
    assert exc.value.reason_code == "release_signature_untrusted"


def test_wrong_trust_root_refuses():
    fs, bd, _trust, kid, _priv = _fs_bundle()
    _priv2, pub2 = generate_keypair()
    other = ReleaseTrustRoot(anchors=(TrustAnchor(kid, pub2),), test_only=True)
    with pytest.raises(ManagementError) as exc:
        verify_release_bundle(bd, trust_root=other, fs=fs)
    assert exc.value.reason_code == "release_signature_untrusted"


def test_modified_manifest_refuses():
    fs, bd, trust, _kid, _priv = _fs_bundle()
    # flip a manifest byte without re-signing → signature no longer covers it
    raw = fs.safe_read(bd + "/release-manifest.json", max_bytes=1 << 20, expected_uid=0)
    tampered = raw.replace(b'"0.1.0"', b'"9.9.9"')
    fs.seed_file(bd + "/release-manifest.json", tampered, mode=0o644)
    with pytest.raises(ManagementError) as exc:
        verify_release_bundle(bd, trust_root=trust, fs=fs)
    assert exc.value.reason_code in (
        "release_signature_untrusted",
        "release_signature_key_mismatch",
    )


def test_modified_artifact_refuses():
    fs, bd, trust, _kid, _priv = _fs_bundle()
    fs.seed_file(bd + "/worker-compose.yml", b"tampered content of same-ish\n", mode=0o644)
    with pytest.raises(ManagementError) as exc:
        verify_release_bundle(bd, trust_root=trust, fs=fs)
    assert exc.value.reason_code in ("release_artifact_digest_mismatch", "fs_read_size_invalid")


def test_missing_artifact_refuses():
    fs, bd, trust, _kid, _priv = _fs_bundle()
    fs.remove_file(bd + "/worker-compose.yml")
    with pytest.raises(ManagementError):
        verify_release_bundle(bd, trust_root=trust, fs=fs)


def test_symlink_artifact_refuses():
    fs, bd, trust, _kid, _priv = _fs_bundle()
    fs.seed_symlink(bd + "/worker-compose.yml")
    with pytest.raises(ManagementError):
        verify_release_bundle(bd, trust_root=trust, fs=fs)


def test_hardlinked_artifact_refuses():
    fs, bd, trust, _kid, _priv = _fs_bundle()
    d = b"# compose template\n"
    fs.seed_file(bd + "/worker-compose.yml", d, mode=0o644, nlink=2)
    with pytest.raises(ManagementError):
        verify_release_bundle(bd, trust_root=trust, fs=fs)


# --- manifest parse refusals (contract-owned) ---


def _signed_manifest_bytes(role, artifacts):
    m = ReleaseManifest.model_validate(manifest_dict(role, artifacts))
    return m.canonical().encode()


def test_unknown_field_refused():
    raw = json.dumps(
        {**manifest_dict("worker", default_artifacts("worker")), "surprise": 1}
    ).encode()
    with pytest.raises(ManagementError) as exc:
        parse_manifest_bytes(raw)
    assert exc.value.reason_code.startswith("release_manifest_invalid")


def test_unknown_artifact_kind_refused():
    arts = default_artifacts("worker")
    arts[0]["kind"] = "scenario_lab_vm"  # a scenario-plane kind is not in the closed set
    with pytest.raises(ManagementError):
        parse_manifest_bytes(json.dumps(manifest_dict("worker", arts)).encode())


def test_duplicate_json_keys_refused():
    body = json.dumps(manifest_dict("worker", default_artifacts("worker")))
    dup = (body[:-1] + ',"role":"controller"}').encode()
    with pytest.raises(ManagementError) as exc:
        parse_manifest_bytes(dup)
    assert exc.value.reason_code == "release_manifest_duplicate_key"


def test_secret_shaped_field_refused():
    raw = json.dumps(
        {**manifest_dict("worker", default_artifacts("worker")), "api_key": "x"}
    ).encode()
    with pytest.raises(ManagementError) as exc:
        parse_manifest_bytes(raw)
    assert exc.value.reason_code == "release_manifest_forbidden_secret"


def test_traversal_artifact_name_refused():
    arts = default_artifacts("worker")
    arts[0]["name"] = "../../etc/evil"
    with pytest.raises(ManagementError) as exc:
        parse_manifest_bytes(json.dumps(manifest_dict("worker", arts)).encode())
    assert exc.value.reason_code == "release_artifact_name_unsafe"


def test_absolute_artifact_name_refused():
    arts = default_artifacts("worker")
    arts[0]["name"] = "/etc/passwd"
    with pytest.raises(ManagementError):
        parse_manifest_bytes(json.dumps(manifest_dict("worker", arts)).encode())


def test_mixed_role_inventory_refused():
    # a worker bundle carrying a controller compose template
    arts = default_artifacts("worker")
    compose = b"# c\n"
    arts.append(
        {
            "name": "controller-compose.yml",
            "kind": "controller_compose_template",
            "role": "controller",
            "sha256": sha256_bytes(compose),
            "size": len(compose),
        }
    )
    with pytest.raises(ManagementError) as exc:
        parse_manifest_bytes(json.dumps(manifest_dict("worker", arts)).encode())
    assert exc.value.reason_code == "mixed_role_inventory"


def test_image_archive_requires_content_digest_not_tag():
    # an image archive with no exact content digest (a floating tag can never substitute)
    arts = default_artifacts("worker")
    del arts[1]["image_digest"]
    with pytest.raises(ManagementError) as exc:
        parse_manifest_bytes(json.dumps(manifest_dict("worker", arts)).encode())
    assert exc.value.reason_code == "release_image_digest_invalid"


def test_oversized_artifact_size_field_refused():
    arts = default_artifacts("worker")
    arts[0]["size"] = 8 * 1024 * 1024 * 1024 + 1  # exceeds the hard cap
    with pytest.raises(ManagementError):
        parse_manifest_bytes(json.dumps(manifest_dict("worker", arts)).encode())


def test_signature_covers_the_whole_release():
    # the aggregate digest == the canonical manifest digest, so signing it signs every artifact
    m = ReleaseManifest.model_validate(manifest_dict("worker", default_artifacts("worker")))
    from secp_management.release_bundle import manifest_aggregate_digest

    assert manifest_aggregate_digest(m) == sha256_bytes(
        canonical_json(m.model_dump(mode="json")).encode()
    )
    assert manifest_signing_message(m) == m.canonical().encode()
