from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import struct
import zipfile
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest
import secp_discovery_activation.runtime_overlay as overlay_module
from secp_discovery_activation import (
    PACKAGE_CONTRACT_VERSION,
    PACKAGE_IMPLEMENTATION_ID,
    PACKAGE_VERSION,
)
from secp_discovery_activation.runtime_overlay import (
    MAX_RUNTIME_OVERLAY_BYTES,
    RUNTIME_OVERLAY_CONTRACT_VERSION,
    RUNTIME_OVERLAY_CRITICAL_FILES,
    RUNTIME_OVERLAY_MANIFEST,
    RUNTIME_OVERLAY_PACKAGES,
    RuntimeOverlayError,
    RuntimeOverlayFile,
    build_runtime_overlay,
    import_runtime_overlay,
    runtime_overlay_sha256,
)

REPOSITORY = Path(__file__).resolve().parents[3]
PACKAGE_ROOTS = {
    "secp_api": REPOSITORY / "apps" / "api" / "secp_api",
    "secp_worker": REPOSITORY / "apps" / "worker" / "secp_worker",
}


@pytest.fixture(scope="module")
def built_overlay() -> bytes:
    return build_runtime_overlay(REPOSITORY)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _members(raw: bytes) -> list[tuple[str, bytes]]:
    with zipfile.ZipFile(io.BytesIO(raw), mode="r") as archive:
        return [(info.filename, archive.read(info)) for info in archive.infolist()]


def _write_zip(
    members: list[tuple[str, bytes]],
    *,
    timestamp: tuple[int, int, int, int, int, int] = (1980, 1, 1, 0, 0, 0),
    compression: int = zipfile.ZIP_DEFLATED,
    external_attributes: int = (stat.S_IFREG | 0o444) << 16,
    member_comment: bytes = b"",
    member_extra: bytes = b"",
    archive_comment: bytes = b"",
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=compression,
        compresslevel=9 if compression == zipfile.ZIP_DEFLATED else None,
        allowZip64=False,
    ) as archive:
        for name, content in members:
            info = zipfile.ZipInfo(name, date_time=timestamp)
            info.compress_type = compression
            info.create_system = 3
            info.create_version = 20
            info.extract_version = 20 if compression == zipfile.ZIP_DEFLATED else 10
            info.external_attr = external_attributes
            info.internal_attr = 0
            info.comment = member_comment
            info.extra = member_extra
            archive.writestr(
                info,
                content,
                compress_type=compression,
                compresslevel=9 if compression == zipfile.ZIP_DEFLATED else None,
            )
        archive.comment = archive_comment
    return output.getvalue()


def _source_members(raw: bytes) -> dict[str, bytes]:
    return {name: content for name, content in _members(raw) if name != RUNTIME_OVERLAY_MANIFEST}


def _consistent_members(sources: dict[str, bytes]) -> list[tuple[str, bytes]]:
    files = tuple(
        RuntimeOverlayFile(
            path=path,
            sha256="sha256:" + hashlib.sha256(content).hexdigest(),
            size=len(content),
        )
        for path, content in sorted(sources.items())
    )
    manifest = overlay_module._manifest_document(files)
    return [
        (RUNTIME_OVERLAY_MANIFEST, overlay_module._canonical_json(manifest)),
        *sorted(sources.items()),
    ]


def _replace_manifest(raw: bytes, transform: Any, *, canonical: bool = True) -> bytes:
    members = _members(raw)
    manifest = json.loads(members[0][1])
    transform(manifest)
    encoded = (
        overlay_module._canonical_json(manifest)
        if canonical
        else json.dumps(manifest, indent=2).encode("ascii")
    )
    members[0] = (RUNTIME_OVERLAY_MANIFEST, encoded)
    return _write_zip(members)


def _assert_rejected(raw: bytes, reason_code: str | None = None) -> RuntimeOverlayError:
    with pytest.raises(RuntimeOverlayError) as caught:
        import_runtime_overlay(raw, _digest(raw))
    if reason_code is not None:
        assert caught.value.reason_code == reason_code
    assert str(caught.value) == caught.value.reason_code
    return caught.value


def test_builder_is_deterministic_for_repo_and_package_mapping(built_overlay: bytes) -> None:
    from_mapping = build_runtime_overlay(
        {"secp_worker": PACKAGE_ROOTS["secp_worker"], "secp_api": PACKAGE_ROOTS["secp_api"]}
    )

    assert built_overlay == from_mapping
    assert built_overlay == build_runtime_overlay(REPOSITORY)
    assert runtime_overlay_sha256(built_overlay) == _digest(built_overlay)


def test_import_returns_immutable_redacted_complete_inventory(built_overlay: bytes) -> None:
    validated = import_runtime_overlay(memoryview(built_overlay), _digest(built_overlay))
    expected_paths = {
        f"{package}/{path.relative_to(root).as_posix()}"
        for package, root in PACKAGE_ROOTS.items()
        for path in root.rglob("*.py")
        if "__pycache__" not in path.parts
    }

    assert validated.sha256 == _digest(built_overlay)
    assert validated.contract_version == RUNTIME_OVERLAY_CONTRACT_VERSION
    assert validated.package_contract_version == PACKAGE_CONTRACT_VERSION
    assert validated.implementation_id == PACKAGE_IMPLEMENTATION_ID
    assert validated.package_version == PACKAGE_VERSION
    assert validated.packages == RUNTIME_OVERLAY_PACKAGES
    assert {entry.path for entry in validated.files} == expected_paths
    assert RUNTIME_OVERLAY_CRITICAL_FILES <= expected_paths
    assert validated.archive_bytes == built_overlay
    assert bytes(validated) == built_overlay
    assert "_archive_bytes" not in repr(validated)
    assert "PK\\x03\\x04" not in repr(validated)
    with pytest.raises(FrozenInstanceError):
        validated.sha256 = "sha256:" + "0" * 64  # type: ignore[misc]


def test_builder_emits_sorted_fixed_read_only_regular_members(built_overlay: bytes) -> None:
    with zipfile.ZipFile(io.BytesIO(built_overlay), mode="r") as archive:
        infos = archive.infolist()
        assert [info.filename for info in infos] == sorted(info.filename for info in infos)
        assert infos[0].filename == RUNTIME_OVERLAY_MANIFEST
        assert archive.comment == b""
        for info in infos:
            assert info.date_time == (1980, 1, 1, 0, 0, 0)
            assert info.compress_type == zipfile.ZIP_DEFLATED
            assert info.create_system == 3
            assert info.flag_bits == 0
            assert info.extra == b""
            assert info.comment == b""
            assert stat.S_IFMT(info.external_attr >> 16) == stat.S_IFREG
            assert stat.S_IMODE(info.external_attr >> 16) == 0o444


def test_manifest_is_canonical_and_accounts_for_every_member(built_overlay: bytes) -> None:
    members = _members(built_overlay)
    manifest = json.loads(members[0][1])

    assert members[0][1] == overlay_module._canonical_json(manifest)
    assert manifest["contract_version"] == RUNTIME_OVERLAY_CONTRACT_VERSION
    assert manifest["implementation_id"] == PACKAGE_IMPLEMENTATION_ID
    assert manifest["package_contract_version"] == PACKAGE_CONTRACT_VERSION
    assert manifest["package_version"] == PACKAGE_VERSION
    assert [package["name"] for package in manifest["packages"]] == list(RUNTIME_OVERLAY_PACKAGES)
    assert [item["path"] for item in manifest["files"]] == [name for name, _ in members[1:]]


@pytest.mark.parametrize("value", [None, "archive", object(), 1])
def test_import_rejects_non_bytes(value: object) -> None:
    with pytest.raises(RuntimeOverlayError, match="runtime_overlay_bytes_invalid"):
        import_runtime_overlay(value, "sha256:" + "0" * 64)  # type: ignore[arg-type]


def test_import_rejects_oversized_raw_before_zip_parsing() -> None:
    raw = b"x" * (MAX_RUNTIME_OVERLAY_BYTES + 1)
    with pytest.raises(RuntimeOverlayError, match="runtime_overlay_size_invalid"):
        import_runtime_overlay(raw, _digest(raw))


@pytest.mark.parametrize(
    "expected",
    ["0" * 64, "sha256:" + "A" * 64, "sha256:" + "0" * 63, "sha512:" + "0" * 64],
)
def test_import_requires_canonical_expected_digest(built_overlay: bytes, expected: str) -> None:
    with pytest.raises(RuntimeOverlayError, match="runtime_overlay_digest_invalid"):
        import_runtime_overlay(built_overlay, expected)


def test_import_rejects_digest_mismatch_before_archive_parsing(built_overlay: bytes) -> None:
    with pytest.raises(RuntimeOverlayError, match="runtime_overlay_digest_mismatch"):
        import_runtime_overlay(built_overlay, "sha256:" + "0" * 64)


@pytest.mark.parametrize(
    ("name", "metadata"),
    [
        ("timestamp", {"timestamp": (1980, 1, 2, 0, 0, 0)}),
        ("stored", {"compression": zipfile.ZIP_STORED}),
        ("writable", {"external_attributes": (stat.S_IFREG | 0o644) << 16}),
        ("symlink", {"external_attributes": (stat.S_IFLNK | 0o444) << 16}),
        ("fifo", {"external_attributes": (stat.S_IFIFO | 0o444) << 16}),
        ("member_comment", {"member_comment": b"comment"}),
        ("member_extra", {"member_extra": b"\xfe\xca\x00\x00"}),
        ("archive_comment", {"archive_comment": b"comment"}),
    ],
)
def test_import_rejects_noncanonical_or_special_metadata(
    built_overlay: bytes,
    name: str,
    metadata: dict[str, Any],
) -> None:
    del name
    _assert_rejected(_write_zip(_members(built_overlay), **metadata))


def test_import_rejects_encrypted_flag_even_when_outer_digest_matches(
    built_overlay: bytes,
) -> None:
    raw = bytearray(built_overlay)
    with zipfile.ZipFile(io.BytesIO(built_overlay), mode="r") as archive:
        target = archive.infolist()[1]
        central_offset = archive.start_dir
        for info in archive.infolist():
            if info.filename == target.filename:
                break
            central_offset += 46 + len(info.filename.encode("ascii"))
    struct.pack_into("<H", raw, target.header_offset + 6, 1)
    struct.pack_into("<H", raw, central_offset + 8, 1)

    _assert_rejected(bytes(raw), "runtime_overlay_metadata_invalid")


@pytest.mark.parametrize("suffix", [b"trailing", b"PK\x05\x06junk"])
def test_import_rejects_trailing_bytes(built_overlay: bytes, suffix: bytes) -> None:
    _assert_rejected(built_overlay + suffix)


def test_import_rejects_prepended_bytes(built_overlay: bytes) -> None:
    _assert_rejected(b"prefix" + built_overlay)


def test_import_rejects_out_of_order_members(built_overlay: bytes) -> None:
    members = _members(built_overlay)
    members[1], members[2] = members[2], members[1]
    _assert_rejected(_write_zip(members), "runtime_overlay_archive_inventory_invalid")


def test_import_rejects_duplicate_members(built_overlay: bytes) -> None:
    members = _members(built_overlay)
    with pytest.warns(UserWarning, match="Duplicate name"):
        raw = _write_zip([members[0], members[1], members[1], *members[2:]])
    _assert_rejected(raw)


@pytest.mark.parametrize(
    "path",
    [
        "secp_api/../escape.py",
        "secp_api\\escape.py",
        "/secp_api/escape.py",
        "other_package/escape.py",
        "secp_api/not-python.txt",
        "secp_api//escape.py",
    ],
)
def test_import_rejects_traversal_backslash_and_extra_tree_paths(
    built_overlay: bytes,
    path: str,
) -> None:
    members = _members(built_overlay)
    _assert_rejected(_write_zip([members[0], (path, b"pass\n"), *members[1:]]))


def test_import_rejects_unlisted_and_missing_archive_members(built_overlay: bytes) -> None:
    members = _members(built_overlay)
    unlisted = sorted([*members, ("secp_api/extra.py", b"pass\n")])
    # Restore the manifest to the first position while preserving sorted source members.
    unlisted = [next(item for item in unlisted if item[0] == RUNTIME_OVERLAY_MANIFEST)] + [
        item for item in unlisted if item[0] != RUNTIME_OVERLAY_MANIFEST
    ]
    _assert_rejected(_write_zip(unlisted))
    _assert_rejected(_write_zip([members[0], *members[2:]]))


def test_import_rejects_consistently_manifested_missing_critical_file(
    built_overlay: bytes,
) -> None:
    sources = _source_members(built_overlay)
    sources.pop("secp_worker/activation_probe.py")
    raw = _write_zip(_consistent_members(sources))

    _assert_rejected(raw, "runtime_overlay_critical_file_missing")


def test_rollback_fence_helper_is_a_required_overlay_member(built_overlay: bytes) -> None:
    path = "secp_api/discovery_activation_rollback_fence.py"
    assert path in RUNTIME_OVERLAY_CRITICAL_FILES
    sources = _source_members(built_overlay)
    sources.pop(path)

    _assert_rejected(
        _write_zip(_consistent_members(sources)),
        "runtime_overlay_critical_file_missing",
    )


def test_import_rejects_missing_nested_package_initializer(built_overlay: bytes) -> None:
    sources = _source_members(built_overlay)
    sources.pop("secp_worker/target_discovery/__init__.py")
    raw = _write_zip(_consistent_members(sources))

    _assert_rejected(raw, "runtime_overlay_package_incomplete")


def test_import_rejects_wrong_implementation_and_package_contracts(
    built_overlay: bytes,
) -> None:
    def wrong_implementation(manifest: dict[str, Any]) -> None:
        manifest["implementation_id"] = "different/implementation"

    def wrong_package_contract(manifest: dict[str, Any]) -> None:
        manifest["package_contract_version"] = "different/package-contract"

    _assert_rejected(
        _replace_manifest(built_overlay, wrong_implementation),
        "runtime_overlay_contract_mismatch",
    )
    _assert_rejected(
        _replace_manifest(built_overlay, wrong_package_contract),
        "runtime_overlay_contract_mismatch",
    )


def test_import_rejects_noncanonical_and_extra_manifest_fields(built_overlay: bytes) -> None:
    def unchanged(_manifest: dict[str, Any]) -> None:
        return None

    def add_field(manifest: dict[str, Any]) -> None:
        manifest["extra"] = True

    _assert_rejected(
        _replace_manifest(built_overlay, unchanged, canonical=False),
        "runtime_overlay_manifest_noncanonical",
    )
    _assert_rejected(
        _replace_manifest(built_overlay, add_field),
        "runtime_overlay_manifest_invalid",
    )


def test_import_rejects_manifest_size_digest_and_tree_tampering(built_overlay: bytes) -> None:
    def wrong_size(manifest: dict[str, Any]) -> None:
        manifest["files"][0]["size"] += 1

    def wrong_digest(manifest: dict[str, Any]) -> None:
        manifest["files"][0]["sha256"] = "sha256:" + "0" * 64

    def wrong_tree(manifest: dict[str, Any]) -> None:
        manifest["packages"][0]["tree_sha256"] = "sha256:" + "0" * 64

    _assert_rejected(_replace_manifest(built_overlay, wrong_size))
    _assert_rejected(_replace_manifest(built_overlay, wrong_digest))
    _assert_rejected(
        _replace_manifest(built_overlay, wrong_tree),
        "runtime_overlay_package_contract_invalid",
    )


def test_import_rejects_source_content_tamper_with_original_manifest(
    built_overlay: bytes,
) -> None:
    members = _members(built_overlay)
    path, content = members[1]
    members[1] = (path, content + b"\n")

    _assert_rejected(_write_zip(members), "runtime_overlay_content_mismatch")


def test_import_rejects_invalid_python_even_with_consistent_manifest(
    built_overlay: bytes,
) -> None:
    sources = _source_members(built_overlay)
    sources["secp_worker/activation_probe.py"] = b"def incomplete(\n"
    raw = _write_zip(_consistent_members(sources))

    _assert_rejected(raw, "runtime_overlay_python_source_invalid")


def test_import_rejects_high_ratio_member_as_zip_bomb(built_overlay: bytes) -> None:
    sources = _source_members(built_overlay)
    sources["secp_api/__init__.py"] = b"#" * 500_000
    raw = _write_zip(_consistent_members(sources))

    _assert_rejected(raw, "runtime_overlay_compression_ratio_invalid")


def test_builder_rejects_incomplete_package_mapping(tmp_path: Path) -> None:
    api = tmp_path / "api"
    worker = tmp_path / "worker"
    api.mkdir()
    worker.mkdir()
    (api / "__init__.py").write_text("", encoding="utf-8")
    (worker / "__init__.py").write_text("", encoding="utf-8")

    with pytest.raises(RuntimeOverlayError, match="runtime_overlay_critical_file_missing"):
        build_runtime_overlay({"secp_api": api, "secp_worker": worker})


def test_builder_rejects_wrong_mapping_keys() -> None:
    with pytest.raises(RuntimeOverlayError, match="runtime_overlay_source_roots_invalid"):
        build_runtime_overlay({"secp_api": PACKAGE_ROOTS["secp_api"]})


def test_builder_rejects_invalid_mapping_values() -> None:
    with pytest.raises(RuntimeOverlayError, match="runtime_overlay_source_roots_invalid"):
        build_runtime_overlay({"secp_api": None, "secp_worker": None})  # type: ignore[dict-item]


def test_builder_rejects_source_symlink(tmp_path: Path) -> None:
    api = tmp_path / "secp_api"
    worker = tmp_path / "secp_worker"
    api.mkdir()
    worker.mkdir()
    (api / "__init__.py").write_text("", encoding="utf-8")
    (worker / "__init__.py").write_text("", encoding="utf-8")
    target = tmp_path / "target.py"
    target.write_text("pass\n", encoding="utf-8")
    try:
        os.symlink(target, api / "linked.py")
    except OSError:
        pytest.skip("source symlink creation is unavailable")

    with pytest.raises(RuntimeOverlayError, match="runtime_overlay_source_tree_invalid"):
        build_runtime_overlay({"secp_api": api, "secp_worker": worker})
