"""Deterministic, content-addressed PR5F Python runtime overlay.

The production worker image remains pinned.  This module packages one reviewed, internally
consistent ``secp_api`` + ``secp_worker`` Python import closure for the worker's read-only ZIP
import path.  Building and importing an overlay are pure local operations: neither function
writes a file, extracts an archive, imports packaged code, or performs network contact.

The importer deliberately accepts only the exact ZIP dialect emitted by the builder.  Besides
the caller-supplied SHA-256 pin, it validates archive structure, metadata, bounds, a canonical
manifest, every source digest, and the PR5F implementation contract.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import io
import json
import os
import re
import stat
import struct
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from secp_discovery_activation import (
    PACKAGE_CONTRACT_VERSION,
    PACKAGE_IMPLEMENTATION_ID,
    PACKAGE_VERSION,
    DiscoveryActivationError,
)

RUNTIME_OVERLAY_CONTRACT_VERSION = "secp.discovery-runtime-overlay/v1"
RUNTIME_OVERLAY_MANIFEST = "MANIFEST.json"

RUNTIME_OVERLAY_PACKAGES = ("secp_api", "secp_worker")

# These are the PR5F compatibility seam, rather than an attempt to enumerate only the modules
# currently imported by one process entry point.  The artifact still contains both complete
# source trees so a later lazy import cannot fall back into the old base image.
RUNTIME_OVERLAY_CRITICAL_FILES = frozenset(
    {
        "secp_api/__init__.py",
        "secp_api/discovery_activation_rollback_fence.py",
        "secp_api/discovery_models.py",
        "secp_api/discovery_activation_rollback_probe.py",
        "secp_api/enums.py",
        "secp_api/models.py",
        "secp_api/routers/target_discovery.py",
        "secp_api/routers/worker_admission.py",
        "secp_api/routers/worker_identity.py",
        "secp_api/routers/worker_nodes.py",
        "secp_api/services/target_discovery.py",
        "secp_api/services/worker_admission.py",
        "secp_api/services/worker_identity.py",
        "secp_api/services/worker_nodes.py",
        "secp_api/worker_admission_contract.py",
        "secp_api/worker_admission_origin.py",
        "secp_api/worker_identity_contract.py",
        "secp_worker/__init__.py",
        "secp_worker/activation_probe.py",
        "secp_worker/admission_http_transport.py",
        "secp_worker/admission_tls_probe.py",
        "secp_worker/bundle_loop_marker.py",
        "secp_worker/bundle_manager.py",
        "secp_worker/discovery_bundle_runtime.py",
        "secp_worker/main.py",
        "secp_worker/target_discovery/admission_client.py",
        "secp_worker/target_discovery/composition.py",
        "secp_worker/target_discovery/consumer.py",
        "secp_worker/target_discovery/engine.py",
        "secp_worker/target_discovery/runtime.py",
    }
)

# The bounds comfortably cover the current two source trees while making all allocations and
# decompression work predictable.  A larger future tree requires a reviewed contract change.
MAX_RUNTIME_OVERLAY_BYTES = 4 * 1024 * 1024
MAX_RUNTIME_OVERLAY_FILES = 512
MAX_RUNTIME_OVERLAY_FILE_BYTES = 512 * 1024
MAX_RUNTIME_OVERLAY_MANIFEST_BYTES = 256 * 1024
MAX_RUNTIME_OVERLAY_EXPANDED_BYTES = 8 * 1024 * 1024
MAX_RUNTIME_OVERLAY_COMPRESSION_RATIO = 100

_FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_FIXED_DOS_DATE = 33
_FIXED_DOS_TIME = 0
_REGULAR_READ_ONLY_MODE = stat.S_IFREG | 0o444
_EXTERNAL_ATTRIBUTES = _REGULAR_READ_ONLY_MODE << 16
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SOURCE_SEGMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class RuntimeOverlayError(DiscoveryActivationError):
    """A fail-closed overlay error that never includes source or archive content."""


@dataclass(frozen=True, slots=True)
class RuntimeOverlayFile:
    """One immutable, content-addressed source member."""

    path: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class ValidatedRuntimeOverlay:
    """An immutable validated overlay; its archive bytes are intentionally repr-redacted."""

    sha256: str
    contract_version: str
    package_contract_version: str
    implementation_id: str
    package_version: str
    packages: tuple[str, ...]
    files: tuple[RuntimeOverlayFile, ...]
    _archive_bytes: bytes = field(repr=False)

    @property
    def archive_bytes(self) -> bytes:
        """Return the immutable, already-validated ZIP bytes."""

        return self._archive_bytes

    def __bytes__(self) -> bytes:
        return self._archive_bytes


def runtime_overlay_sha256(raw: bytes | bytearray | memoryview) -> str:
    """Return the canonical profile-form SHA-256 digest for bounded byte-like input."""

    archive = _bounded_raw(raw)
    return "sha256:" + hashlib.sha256(archive).hexdigest()


def build_runtime_overlay(
    package_roots: Mapping[str, str | os.PathLike[str]] | str | os.PathLike[str],
) -> bytes:
    """Build deterministic ZIP bytes from package roots or a monorepo root.

    A mapping must contain exactly ``secp_api`` and ``secp_worker`` and point at those package
    directories.  A single path is interpreted as the repository root containing
    ``apps/api/secp_api`` and ``apps/worker/secp_worker``.  Only regular ``.py`` files are read.
    """

    roots = _resolve_package_roots(package_roots)
    sources: dict[str, bytes] = {}
    for package in RUNTIME_OVERLAY_PACKAGES:
        for relative_path, content in _collect_package(package, roots[package]):
            archive_path = f"{package}/{relative_path}"
            if archive_path in sources:
                raise RuntimeOverlayError("runtime_overlay_source_duplicate")
            sources[archive_path] = content

    _validate_source_inventory(frozenset(sources))
    file_records = tuple(
        RuntimeOverlayFile(
            path=path,
            sha256="sha256:" + hashlib.sha256(sources[path]).hexdigest(),
            size=len(sources[path]),
        )
        for path in sorted(sources)
    )
    manifest = _manifest_document(file_records)
    manifest_bytes = _canonical_json(manifest)
    if len(manifest_bytes) > MAX_RUNTIME_OVERLAY_MANIFEST_BYTES:
        raise RuntimeOverlayError("runtime_overlay_manifest_too_large")

    members = {RUNTIME_OVERLAY_MANIFEST: manifest_bytes, **sources}
    raw = _write_canonical_zip(members)
    digest = runtime_overlay_sha256(raw)
    # Keep the builder and importer as one contract.  This also proves that a source tree which
    # built successfully has no syntax or manifest issue before its bytes can be distributed.
    import_runtime_overlay(raw, digest)
    return raw


def import_runtime_overlay(
    raw: bytes | bytearray | memoryview,
    expected_sha256: str,
) -> ValidatedRuntimeOverlay:
    """Validate and import bounded ZIP bytes without extracting or importing packaged code."""

    archive = _bounded_raw(raw)
    if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256):
        raise RuntimeOverlayError("runtime_overlay_digest_invalid")
    actual_sha256 = "sha256:" + hashlib.sha256(archive).hexdigest()
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise RuntimeOverlayError("runtime_overlay_digest_mismatch")

    try:
        with zipfile.ZipFile(io.BytesIO(archive), mode="r", allowZip64=False) as bundle:
            infos = bundle.infolist()
            _validate_archive_inventory(archive, bundle, infos)
            manifest_info = infos[0]
            manifest_bytes = _read_member(bundle, manifest_info, MAX_RUNTIME_OVERLAY_MANIFEST_BYTES)
            manifest = _parse_manifest(manifest_bytes)
            files = _validate_manifest(manifest, infos)
            _validate_member_contents(bundle, infos[1:], files)
    except RuntimeOverlayError:
        raise
    except (
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        EOFError,
        OSError,
        RuntimeError,
        NotImplementedError,
        ValueError,
    ) as exc:
        raise RuntimeOverlayError("runtime_overlay_archive_invalid") from exc

    return ValidatedRuntimeOverlay(
        sha256=actual_sha256,
        contract_version=RUNTIME_OVERLAY_CONTRACT_VERSION,
        package_contract_version=PACKAGE_CONTRACT_VERSION,
        implementation_id=PACKAGE_IMPLEMENTATION_ID,
        package_version=PACKAGE_VERSION,
        packages=RUNTIME_OVERLAY_PACKAGES,
        files=files,
        _archive_bytes=archive,
    )


def _bounded_raw(raw: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise RuntimeOverlayError("runtime_overlay_bytes_invalid")
    try:
        size = raw.nbytes if isinstance(raw, memoryview) else len(raw)
    except (TypeError, ValueError, BufferError) as exc:
        raise RuntimeOverlayError("runtime_overlay_bytes_invalid") from exc
    if size < 22 or size > MAX_RUNTIME_OVERLAY_BYTES:
        raise RuntimeOverlayError("runtime_overlay_size_invalid")
    try:
        result = bytes(raw)
    except (TypeError, ValueError, BufferError, MemoryError) as exc:
        raise RuntimeOverlayError("runtime_overlay_bytes_invalid") from exc
    if len(result) != size:
        raise RuntimeOverlayError("runtime_overlay_bytes_invalid")
    return result


def _resolve_package_roots(
    value: Mapping[str, str | os.PathLike[str]] | str | os.PathLike[str],
) -> dict[str, Path]:
    if isinstance(value, Mapping):
        if set(value) != set(RUNTIME_OVERLAY_PACKAGES) or any(
            not isinstance(name, str) for name in value
        ):
            raise RuntimeOverlayError("runtime_overlay_source_roots_invalid")
        try:
            candidates = {name: Path(value[name]) for name in RUNTIME_OVERLAY_PACKAGES}
        except (TypeError, ValueError, OSError) as exc:
            raise RuntimeOverlayError("runtime_overlay_source_roots_invalid") from exc
    elif isinstance(value, (str, os.PathLike)):
        try:
            repository = Path(value)
        except (TypeError, ValueError, OSError) as exc:
            raise RuntimeOverlayError("runtime_overlay_source_roots_invalid") from exc
        candidates = {
            "secp_api": repository / "apps" / "api" / "secp_api",
            "secp_worker": repository / "apps" / "worker" / "secp_worker",
        }
    else:
        raise RuntimeOverlayError("runtime_overlay_source_roots_invalid")

    roots: dict[str, Path] = {}
    for package, candidate in candidates.items():
        try:
            metadata = candidate.lstat()
        except (OSError, ValueError) as exc:
            raise RuntimeOverlayError("runtime_overlay_source_root_invalid") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeOverlayError("runtime_overlay_source_root_invalid")
        roots[package] = candidate
    return roots


def _collect_package(package: str, root: Path) -> tuple[tuple[str, bytes], ...]:
    collected: list[tuple[str, bytes]] = []
    try:
        walk = os.walk(root, topdown=True, followlinks=False)
        for current_raw, directory_names, file_names in walk:
            current = Path(current_raw)
            directory_names.sort()
            file_names.sort()
            for directory_name in tuple(directory_names):
                child = current / directory_name
                metadata = child.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    raise RuntimeOverlayError("runtime_overlay_source_tree_invalid")
                if directory_name == "__pycache__":
                    directory_names.remove(directory_name)
                    continue
                if not _SOURCE_SEGMENT.fullmatch(directory_name):
                    raise RuntimeOverlayError("runtime_overlay_source_path_invalid")
            for file_name in file_names:
                path = current / file_name
                metadata = path.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                    raise RuntimeOverlayError("runtime_overlay_source_tree_invalid")
                if path.suffix != ".py":
                    continue
                if not _SOURCE_SEGMENT.fullmatch(path.stem):
                    raise RuntimeOverlayError("runtime_overlay_source_path_invalid")
                relative = path.relative_to(root).as_posix()
                _validate_source_path(f"{package}/{relative}")
                content = _read_regular_source(path, metadata)
                _validate_python_source(content, f"{package}/{relative}")
                collected.append((relative, content))
    except RuntimeOverlayError:
        raise
    except (OSError, ValueError) as exc:
        raise RuntimeOverlayError("runtime_overlay_source_tree_invalid") from exc

    collected.sort(key=lambda item: item[0])
    return tuple(collected)


def _read_regular_source(path: Path, initial: os.stat_result) -> bytes:
    if initial.st_size < 0 or initial.st_size > MAX_RUNTIME_OVERLAY_FILE_BYTES:
        raise RuntimeOverlayError("runtime_overlay_source_file_too_large")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_RUNTIME_OVERLAY_FILE_BYTES:
            raise RuntimeOverlayError("runtime_overlay_source_tree_invalid")
        if _identity_changed(initial, before):
            raise RuntimeOverlayError("runtime_overlay_source_changed")
        chunks: list[bytes] = []
        remaining = MAX_RUNTIME_OVERLAY_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(content) > MAX_RUNTIME_OVERLAY_FILE_BYTES:
            raise RuntimeOverlayError("runtime_overlay_source_file_too_large")
        if _identity_changed(before, after) or before.st_size != after.st_size:
            raise RuntimeOverlayError("runtime_overlay_source_changed")
        if len(content) != after.st_size:
            raise RuntimeOverlayError("runtime_overlay_source_changed")
        return content
    except RuntimeOverlayError:
        raise
    except OSError as exc:
        raise RuntimeOverlayError("runtime_overlay_source_read_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _identity_changed(left: os.stat_result, right: os.stat_result) -> bool:
    if not stat.S_ISREG(right.st_mode):
        return True
    # st_ino may be zero on unusual filesystems.  Size/mode checks still protect that fallback.
    if left.st_ino and right.st_ino:
        return left.st_dev != right.st_dev or left.st_ino != right.st_ino
    return stat.S_IFMT(left.st_mode) != stat.S_IFMT(right.st_mode)


def _validate_source_inventory(paths: frozenset[str]) -> None:
    if not RUNTIME_OVERLAY_CRITICAL_FILES.issubset(paths):
        raise RuntimeOverlayError("runtime_overlay_critical_file_missing")
    if len(paths) > MAX_RUNTIME_OVERLAY_FILES:
        raise RuntimeOverlayError("runtime_overlay_file_count_invalid")
    for package in RUNTIME_OVERLAY_PACKAGES:
        if f"{package}/__init__.py" not in paths:
            raise RuntimeOverlayError("runtime_overlay_package_incomplete")
    # A regular package at every level prevents an overlay import from silently extending into
    # the older image through namespace-package resolution.
    for path in paths:
        parts = PurePosixPath(path).parts
        for depth in range(2, len(parts)):
            package_init = "/".join((*parts[:depth], "__init__.py"))
            if package_init not in paths:
                raise RuntimeOverlayError("runtime_overlay_package_incomplete")


def _manifest_document(files: tuple[RuntimeOverlayFile, ...]) -> dict[str, Any]:
    packages: list[dict[str, Any]] = []
    for package in RUNTIME_OVERLAY_PACKAGES:
        package_files = tuple(item for item in files if item.path.startswith(f"{package}/"))
        packages.append(
            {
                "file_count": len(package_files),
                "name": package,
                "tree_sha256": _tree_sha256(package_files),
            }
        )
    return {
        "contract_version": RUNTIME_OVERLAY_CONTRACT_VERSION,
        "files": [{"path": item.path, "sha256": item.sha256, "size": item.size} for item in files],
        "implementation_id": PACKAGE_IMPLEMENTATION_ID,
        "package_contract_version": PACKAGE_CONTRACT_VERSION,
        "package_version": PACKAGE_VERSION,
        "packages": packages,
    }


def _tree_sha256(files: tuple[RuntimeOverlayFile, ...]) -> str:
    digest = hashlib.sha256()
    for item in files:
        digest.update(item.path.encode("ascii"))
        digest.update(b"\0")
        digest.update(item.sha256.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(item.size).encode("ascii"))
        digest.update(b"\n")
    return "sha256:" + digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        + b"\n"
    )


def _write_canonical_zip(members: Mapping[str, bytes]) -> bytes:
    ordered_names = sorted(members)
    if not ordered_names or ordered_names[0] != RUNTIME_OVERLAY_MANIFEST:
        raise RuntimeOverlayError("runtime_overlay_archive_inventory_invalid")
    output = io.BytesIO()
    try:
        with zipfile.ZipFile(
            output,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            allowZip64=False,
            strict_timestamps=True,
        ) as bundle:
            for name in ordered_names:
                info = zipfile.ZipInfo(name, date_time=_FIXED_TIMESTAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.create_version = 20
                info.extract_version = 20
                info.external_attr = _EXTERNAL_ATTRIBUTES
                info.internal_attr = 0
                info.flag_bits = 0
                info.extra = b""
                info.comment = b""
                bundle.writestr(
                    info,
                    members[name],
                    compress_type=zipfile.ZIP_DEFLATED,
                    compresslevel=9,
                )
    except (OSError, RuntimeError, ValueError, zipfile.LargeZipFile) as exc:
        raise RuntimeOverlayError("runtime_overlay_build_failed") from exc
    raw = output.getvalue()
    if len(raw) > MAX_RUNTIME_OVERLAY_BYTES:
        raise RuntimeOverlayError("runtime_overlay_size_invalid")
    return raw


def _validate_archive_inventory(
    raw: bytes,
    bundle: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
) -> None:
    if bundle.comment != b"" or not (2 <= len(infos) <= MAX_RUNTIME_OVERLAY_FILES + 1):
        raise RuntimeOverlayError("runtime_overlay_archive_inventory_invalid")
    names = [info.filename for info in infos]
    if names != sorted(names) or names[0] != RUNTIME_OVERLAY_MANIFEST:
        raise RuntimeOverlayError("runtime_overlay_archive_inventory_invalid")
    if len(names) != len(set(names)) or len(names) != len({name.casefold() for name in names}):
        raise RuntimeOverlayError("runtime_overlay_archive_duplicate")

    expanded = 0
    compressed = 0
    for index, info in enumerate(infos):
        _validate_zip_info(info, is_manifest=index == 0)
        expanded += info.file_size
        compressed += info.compress_size
        if expanded > MAX_RUNTIME_OVERLAY_EXPANDED_BYTES:
            raise RuntimeOverlayError("runtime_overlay_expanded_size_invalid")
        if info.file_size and (
            info.compress_size <= 0
            or info.file_size > info.compress_size * MAX_RUNTIME_OVERLAY_COMPRESSION_RATIO
        ):
            raise RuntimeOverlayError("runtime_overlay_compression_ratio_invalid")
    if expanded and (
        compressed <= 0 or expanded > compressed * MAX_RUNTIME_OVERLAY_COMPRESSION_RATIO
    ):
        raise RuntimeOverlayError("runtime_overlay_compression_ratio_invalid")
    _validate_zip_structure(raw, bundle, infos)


def _validate_zip_info(info: zipfile.ZipInfo, *, is_manifest: bool) -> None:
    if not isinstance(info.filename, str):
        raise RuntimeOverlayError("runtime_overlay_archive_path_invalid")
    if is_manifest:
        if info.filename != RUNTIME_OVERLAY_MANIFEST:
            raise RuntimeOverlayError("runtime_overlay_archive_inventory_invalid")
        limit = MAX_RUNTIME_OVERLAY_MANIFEST_BYTES
    else:
        _validate_source_path(info.filename)
        limit = MAX_RUNTIME_OVERLAY_FILE_BYTES
    if (
        info.date_time != _FIXED_TIMESTAMP
        or info.compress_type != zipfile.ZIP_DEFLATED
        or info.comment != b""
        or info.extra != b""
        or info.create_system != 3
        or info.create_version != 20
        or info.extract_version != 20
        or info.external_attr != _EXTERNAL_ATTRIBUTES
        or info.internal_attr != 0
        or info.flag_bits != 0
        or info.volume != 0
        or info.reserved != 0
    ):
        raise RuntimeOverlayError("runtime_overlay_metadata_invalid")
    if info.is_dir() or info.file_size < 0 or info.file_size > limit or info.compress_size < 0:
        raise RuntimeOverlayError("runtime_overlay_member_size_invalid")
    mode = info.external_attr >> 16
    if stat.S_IFMT(mode) != stat.S_IFREG or stat.S_IMODE(mode) != 0o444:
        raise RuntimeOverlayError("runtime_overlay_member_type_invalid")


def _validate_source_path(path: str) -> None:
    if (
        not path
        or len(path) > 255
        or "\\" in path
        or "\0" in path
        or not path.isascii()
        or path.startswith("/")
        or path.endswith("/")
    ):
        raise RuntimeOverlayError("runtime_overlay_archive_path_invalid")
    parsed = PurePosixPath(path)
    if parsed.as_posix() != path or any(part in {"", ".", ".."} for part in parsed.parts):
        raise RuntimeOverlayError("runtime_overlay_archive_path_invalid")
    if len(parsed.parts) < 2 or parsed.parts[0] not in RUNTIME_OVERLAY_PACKAGES:
        raise RuntimeOverlayError("runtime_overlay_archive_path_invalid")
    if parsed.suffix != ".py" or not _SOURCE_SEGMENT.fullmatch(parsed.stem):
        raise RuntimeOverlayError("runtime_overlay_archive_path_invalid")
    if any(not _SOURCE_SEGMENT.fullmatch(part) for part in parsed.parts[1:-1]):
        raise RuntimeOverlayError("runtime_overlay_archive_path_invalid")


def _validate_zip_structure(
    raw: bytes,
    bundle: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
) -> None:
    next_offset = 0
    for info in infos:
        name = info.filename.encode("ascii")
        if info.header_offset != next_offset or raw[next_offset : next_offset + 4] != b"PK\x03\x04":
            raise RuntimeOverlayError("runtime_overlay_structure_invalid")
        try:
            local = struct.unpack_from("<4s5H3L2H", raw, next_offset)
        except struct.error as exc:
            raise RuntimeOverlayError("runtime_overlay_structure_invalid") from exc
        (
            signature,
            extract_version,
            flags,
            compression,
            modified_time,
            modified_date,
            crc,
            compressed_size,
            file_size,
            name_size,
            extra_size,
        ) = local
        local_name_start = next_offset + 30
        local_name_end = local_name_start + name_size
        if (
            signature != b"PK\x03\x04"
            or extract_version != 20
            or flags != 0
            or compression != zipfile.ZIP_DEFLATED
            or modified_time != _FIXED_DOS_TIME
            or modified_date != _FIXED_DOS_DATE
            or crc != info.CRC
            or compressed_size != info.compress_size
            or file_size != info.file_size
            or name_size != len(name)
            or extra_size != 0
            or raw[local_name_start:local_name_end] != name
        ):
            raise RuntimeOverlayError("runtime_overlay_structure_invalid")
        next_offset = local_name_end + info.compress_size

    if bundle.start_dir != next_offset:
        raise RuntimeOverlayError("runtime_overlay_structure_invalid")
    central_size = sum(46 + len(info.filename.encode("ascii")) for info in infos)
    eocd_offset = next_offset + central_size
    if eocd_offset + 22 != len(raw) or raw[eocd_offset : eocd_offset + 4] != b"PK\x05\x06":
        raise RuntimeOverlayError("runtime_overlay_structure_invalid")
    try:
        eocd = struct.unpack_from("<4s4H2LH", raw, eocd_offset)
    except struct.error as exc:
        raise RuntimeOverlayError("runtime_overlay_structure_invalid") from exc
    signature, disk, central_disk, disk_count, total_count, size, offset, comment_size = eocd
    if (
        signature != b"PK\x05\x06"
        or disk != 0
        or central_disk != 0
        or disk_count != len(infos)
        or total_count != len(infos)
        or size != central_size
        or offset != next_offset
        or comment_size != 0
    ):
        raise RuntimeOverlayError("runtime_overlay_structure_invalid")


def _read_member(bundle: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    try:
        with bundle.open(info, mode="r") as stream:
            content = stream.read(limit + 1)
            if len(content) > limit or stream.read(1):
                raise RuntimeOverlayError("runtime_overlay_member_size_invalid")
    except RuntimeOverlayError:
        raise
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError, NotImplementedError) as exc:
        raise RuntimeOverlayError("runtime_overlay_member_invalid") from exc
    if len(content) != info.file_size:
        raise RuntimeOverlayError("runtime_overlay_member_size_invalid")
    return content


def _parse_manifest(raw: bytes) -> dict[str, Any]:
    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeOverlayError("runtime_overlay_manifest_invalid")
            result[key] = value
        return result

    def reject_constant(_value: str) -> Any:
        raise RuntimeOverlayError("runtime_overlay_manifest_invalid")

    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except RuntimeOverlayError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RuntimeOverlayError("runtime_overlay_manifest_invalid") from exc
    if not isinstance(value, dict) or raw != _canonical_json(value):
        raise RuntimeOverlayError("runtime_overlay_manifest_noncanonical")
    return value


def _validate_manifest(
    manifest: dict[str, Any],
    infos: list[zipfile.ZipInfo],
) -> tuple[RuntimeOverlayFile, ...]:
    if set(manifest) != {
        "contract_version",
        "files",
        "implementation_id",
        "package_contract_version",
        "package_version",
        "packages",
    }:
        raise RuntimeOverlayError("runtime_overlay_manifest_invalid")
    if (
        manifest.get("contract_version") != RUNTIME_OVERLAY_CONTRACT_VERSION
        or manifest.get("implementation_id") != PACKAGE_IMPLEMENTATION_ID
        or manifest.get("package_contract_version") != PACKAGE_CONTRACT_VERSION
        or manifest.get("package_version") != PACKAGE_VERSION
    ):
        raise RuntimeOverlayError("runtime_overlay_contract_mismatch")

    raw_files = manifest.get("files")
    if not isinstance(raw_files, list) or len(raw_files) != len(infos) - 1:
        raise RuntimeOverlayError("runtime_overlay_manifest_invalid")
    files: list[RuntimeOverlayFile] = []
    for raw_file in raw_files:
        if not isinstance(raw_file, dict) or set(raw_file) != {"path", "sha256", "size"}:
            raise RuntimeOverlayError("runtime_overlay_manifest_invalid")
        path = raw_file.get("path")
        digest = raw_file.get("sha256")
        size = raw_file.get("size")
        if not isinstance(path, str):
            raise RuntimeOverlayError("runtime_overlay_manifest_invalid")
        _validate_source_path(path)
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise RuntimeOverlayError("runtime_overlay_manifest_invalid")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not (0 <= size <= MAX_RUNTIME_OVERLAY_FILE_BYTES)
        ):
            raise RuntimeOverlayError("runtime_overlay_manifest_invalid")
        files.append(RuntimeOverlayFile(path=path, sha256=digest, size=size))
    paths = [item.path for item in files]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise RuntimeOverlayError("runtime_overlay_manifest_invalid")
    if [info.filename for info in infos[1:]] != paths:
        raise RuntimeOverlayError("runtime_overlay_archive_unlisted_member")
    _validate_source_inventory(frozenset(paths))

    raw_packages = manifest.get("packages")
    if not isinstance(raw_packages, list) or len(raw_packages) != len(RUNTIME_OVERLAY_PACKAGES):
        raise RuntimeOverlayError("runtime_overlay_manifest_invalid")
    expected_packages: list[dict[str, Any]] = []
    file_tuple = tuple(files)
    for package in RUNTIME_OVERLAY_PACKAGES:
        package_files = tuple(item for item in file_tuple if item.path.startswith(f"{package}/"))
        expected_packages.append(
            {
                "file_count": len(package_files),
                "name": package,
                "tree_sha256": _tree_sha256(package_files),
            }
        )
    if raw_packages != expected_packages:
        raise RuntimeOverlayError("runtime_overlay_package_contract_invalid")
    return file_tuple


def _validate_member_contents(
    bundle: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
    files: tuple[RuntimeOverlayFile, ...],
) -> None:
    for info, declared in zip(infos, files, strict=True):
        if info.file_size != declared.size:
            raise RuntimeOverlayError("runtime_overlay_content_mismatch")
        content = _read_member(bundle, info, MAX_RUNTIME_OVERLAY_FILE_BYTES)
        actual = "sha256:" + hashlib.sha256(content).hexdigest()
        if not hmac.compare_digest(actual, declared.sha256):
            raise RuntimeOverlayError("runtime_overlay_content_mismatch")
        _validate_python_source(content, declared.path)


def _validate_python_source(content: bytes, path: str) -> None:
    try:
        compile(content, path, "exec", flags=ast.PyCF_ONLY_AST, dont_inherit=True, optimize=0)
    except (SyntaxError, UnicodeError, ValueError, TypeError, MemoryError) as exc:
        raise RuntimeOverlayError("runtime_overlay_python_source_invalid") from exc


__all__ = [
    "MAX_RUNTIME_OVERLAY_BYTES",
    "MAX_RUNTIME_OVERLAY_COMPRESSION_RATIO",
    "MAX_RUNTIME_OVERLAY_EXPANDED_BYTES",
    "MAX_RUNTIME_OVERLAY_FILES",
    "MAX_RUNTIME_OVERLAY_FILE_BYTES",
    "MAX_RUNTIME_OVERLAY_MANIFEST_BYTES",
    "RUNTIME_OVERLAY_CONTRACT_VERSION",
    "RUNTIME_OVERLAY_CRITICAL_FILES",
    "RUNTIME_OVERLAY_MANIFEST",
    "RUNTIME_OVERLAY_PACKAGES",
    "RuntimeOverlayError",
    "RuntimeOverlayFile",
    "ValidatedRuntimeOverlay",
    "build_runtime_overlay",
    "import_runtime_overlay",
    "runtime_overlay_sha256",
]
