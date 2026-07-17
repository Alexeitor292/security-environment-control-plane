"""Root-controlled hardened readers for the descriptor + evidence (SECP-PR5C, defects #5C, #8A).

One shared hardening path reads BOTH the fixed root-controlled descriptor and the fixed root-
controlled evidence file: every path component is ``lstat``-ed and any symlink is refused; the final
file is opened ``O_NOFOLLOW`` and re-validated BY DESCRIPTOR (``fstat``: regular / root-owned /
single-hardlink / non-world-writable / bounded); the EXACT ``fstat`` size is read in a bounded loop
(a short read, growth, or trailing byte is refused, and the inode/size is re-checked after the
read);
JSON is parsed with duplicate-key rejection; the file is consumed exactly once. Every failure is a
bounded reason code that never echoes a path, a byte of content, or a parsed value.

All OS interaction goes through an injectable :class:`OsSeam`, so the full hardening —
wrong-ownership,
symlink, permissive-mode, oversize, hardlink, short-read, growth, and replacement-race paths — is
deterministically testable on any platform without real root or real symlinks.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from typing import Any, NoReturn, Protocol

from secp_commissioning.canonical import sha256_bytes
from secp_commissioning.descriptor import (
    MAX_DESCRIPTOR_BYTES,
    CommissioningDescriptor,
    descriptor_digest,
    parse_descriptor,
)
from secp_commissioning.errors import CommissioningError
from secp_commissioning.evidence import evidence_from_dict

ROOT_UID = 0
_WRITE_MASK = 0o022
MAX_EVIDENCE_BYTES = 128 * 1024


class ReaderError(CommissioningError):
    """A root-controlled file failed a strict read check (bounded reason code; never a value)."""


def reject_reader(reason_code: str) -> NoReturn:
    raise ReaderError(reason_code)


class OsSeam(Protocol):
    is_posix: bool

    def lstat(self, path: str) -> os.stat_result: ...
    def open_nofollow(self, path: str) -> int: ...
    def fstat(self, fd: int) -> os.stat_result: ...
    def read(self, fd: int, size: int) -> bytes: ...
    def close(self, fd: int) -> None: ...


class _RealOsSeam:
    is_posix = os.name == "posix"
    _O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
    _O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)

    def lstat(self, path: str) -> os.stat_result:
        return os.lstat(path)

    def open_nofollow(self, path: str) -> int:
        return os.open(path, os.O_RDONLY | self._O_NOFOLLOW | self._O_CLOEXEC)

    def fstat(self, fd: int) -> os.stat_result:
        return os.fstat(fd)

    def read(self, fd: int, size: int) -> bytes:
        return os.read(fd, size)

    def close(self, fd: int) -> None:
        os.close(fd)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            reject_reader("duplicate_key")
        seen[key] = value
    return seen


def _clean_absolute(path: str) -> list[str]:
    if not isinstance(path, str) or not path:
        reject_reader("path_unset")
    if not path.startswith("/"):
        reject_reader("path_not_absolute")
    if "\\" in path or "//" in path or "\x00" in path:
        reject_reader("path_malformed")
    parts = [p for p in path.split("/") if p != ""]
    if not parts or any(p in (".", "..") for p in parts):
        reject_reader("path_traversal")
    return parts


def _check_dir_component(st: os.stat_result, expected_uid: int) -> None:
    if stat.S_ISLNK(st.st_mode):
        reject_reader("path_component_symlink")
    if not stat.S_ISDIR(st.st_mode):
        reject_reader("path_component_not_directory")
    if st.st_uid != expected_uid:
        reject_reader("path_component_not_root_owned")
    if st.st_mode & _WRITE_MASK:
        reject_reader("path_component_world_writable")


def _read_hardened(seam: OsSeam, path: str, *, expected_uid: int, max_bytes: int) -> bytes:
    """Validate every path component, open O_NOFOLLOW, fstat-validate, read the EXACT size, refuse a
    short read / growth / trailing byte / inode change, and return the bytes."""
    if not seam.is_posix:
        reject_reader("reader_non_posix")
    parts = _clean_absolute(path)
    cumulative = ""
    for part in parts[:-1]:
        cumulative += "/" + part
        try:
            st = seam.lstat(cumulative)
        except OSError:
            reject_reader("path_component_missing")
        _check_dir_component(st, expected_uid)
    try:
        leaf = seam.lstat(path)
    except OSError:
        reject_reader("file_missing")
    if stat.S_ISLNK(leaf.st_mode):
        reject_reader("file_symlink")
    try:
        fd = seam.open_nofollow(path)
    except OSError:
        reject_reader("file_open_failed")
    try:
        fst = seam.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            reject_reader("file_not_regular")
        if fst.st_nlink != 1:
            reject_reader("file_hardlinked")
        if fst.st_uid != expected_uid:
            reject_reader("file_not_root_owned")
        if fst.st_mode & _WRITE_MASK:
            reject_reader("file_world_writable")
        size = fst.st_size
        if size <= 0 or size > max_bytes:
            reject_reader("file_size_invalid")
        data = _read_exact(seam, fd, size)
        if seam.read(fd, 1) != b"":
            reject_reader("file_grew")
        fst2 = seam.fstat(fd)
        if fst2.st_size != size or fst2.st_ino != fst.st_ino:
            reject_reader("file_changed")
        return data
    finally:
        seam.close(fd)


def _read_exact(seam: OsSeam, fd: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = seam.read(fd, remaining)
        if not chunk:
            reject_reader("file_short_read")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _parse_json(raw: bytes) -> dict:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        reject_reader("file_not_utf8")
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except ReaderError:
        raise
    except ValueError:
        reject_reader("file_malformed_json")
    if not isinstance(data, dict):
        reject_reader("file_not_object")
    return data


@dataclass(frozen=True)
class ReadDescriptor:
    descriptor: CommissioningDescriptor
    descriptor_digest: str
    raw_sha256: str

    def __repr__(self) -> str:
        return f"ReadDescriptor(digest={self.descriptor_digest})"


class RootControlledDescriptorReader:
    """Reads + strictly validates the root-controlled descriptor, exactly once, failing closed."""

    def __init__(
        self,
        descriptor_path: str,
        *,
        expected_owner_uid: int = ROOT_UID,
        max_bytes: int = MAX_DESCRIPTOR_BYTES,
        os_seam: OsSeam | None = None,
    ) -> None:
        self._path = descriptor_path
        self._uid = expected_owner_uid
        self._max = max_bytes
        self._seam: OsSeam = os_seam if os_seam is not None else _RealOsSeam()
        self._consumed = False

    def read(self) -> ReadDescriptor:
        if self._consumed:
            reject_reader("descriptor_already_read")
        self._consumed = True
        raw = _read_hardened(self._seam, self._path, expected_uid=self._uid, max_bytes=self._max)
        descriptor = parse_descriptor(_parse_json(raw))
        return ReadDescriptor(
            descriptor=descriptor,
            descriptor_digest=descriptor_digest(descriptor),
            raw_sha256=sha256_bytes(raw),
        )


def evidence_exists(fs: object, evidence_path: str) -> bool:
    """True if the fixed evidence path exists (via the filesystem backend's ``lstat``)."""
    return fs.lstat(evidence_path) is not None  # type: ignore[attr-defined]


def read_evidence(fs: object, evidence_path: str, *, max_bytes: int = MAX_EVIDENCE_BYTES):  # noqa: ANN201
    """Strictly read + validate the root-controlled evidence file through the HARDENED filesystem
    backend (``safe_read``: O_NOFOLLOW, root-owned, single hardlink, non-world-writable, EXACT
    bounded
    read with short-read/growth refusal, symlink-safe ancestors), then duplicate-key parse + strict
    schema validation. The same seam as the writer, so read/write share state; never a broad
    unbounded read.
    """
    st = fs.lstat(evidence_path)  # type: ignore[attr-defined]
    if st is None:
        reject_reader("evidence_absent")
    raw = fs.safe_read(evidence_path, max_bytes=max_bytes, expected_uid=ROOT_UID)  # type: ignore[attr-defined]
    return evidence_from_dict(_parse_json(raw))
