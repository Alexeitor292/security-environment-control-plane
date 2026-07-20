"""Exclusive-create receipt semantics for evidence-key installation."""

from __future__ import annotations

import pytest
from secp_commissioning.runtime import FilesystemError, InMemoryFilesystem


def test_in_memory_exclusive_create_refuses_replace_and_removes_only_receipt_object() -> None:
    fs = InMemoryFilesystem()
    path = "/var/lib/secp/commissioning/exclusive.key"
    receipt = fs.exclusive_install(path, b"owned", uid=0, gid=0, mode=0o600)

    assert fs.created_file_matches(receipt) is True
    with pytest.raises(FilesystemError, match="fs_target_exists"):
        fs.exclusive_install(path, b"replacement", uid=0, gid=0, mode=0o600)
    assert fs.safe_read(path, max_bytes=16, expected_uid=0) == b"owned"
    assert fs.remove_created_file(receipt) is True
    assert fs.lstat(path) is None


def test_in_memory_receipt_never_removes_substituted_object() -> None:
    fs = InMemoryFilesystem()
    path = "/var/lib/secp/commissioning/exclusive.key"
    receipt = fs.exclusive_install(path, b"owned", uid=0, gid=0, mode=0o600)
    fs.seed_file(path, b"foreign", uid=0, gid=0, mode=0o600)

    assert fs.created_file_matches(receipt) is False
    assert fs.remove_created_file(receipt) is False
    assert fs.safe_read(path, max_bytes=16, expected_uid=0) == b"foreign"
