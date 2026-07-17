"""Symlink-safe filesystem backend (SECP-PR5C, defects #2, #8, #9)."""

from __future__ import annotations

import pytest
from secp_commissioning.runtime import FilesystemError, InMemoryFilesystem

ROOT = "/opt/secp/operator"
FILE = ROOT + "/entrypoint.py"


def _fs():
    return InMemoryFilesystem()


def test_makedir_and_install_and_read_roundtrip():
    fs = _fs()
    fs.makedir(ROOT, uid=0, gid=0, mode=0o750)
    fs.atomic_install(FILE, b"data", uid=0, gid=0, mode=0o750)
    assert fs.safe_read(FILE, max_bytes=100, expected_uid=0) == b"data"
    assert fs.sha256(FILE).startswith("sha256:")


def test_ancestor_symlink_is_refused():
    fs = _fs()
    fs.seed_symlink(ROOT)  # operator root replaced by a symlink
    with pytest.raises(FilesystemError) as exc:
        fs.atomic_install(FILE, b"x", uid=0, gid=0, mode=0o750)
    assert exc.value.reason_code == "fs_ancestor_symlink"


def test_ancestor_not_directory_is_refused():
    fs = _fs()
    fs.seed_file(ROOT, b"iamfile")  # operator root is a file
    with pytest.raises(FilesystemError) as exc:
        fs.atomic_install(FILE, b"x", uid=0, gid=0, mode=0o750)
    assert exc.value.reason_code == "fs_ancestor_not_directory"


def test_target_symlink_is_refused():
    fs = _fs()
    fs.makedir(ROOT, uid=0, gid=0, mode=0o750)
    fs.seed_symlink(FILE)
    with pytest.raises(FilesystemError) as exc:
        fs.atomic_install(FILE, b"x", uid=0, gid=0, mode=0o750)
    assert exc.value.reason_code == "fs_target_symlink"


def test_target_directory_is_refused():
    fs = _fs()
    fs.makedir(ROOT, uid=0, gid=0, mode=0o750)
    fs.seed_dir(FILE)
    with pytest.raises(FilesystemError) as exc:
        fs.atomic_install(FILE, b"x", uid=0, gid=0, mode=0o750)
    assert exc.value.reason_code == "fs_target_is_directory"


def test_target_special_is_refused():
    fs = _fs()
    fs.makedir(ROOT, uid=0, gid=0, mode=0o750)
    fs.seed_special(FILE)
    with pytest.raises(FilesystemError) as exc:
        fs.atomic_install(FILE, b"x", uid=0, gid=0, mode=0o750)
    assert exc.value.reason_code == "fs_target_special"


def test_target_hardlink_is_refused():
    fs = _fs()
    fs.makedir(ROOT, uid=0, gid=0, mode=0o750)
    fs.seed_file(FILE, b"x", nlink=2)
    with pytest.raises(FilesystemError) as exc:
        fs.atomic_install(FILE, b"x", uid=0, gid=0, mode=0o750)
    assert exc.value.reason_code == "fs_target_hardlinked"


def test_makedir_target_symlink_is_refused():
    fs = _fs()
    fs.seed_symlink(ROOT)
    with pytest.raises(FilesystemError) as exc:
        fs.makedir(ROOT, uid=0, gid=0, mode=0o750)
    assert exc.value.reason_code == "fs_target_symlink"


def test_safe_read_refuses_oversize_and_untrusted():
    fs = _fs()
    fs.makedir(ROOT, uid=0, gid=0, mode=0o750)
    fs.seed_file(FILE, b"toolong", uid=0, mode=0o640)
    with pytest.raises(FilesystemError) as exc:
        fs.safe_read(FILE, max_bytes=3, expected_uid=0)
    assert exc.value.reason_code == "fs_read_size_invalid"
    fs.seed_file(FILE, b"data", uid=1000, mode=0o640)  # wrong owner
    with pytest.raises(FilesystemError):
        fs.safe_read(FILE, max_bytes=100, expected_uid=0)


def test_safe_read_refuses_hardlinked_and_symlink():
    fs = _fs()
    fs.makedir(ROOT, uid=0, gid=0, mode=0o750)
    fs.seed_file(FILE, b"data", nlink=2)
    with pytest.raises(FilesystemError) as exc:
        fs.safe_read(FILE, max_bytes=100, expected_uid=0)
    assert exc.value.reason_code == "fs_read_hardlinked"
    fs.seed_symlink(FILE)
    with pytest.raises(FilesystemError):
        fs.safe_read(FILE, max_bytes=100, expected_uid=0)


def test_remove_refuses_symlink_and_nonempty_dir():
    fs = _fs()
    fs.makedir(ROOT, uid=0, gid=0, mode=0o750)
    fs.seed_symlink(FILE)
    with pytest.raises(FilesystemError):
        fs.remove_file(FILE)
    fs2 = _fs()
    fs2.makedir(ROOT, uid=0, gid=0, mode=0o750)
    fs2.seed_file(FILE, b"child")
    with pytest.raises(FilesystemError) as exc:
        fs2.remove_dir(ROOT)  # non-empty
    assert exc.value.reason_code == "fs_remove_dir_not_empty"


# --- defect #3: every ancestor must EXIST + be root-owned + not group/other-writable ---


def test_ancestor_wrong_owner_is_refused():
    fs = _fs()
    fs.seed_dir("/opt/secp", uid=1000, gid=0, mode=0o755)  # ancestor no longer root-owned
    with pytest.raises(FilesystemError) as exc:
        fs.makedir(ROOT, uid=0, gid=0, mode=0o750)
    assert exc.value.reason_code == "fs_ancestor_untrusted_owner"


def test_ancestor_group_world_writable_is_refused():
    fs = _fs()
    fs.seed_dir("/opt/secp", uid=0, gid=0, mode=0o777)  # group/other writable
    with pytest.raises(FilesystemError) as exc:
        fs.makedir(ROOT, uid=0, gid=0, mode=0o750)
    assert exc.value.reason_code == "fs_ancestor_world_writable"


def test_missing_ancestor_is_refused_not_magically_created():
    # A managed write NEVER silently relies on an absent parent: an install target whose parent does
    # not exist is refused rather than created.
    fs = _fs()
    orphan = "/opt/secp/nowhere/child.py"
    with pytest.raises(FilesystemError) as exc:
        fs.atomic_install(orphan, b"x", uid=0, gid=0, mode=0o640)
    assert exc.value.reason_code == "fs_ancestor_absent"
    assert fs.lstat(orphan) is None


def test_evidence_parent_must_pre_exist_root_owned():
    # The bootstrap-owned evidence parent is pre-seeded root-owned; if it is replaced by an
    # untrusted-owner directory, the evidence write is refused (never silently trusted).
    fs = _fs()
    fs.seed_dir("/var/lib/secp/commissioning", uid=1000, gid=0, mode=0o755)
    with pytest.raises(FilesystemError) as exc:
        fs.atomic_install(
            "/var/lib/secp/commissioning/evidence.json", b"{}", uid=0, gid=0, mode=0o640
        )
    assert exc.value.reason_code == "fs_ancestor_untrusted_owner"


def test_list_dir_enumerates_immediate_children_only():
    fs = _fs()
    fs.makedir(ROOT, uid=0, gid=0, mode=0o750)
    fs.seed_file(ROOT + "/a.py", b"a")
    fs.seed_file(ROOT + "/b.py", b"b")
    assert fs.list_dir(ROOT) == ("a.py", "b.py")
    assert fs.list_dir(ROOT + "/missing") is None


def test_sha256_and_list_dir_refuse_unsafe_ancestor():
    # Parity with RealFilesystem: content read + enumeration route through the ancestor check, so a
    # world-writable ancestor is refused the same way on both backends.
    fs = _fs()
    fs.makedir(ROOT, uid=0, gid=0, mode=0o750)
    fs.seed_file(FILE, b"x", uid=0, gid=0, mode=0o640)
    fs.seed_dir("/opt/secp", uid=0, gid=0, mode=0o777)  # ancestor now group/other writable
    with pytest.raises(FilesystemError) as exc:
        fs.sha256(FILE)
    assert exc.value.reason_code == "fs_ancestor_world_writable"
    with pytest.raises(FilesystemError):
        fs.list_dir(ROOT)
