"""Plane-neutral hardened fixed-handoff reader (SECP-PR5H-B2, 2b-3b C2).

POSIX-only: the reader authenticates the fixed handoff object (no-follow open, fstat-on-descriptor,
exact owner/group/mode/nlink, trusted ancestors, bounded read, before/after identity sample). A
non-root CI cannot create a uid-0 file, so these tests pass the process's own uid; production always
uses the uid-0 default. Off POSIX the reader fails closed.
"""

from __future__ import annotations

import os

import pytest
from secp_commissioning.hardened_handoff import HardenedHandoffError, read_hardened_fixed_handoff

_POSIX = os.name == "posix"
_posix = pytest.mark.skipif(not _POSIX, reason="the hardened reader is POSIX-only")


def _read(path, **over):
    kw = {
        "expected_gid": os.getgid() if _POSIX else 0,
        "max_bytes": 4096,
        "expected_uid": os.getuid() if _POSIX else 0,
    }
    kw.update(over)
    return read_hardened_fixed_handoff(path, **kw)


def _valid(tmp_path, data=b"handoff\n"):
    p = tmp_path / "h.json"
    p.write_bytes(data)
    os.chmod(p, 0o640)
    return str(p)


@pytest.mark.skipif(_POSIX, reason="the off-POSIX unsupported refusal")
def test_off_posix_is_unsupported(tmp_path):
    with pytest.raises(HardenedHandoffError) as e:
        read_hardened_fixed_handoff(str(tmp_path / "x"), expected_gid=0, max_bytes=10)
    assert e.value.reason_code == "handoff_reader_unsupported_platform"


@_posix
def test_valid_object_is_read(tmp_path):
    assert _read(_valid(tmp_path)) == b"handoff\n"


@_posix
@pytest.mark.parametrize("mode", [0o600, 0o644, 0o660, 0o604])
def test_wrong_mode_refuses(tmp_path, mode):
    p = _valid(tmp_path)
    os.chmod(p, mode)
    with pytest.raises(HardenedHandoffError) as e:
        _read(p)
    assert e.value.reason_code == "handoff_object_unsafe"


@_posix
def test_wrong_group_refuses(tmp_path):
    with pytest.raises(HardenedHandoffError) as e:
        _read(_valid(tmp_path), expected_gid=os.getgid() + 99999)
    assert e.value.reason_code == "handoff_object_unsafe"


@_posix
def test_symlink_refuses(tmp_path):
    target = _valid(tmp_path)
    link = str(tmp_path / "link.json")
    os.symlink(target, link)
    with pytest.raises(HardenedHandoffError) as e:
        _read(link)
    assert e.value.reason_code == "handoff_unreadable"  # O_NOFOLLOW ELOOP


@_posix
def test_hard_link_refuses(tmp_path):
    target = _valid(tmp_path)
    link = str(tmp_path / "hard.json")
    os.link(target, link)  # nlink becomes 2 on both
    os.chmod(link, 0o640)
    with pytest.raises(HardenedHandoffError) as e:
        _read(link)
    assert e.value.reason_code == "handoff_object_unsafe"


@_posix
def test_non_regular_refuses(tmp_path):
    d = tmp_path / "adir"
    d.mkdir()
    os.chmod(d, 0o640)
    with pytest.raises(HardenedHandoffError) as e:
        _read(str(d))
    assert e.value.reason_code == "handoff_object_unsafe"


@_posix
def test_unsafe_ancestor_refuses(tmp_path):
    parent = tmp_path / "loose"
    parent.mkdir()
    os.chmod(parent, 0o777)  # group/other-writable, non-sticky
    p = parent / "h.json"
    p.write_bytes(b"x")
    os.chmod(p, 0o640)
    with pytest.raises(HardenedHandoffError) as e:
        _read(str(p))
    assert e.value.reason_code == "handoff_ancestor_unsafe"


@_posix
def test_oversized_refuses(tmp_path):
    with pytest.raises(HardenedHandoffError) as e:
        _read(_valid(tmp_path, data=b"x" * 5000), max_bytes=4096)
    assert e.value.reason_code == "handoff_too_large"


@_posix
def test_missing_refuses(tmp_path):
    with pytest.raises(HardenedHandoffError) as e:
        _read(str(tmp_path / "absent.json"))
    assert e.value.reason_code == "handoff_unreadable"


@_posix
def test_relative_path_refuses():
    with pytest.raises(HardenedHandoffError) as e:
        _read("relative/handoff.json")
    assert e.value.reason_code == "handoff_path_not_absolute"
