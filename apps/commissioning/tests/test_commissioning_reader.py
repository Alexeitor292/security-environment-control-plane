"""Hardened descriptor reader — symlink / race / hardlink / short-read / growth (defect #8A, #9)."""

from __future__ import annotations

import json
import stat

import pytest
from _support import (
    DESCRIPTOR_PATH,
    S_DIR,
    S_LNK,
    S_REG,
    FakeOsSeam,
    FakeStat,
    good_lstats,
    valid_descriptor_raw,
)
from secp_commissioning.reader import ReaderError, RootControlledDescriptorReader

_CONTENT = json.dumps(valid_descriptor_raw()).encode("utf-8")


def _reader(lstats, fstat, content=_CONTENT, is_posix=True):
    seam = FakeOsSeam(lstats, fstat, content, is_posix=is_posix)
    return RootControlledDescriptorReader(DESCRIPTOR_PATH, os_seam=seam)


def _fstat(content=_CONTENT):
    return FakeStat(S_REG, st_size=len(content))


def test_happy_path():
    r = _reader(good_lstats(_CONTENT), _fstat()).read()
    assert r.descriptor_digest.startswith("sha256:")
    assert r.raw_sha256.startswith("sha256:")


def test_second_read_refused():
    reader = _reader(good_lstats(_CONTENT), _fstat())
    reader.read()
    with pytest.raises(ReaderError) as exc:
        reader.read()
    assert exc.value.reason_code == "descriptor_already_read"


def test_symlink_leaf_refused():
    lstats = {**good_lstats(_CONTENT), DESCRIPTOR_PATH: FakeStat(S_LNK)}
    with pytest.raises(ReaderError) as exc:
        _reader(lstats, _fstat()).read()
    assert exc.value.reason_code == "file_symlink"


def test_symlink_ancestor_refused():
    lstats = {**good_lstats(_CONTENT), "/etc/secp": FakeStat(S_LNK)}
    with pytest.raises(ReaderError) as exc:
        _reader(lstats, _fstat()).read()
    assert exc.value.reason_code == "path_component_symlink"


def test_non_root_ancestor_refused():
    lstats = {**good_lstats(_CONTENT), "/etc/secp": FakeStat(S_DIR, st_uid=1000)}
    with pytest.raises(ReaderError) as exc:
        _reader(lstats, _fstat()).read()
    assert exc.value.reason_code == "path_component_not_root_owned"


def test_replacement_race_wrong_owner_via_fstat_refused():
    with pytest.raises(ReaderError) as exc:
        _reader(good_lstats(_CONTENT), FakeStat(S_REG, st_uid=1000, st_size=len(_CONTENT))).read()
    assert exc.value.reason_code == "file_not_root_owned"


def test_hardlinked_refused():
    with pytest.raises(ReaderError) as exc:
        _reader(good_lstats(_CONTENT), FakeStat(S_REG, st_nlink=2, st_size=len(_CONTENT))).read()
    assert exc.value.reason_code == "file_hardlinked"


def test_world_writable_refused():
    with pytest.raises(ReaderError) as exc:
        _reader(good_lstats(_CONTENT), FakeStat(stat.S_IFREG | 0o646, st_size=len(_CONTENT))).read()
    assert exc.value.reason_code == "file_world_writable"


def test_oversized_refused():
    with pytest.raises(ReaderError) as exc:
        _reader(good_lstats(_CONTENT), FakeStat(S_REG, st_size=10**9)).read()
    assert exc.value.reason_code == "file_size_invalid"


def test_short_read_refused():
    # fstat claims a large size, but the file yields fewer bytes.
    with pytest.raises(ReaderError) as exc:
        _reader(good_lstats(_CONTENT), FakeStat(S_REG, st_size=len(_CONTENT) + 50)).read()
    assert exc.value.reason_code == "file_short_read"


def test_growth_refused():
    # fstat claims a small size, but the file has more bytes (trailing growth).
    big = _CONTENT + b"EXTRA"
    with pytest.raises(ReaderError) as exc:
        _reader(good_lstats(big), FakeStat(S_REG, st_size=len(_CONTENT)), content=big).read()
    assert exc.value.reason_code == "file_grew"


def test_duplicate_keys_refused():
    dup = b'{"contract_version":"a","contract_version":"b"}'
    with pytest.raises(ReaderError) as exc:
        _reader(good_lstats(dup), FakeStat(S_REG, st_size=len(dup)), content=dup).read()
    assert exc.value.reason_code == "duplicate_key"


def test_malformed_json_refused():
    bad = b"{not json"
    with pytest.raises(ReaderError) as exc:
        _reader(good_lstats(bad), FakeStat(S_REG, st_size=len(bad)), content=bad).read()
    assert exc.value.reason_code == "file_malformed_json"


def test_non_posix_refused():
    with pytest.raises(ReaderError) as exc:
        _reader(good_lstats(_CONTENT), _fstat(), is_posix=False).read()
    assert exc.value.reason_code == "reader_non_posix"


def test_traversal_path_refused():
    seam = FakeOsSeam(good_lstats(_CONTENT), _fstat(), _CONTENT)
    with pytest.raises(ReaderError) as exc:
        RootControlledDescriptorReader("/etc/secp/../secret", os_seam=seam).read()
    assert exc.value.reason_code == "path_traversal"
