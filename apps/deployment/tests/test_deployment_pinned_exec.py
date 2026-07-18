"""Executable object-pinning (SECP-PR5D, blocker #3), POSIX.

Exercises the digest / symlink / type / absolute-path checks on a user-owned sandbox binary
(``require_root=False``). The ownership refusal (``require_root=True``) is a root-only check and
runs
only under euid 0. Skips on non-POSIX (the pinning uses O_NOFOLLOW + /proc/self/fd).
"""

from __future__ import annotations

import hashlib
import os

import pytest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="object pinning is POSIX-only")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write_exe(tmp_path, name, data=b"#!/bin/true\n"):
    p = tmp_path / name
    p.write_bytes(data)
    os.chmod(p, 0o755)
    return str(p)


def test_valid_object_opens_and_matches(tmp_path):
    from secp_operator_deployment.pinned_exec import ExecutablePin, open_pinned_executable

    data = b"#!/bin/sh\nexit 0\n"
    path = _write_exe(tmp_path, "tool", data)
    fd = open_pinned_executable(ExecutablePin(path, _digest(data)), require_root=False)
    try:
        assert isinstance(fd, int)
    finally:
        os.close(fd)


def test_digest_mismatch_refuses(tmp_path):
    from secp_operator_deployment.pinned_exec import (
        ExecutablePin,
        ExecutablePinError,
        open_pinned_executable,
    )

    path = _write_exe(tmp_path, "tool", b"real-content")
    with pytest.raises(ExecutablePinError) as exc:
        open_pinned_executable(ExecutablePin(path, _digest(b"different")), require_root=False)
    assert exc.value.reason_code == "executable_digest_mismatch"


def test_symlink_refuses(tmp_path):
    from secp_operator_deployment.pinned_exec import (
        ExecutablePin,
        ExecutablePinError,
        open_pinned_executable,
    )

    data = b"#!/bin/sh\nexit 0\n"
    real = _write_exe(tmp_path, "real", data)
    link = str(tmp_path / "link")
    os.symlink(real, link)
    with pytest.raises(ExecutablePinError):  # O_NOFOLLOW refuses the symlink
        open_pinned_executable(ExecutablePin(link, _digest(data)), require_root=False)


def test_non_absolute_refuses():
    from secp_operator_deployment.pinned_exec import (
        ExecutablePin,
        ExecutablePinError,
        open_pinned_executable,
    )

    with pytest.raises(ExecutablePinError) as exc:
        open_pinned_executable(
            ExecutablePin("relative/tool", "sha256:" + "0" * 64), require_root=False
        )
    assert exc.value.reason_code == "executable_not_absolute"


def test_group_writable_refuses(tmp_path):
    from secp_operator_deployment.pinned_exec import (
        ExecutablePin,
        ExecutablePinError,
        open_pinned_executable,
    )

    data = b"x"
    path = _write_exe(tmp_path, "tool", data)
    os.chmod(path, 0o775)  # group-writable → untrusted
    with pytest.raises(ExecutablePinError) as exc:
        open_pinned_executable(ExecutablePin(path, _digest(data)), require_root=False)
    assert exc.value.reason_code == "executable_untrusted_mode"


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="root-owner refusal needs a non-root file under root",
)
def test_untrusted_owner_refuses_as_root(tmp_path):
    from secp_operator_deployment.pinned_exec import (
        ExecutablePin,
        ExecutablePinError,
        open_pinned_executable,
    )

    data = b"x"
    path = _write_exe(tmp_path, "tool", data)
    os.chown(path, 1000, 0)  # non-root owner
    with pytest.raises(ExecutablePinError) as exc:
        open_pinned_executable(ExecutablePin(path, _digest(data)))  # require_root=True (default)
    assert exc.value.reason_code == "executable_untrusted_owner"
