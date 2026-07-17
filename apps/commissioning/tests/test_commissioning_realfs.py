"""RealFilesystem (POSIX + root) behaviours (SECP-PR5C, defects #3, #4).

The production backend refuses to operate unless EVERY ancestor is a real, root-owned, non-group/
other-writable directory, so it can only run on POSIX AS ROOT under a root-owned sandbox. These
tests build such a sandbox directly beneath ``/`` (whose only ancestor is ``/`` itself, root-owned
0755) and exercise the ancestor-ownership walk + the TRANSACTIONAL makedir cleanup (a post-mkdir
failure must remove the directory THIS call created). They skip on any host that is not POSIX-root —
the backend-agnostic logic is covered cross-platform by the in-memory backend tests.
"""

from __future__ import annotations

import os
import shutil

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="RealFilesystem requires POSIX + root + root-owned ancestors",
)


@pytest.fixture
def sandbox():
    base = f"/secp_rt_{os.getpid()}"
    shutil.rmtree(base, ignore_errors=True)
    os.mkdir(base, 0o755)
    os.chown(base, 0, 0)
    os.chmod(base, 0o755)
    try:
        yield base
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _fs():
    from secp_commissioning.runtime import RealFilesystem

    return RealFilesystem()


def test_makedir_install_read_list_roundtrip(sandbox):
    fs = _fs()
    d = sandbox + "/d"
    f = d + "/entrypoint.py"
    fs.makedir(d, uid=0, gid=0, mode=0o750)
    fs.atomic_install(f, b"payload", uid=0, gid=0, mode=0o640)
    assert fs.safe_read(f, max_bytes=100, expected_uid=0) == b"payload"
    assert fs.sha256(f).startswith("sha256:")
    assert fs.list_dir(d) == ("entrypoint.py",)
    st = fs.lstat(d)
    assert st.uid == 0 and st.gid == 0 and st.mode == 0o750


def test_untrusted_owner_ancestor_is_refused(sandbox):
    from secp_commissioning.runtime import FilesystemError

    fs = _fs()
    u = sandbox + "/u"
    fs.makedir(u, uid=0, gid=0, mode=0o750)
    os.chown(u, 1000, 0)  # ancestor no longer root-owned
    with pytest.raises(FilesystemError) as exc:
        fs.atomic_install(u + "/f", b"x", uid=0, gid=0, mode=0o640)
    assert exc.value.reason_code == "fs_ancestor_untrusted_owner"


def test_group_world_writable_ancestor_is_refused(sandbox):
    from secp_commissioning.runtime import FilesystemError

    fs = _fs()
    w = sandbox + "/w"
    fs.makedir(w, uid=0, gid=0, mode=0o750)
    os.chmod(w, 0o777)  # group/other writable
    with pytest.raises(FilesystemError) as exc:
        fs.atomic_install(w + "/f", b"x", uid=0, gid=0, mode=0o640)
    assert exc.value.reason_code == "fs_ancestor_world_writable"


def test_transactional_makedir_removes_dir_on_fchown_failure(sandbox, monkeypatch):
    from secp_commissioning.runtime import FilesystemError

    fs = _fs()
    target = sandbox + "/t"

    def _boom(*_a, **_k):
        raise OSError("chown denied")

    monkeypatch.setattr(os, "fchown", _boom)
    with pytest.raises(FilesystemError):
        fs.makedir(target, uid=0, gid=0, mode=0o750)
    assert not os.path.exists(target)  # the directory THIS call created was rolled back


def test_transactional_makedir_removes_dir_on_fchmod_failure(sandbox, monkeypatch):
    from secp_commissioning.runtime import FilesystemError

    fs = _fs()
    target = sandbox + "/t2"

    def _boom(*_a, **_k):
        raise OSError("chmod denied")

    monkeypatch.setattr(os, "fchmod", _boom)
    with pytest.raises(FilesystemError):
        fs.makedir(target, uid=0, gid=0, mode=0o750)
    assert not os.path.exists(target)


def test_transactional_makedir_keeps_preexisting_dir_on_failure(sandbox, monkeypatch):
    # A pre-existing directory (not created by this call) is NEVER removed, even if a post-open step
    # would fail — the cleanup only removes what this invocation created.

    fs = _fs()
    target = sandbox + "/pre"
    fs.makedir(target, uid=0, gid=0, mode=0o750)  # created first, cleanly

    def _boom(*_a, **_k):
        raise OSError("chown denied")

    monkeypatch.setattr(os, "fchown", _boom)
    # Idempotent re-makedir: the dir already exists, so ``created`` is False and no chown runs; it
    # must succeed and leave the directory intact.
    fs.makedir(target, uid=0, gid=0, mode=0o750)
    assert os.path.exists(target)


def test_transactional_makedir_removes_dir_on_open_failure(sandbox, monkeypatch):
    # Failure OPENING the just-created leaf after mkdir succeeds: the trusted-parent walk must be
    # untouched, the created directory rolled back, and the bounded reason preserved.
    from secp_commissioning.runtime import FilesystemError

    fs = _fs()
    target = sandbox + "/aopen"  # unique basename so only the leaf open is intercepted
    real_open = os.open

    def _open(path, *a, **k):
        # Fail ONLY the post-mkdir leaf open (basename), never the "/"+ancestor walk opens.
        if path == "aopen":
            raise OSError("open denied")
        return real_open(path, *a, **k)

    monkeypatch.setattr(os, "open", _open)
    with pytest.raises(FilesystemError) as exc:
        fs.makedir(target, uid=0, gid=0, mode=0o750)
    assert exc.value.reason_code == "fs_makedir_failed"
    monkeypatch.undo()  # restore os.open before the existence check / teardown
    assert not os.path.exists(target)  # the directory this call created was removed


def test_transactional_makedir_cleanup_failure_reason(sandbox, monkeypatch):
    # Failure of the COMPENSATING cleanup: a post-mkdir chown fails AND the rollback rmdir also
    # fails, so absolute atomicity cannot be guaranteed — the distinct reason must surface, and a
    # pre-existing directory must still never be removed.
    from secp_commissioning.runtime import FilesystemError

    fs = _fs()
    preexisting = sandbox + "/keep"
    fs.makedir(preexisting, uid=0, gid=0, mode=0o750)  # created cleanly, must survive

    def _chown_boom(*_a, **_k):
        raise OSError("chown denied")

    def _rmdir_boom(*_a, **_k):
        raise OSError("rmdir denied")

    monkeypatch.setattr(os, "fchown", _chown_boom)
    monkeypatch.setattr(os, "rmdir", _rmdir_boom)

    target = sandbox + "/cleanupfail"
    with pytest.raises(FilesystemError) as exc:
        fs.makedir(target, uid=0, gid=0, mode=0o750)
    assert exc.value.reason_code == "fs_makedir_cleanup_failed"

    # A pre-existing directory is idempotent (created=False → no chown, no rmdir) and is preserved
    # even with both fault injections active.
    fs.makedir(preexisting, uid=0, gid=0, mode=0o750)  # must NOT raise
    assert os.path.exists(preexisting)
