"""Root-only trusted dir-fd manifest verification (SECP-PR5D, blocker #2).

Exercises :class:`TrustedManifestReader` / :func:`verify_installed_package_trust` against REAL
root-owned trees on a POSIX host: the happy path (a trusted install's aggregate equals the source
aggregate), and fail-closed refusal of a symlinked package dir, a symlinked ancestor, a
directory-replacement race, a hardlinked module, a non-root-owned / world-writable component, and
extra / missing modules. Trust is anchored in directory FILE DESCRIPTORS from ``/`` — never
``Path.resolve()``.

Requires POSIX + root (only root can create the root-owned adversarial files these checks demand);
skips otherwise. Built root-owned under ``$SECP_ROOT_TEST_DIR`` (default ``/opt``), whose own
ancestors are themselves root-owned and non-world-writable. Wired into the deployment root-security
CI job.
"""

from __future__ import annotations

import os
import shutil
import tempfile

import pytest
from secp_operator_deployment.manifest import (
    COVERED_MODULES,
    ManifestError,
    RealManifestReader,
    TrustedManifestReader,
    compute_manifest,
    verify_installed_package_trust,
)

pytestmark = pytest.mark.skipif(
    os.name != "posix" or getattr(os, "geteuid", lambda: 1)() != 0,  # type: ignore[attr-defined]
    reason="trusted dir-fd trust checks require POSIX + root",
)


def _source_pkg_dir() -> str:
    import secp_operator_deployment

    return os.path.dirname(secp_operator_deployment.__file__)


def _source_aggregate() -> str:
    _per, agg = compute_manifest(RealManifestReader(_source_pkg_dir()))
    return agg


@pytest.fixture
def root_base():  # noqa: ANN201
    # A root-owned, non-world-writable base whose ancestors (/, $SECP_ROOT_TEST_DIR) are root-owned.
    parent = os.environ.get("SECP_ROOT_TEST_DIR", "/opt")
    base = tempfile.mkdtemp(prefix="secp-roottest-", dir=parent)
    os.chmod(base, 0o755)
    try:
        yield base
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _make_trusted_pkg(base: str, name: str = "secp_operator_deployment") -> str:
    """Copy the real covered modules into ``base/name`` as root-owned 0644 files in a 0755 dir (this
    process runs as root, so the copies are root-owned)."""
    pkg = os.path.join(base, name)
    os.mkdir(pkg, 0o755)
    src = _source_pkg_dir()
    for mod in COVERED_MODULES:
        with open(os.path.join(src, mod), "rb") as f:
            data = f.read()
        dest = os.path.join(pkg, mod)
        with open(dest, "wb") as f:
            f.write(data)
        os.chmod(dest, 0o644)
    os.chmod(pkg, 0o755)
    return pkg


def test_trusted_install_aggregate_equals_source(root_base):
    pkg = _make_trusted_pkg(root_base)
    assert verify_installed_package_trust(pkg) == _source_aggregate()


def test_expected_aggregate_match_and_mismatch(root_base):
    pkg = _make_trusted_pkg(root_base)
    # exact match passes
    assert verify_installed_package_trust(pkg, expected_aggregate=_source_aggregate())
    # any other aggregate is refused
    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg, expected_aggregate="sha256:" + "0" * 64)
    assert exc.value.reason_code == "manifest_installed_aggregate_mismatch"


def test_symlinked_package_dir_refused(root_base):
    pkg = _make_trusted_pkg(root_base)
    link = os.path.join(root_base, "linkpkg")
    os.symlink(pkg, link)
    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(link)
    assert exc.value.reason_code == "manifest_ancestor_open_failed"


def test_symlinked_ancestor_refused(root_base):
    real_parent = os.path.join(root_base, "realparent")
    os.mkdir(real_parent, 0o755)
    _make_trusted_pkg(real_parent)
    link_parent = os.path.join(root_base, "linkparent")
    os.symlink(real_parent, link_parent)
    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(os.path.join(link_parent, "secp_operator_deployment"))
    assert exc.value.reason_code == "manifest_ancestor_open_failed"


def test_non_root_owned_ancestor_refused(root_base):
    parent = os.path.join(root_base, "p")
    os.mkdir(parent, 0o755)
    pkg = _make_trusted_pkg(parent)
    os.chown(parent, 1000, 0)  # ancestor no longer root-owned
    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg)
    assert exc.value.reason_code == "manifest_ancestor_not_root_owned"


def test_world_writable_package_dir_refused(root_base):
    pkg = _make_trusted_pkg(root_base)
    os.chmod(pkg, 0o757)  # group/other-writable package dir
    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg)
    assert exc.value.reason_code == "manifest_ancestor_world_writable"


def test_non_root_owned_module_refused(root_base):
    pkg = _make_trusted_pkg(root_base)
    os.chown(os.path.join(pkg, "verify.py"), 1000, 0)  # module no longer root-owned
    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg)
    assert exc.value.reason_code == "manifest_module_not_root_owned"


def test_world_writable_module_refused(root_base):
    pkg = _make_trusted_pkg(root_base)
    os.chmod(os.path.join(pkg, "verify.py"), 0o646)  # group/other-writable module
    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg)
    assert exc.value.reason_code == "manifest_module_untrusted_mode"


def test_hardlinked_module_refused(root_base):
    pkg = _make_trusted_pkg(root_base)
    # A second hard link to a covered module (outside the inventory) makes its nlink == 2.
    os.link(os.path.join(pkg, "verify.py"), os.path.join(root_base, "outside.hardlink"))
    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg)
    assert exc.value.reason_code == "manifest_module_hardlinked"


def test_extra_module_refused(root_base):
    pkg = _make_trusted_pkg(root_base)
    extra = os.path.join(pkg, "sneaky.py")
    with open(extra, "wb") as f:
        f.write(b"x = 1\n")
    os.chmod(extra, 0o644)
    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg)
    assert exc.value.reason_code == "manifest_inventory_mismatch"


def test_missing_module_refused(root_base):
    pkg = _make_trusted_pkg(root_base)
    os.remove(os.path.join(pkg, "runner.py"))
    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg)
    assert exc.value.reason_code == "manifest_inventory_mismatch"


def test_replacement_race_uses_fd_not_path(root_base):
    # After the trusted dir fd is obtained, swapping the path for a symlink to an EVIL dir must NOT
    # change what the reader sees: enumeration + reads go through the fd (the original inode), so a
    # path-level replacement race cannot substitute a different tree. This is the property a
    # Path.resolve()-based check would fail to provide.
    pkg = _make_trusted_pkg(root_base)
    reader = TrustedManifestReader.open(pkg)
    try:
        evil = os.path.join(root_base, "evil")
        os.mkdir(evil, 0o755)
        with open(os.path.join(evil, "sneaky.py"), "wb") as f:
            f.write(b"evil\n")
        os.rename(pkg, pkg + ".moved")
        os.symlink(evil, pkg)  # the path now resolves to evil, but the held fd does not
        names = set(reader.list_modules())
        assert names == set(COVERED_MODULES)  # original inventory via the fd
        assert "sneaky.py" not in names
    finally:
        reader.close()
