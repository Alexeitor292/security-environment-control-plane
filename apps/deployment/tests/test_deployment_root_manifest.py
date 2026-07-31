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

The fixtures here were STRICTLY FLAT, and every test above behaved identically whether
:meth:`TrustedManifestReader.list_modules` descended into a subdirectory or not — so the bounded
one-level descent, the symlinked-directory refusal and ``_list_subdirectory`` were observed by
nothing on any platform, and ``manifest_nested_directory_unverifiable`` was produced by no test at
all. Deleting all three left the suite green. The descent section at the bottom of this file is the
coverage that makes that revert go red: it is the only place the fd descent EXECUTES, and it can
only run here, because a nested tree of root-owned directories reached through a trusted fd chain
is exactly what the non-root, cross-platform manifest tests cannot build.
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


# --------------------------------------------------------------------------- the bounded descent
#
# Everything above builds a FLAT package, so none of it enters ``_list_subdirectory``. These do.


def _add_subdir(pkg: str, name: str = "sub", mode: int = 0o755) -> str:
    """A root-owned subdirectory inside the package dir (``os.mkdir`` honours umask, so the mode is
    set explicitly — a fixture that silently produced 0755 when it asked for 0777 would make the
    writable-subdirectory test pass for the wrong reason)."""
    sub = os.path.join(pkg, name)
    os.mkdir(sub, mode)
    os.chmod(sub, mode)
    return sub


def _write_module(directory: str, name: str, body: bytes = b"x = 1\n") -> str:
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(body)
    os.chmod(path, 0o644)
    return path


def test_a_nested_module_is_enumerated_by_the_descent_and_refused_by_the_inventory(root_base):
    """The descent's reason for existing: a nested ``.py`` must reach the inventory check.

    A flat enumeration returns exactly ``COVERED_MODULES`` here, matches, and hands back the pinned
    source aggregate — the module sits outside the digest and tampering with it is undetectable.
    So this asserts BOTH that the nested name is enumerated and that it refuses.
    """
    pkg = _make_trusted_pkg(root_base)
    sub = _add_subdir(pkg)
    _write_module(sub, "nested.py")

    reader = TrustedManifestReader.open(pkg)
    try:
        assert "sub/nested.py" in reader.list_modules()
    finally:
        reader.close()

    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg)
    assert exc.value.reason_code == "manifest_inventory_mismatch"


def test_a_trusted_empty_subdirectory_is_walked_not_refused(root_base):
    """The descent refuses SPECIFIC things, not every subdirectory.

    Without this, every refusal below would also be satisfied by a ``_list_subdirectory`` that
    raised unconditionally — the tightening that looks like a fix and is a denial of service.
    """
    pkg = _make_trusted_pkg(root_base)
    _add_subdir(pkg)  # root-owned, 0755, holds nothing
    assert verify_installed_package_trust(pkg) == _source_aggregate()


def test_a_symlinked_subdirectory_one_level_down_is_refused(root_base):
    """A symlinked directory INSIDE a subdirectory, which is where the descent read it.

    ``os.stat(..., follow_symlinks=False)`` reports a symlink-to-directory as neither a symlink the
    old code looked for nor ``S_ISDIR``, so it fell through the non-directory ``continue`` and the
    subtree behind it was enumerated as NOTHING — silently, with no refusal, which is the one
    outcome this reader must never produce for content it cannot verify.
    """
    pkg = _make_trusted_pkg(root_base)
    sub = _add_subdir(pkg)
    outside = os.path.join(root_base, "outside")
    os.mkdir(outside, 0o755)
    _write_module(outside, "hidden.py")
    os.symlink(outside, os.path.join(sub, "evil"))

    reader = TrustedManifestReader.open(pkg)
    try:
        with pytest.raises(ManifestError) as exc:
            reader.list_modules()
    finally:
        reader.close()
    assert exc.value.reason_code == "manifest_symlinked_directory"


def test_a_symlinked_subdirectory_at_the_top_level_is_refused(root_base):
    """The same refusal at the top level, pinned alongside the nested one so the two sites cannot
    drift apart again — the gap was that only ONE of them enforced it."""
    pkg = _make_trusted_pkg(root_base)
    outside = os.path.join(root_base, "outside_top")
    os.mkdir(outside, 0o755)
    _write_module(outside, "hidden.py")
    os.symlink(outside, os.path.join(pkg, "evil"))

    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg)
    assert exc.value.reason_code == "manifest_symlinked_directory"


def test_both_readers_refuse_the_symlinked_subdirectory_tree_identically(root_base):
    """The ASYMMETRY is the defect, so it is asserted directly rather than left to two separate
    tests that could each keep passing while diverging.

    The source-side reader refused this tree at any depth while the TRUSTED reader — the one whose
    answer becomes ``installed_trust_ok`` — accepted it. A trust claim that holds only because a
    different reader elsewhere happens to refuse is not a guarantee; it is a coincidence one layer
    away. Both readers, same tree, same bounded code.
    """
    pkg = _make_trusted_pkg(root_base)
    sub = _add_subdir(pkg)
    outside = os.path.join(root_base, "outside_parity")
    os.mkdir(outside, 0o755)
    _write_module(outside, "hidden.py")
    os.symlink(outside, os.path.join(sub, "evil"))

    with pytest.raises(ManifestError) as trusted_exc:
        verify_installed_package_trust(pkg)
    with pytest.raises(ManifestError) as real_exc:
        RealManifestReader(pkg).list_modules()
    assert trusted_exc.value.reason_code == "manifest_symlinked_directory"
    assert real_exc.value.reason_code == "manifest_symlinked_directory"
    assert trusted_exc.value.reason_code == real_exc.value.reason_code


def test_a_module_hidden_behind_a_symlinked_subdirectory_cannot_pass_as_the_source_aggregate(
    root_base,
):
    """The operator-visible consequence — and BOUND to the reason code that carries it.

    The hidden module is importable through the package path as a namespace sub-portion, and no
    digest covers it — so if this tree verified, ``verify`` would report ``installed_trust_ok`` and
    ``provenance`` would carry ``trusted: true`` for content the tamper guarantee does not reach.

    The reason code is asserted even though the claim above is the point. This test is one of the
    witnesses that attributes a failure to the DESCENT's refusal specifically, and a bare
    ``pytest.raises(ManifestError)`` is satisfied by ANY refusal on this tree. It is unique in
    effect today; it would stop being so the moment the fixture grew a second fault — a stray
    ``.py``, a mode change — and would then keep passing for a reason unrelated to the site it
    witnesses, while still reading as that site's witness. Unique in name is not unique in effect,
    and binding the code is what keeps the two the same thing as the fixtures change.
    """
    pkg = _make_trusted_pkg(root_base)
    sub = _add_subdir(pkg)
    outside = os.path.join(root_base, "outside_claim")
    os.mkdir(outside, 0o755)
    hidden = _write_module(outside, "backdoor.py", b"BACKDOOR = 1\n")
    os.symlink(outside, os.path.join(sub, "evil"))

    # reachable through the package directory itself, not merely present somewhere on the host
    assert os.path.exists(os.path.join(pkg, "sub", "evil", "backdoor.py"))

    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg, expected_aggregate=_source_aggregate())
    assert exc.value.reason_code == "manifest_symlinked_directory"
    # and editing the hidden module still cannot produce a passing aggregate
    with open(hidden, "ab") as f:
        f.write(b"BACKDOOR = 2\n")
    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg, expected_aggregate=_source_aggregate())
    assert exc.value.reason_code == "manifest_symlinked_directory"


def test_a_directory_below_the_bounded_descent_is_refused_not_skipped(root_base):
    """``manifest_nested_directory_unverifiable`` — catalogued, documented, and produced by no test
    until this one. The descent is bounded at one level and must refuse what it cannot walk."""
    pkg = _make_trusted_pkg(root_base)
    sub = _add_subdir(pkg)
    deeper = os.path.join(sub, "deeper")
    os.mkdir(deeper, 0o755)
    _write_module(deeper, "buried.py")

    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg)
    assert exc.value.reason_code == "manifest_nested_directory_unverifiable"


def test_the_descent_has_no_pycache_name_exemption(root_base):
    """The trusted reader's half of ``test_pycache_needs_no_name_exemption``.

    That test pins the property for the SOURCE reader only, and a name-keyed skip is precisely
    the trap that makes a recursive enumeration worse than a flat one — something could hide
    behind the exempt name. The descent must reach ``__pycache__`` on its content, like any other
    directory: ``.pyc`` is not a module and contributes nothing, a ``.py`` inside it is reported.

    It matters more here than for the source reader, because a real run of this package's own test
    suite WRITES a ``__pycache__`` into the package directory the enumeration walks — the observed
    tree is not static, and the answer must not depend on whether pytest ran first.
    """
    pkg = _make_trusted_pkg(root_base)
    cache = _add_subdir(pkg, "__pycache__")
    _write_module(cache, "verify.cpython-311.pyc", b"\x00")

    # a cache holding only bytecode contributes nothing AND does not refuse
    assert verify_installed_package_trust(pkg) == _source_aggregate()

    # but nothing is keyed on the name, so a .py placed there is REPORTED, not skipped
    _write_module(cache, "sneaky.py")
    reader = TrustedManifestReader.open(pkg)
    try:
        assert "__pycache__/sneaky.py" in reader.list_modules()
    finally:
        reader.close()
    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg)
    assert exc.value.reason_code == "manifest_inventory_mismatch"


@pytest.mark.parametrize(
    ("umask", "mode", "refused"),
    [
        (0o022, 0o755, False),  # the common install posture — verifies
        (0o002, 0o775, True),  # group-writable: a REAL install posture, and refused
        (0o000, 0o777, True),  # group- and other-writable
    ],
    ids=["umask022", "umask002", "umask000"],
)
def test_the_subdirectory_trust_gate_has_no_pycache_exemption_either(
    root_base, umask, mode, refused
):
    """The trust gate applies to ``__pycache__`` by the same rule — a cache directory an
    unprivileged user can write is not made trustworthy by its name.

    Parametrised over the modes a root ``compileall`` ACTUALLY produces, because the interesting
    case is not 0777. It is 0775 from umask 002, which is a normal install posture on plenty of
    hosts: the package is untampered, the cache is root-owned, and it is still refused. That is
    correct — group-writable under a root-owned package dir is a ``.pyc`` injection path — but it
    is an operator-visible exit 15 on a clean install, so it is pinned rather than left to be
    discovered. Only 0755 was covered before, so nothing went red when the docstring's claim that
    "the install's cache passes" stopped being true.
    """
    assert mode == 0o777 & ~umask, "the fixture must model the umask it names"
    pkg = _make_trusted_pkg(root_base)
    cache = _add_subdir(pkg, "__pycache__", mode=mode)
    _write_module(cache, "verify.cpython-311.pyc", b"\x00")
    assert os.stat(cache).st_uid == 0  # root-owned either way; only the mode differs

    if not refused:
        assert verify_installed_package_trust(pkg) == _source_aggregate()
        return
    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg)
    assert exc.value.reason_code == "manifest_ancestor_world_writable"


def test_a_non_root_owned_subdirectory_is_refused(root_base):
    """The subdirectory was the ONE directory in the chain opened without ``_require_trusted_dir``.

    Every ancestor from ``/`` and the package dir itself must be root-owned; a subdirectory read
    through the same trusted fd chain, contributing to the same aggregate, was not checked at all.
    """
    pkg = _make_trusted_pkg(root_base)
    sub = _add_subdir(pkg)
    os.chown(sub, 1000, 0)

    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg)
    assert exc.value.reason_code == "manifest_ancestor_not_root_owned"


def test_a_group_or_other_writable_subdirectory_is_refused(root_base):
    """The other half of the same gate: an unprivileged user who can write the subdirectory can
    change what the enumeration returns, so it is not a trusted directory."""
    pkg = _make_trusted_pkg(root_base)
    sub = _add_subdir(pkg, mode=0o757)
    assert os.stat(sub).st_mode & 0o022  # the fixture really is writable

    with pytest.raises(ManifestError) as exc:
        verify_installed_package_trust(pkg)
    assert exc.value.reason_code == "manifest_ancestor_world_writable"
