"""The real implementation manifest over the covered package modules (SECP-PR5D, blocker #5)."""

from __future__ import annotations

import os

import pytest
from secp_operator_deployment import package_implementation_digest
from secp_operator_deployment.manifest import (
    COVERED_MODULES,
    InMemoryManifestReader,
    ManifestError,
    RealManifestReader,
    compute_manifest,
)


def _full_files(content_overrides: dict | None = None) -> dict:
    files = {name: (name + " contents").encode("utf-8") for name in COVERED_MODULES}
    if content_overrides:
        files.update({k: v for k, v in content_overrides.items()})
    return files


def test_manifest_is_deterministic_and_aggregate_covers_all_modules():
    per, agg = compute_manifest(InMemoryManifestReader(_full_files()))
    assert set(per) == set(COVERED_MODULES)
    per2, agg2 = compute_manifest(InMemoryManifestReader(_full_files()))
    assert agg == agg2 and per == per2
    assert agg.startswith("sha256:")


def test_real_package_manifest_equals_public_digest():
    import secp_operator_deployment

    pkg_dir = os.path.dirname(secp_operator_deployment.__file__)
    _per, agg = compute_manifest(RealManifestReader(pkg_dir))
    assert agg == package_implementation_digest()


def test_content_mutation_changes_aggregate_even_with_same_label():
    # PACKAGE_IMPLEMENTATION_ID is a constant; changing a covered module's CONTENT changes the
    # digest.
    _p, base = compute_manifest(InMemoryManifestReader(_full_files()))
    mutated = _full_files({"compositions.py": b"TAMPERED"})
    _p2, changed = compute_manifest(InMemoryManifestReader(mutated))
    assert base != changed


def test_extra_module_on_disk_refuses():
    files = _full_files()
    listing = (*COVERED_MODULES, "sneaky.py")
    with pytest.raises(ManifestError) as exc:
        compute_manifest(InMemoryManifestReader(files, listing=listing))
    assert exc.value.reason_code == "manifest_inventory_mismatch"


def test_missing_covered_module_refuses():
    files = _full_files()
    missing = tuple(n for n in COVERED_MODULES if n != "runner.py")
    with pytest.raises(ManifestError) as exc:
        compute_manifest(InMemoryManifestReader(files, listing=missing))
    assert exc.value.reason_code == "manifest_inventory_mismatch"


def test_symlinked_covered_module_refuses():
    files = _full_files()
    reader = InMemoryManifestReader(files, symlinks=frozenset({"verify.py"}))
    with pytest.raises(ManifestError):
        compute_manifest(reader)


def test_fixed_inventory_lists_reviewed_executable_modules():
    # The inventory is a fixed, closed set — it can only change by review.
    assert "runner.py" in COVERED_MODULES
    assert "compositions.py" in COVERED_MODULES
    assert "host_process.py" in COVERED_MODULES
    assert "pinned_exec.py" in COVERED_MODULES
    assert len(COVERED_MODULES) == len(set(COVERED_MODULES))


# --------------------------------------------------------------------------- nested-module hiding
#
# WS-E: `list_modules` was a FLAT listing filtered to `.py`, so a nested module appeared in neither
# the listing nor COVERED_MODULES. `present != covered` did not trip, and the file sat silently
# outside the implementation aggregate — tampering with it would not change the digest. That is a
# hole in a tamper-detection guarantee, and it made `provenance`'s "the installed content
# recomputes to its reviewed aggregate" true of a subset while reading as true of the package.


def test_the_real_reader_enumerates_nested_modules(tmp_path):
    """Coverage proof: build the tree that defeated the flat listing and require the production
    reader to return the nested path, not merely to be recursive in principle."""
    from secp_operator_deployment.manifest import RealManifestReader

    pkg = tmp_path / "secp_operator_deployment"
    (pkg / "adapters").mkdir(parents=True)
    (pkg / "verify.py").write_text("", encoding="utf-8")
    (pkg / "adapters" / "systemd.py").write_text("import subprocess\n", encoding="utf-8")

    names = set(RealManifestReader(str(pkg)).list_modules())
    assert "adapters/systemd.py" in names, "a nested module is still invisible to the manifest"
    assert "verify.py" in names  # flat modules keep their bare name, so COVERED_MODULES still fits


def test_a_nested_module_makes_the_inventory_check_refuse(tmp_path):
    """And that the enumeration change actually reaches the guarantee: the aggregate refuses."""
    import pytest
    from secp_operator_deployment.manifest import (
        COVERED_MODULES,
        ManifestError,
        RealManifestReader,
        compute_manifest,
    )

    pkg = tmp_path / "secp_operator_deployment"
    (pkg / "adapters").mkdir(parents=True)
    for name in COVERED_MODULES:
        (pkg / name).write_text("", encoding="utf-8")
    (pkg / "adapters" / "systemd.py").write_text("hidden\n", encoding="utf-8")

    with pytest.raises(ManifestError) as excinfo:
        compute_manifest(RealManifestReader(str(pkg)))
    assert excinfo.value.reason_code == "manifest_inventory_mismatch"


def test_pycache_needs_no_name_exemption(tmp_path):
    """The content filter already ignores it — so no name-keyed skip exists to hide behind.

    A name-based exemption is what would make a recursive scan WORSE than a flat one, which is the
    trap this fix was required to avoid.
    """
    from secp_operator_deployment.manifest import RealManifestReader

    pkg = tmp_path / "secp_operator_deployment"
    (pkg / "__pycache__").mkdir(parents=True)
    (pkg / "verify.py").write_text("", encoding="utf-8")
    (pkg / "__pycache__" / "verify.cpython-311.pyc").write_bytes(b"\x00")

    assert set(RealManifestReader(str(pkg)).list_modules()) == {"verify.py"}

    # But a .py placed there is NOT skipped, because nothing is keyed on the directory's name.
    (pkg / "__pycache__" / "sneaky.py").write_text("", encoding="utf-8")
    assert "__pycache__/sneaky.py" in set(RealManifestReader(str(pkg)).list_modules())


def test_a_missing_package_dir_raises_rather_than_enumerating_nothing(tmp_path):
    """``os.walk`` swallows enumeration errors by default, so a missing or unreadable directory
    returned ``()`` — and an empty listing against a flat inventory is indistinguishable from a
    tampered one until the counts differ. Not-present and not-readable must not look like clean.
    """
    import pytest
    from secp_operator_deployment.manifest import ManifestError, RealManifestReader

    with pytest.raises(ManifestError) as excinfo:
        RealManifestReader(str(tmp_path / "does_not_exist")).list_modules()
    assert excinfo.value.reason_code == "manifest_dir_unreadable"


def test_a_symlinked_subdirectory_is_refused_not_skipped(tmp_path):
    """Neither reader DESCENDS a symlinked directory, so one would enumerate nothing silently —
    the same "contributes nothing" failure as an unreadable subtree.

    A plain nested directory is refused, and placing a symlink needs the same write access to the
    root-owned package dir, so the asymmetry is the finding rather than the privilege level.
    """
    import pytest
    from secp_operator_deployment.manifest import ManifestError, RealManifestReader

    pkg = tmp_path / "secp_operator_deployment"
    pkg.mkdir()
    (pkg / "verify.py").write_text("", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "systemd.py").write_text("hidden\n", encoding="utf-8")
    try:
        (pkg / "adapters").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")

    with pytest.raises(ManifestError) as excinfo:
        RealManifestReader(str(pkg)).list_modules()
    assert excinfo.value.reason_code == "manifest_symlinked_directory"


def test_the_symlinked_directory_refusal_is_expressed_once_and_reused_at_every_site():
    """One rule, one expression — the property, not "site 3 now also refuses".

    Three sites enumerate directory entries and none of them descends a symlinked directory, so
    each must refuse one. The rule was written at two of them and missed at the third, inside the
    very function the descent lives in. Three hand-written copies is the enumeration problem in
    miniature: an attacker needs only the most lenient copy, and a fourth site — the descent bound
    moving past one level — would invite a fourth.

    So this asserts the SHAPE that makes that unrepeatable: the ``raise`` exists exactly once, and
    each of the three sites reaches it through the shared helper. A site can then fail to CALL the
    rule, which is visible here, but cannot restate it differently.

    Structural on purpose, and it is not the whole guard: the behavioural half is
    ``test_a_symlinked_subdirectory_is_refused_not_skipped`` above for the source reader, and the
    two trusted-reader cases in ``test_deployment_root_manifest.py``, which need POSIX + root.
    """
    import ast
    import pathlib

    from secp_operator_deployment import manifest

    tree = ast.parse(pathlib.Path(manifest.__file__).read_text(encoding="utf-8"))

    def _calls_in(node: ast.AST) -> int:
        return sum(
            1
            for n in ast.walk(node)
            if isinstance(n, ast.Call)
            and getattr(n.func, "id", None) == "_refuse_symlinked_directory"
        )

    raises = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Raise)
        and isinstance(n.exc, ast.Call)
        and getattr(n.exc.func, "id", None) == "ManifestError"
        and n.exc.args
        and isinstance(n.exc.args[0], ast.Constant)
        and n.exc.args[0].value == "manifest_symlinked_directory"
    ]
    assert len(raises) == 1, (
        f"the refusal is raised at {len(raises)} places — express it once and call it, so a site "
        "can only fail to apply the rule, never restate it differently"
    )

    classes = {c.name: c for c in tree.body if isinstance(c, ast.ClassDef)}
    assert _calls_in(classes["RealManifestReader"]) == 1, "the source-side walk must call it"
    assert _calls_in(classes["TrustedManifestReader"]) == 2, (
        "the trusted reader has TWO enumeration sites — the package dir and the one-level "
        "descent — and both must call it; one call means the descent is unguarded again"
    )


def test_the_new_manifest_reason_codes_are_catalogued():
    """An operator meeting either must be able to look it up like any other."""
    from secp_operator_deployment.verify import classify_reason_code

    for code in (
        "manifest_dir_unreadable",
        "manifest_symlinked_directory",
        "manifest_nested_directory_unverifiable",
    ):
        assert classify_reason_code(code) is not None, code
