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
