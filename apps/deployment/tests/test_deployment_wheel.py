"""Wheel build / install manifest round-trip (SECP-PR5D, blocker #3).

Builds the distribution WHEEL from the exact source tree, extracts the shipped
``secp_operator_deployment`` modules into a clean location, recomputes the implementation manifest
over the INSTALLED modules, and proves: the wheel's aggregate == the source aggregate, every
covered module is shipped exactly once, no unexpected module is shipped, and MODIFYING a module
inside the extracted wheel INVALIDATES the match. Everything happens in a temp dir — no built wheel
is committed. Wired into CI (runs wherever ``uv`` is available; skips otherwise).
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
from secp_operator_deployment.manifest import (
    COVERED_MODULES,
    RealManifestReader,
    compute_manifest,
)

REPO = Path(__file__).resolve().parents[3]  # apps/deployment/tests -> repo root


def _source_pkg_dir() -> Path:
    import secp_operator_deployment

    return Path(secp_operator_deployment.__file__).resolve().parent


def _source_aggregate() -> str:
    _per, agg = compute_manifest(RealManifestReader(str(_source_pkg_dir())))
    return agg


def _aggregate_of(pkg_dir: Path) -> tuple[dict[str, str], str]:
    return compute_manifest(RealManifestReader(str(pkg_dir)))


@pytest.fixture(scope="module")
def wheel_path(tmp_path_factory) -> Path:  # noqa: ANN001
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build the distribution wheel")
    outdir = tmp_path_factory.mktemp("dist")
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [uv, "build", "--wheel", "--out-dir", str(outdir)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        pytest.fail(f"wheel build failed:\n{proc.stderr[-2000:]}")
    wheels = list(outdir.glob("*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel, got {wheels}"
    return wheels[0]


def _extract_pkg(wheel: Path, dest: Path) -> Path:
    with zipfile.ZipFile(wheel) as zf:
        zf.extractall(dest)
    pkg = dest / "secp_operator_deployment"
    assert pkg.is_dir(), "the wheel did not ship secp_operator_deployment/"
    return pkg


def test_wheel_aggregate_equals_source_and_ships_exact_inventory(wheel_path, tmp_path):
    pkg = _extract_pkg(wheel_path, tmp_path / "extracted")
    per, agg = _aggregate_of(pkg)
    # the shipped wheel's aggregate equals the source aggregate (byte-identical modules)
    assert agg == _source_aggregate()
    # every covered module shipped exactly once; no unexpected module
    shipped = sorted(p.name for p in pkg.glob("*.py"))
    assert tuple(shipped) == tuple(sorted(COVERED_MODULES))
    assert set(per) == set(COVERED_MODULES)
    assert len(shipped) == len(set(shipped))  # no duplicate module


def test_modified_wheel_module_invalidates_the_match(wheel_path, tmp_path):
    pkg = _extract_pkg(wheel_path, tmp_path / "extracted")
    _per, base = _aggregate_of(pkg)
    assert base == _source_aggregate()
    # tamper with a shipped module → the recomputed aggregate no longer matches
    target = pkg / "verify.py"
    target.write_bytes(target.read_bytes() + b"\n# tampered\n")
    _per2, tampered = _aggregate_of(pkg)
    assert tampered != base
    assert tampered != _source_aggregate()
