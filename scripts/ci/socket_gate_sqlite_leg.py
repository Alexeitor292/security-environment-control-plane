#!/usr/bin/env python3
"""Run the socket gate's body against SQLite and enforce the outcome strictly.

    python scripts/ci/socket_gate_sqlite_leg.py --runs 5

Why this exists
---------------
The gate is currently scoped to PostgreSQL. That scoping is a CI-coupling decision, **not** a claim
that SQLite hides the defect — it does not, and 110/110 local runs say so. Before the scoping is
widened (a two-line deletion that would put the gate into the required shards and every developer's
loop), the same body has to be characterised on the platform that actually matters: a Linux runner.
This leg gathers that distribution on a job that is already red-or-green, so a platform difference
surfaces here rather than on every stream's PR.

Why an overlay rather than an env-var escape hatch
--------------------------------------------------
The shipped module is left **byte-for-byte untouched**. This builds a temporary copy under a
different package name and removes exactly the two engine-scope guards — `pytestmark`'s skipif and
`_require_postgresql`'s dialect assertion — then repoints the engine fixture at SQLite. Those two
guards are precisely what promotion would delete, so what runs here is a **preview of the promoted
module**, not an approximation of it.

The alternative — an opt-in env var inside the module — would have meant editing the two lines the
owner asked to leave alone, and would have left a permanent widening seam behind after promotion
made it redundant. This scaffold is meant to be deleted when the scoping is widened.

Fail-closed in every direction: a substitution that does not land, a copy that still references the
shipped package, a run that produces no JUnit, or any outcome other than the expected violation all
exit non-zero. An inconclusive is a hard failure here, exactly as on the PostgreSQL leg — if Linux
behaves differently from the machine this was characterised on, that must be loud and immediate.
"""

from __future__ import annotations

import argparse
import ast
import collections
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SHIPPED_PACKAGE = REPO_ROOT / "apps/api/socket_gate_tests"
MODULE_NAME = "test_api_read_after_write_over_socket.py"
OVERLAY_PACKAGE = "socket_gate_sqlite_preview"
GATE_TEST = "test_a_created_template_is_readable_by_the_immediately_following_request"

VIOLATION = "VIOLATION"
INCONCLUSIVE = "INCONCLUSIVE"
PASSED = "PASS"


class OverlayError(RuntimeError):
    """The preview could not be built faithfully, so nothing it produced would mean anything."""


def build_overlay(root: Path) -> Path:
    """Copy the shipped package, remove ONLY the two scope guards, prove every edit landed."""
    package = root / OVERLAY_PACKAGE
    shutil.copytree(SHIPPED_PACKAGE, package)
    target = package / MODULE_NAME
    text = target.read_text(encoding="utf-8")

    # 1. the module-level PostgreSQL skipif
    replaced = re.sub(
        r"pytestmark = pytest\.mark\.skipif\(\n.*?\n\)\n",
        "pytestmark = []  # engine scope removed for the SQLite preview only\n",
        text,
        count=1,
        flags=re.S,
    )
    if replaced == text:
        raise OverlayError("the pytestmark skipif was not found; the shipped module has changed")
    text = replaced

    # 2. the per-test dialect assertion
    dialect = '    if engine.dialect.name != "postgresql":'
    if text.count(dialect) != 1:
        raise OverlayError(f"expected exactly one dialect guard, found {text.count(dialect)}")
    text = text.replace(dialect, "    if False:  # SQLite preview", 1)

    # 3. the engine fixture must build SQLite instead of PostgreSQL
    pg_fixture = (
        "    assert PG_URL\n"
        "    engine = reset_engine_for_tests(PG_URL)\n"
        "    with engine.begin() as conn:\n"
        '        conn.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")\n'
        '        conn.exec_driver_sql("CREATE SCHEMA public")\n'
    )
    if pg_fixture not in text:
        raise OverlayError("the PostgreSQL engine fixture body was not found; module has changed")
    text = text.replace(
        pg_fixture,
        "    import tempfile as _tf\n"
        "    from pathlib import Path as _P\n"
        "    _dir = _P(_tf.mkdtemp(prefix='secp-sqlite-preview-'))\n"
        "    engine = reset_engine_for_tests(\n"
        "        f\"sqlite+pysqlite:///{(_dir / 'gate.db').as_posix()}\"\n"
        "    )\n",
        1,
    )

    # 4. the intra-package import must resolve to the OVERLAY, never to the shipped package that
    #    `apps/api` (on pythonpath) would otherwise satisfy silently.
    shipped_import = "from socket_gate_tests.live_api_server import"
    if shipped_import not in text:
        raise OverlayError("the intra-package import was not found; module has changed")
    text = text.replace(shipped_import, f"from {OVERLAY_PACKAGE}.live_api_server import", 1)

    target.write_text(text, encoding="utf-8")

    written = target.read_text(encoding="utf-8")
    problems = []
    if "pytest.mark.skipif" in written:
        problems.append("a skipif marker survived")
    if 'engine.dialect.name != "postgresql"' in written:
        problems.append("the dialect guard survived")
    if "socket_gate_tests" in written:
        problems.append("a reference to the shipped package survived")
    if "reset_engine_for_tests(PG_URL)" in written:
        problems.append("the PostgreSQL engine binding survived")
    if problems:
        raise OverlayError("; ".join(problems))
    ast.parse(written)  # a syntax error would fail every run for the wrong reason
    return target


def classify(junit: Path) -> tuple[str, str]:
    if not junit.exists():
        return "OTHER(no junit)", ""
    root = ET.parse(junit).getroot()
    for case in root.iter("testcase"):
        if case.get("name") != GATE_TEST:
            continue
        skipped = case.find("skipped")
        if skipped is not None:
            if skipped.get("type") == "pytest.xfail":
                return VIOLATION, ""
            return "OTHER(plain skip)", (skipped.get("message") or "")[:200]
        failure = case.find("failure")
        if failure is not None:
            detail = ((failure.get("message") or "") + " " + (failure.text or ""))[:400]
            if "LiveGateInconclusive" in detail:
                return INCONCLUSIVE, detail
            if "XPASS" in detail:
                return PASSED, detail
            return "OTHER(failure)", detail
        return PASSED, ""
    return "OTHER(gate test absent)", ""


def run_once(module: Path, overlay_root: Path, index: int) -> tuple[str, float, str]:
    work = Path(tempfile.mkdtemp(prefix=f"secp-sqlite-leg-{index}-"))
    junit = work / "junit.xml"
    env = dict(os.environ)
    env.pop("SECP_TEST_POSTGRES_URL", None)  # the preview must not reach a real PostgreSQL
    env["SECP_APP_ENV"] = "test"
    env["PYTHONPATH"] = str(overlay_root)
    started = time.perf_counter()
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(module),
            "-q",
            "-p",
            "no:cacheprovider",
            f"--junitxml={junit}",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    elapsed = time.perf_counter() - started
    verdict, detail = classify(junit)
    if verdict != VIOLATION and not detail:
        detail = (proc.stdout or "")[-400:]
    shutil.rmtree(work, ignore_errors=True)
    return verdict, elapsed, detail


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--summary", type=Path, default=REPO_ROOT / "sqlite-leg-summary.json")
    args = parser.parse_args()
    if args.runs < 1:
        print("::error::--runs must be >= 1; a zero-run leg would pass vacuously")
        return 1

    shipped = SHIPPED_PACKAGE / MODULE_NAME
    before = hashlib.sha256(shipped.read_bytes()).hexdigest()

    root = Path(tempfile.mkdtemp(prefix="secp-sqlite-preview-"))
    try:
        module = build_overlay(root)
    except OverlayError as exc:
        print(f"::error::the SQLite preview could not be built faithfully: {exc}")
        return 1
    print(
        f"platform: {platform.system()} {platform.release()} / python {platform.python_version()}"
    )
    print(f"SQLite preview built at {module}")
    print(f"shipped module sha256 {before[:16]}… (must be unchanged at exit)")
    print(f"running the gate {args.runs}x on SQLite\n")

    results = [run_once(module, root, i) for i in range(args.runs)]
    for index, (verdict, elapsed, detail) in enumerate(results, 1):
        print(f"  run {index}/{args.runs}: {verdict} ({elapsed:.1f}s)")
        if detail and verdict != VIOLATION:
            print(f"      {detail[:300]}")

    counts = collections.Counter(verdict for verdict, _, _ in results)
    durations = sorted(elapsed for _, elapsed, _ in results)
    print(f"\nDISTRIBUTION ({platform.system()} {platform.release()}):")
    for verdict, count in counts.most_common():
        print(f"  {verdict:<22} {count:>3} / {len(results)}")
    print(
        f"  wall clock: min {durations[0]:.1f}s  p50 {durations[len(durations) // 2]:.1f}s  "
        f"max {durations[-1]:.1f}s"
    )
    args.summary.write_text(
        json.dumps(
            {
                "runs": len(results),
                "counts": dict(counts),
                "seconds": {"min": durations[0], "max": durations[-1]},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"\nsummary written to {args.summary}")

    shutil.rmtree(root, ignore_errors=True)

    # The preview must never have touched the shipped module. Checked, not asserted in prose.
    after = hashlib.sha256(shipped.read_bytes()).hexdigest()
    if after != before:
        print(
            f"::error::the shipped gate module changed during this run ({before[:16]} -> "
            f"{after[:16]}); the preview is supposed to be a temp copy and nothing else"
        )
        return 1
    print(f"shipped module unchanged: sha256 {after[:16]}…")

    # An inconclusive is a HARD failure here, exactly as on the PostgreSQL leg. This leg exists to
    # discover a platform difference loudly; tolerating one would defeat the entire point.
    if counts[VIOLATION] != len(results):
        print(
            f"::error::expected {len(results)}/{len(results)} {VIOLATION}, got "
            f"{dict(counts)}. Either the SQLite leg is not deterministic on this platform, or the "
            "defect's behaviour differs here — both must block promotion of the engine scoping."
        )
        return 1
    print(
        f"\nSQLite leg: {len(results)}/{len(results)} {VIOLATION}, 0 inconclusive. The gate's body "
        "reproduces the defect on this platform."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
