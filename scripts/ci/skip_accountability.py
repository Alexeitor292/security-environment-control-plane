"""Make skips in the main pytest corpus accountable.

The specialised CI jobs (both PostgreSQL fences, the four root-security jobs, the device-flow job)
each parse their JUnit and go red on ``skipped != 0``. The four main ``backend-pytest`` shards
enforce nothing, and on a recent run reported 41, 5, 23 and 30 skips that nobody had reviewed. A
test can therefore stop running -- a marker flips, an optional dependency vanishes, a platform gate
changes -- and the corpus silently loses coverage while CI stays green.

This tool closes that. Every skip must be *declared*, and an undeclared one refuses.


TWO READINGS, DELIBERATELY INDEPENDENT
--------------------------------------
A derived expectation is only as independent as its derivation: if the expectation is computed by
the same machinery that produces the observation, both move together and the check passes while
covering nothing. So this tool never derives its expectation from the skip markers the tests use.

* **Runtime reading** -- the JUnit XML pytest emitted for a real run. What actually happened.
* **Structural reading** -- the set of Git-tracked managed test files (from the shard planner,
  which reads Git) versus the nodes collection actually produced. What exists.

The expectation itself is a reviewed, checked-in manifest -- a third artefact a human must edit.


WHY THE RUNTIME READING ALONE IS NOT ENOUGH (measured, not assumed)
-------------------------------------------------------------------
A module skipped at *collection* time -- ``pytest.importorskip`` at module scope, or
``pytest.skip(allow_module_level=True)`` -- is recorded by JUnit as **one** entry, named after the
module, with ``classname=''`` and the message ``collection skipped``. Measured directly:

    module with importorskip + 2 tests   ->  JUnit: 1 entry, reason "collection skipped"
                                        ->  collection: 0 nodes

Both of the module's tests are simply absent, and the *authored* reason is discarded. So an
instrument keyed on skip reasons is blind to exactly the largest coverage loss available: a whole
module going quiet reports as a single bland entry that says nothing about how much was lost.

Worse, the existing inventory proof cannot see it either -- it compares canonical collection to the
sharded union, and a collection-skipped module is absent from *both* sides equally.

The structural reading is what closes this: a managed test file that contributes zero collected
nodes has vanished, and that is reported as a distinct failure from any skip.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO / ".ci" / "skip-manifest.json"

# Messages pytest generates when nobody authored a reason, or when a whole module went quiet.
# These are never acceptable: the first means a skip exists that states no cause, and the second
# means collection lost a module and the real reason was discarded before it reached the report.
PLACEHOLDER_REASONS = {
    "": "a skip with no message at all",
    "unconditional skip": "a bare @pytest.mark.skip that states no reason",
    "collection skipped": "a module that skipped at collection -- its tests are absent entirely",
}


class SkipAccountabilityError(Exception):
    """A refusal. Carries the problems found, never a partial pass."""


@dataclass(frozen=True)
class ObservedSkip:
    """One skip as the JUnit report recorded it."""

    module: str
    name: str
    reason: str

    @property
    def is_collection_level(self) -> bool:
        """A collection-time skip: JUnit gives it an empty classname and names it for the module."""
        return self.module == ""


def load_manifest(path: Path = MANIFEST_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def permitted_reasons(manifest: dict) -> dict[str, str]:
    """Declared reason -> the justification for permitting it."""
    return {entry["reason"]: entry["why"] for entry in manifest["permitted"]}


def observed_skips(junit_paths: list[Path]) -> list[ObservedSkip]:
    """Every skip across one or more JUnit reports.

    Reads what the run actually did. Nothing here consults a marker, a condition or the manifest.
    """
    found: list[ObservedSkip] = []
    for path in junit_paths:
        root = ET.parse(path).getroot()
        for case in root.iter("testcase"):
            skipped = case.find("skipped")
            if skipped is None:
                continue
            found.append(
                ObservedSkip(
                    module=case.get("classname") or "",
                    name=case.get("name") or "",
                    reason=(skipped.get("message") or "").strip(),
                )
            )
    return found


def junit_totals(junit_paths: list[Path]) -> Counter:
    """Suite-level totals, read off the report's own attributes rather than recomputed from the
    testcase elements -- so a report that disagrees with itself is visible."""
    totals: Counter = Counter()
    for path in junit_paths:
        root = ET.parse(path).getroot()
        for suite in root.iter("testsuite"):
            for key in ("tests", "skipped", "failures", "errors"):
                totals[key] += int(suite.get(key, 0))
    return totals


def collected_nodes_by_file(python: str, targets: list[str]) -> dict[str, int]:
    """How many nodes each file contributes, from a real collection pass.

    The structural reading. Independent of both the JUnit report and the skip markers: it asks what
    exists, not what ran.
    """
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [python, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *targets],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    counts: Counter = Counter()
    for line in result.stdout.splitlines():
        line = line.strip()
        if "::" not in line:
            continue
        counts[line.split("::", 1)[0].replace("\\", "/")] += 1
    return dict(counts)


def managed_test_files() -> list[str]:
    """The Git-tracked managed test files, from the shard planner.

    Read through the planner rather than reimplemented, because the planner is the definition of
    "in the corpus" that CI already uses. It reads Git; collection reads the filesystem. Those are
    the two independent sides of the structural check.
    """
    sys.path.insert(0, str(REPO / "scripts" / "ci"))
    import pytest_shards  # noqa: PLC0415

    config = pytest_shards.load_config(REPO / ".ci" / "pytest-suite.json")
    return pytest_shards.managed_files(config, pytest_shards.git_tracked_files())


def verify(
    *,
    junit_paths: list[Path],
    manifest: dict,
    collected: dict[str, int] | None,
    managed: list[str] | None,
) -> list[str]:
    """Every problem found. Returns them all rather than the first, so one run shows the whole
    picture; an empty list is the only pass."""
    problems: list[str] = []
    permitted = permitted_reasons(manifest)
    skips = observed_skips(junit_paths)

    # 1. No placeholder reasons. A skip that states no cause is not accountable, and a
    #    collection-level skip means a module's tests are gone rather than merely idle.
    for skip in skips:
        if skip.reason in PLACEHOLDER_REASONS:
            problems.append(
                f"unaccountable skip in {skip.module or '<module scope>'}::{skip.name} -- "
                f"{PLACEHOLDER_REASONS[skip.reason]}"
            )

    # 2. Fail loudly on the unknown. No 'other' bucket: an unrecognised reason refuses.
    for skip in skips:
        if skip.reason in PLACEHOLDER_REASONS:
            continue  # already reported above; do not report the same skip twice
        if skip.reason not in permitted:
            problems.append(
                f"undeclared skip reason {skip.reason!r} "
                f"({skip.module}::{skip.name}) -- add it to {MANIFEST_PATH.name} with a "
                f"justification, or stop skipping"
            )

    # 3. A declared reason nobody produces is a permit nobody is using. Reported separately from
    #    the environment-conditional case below, which this deliberately does not conflate.
    observed_reasons = {skip.reason for skip in skips}
    always_expected = {
        entry["reason"] for entry in manifest["permitted"] if entry.get("always_expected") is True
    }
    for reason in sorted(always_expected - observed_reasons):
        problems.append(
            f"declared reason {reason!r} is marked always_expected but did not occur -- "
            "either the skip stopped happening (good: remove the entry) or the test vanished"
        )

    # 4. The structural reading: a managed file contributing zero nodes has disappeared from the
    #    corpus. This is the case a skip-only instrument cannot see, and it is reported as its own
    #    failure rather than folded in with skips.
    if collected is not None and managed is not None:
        for path in managed:
            if collected.get(path, 0) == 0:
                problems.append(
                    f"managed test file {path} contributed ZERO collected nodes -- it is in the "
                    "corpus but produced nothing, which a skip report cannot distinguish from a "
                    "file that simply has no tests left"
                )
    return problems


def _report(args) -> int:
    junit_paths = [Path(p) for p in args.junit]
    skips = observed_skips(junit_paths)
    totals = junit_totals(junit_paths)
    print(f"junit totals: {dict(totals)}")
    print(f"skips recorded: {len(skips)}")
    by_reason = Counter(skip.reason for skip in skips)
    print("\nby reason (count, reason):")
    for reason, count in sorted(by_reason.items(), key=lambda kv: (-kv[1], kv[0])):
        marker = "  <-- PLACEHOLDER" if reason in PLACEHOLDER_REASONS else ""
        print(f"  {count:5d}  {reason!r}{marker}")
    print("\nby module:")
    for module, count in sorted(Counter(s.module for s in skips).items()):
        print(f"  {count:5d}  {module or '<module scope>'}")
    return 0


def _verify(args) -> int:
    junit_paths = [Path(p) for p in args.junit]
    manifest = load_manifest()
    collected = managed = None
    if args.structural:
        managed = managed_test_files()
        collected = collected_nodes_by_file(sys.executable, manifest["collect_targets"])
    problems = verify(
        junit_paths=junit_paths, manifest=manifest, collected=collected, managed=managed
    )
    if problems:
        print("SKIP ACCOUNTABILITY FAILED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    total = len(observed_skips(junit_paths))
    print(f"SKIP ACCOUNTABILITY OK: {total} skip(s), every one declared and justified.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    report = sub.add_parser("report", help="print the observed skip inventory")
    report.add_argument("--junit", action="append", required=True)
    report.set_defaults(func=_report)

    check = sub.add_parser("verify", help="refuse on any undeclared or unaccountable skip")
    check.add_argument("--junit", action="append", required=True)
    check.add_argument(
        "--structural",
        action="store_true",
        help="also run a collection pass and refuse if a managed file contributes zero nodes",
    )
    check.set_defaults(func=_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
