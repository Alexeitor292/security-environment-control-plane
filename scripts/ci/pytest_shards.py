#!/usr/bin/env python3
"""Deterministic, complete pytest sharding + machine-checked coverage proof (SECP CI).

The single source of truth for "the complete required backend test corpus, divided into
balanced parallel shards". It derives its candidate files from Git-tracked files (never
``.venv`` or generated files), assigns every managed test file to exactly one shard, refuses
to let a test silently disappear, and proves — at the pytest *node* level — that the union of
the shards equals the canonical unsharded collection.

Cross-platform (pure Python + ``subprocess``; no bash-only behavior). Runs under ``uv run`` so
``sys.executable -m pytest`` resolves the project venv.

Commands (``python scripts/ci/pytest_shards.py <command>``):

  verify [--collect]   Fail-closed inventory proof. Always checks the file-level partition
                       (roots exist, every managed file assigned exactly once, no unmanaged
                       pytest file, exclusions valid). With ``--collect`` it additionally runs
                       pytest collection and proves the node-ID union/disjointness equality.
  plan                 Print the shard assignment table (files + collected counts + weight).
  list --shard N       Print the files assigned to shard N (one per line).
  count --shard N      Print the collected node count for shard N.
  run --shard N ...    Run pytest for shard N (extra args after the shard are forwarded).
  run-all ...          Run the canonical corpus unsharded (one-command full audit).
  shard-count          Print the configured shard count (for the CI matrix).
  weights-from-junit --junit X [--out Y]
                       (Re)generate committed per-file timing weights from a baseline JUnit XML.

Exit status is non-zero on any verification failure or forwarded pytest failure.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import statistics
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

# A random UUID appended to a stable parametrize case label (for example ``field-<uuid4>``) leaks
# into the pytest node ID and makes it non-deterministic across collection runs. Canonicalize only a
# UUID preceded by that stable ``-`` separator. A UUID that is the entire case ID is semantic test
# data and MUST remain distinct; otherwise two literal invalid-UUID cases can collapse into one.
_VOLATILE_UUID_RE = re.compile(
    r"(?<=-)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def normalize_node_id(node_id: str) -> str:
    """Replace provably-volatile UUID tokens in a node ID with a stable placeholder."""
    return _VOLATILE_UUID_RE.sub("<uuid>", node_id.replace("\\", "/"))


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / ".ci" / "pytest-suite.json"


class InventoryError(Exception):
    """A fail-closed coverage/partition violation."""


@dataclass(frozen=True)
class Config:
    shard_count: int
    roots: tuple[str, ...]
    test_globs: tuple[str, ...]
    exclusions: tuple[str, ...]
    timings_path: str
    raw: dict = field(default_factory=dict)


def load_config(path: Path = DEFAULT_CONFIG) -> Config:
    data = json.loads(path.read_text(encoding="utf-8"))
    shard_count = int(data["shard_count"])
    if shard_count < 1:
        raise InventoryError(f"shard_count must be >= 1, got {shard_count}")
    roots = tuple(_norm(r) for r in data["roots"])
    if not roots:
        raise InventoryError("config defines no roots")
    globs = tuple(data.get("test_globs", ["test_*.py", "*_test.py"]))
    exclusions = tuple(_norm(e["path"]) for e in data.get("exclusions", []))
    return Config(
        shard_count=shard_count,
        roots=roots,
        test_globs=globs,
        exclusions=exclusions,
        timings_path=str(data.get("timings_path", ".ci/pytest-timings.json")),
        raw=data,
    )


# --------------------------------------------------------------------------- pure helpers


def _norm(path: str) -> str:
    """Normalize to a repo-relative forward-slash path."""
    return path.replace("\\", "/").strip("/")


def is_test_file(path: str, globs: tuple[str, ...]) -> bool:
    """True if the file's basename matches a pytest ``python_files`` glob (default patterns)."""
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name, g) for g in globs)


def _under_root(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def managed_files(config: Config, tracked: list[str]) -> list[str]:
    """Every Git-tracked pytest file under a canonical root, minus explicit exclusions.

    Deterministically sorted. A new test file added under a root is automatically included.
    """
    excluded = set(config.exclusions)
    found = [
        p
        for p in tracked
        if p not in excluded
        and is_test_file(p, config.test_globs)
        and any(_under_root(p, r) for r in config.roots)
    ]
    return sorted(set(found))


def unmanaged_pytest_files(config: Config, tracked: list[str]) -> list[str]:
    """Pytest-shaped, Git-tracked files that are NOT under a root and NOT allow-listed.

    A non-empty result is a fail-closed condition: a new test file appeared outside the
    managed roots and was neither included nor deliberately excluded.
    """
    excluded = set(config.exclusions)
    out = [
        p
        for p in tracked
        if is_test_file(p, config.test_globs)
        and p not in excluded
        and not any(_under_root(p, r) for r in config.roots)
    ]
    return sorted(out)


def load_weights(path: Path) -> dict[str, float]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {_norm(k): float(v) for k, v in data.get("weights", {}).items()}


def fallback_weight(weights: dict[str, float]) -> float:
    """Estimate for a file with no committed timing: the median known weight (>=1.0)."""
    if not weights:
        return 1.0
    return max(1.0, float(statistics.median(weights.values())))


def plan_shards(
    files: list[str],
    weights: dict[str, float],
    shard_count: int,
    fallback: float,
) -> list[list[str]]:
    """Deterministic greedy bin-packing (longest-processing-time-first).

    Files are sorted by (weight desc, path asc); each is placed into the currently-lightest
    bin, ties broken by lowest shard index. The result is identical for the same
    (files, weights, shard_count) — never random.
    """
    ordered = sorted(files, key=lambda f: (-weights.get(f, fallback), f))
    bins: list[list[str]] = [[] for _ in range(shard_count)]
    loads = [0.0] * shard_count
    for f in ordered:
        w = weights.get(f, fallback)
        idx = min(range(shard_count), key=lambda k: (loads[k], k))
        bins[idx].append(f)
        loads[idx] += w
    return [sorted(b) for b in bins]


def verify_partition(shards: list[list[str]], expected: list[str]) -> list[str]:
    """Return a list of human-readable partition errors (empty == valid)."""
    errors: list[str] = []
    seen: dict[str, int] = {}
    for i, shard in enumerate(shards):
        for f in shard:
            if f in seen:
                errors.append(f"{f} assigned to shard {seen[f]} AND shard {i} (duplicate)")
            seen[f] = i
    expected_set = set(expected)
    assigned_set = set(seen)
    for missing in sorted(expected_set - assigned_set):
        errors.append(f"{missing} is a managed test file but assigned to NO shard")
    for extra in sorted(assigned_set - expected_set):
        errors.append(f"{extra} is assigned to a shard but is not a managed test file")
    for i, shard in enumerate(shards):
        if not shard:
            errors.append(f"shard {i} is empty (unexpected for shard_count vs. corpus size)")
    return errors


# --------------------------------------------------------------------------- git / pytest


def git_tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [_norm(line) for line in out.stdout.splitlines() if line.strip()]


def collect_node_ids(paths: list[str]) -> set[str]:
    """Collected pytest node IDs for the given paths (parametrized nodes included)."""
    if not paths:
        return set()
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "--no-header",
            "-p",
            "no:cacheprovider",
            *paths,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise InventoryError(
            "pytest collection failed for "
            f"{paths[:3]}{'...' if len(paths) > 3 else ''}:\n{proc.stdout}\n{proc.stderr}"
        )
    nodes: set[str] = set()
    for line in proc.stdout.splitlines():
        line = line.strip()
        if "::" in line and not line.startswith(("<", "=")):
            nodes.add(line.replace("\\", "/"))
    return nodes


# --------------------------------------------------------------------------- orchestration


def build_plan(config: Config) -> tuple[list[str], list[str], list[list[str]]]:
    """Return (managed_files, unmanaged_pytest_files, shards). Raises on stale exclusions."""
    tracked = git_tracked_files()
    tracked_set = set(tracked)
    for exc in config.exclusions:
        if exc not in tracked_set:
            raise InventoryError(f"exclusion path is not Git-tracked (stale manifest): {exc}")
    for root in config.roots:
        if not (REPO_ROOT / root).is_dir():
            raise InventoryError(f"canonical root does not exist: {root}")
    files = managed_files(config, tracked)
    unmanaged = unmanaged_pytest_files(config, tracked)
    weights = load_weights(REPO_ROOT / config.timings_path)
    shards = plan_shards(files, weights, config.shard_count, fallback_weight(weights))
    return files, unmanaged, shards


def cmd_verify(config: Config, do_collect: bool) -> int:
    files, unmanaged, shards = build_plan(config)
    errors: list[str] = []

    if unmanaged:
        errors.append(
            "unmanaged pytest-shaped files outside the canonical roots (add to a root or to "
            "`exclusions` with justification):\n  - " + "\n  - ".join(unmanaged)
        )
    errors.extend(verify_partition(shards, files))

    print(f"managed test files: {len(files)}")
    print(f"shards: {len(shards)}  sizes: {[len(s) for s in shards]}")
    if unmanaged:
        print(f"unmanaged pytest files: {len(unmanaged)}")

    if do_collect:
        canonical_raw = collect_node_ids(list(config.roots))
        shard_raw = [collect_node_ids(s) for s in shards]
        canonical = {normalize_node_id(n) for n in canonical_raw}
        # If normalization merged distinct canonical nodes it could hide an omission; refuse to
        # proceed on a weakened comparison rather than mask it.
        if len(canonical) != len(canonical_raw):
            errors.append(
                "node-id normalization collapsed distinct canonical nodes "
                f"({len(canonical_raw)} -> {len(canonical)}); the volatile-token rule is too broad"
            )
        shard_nodes = [{normalize_node_id(n) for n in s} for s in shard_raw]
        union: set[str] = set()
        for i, ns in enumerate(shard_nodes):
            overlap = union & ns
            if overlap:
                errors.append(
                    f"shard {i} shares {len(overlap)} node(s) with earlier shards, e.g. "
                    f"{sorted(overlap)[:3]}"
                )
            if not ns:
                errors.append(f"shard {i} collected ZERO nodes")
            union |= ns
        missing = canonical - union
        extra = union - canonical
        if missing:
            errors.append(
                f"{len(missing)} canonical node(s) missing from all shards, e.g. "
                f"{sorted(missing)[:5]}"
            )
        if extra:
            errors.append(
                f"{len(extra)} sharded node(s) not in the canonical collection, e.g. "
                f"{sorted(extra)[:5]}"
            )
        print(f"canonical collected nodes: {len(canonical_raw)} ({len(canonical)} normalized)")
        print(f"sharded union nodes:       {len(union)}")
        print(f"per-shard node counts:     {[len(ns) for ns in shard_raw]}")

    if errors:
        print("\nINVENTORY VERIFICATION FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print("\nINVENTORY OK: sharded corpus == canonical corpus (fail-closed proof passed)")
    return 0


def cmd_plan(config: Config) -> int:
    files, unmanaged, shards = build_plan(config)
    weights = load_weights(REPO_ROOT / config.timings_path)
    fb = fallback_weight(weights)
    for i, shard in enumerate(shards):
        load = sum(weights.get(f, fb) for f in shard)
        print(f"shard {i}: {len(shard)} files, est. weight {load:.1f}s")
        for f in shard:
            marker = "" if f in weights else "  (new/estimated)"
            print(f"    {f}{marker}")
    if unmanaged:
        print(f"\nWARNING unmanaged pytest files: {unmanaged}")
    return 0


def cmd_list(config: Config, shard: int) -> int:
    _, _, shards = build_plan(config)
    _check_shard_index(shard, len(shards))
    for f in shards[shard]:
        print(f)
    return 0


def cmd_count(config: Config, shard: int) -> int:
    _, _, shards = build_plan(config)
    _check_shard_index(shard, len(shards))
    print(len(collect_node_ids(shards[shard])))
    return 0


def cmd_run(config: Config, shard: int, extra: list[str]) -> int:
    _, _, shards = build_plan(config)
    _check_shard_index(shard, len(shards))
    files = shards[shard]
    print(f"[shard {shard}/{config.shard_count}] {len(files)} files:", flush=True)
    for f in files:
        print(f"    {f}", flush=True)
    cmd = [sys.executable, "-m", "pytest", *extra, *files]
    print("+ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=REPO_ROOT).returncode


def cmd_run_all(config: Config, extra: list[str]) -> int:
    cmd = [sys.executable, "-m", "pytest", *extra, *config.roots]
    print("+ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=REPO_ROOT).returncode


def cmd_weights_from_junit(config: Config, junit: Path, out: Path) -> int:
    known = managed_files(config, git_tracked_files())
    weights = weights_from_junit(junit, known)
    payload = {
        "description": (
            "Per-file pytest runtime weights (seconds), aggregated from a baseline JUnit run. "
            "Consumed by scripts/ci/pytest_shards.py for deterministic runtime-balanced "
            "bin-packing. Regenerate with `weights-from-junit`."
        ),
        "weights": {k: round(v, 3) for k, v in sorted(weights.items())},
    }
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(weights)} file weights to {out}")
    return 0


def _classname_to_file(classname: str, known: set[str]) -> str:
    """Map a JUnit dotted ``classname`` (``pkg.mod`` or ``pkg.mod.TestClass``) to its file.

    pytest's JUnit omits the ``file`` attribute, so the module boundary is ambiguous in the
    dotted name. Resolve it to the longest dotted prefix that IS a known managed test file, which
    strips any trailing ``TestClass`` component(s). Falls back to the naive whole-name mapping.
    """
    parts = classname.split(".")
    for cut in range(len(parts), 0, -1):
        candidate = "/".join(parts[:cut]) + ".py"
        if candidate in known:
            return candidate
    return "/".join(parts) + ".py"


def weights_from_junit(junit: Path, known_files: list[str] | None = None) -> dict[str, float]:
    """Aggregate per-file wall time from a pytest JUnit XML.

    Prefers the ``file`` attribute when present; otherwise resolves the dotted ``classname`` to a
    known managed file (so class-based tests are attributed to their module, not a fake path).
    """
    known = set(known_files or [])
    tree = ET.parse(junit)
    weights: dict[str, float] = {}
    for case in tree.iter("testcase"):
        file_attr = case.get("file")
        if file_attr:
            path = _norm(file_attr)
        else:
            path = _classname_to_file(case.get("classname", ""), known)
        weights[path] = weights.get(path, 0.0) + float(case.get("time", "0") or 0)
    return weights


def _check_shard_index(shard: int, count: int) -> None:
    if not 0 <= shard < count:
        raise SystemExit(f"shard index {shard} out of range [0, {count})")


# --------------------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("verify", help="fail-closed inventory + optional node-level proof")
    v.add_argument("--collect", action="store_true", help="also run the node-ID coverage proof")

    sub.add_parser("plan", help="print the shard assignment table")
    sub.add_parser("shard-count", help="print the configured shard count")

    ls = sub.add_parser("list", help="print files in one shard")
    ls.add_argument("--shard", type=int, required=True)

    ct = sub.add_parser("count", help="print collected node count for one shard")
    ct.add_argument("--shard", type=int, required=True)

    r = sub.add_parser("run", help="run pytest for one shard")
    r.add_argument("--shard", type=int, required=True)
    r.add_argument("pytest_args", nargs=argparse.REMAINDER)

    ra = sub.add_parser("run-all", help="run the canonical corpus unsharded")
    ra.add_argument("pytest_args", nargs=argparse.REMAINDER)

    w = sub.add_parser("weights-from-junit", help="regenerate timing weights from JUnit XML")
    w.add_argument("--junit", type=Path, required=True)
    w.add_argument("--out", type=Path, default=REPO_ROOT / ".ci" / "pytest-timings.json")
    return parser


def _forwarded(args: list[str]) -> list[str]:
    # argparse.REMAINDER keeps a leading "--"; drop it so pytest sees clean args.
    return args[1:] if args and args[0] == "--" else args


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_config(args.config)
    try:
        if args.command == "verify":
            return cmd_verify(config, args.collect)
        if args.command == "plan":
            return cmd_plan(config)
        if args.command == "shard-count":
            print(config.shard_count)
            return 0
        if args.command == "list":
            return cmd_list(config, args.shard)
        if args.command == "count":
            return cmd_count(config, args.shard)
        if args.command == "run":
            return cmd_run(config, args.shard, _forwarded(args.pytest_args))
        if args.command == "run-all":
            return cmd_run_all(config, _forwarded(args.pytest_args))
        if args.command == "weights-from-junit":
            return cmd_weights_from_junit(config, args.junit, args.out)
    except InventoryError as exc:
        print(f"INVENTORY ERROR: {exc}", file=sys.stderr)
        return 1
    raise SystemExit(f"unknown command {args.command!r}")


if __name__ == "__main__":
    raise SystemExit(main())
