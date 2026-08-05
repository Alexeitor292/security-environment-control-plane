"""Shared frontend source scanning for the secret-surface guards.

WHY THIS EXISTS
----------------
``test_openbao_resolver`` and ``test_resolver_activation_security`` each scanned
``apps/web/src`` for forbidden tokens and each ended with ``assert scanned >= 5``. That floor was
written when the frontend was a handful of files. It is now 200+ TypeScript files and growing, so
a floor of five means the scan could collapse to six — a bad glob, a moved directory, a renamed
``WEB_SRC`` root — and the guard would still report green while covering about three percent of
the tree. The thing measured stops being the thing believed to be measured, and the summary line
still reads pass.

Both guards matter: they caught a real secret-surface boundary violation that the entire frontend
test suite missed. So the fix is to make their coverage claim real rather than to relax it.

TWO CHANGES, AND THE FIRST IS THE LOAD-BEARING ONE
----------------------------------------------------
**The floor is replaced by a second, independent source of truth.** ``git ls-files`` is asked what
TypeScript files actually exist under the root, and the scan must have visited exactly those. That
is not a number somebody chose — it tracks the tree, it grows when the tree grows, and it names the
files that were missed rather than reporting a count that happens to clear a bar. A guard whose
coverage is asserted against its own traversal cannot notice the traversal breaking; this one is
checked against something that does not share the bug.

**Violations are collected, not raised on the first one.** Both guards asserted inside the loop, so
they stopped at the first offending file and reported one name. Whoever fixed it learned they were
done when they were not. Every violation is now reported together.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
WEB_SRC = REPO_ROOT / "apps" / "web" / "src"

#: Extensions the guards care about. Kept here so both guards scan the same set, and so the
#: git cross-check below is asking about the same thing the traversal walks.
SOURCE_SUFFIXES = (".ts", ".tsx")

_IGNORED_PARTS = frozenset({".mypy_cache", "node_modules", "dist", "coverage"})


class FrontendScanUnmeasurable(AssertionError):
    """The scan could not establish what it covered, so it refuses to report a verdict.

    A dedicated type: "the guard could not measure" and "the guard measured and found a violation"
    are different outcomes, and a green run must not be reachable from the first.
    """


def _walked(root: Path) -> set[Path]:
    found: set[Path] = set()
    for suffix in SOURCE_SUFFIXES:
        for path in root.rglob(f"*{suffix}"):
            if _IGNORED_PARTS & set(path.parts):
                continue
            found.add(path.resolve())
    return found


def _tracked(root: Path) -> set[Path]:
    """What Git says is actually there — the independent second source of truth.

    Deliberately NOT another ``rglob``. If the traversal above is wrong (wrong root, wrong
    extension, an exclusion that swallows a directory) a second traversal written the same way is
    wrong in the same way and the two agree on a lie.
    """
    try:
        completed = subprocess.run(
            ["git", "ls-files", "--", str(root)],
            capture_output=True,
            text=True,
            check=True,
            cwd=REPO_ROOT,
        )
    except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover - defensive
        raise FrontendScanUnmeasurable(
            "git ls-files could not be run, so the scan's coverage cannot be established against "
            "anything independent of its own traversal"
        ) from exc
    tracked: set[Path] = set()
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        path = (REPO_ROOT / line.strip()).resolve()
        if path.suffix in SOURCE_SUFFIXES and not (_IGNORED_PARTS & set(path.parts)):
            tracked.add(path)
    return tracked


@dataclass(frozen=True)
class Violation:
    path: Path
    token: str

    def describe(self, root: Path) -> str:
        try:
            shown = self.path.relative_to(root)
        except ValueError:  # pragma: no cover - defensive
            shown = self.path
        return f"{shown}: {self.token}"


def scan_frontend_sources(root: Path = WEB_SRC) -> set[Path]:
    """Every frontend source file the guards must cover, proved complete against Git.

    Raises :class:`FrontendScanUnmeasurable` when the traversal and Git disagree — which is the
    case that used to pass silently as long as at least five files happened to be found.
    """
    if not root.is_dir():
        raise FrontendScanUnmeasurable(f"the frontend source root {root} does not exist")

    walked = _walked(root)
    tracked = _tracked(root)
    if not tracked:
        raise FrontendScanUnmeasurable(
            f"Git reports no tracked TypeScript sources under {root}. Either the root moved or the "
            "checkout is not a repository; either way this scan proves nothing."
        )
    missed = tracked - walked
    if missed:
        raise FrontendScanUnmeasurable(
            f"the scan visited {len(walked)} file(s) but Git tracks {len(tracked)} under {root}; "
            f"{len(missed)} tracked file(s) were never opened, so the guard covers less than it "
            f"claims: {sorted(str(p.relative_to(REPO_ROOT)) for p in missed)[:20]}"
        )
    return walked


def assert_no_forbidden_tokens(forbidden, *, root: Path = WEB_SRC) -> int:
    """Scan every frontend source for ``forbidden`` and report EVERY violation at once.

    Returns the number of files scanned, so a caller can assert on it if it wants — but the
    completeness of the scan is already proved against Git, so a count assertion is no longer the
    thing standing between this guard and a silently-empty run.
    """
    scanned = scan_frontend_sources(root)
    violations: list[Violation] = []
    for path in sorted(scanned):
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                violations.append(Violation(path=path, token=token))
    assert not violations, (
        f"{len(violations)} forbidden secret-surface reference(s) in the frontend "
        f"({len(scanned)} file(s) scanned):\n  "
        + "\n  ".join(violation.describe(root) for violation in violations)
    )
    return len(scanned)
