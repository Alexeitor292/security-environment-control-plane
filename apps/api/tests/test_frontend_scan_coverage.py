"""The frontend secret-surface scan proves its own coverage — and is proved IN THE RED DIRECTION.

The two guards that use ``frontend_scan`` are load-bearing: they caught a real secret-surface
boundary violation that the whole frontend test suite missed. Both used to end with
``assert scanned >= 5``, a floor written when ``apps/web/src`` was a handful of files. It is now
200+, so the scan could have collapsed to six files — a bad glob, a moved root, a renamed
constant — and still reported green while covering about three percent of the tree.

A guard that cannot fail is not a guard, so this module makes it fail on purpose:

* point the scan at a directory Git does not track and it REFUSES rather than passing on a small
  clean sample;
* hide files from the traversal and it names them instead of quietly covering less;
* plant a forbidden token and it reports EVERY violation, not the first.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from frontend_scan import (
    REPO_ROOT,
    WEB_SRC,
    FrontendScanUnmeasurable,
    assert_no_forbidden_tokens,
    scan_frontend_sources,
)


def test_the_scan_covers_the_whole_tracked_frontend():
    """Coverage asserted against Git, which does not share the traversal's bugs."""
    scanned = scan_frontend_sources()
    assert len(scanned) > 100, (
        f"only {len(scanned)} frontend source(s) were scanned. The tree has hundreds; a number "
        "this small means the traversal is broken, which is exactly what the old floor of five "
        "could not notice."
    )
    assert all(path.is_file() for path in scanned)
    assert all(path.suffix in (".ts", ".tsx") for path in scanned)


def test_a_directory_git_does_not_track_is_refused_not_passed(tmp_path: Path):
    """THE RED DIRECTION the floor could never express.

    A handful of clean files used to be enough to satisfy ``scanned >= 5``. Point the scan at a
    small clean directory now and it refuses to report a verdict at all, because it cannot
    establish that it covered anything real.
    """
    fake = tmp_path / "src"
    fake.mkdir()
    for name in ("a.ts", "b.ts", "c.ts", "d.tsx", "e.tsx", "f.ts"):
        (fake / name).write_text("export const clean = true;\n", encoding="utf-8")

    # Six clean files: comfortably over the old floor of five.
    assert len(list(fake.rglob("*.ts"))) + len(list(fake.rglob("*.tsx"))) == 6
    with pytest.raises(FrontendScanUnmeasurable) as excinfo:
        scan_frontend_sources(fake)
    # Either refusal is correct and which one fires depends on whether the path is inside the
    # repository at all — `git ls-files` errors for a path outside it and returns nothing for an
    # untracked path inside it. What matters is that neither is a pass.
    message = str(excinfo.value)
    assert (
        "no tracked TypeScript sources" in message or "git ls-files could not be run" in message
    ), message
    assert "cannot be established" in message or "proves nothing" in message


def test_a_missing_root_is_refused(tmp_path: Path):
    with pytest.raises(FrontendScanUnmeasurable):
        scan_frontend_sources(tmp_path / "does-not-exist")


def test_a_traversal_that_misses_tracked_files_is_refused(monkeypatch):
    """If the walk starts skipping files Git knows about, the guard says which ones.

    This is the shape the floor was blind to: the traversal keeps working, just over less. Here it
    is simulated by making the walk drop everything under one directory, and the scan must name the
    files rather than reporting a smaller-but-passing count.
    """
    import frontend_scan

    real_walk = frontend_scan._walked

    def crippled(root: Path) -> set[Path]:
        return {path for path in real_walk(root) if "api" not in path.parts}

    monkeypatch.setattr(frontend_scan, "_walked", crippled)
    with pytest.raises(FrontendScanUnmeasurable) as excinfo:
        scan_frontend_sources()
    message = str(excinfo.value)
    assert "were never opened" in message
    assert "covers less than it claims" in message


def test_every_violation_is_reported_not_just_the_first(tmp_path: Path, monkeypatch):
    """A guard that reports 1 of N teaches whoever fixes it that they are done when they are not."""
    import frontend_scan

    root = tmp_path / "src"
    root.mkdir()
    offenders = {}
    for name in ("one.ts", "two.ts", "three.tsx"):
        path = root / name
        path.write_text("const field = 'type=\"password\"';\n", encoding="utf-8")
        offenders[name] = path.resolve()
    (root / "clean.ts").write_text("export const ok = true;\n", encoding="utf-8")

    # Stand in for Git: this temp tree is genuinely not tracked, and the point of this test is the
    # violation reporting rather than the coverage proof, which has its own tests above.
    monkeypatch.setattr(frontend_scan, "_tracked", lambda _root: frontend_scan._walked(root))

    with pytest.raises(AssertionError) as excinfo:
        assert_no_forbidden_tokens(('type="password"',), root=root)
    message = str(excinfo.value)
    assert "3 forbidden secret-surface reference(s)" in message
    for name in offenders:
        assert name in message, f"{name} was not named; the guard stopped early again"
    assert "clean.ts" not in message


def test_the_real_frontend_is_clean_and_the_scan_says_how_much_it_read():
    """The positive case, with the count reported rather than merely cleared."""
    scanned = assert_no_forbidden_tokens(('type="password"', "readSecret", "resolveSecret"))
    assert scanned == len(scan_frontend_sources())
    assert scanned > 100


def test_the_scan_root_is_the_real_frontend():
    assert WEB_SRC == REPO_ROOT / "apps" / "web" / "src"
    assert WEB_SRC.is_dir()
