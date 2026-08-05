"""``models.Artifact`` is declared, migrated, and never written. This test says so, and checks.

WHY A TEST AND NOT JUST A COMMENT
----------------------------------
A comment saying "nothing writes this" is true on the day it is written and silently false
afterwards. This assertion fails the moment a producer appears, which is exactly when the docstring
on the model needs updating — so the claim and the code cannot drift apart.

The trap being guarded is a specific one. ``Artifact`` carries ``kind``, ``sha256``, ``uri`` and
``created_at``, which maps almost field-for-field onto what a client would want from an evidence or
artifact index. A reader who finds it will reasonably assume it is populated and build against it.
It is not populated, and there is no artifact store for ``uri`` to point at, so a read surface over
it would return an empty list forever — and an empty list reads as "no evidence exists", which is a
claim, where a missing route reads as "not built yet", which is the truth.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


class ArtifactScanUnmeasurable(AssertionError):
    """The scan could not establish what it covered, so it declines to return a verdict."""


def _tracked_python_files() -> list[Path]:
    """Ask Git, not the filesystem.

    A ``.gitignore`` rule can swallow a directory while ``git status`` stays silent, and this repo
    has been bitten by exactly that. The committed tree is the thing the claim is about.
    """
    try:
        completed = subprocess.run(
            ["git", "ls-files", "--", "*.py"],
            capture_output=True,
            check=True,
            cwd=REPO_ROOT,
        )
    except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover - defensive
        raise ArtifactScanUnmeasurable("git ls-files could not be run") from exc
    files = [
        REPO_ROOT / line.strip()
        for line in completed.stdout.decode("utf-8").splitlines()
        if line.strip()
    ]
    if not files:
        raise ArtifactScanUnmeasurable("Git reports no tracked Python files; this proves nothing")
    return files


def _constructions(paths: list[Path], symbol: str) -> list[str]:
    """Every ``symbol(...)`` call in the tracked tree, by AST.

    By AST rather than by text so a mention in a docstring — including this module's own — is not
    counted. That is the same mistake a text scan made in the audit-outcome guard, caught by a
    cross-check; here the shape is avoided rather than detected.
    """
    found: list[str] = []
    for path in paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, SyntaxError):  # pragma: no cover - defensive
            continue
        try:
            rel = str(path.relative_to(REPO_ROOT)).replace("\\", "/")
        except ValueError:  # a planted file in tmp_path, used by the red-direction tests
            rel = str(path).replace("\\", "/")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = (
                    func.id
                    if isinstance(func, ast.Name)
                    else func.attr
                    if isinstance(func, ast.Attribute)
                    else None
                )
                if name == symbol:
                    found.append(f"{rel}:{node.lineno}")
    return found


def test_artifact_table_has_no_producer() -> None:
    """Nothing constructs an ``Artifact``, anywhere in the committed tree.

    When this fails, the table has gained a producer — which is good news, and it means the
    docstring on ``secp_api.models.Artifact`` is now wrong and a read surface may finally be
    honest. Update both together.
    """
    producers = _constructions(_tracked_python_files(), "Artifact")
    assert not producers, (
        "secp_api.models.Artifact now has a producer, so the model's docstring — which states that "
        "nothing writes it and that no artifact store exists — is out of date. Update it, and "
        "revisit whether a read surface over the table is now truthful:\n  "
        + "\n  ".join(producers)
    )


def test_the_scan_would_notice_a_producer(tmp_path: Path) -> None:
    """Red-direction. An assertion that has only ever been observed passing proves nothing.

    A guard whose success branch is "pattern not found" is satisfied by a broken scan, so the scan
    must be shown to find a planted case before its silence means anything.
    """
    planted = tmp_path / "planted.py"
    planted.write_text(
        "from secp_api.models import Artifact\n"
        "def go(session):\n"
        "    session.add(Artifact(kind='plan', name='x'))\n",
        encoding="utf-8",
    )
    found = _constructions([planted], "Artifact")
    assert len(found) == 1, "the scan cannot see a construction, so its silence means nothing"


def test_the_scan_ignores_mentions_that_are_not_constructions(tmp_path: Path) -> None:
    """A docstring, a comment, an import and a type annotation are not producers.

    Without this the guard would fire on its own explanatory prose and get relaxed or deleted —
    the way a guard that cries wolf always does, leaving the real producer unguarded afterwards.
    """
    planted = tmp_path / "mentions.py"
    planted.write_text(
        '"""Artifact is never constructed here."""\n'
        "from secp_api.models import Artifact\n"
        "# Artifact(kind='plan') would be a producer\n"
        "SAMPLE = \"Artifact(kind='plan')\"\n"
        "def go() -> Artifact | None:\n"
        "    return None\n",
        encoding="utf-8",
    )
    assert _constructions([planted], "Artifact") == []


def test_the_real_tree_is_actually_being_scanned() -> None:
    """Positive control: the scan must find a symbol that certainly IS constructed.

    Otherwise ``no producers found`` is indistinguishable from ``nothing was scanned`` — the two
    have the same output and opposite meanings, and only one of them is a finding.
    """
    found = _constructions(_tracked_python_files(), "AuditEvent")
    assert found, (
        "the scan found no AuditEvent constructions either, so it is not reaching the tree and the "
        "Artifact result above is vacuous rather than informative"
    )
