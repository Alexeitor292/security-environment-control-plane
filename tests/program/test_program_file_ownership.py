"""The collision map must stay true as the repository moves.

The single most dangerous coupling in SECP is the Alembic head literal: it is duplicated
across many files in four planes, and advancing it is an atomic edit. If a new file starts
carrying the head without being listed as serialised, a parallel agent will eventually miss
it and produce a half-advanced head. That is the one part of the map worth enforcing
mechanically rather than by review.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
OWNERSHIP = REPO_ROOT / "docs" / "program" / "FILE_OWNERSHIP.md"
VERSIONS_DIR = REPO_ROOT / "apps" / "api" / "migrations" / "versions"

_REVISION = re.compile(r"^revision\s*(?::[^=\n]*)?=\s*['\"]([^'\"]+)['\"]", re.MULTILINE)
_DOWN_REVISION = re.compile(r"^down_revision\s*(?::[^=\n]*)?=\s*['\"]([^'\"]+)['\"]", re.MULTILINE)


def alembic_head() -> str:
    revisions: set[str] = set()
    parents: set[str] = set()
    for path in VERSIONS_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        match = _REVISION.search(text)
        if match:
            revisions.add(match.group(1))
        parents.update(_DOWN_REVISION.findall(text))
    heads = sorted(revisions - parents)
    assert len(heads) == 1, f"expected exactly one Alembic head, found {heads}"
    return heads[0]


OWNERSHIP_REL = "docs/program/FILE_OWNERSHIP.md"


def files_carrying(literal: str) -> list[str]:
    """Tracked files carrying `literal`, excluding the ownership map itself.

    The map necessarily names the current head; counting it would make the census
    self-referential and would change the answer every time the map is edited.
    """
    completed = subprocess.run(
        ["git", "grep", "-l", literal],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    return sorted(
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip() and line.strip() != OWNERSHIP_REL
    )


@pytest.fixture(scope="module")
def ownership_text() -> str:
    assert OWNERSHIP.is_file(), f"{OWNERSHIP} is missing"
    return OWNERSHIP.read_text(encoding="utf-8")


def test_ownership_document_names_the_current_head(ownership_text: str) -> None:
    """A stale head literal in the map is worse than none: it looks authoritative."""
    head = alembic_head()
    assert head in ownership_text, (
        f"FILE_OWNERSHIP.md does not mention the current Alembic head {head!r}. "
        "The serialised cluster must be re-derived when the head advances."
    )


def test_head_literal_cluster_is_fully_enumerated(ownership_text: str) -> None:
    """Every file carrying the head literal must be visible in the ownership map.

    A file is 'visible' if it is named, or if a directory prefix it lives under is named.
    """
    head = alembic_head()
    carriers = files_carrying(head)
    assert carriers, "expected the head literal to appear somewhere"

    missing: list[str] = []
    for carrier in carriers:
        if carrier in ownership_text:
            continue
        if Path(carrier).name in ownership_text:
            continue
        parents = [str(p).replace("\\", "/") for p in Path(carrier).parents]
        if any(parent and parent != "." and parent in ownership_text for parent in parents):
            continue
        missing.append(carrier)

    assert not missing, (
        "FILE_OWNERSHIP.md must account for every file carrying the Alembic head literal. "
        f"Unlisted: {missing}"
    )


def test_ownership_records_the_real_carrier_count(ownership_text: str) -> None:
    count = len(files_carrying(alembic_head()))
    assert str(count) in ownership_text, (
        f"{count} files currently carry the head literal; FILE_OWNERSHIP.md does not state "
        "that number, so the map has drifted from the tree."
    )


TIER_HEADINGS = ("Tier 1", "Tier 2", "Tier 3", "Tier 4")


@pytest.mark.parametrize("heading", TIER_HEADINGS)
def test_ownership_declares_every_tier(ownership_text: str, heading: str) -> None:
    assert heading in ownership_text, f"FILE_OWNERSHIP.md is missing {heading}"


OPERATOR_ONLY = (
    ".github/**",
    "infra/ci/**",
    "production.py",
    "signing.py",
)


@pytest.mark.parametrize("path", OPERATOR_ONLY)
def test_operator_only_paths_are_listed(ownership_text: str, path: str) -> None:
    assert path in ownership_text, f"{path} must be listed as operator-only"


SHARED_RUNTIME_RESOURCES = (
    "SECP_TEST_POSTGRES_URL",
    ".venv",
    "node_modules",
)


@pytest.mark.parametrize("resource", SHARED_RUNTIME_RESOURCES)
def test_shared_runtime_resources_are_documented(ownership_text: str, resource: str) -> None:
    """Worktrees isolate the working tree and nothing else; these must be called out."""
    assert resource in ownership_text, f"{resource} is a shared resource and must be documented"
